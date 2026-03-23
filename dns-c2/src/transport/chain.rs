//! Transport chain — orchestrates multiple channels with failover.

use super::channel::{ChannelHealth, ChannelState};
use super::TransportError;
use log::{info, warn};

/// Multi-channel transport chain with automatic failover
pub struct TransportChain {
    channels: Vec<ChannelState>,
    /// Strategy for selecting the next channel
    strategy: FailoverStrategy,
    /// Maximum attempts across all channels
    max_total_attempts: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum FailoverStrategy {
    /// Try channels in priority order (lowest priority number first)
    Priority,
    /// Round-robin across healthy channels
    RoundRobin,
    /// Pick the channel with the lowest average latency
    LowestLatency,
    /// Random selection among healthy channels (harder to fingerprint)
    Random,
}

impl TransportChain {
    pub fn new(channels: Vec<ChannelState>, strategy: FailoverStrategy) -> Self {
        let mut sorted = channels;
        sorted.sort_by_key(|c| c.priority);
        Self {
            channels: sorted,
            strategy,
            max_total_attempts: 10,
        }
    }

    /// Get the next channel to try based on the failover strategy
    pub fn select_channel(&self) -> Result<usize, TransportError> {
        let available: Vec<(usize, &ChannelState)> = self.channels.iter()
            .enumerate()
            .filter(|(_, c)| c.should_retry())
            .collect();

        if available.is_empty() {
            return Err(TransportError::AllChannelsFailed);
        }

        match self.strategy {
            FailoverStrategy::Priority => {
                // Already sorted by priority
                Ok(available[0].0)
            }
            FailoverStrategy::RoundRobin => {
                // Pick the channel with the longest time since last use (least recently used)
                let idx = available.iter()
                    .max_by_key(|(_, c)| c.last_success.map(|t| t.elapsed()).unwrap_or(std::time::Duration::MAX))
                    .map(|(i, _)| *i)
                    .unwrap_or(available[0].0);
                Ok(idx)
            }
            FailoverStrategy::LowestLatency => {
                let idx = available.iter()
                    .filter(|(_, c)| c.health == ChannelHealth::Healthy)
                    .min_by(|(_, a), (_, b)| {
                        a.avg_latency_ms.partial_cmp(&b.avg_latency_ms)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .or_else(|| available.first())
                    .map(|(i, _)| *i)
                    .unwrap_or(0);
                Ok(idx)
            }
            FailoverStrategy::Random => {
                use rand::Rng;
                let idx = rand::thread_rng().gen_range(0..available.len());
                Ok(available[idx].0)
            }
        }
    }

    /// Record an operation result for a channel
    pub fn record_success(&mut self, channel_idx: usize, bytes_sent: u64, bytes_recv: u64, latency_ms: f64) {
        if let Some(ch) = self.channels.get_mut(channel_idx) {
            info!("channel '{}' success: {}B sent, {}B recv, {:.0}ms",
                ch.name, bytes_sent, bytes_recv, latency_ms);
            ch.record_success(bytes_sent, bytes_recv, latency_ms);
        }
    }

    pub fn record_failure(&mut self, channel_idx: usize) {
        if let Some(ch) = self.channels.get_mut(channel_idx) {
            warn!("channel '{}' failure (consecutive: {})", ch.name, ch.consecutive_failures + 1);
            ch.record_failure();
        }
    }

    /// Get a status report of all channels
    pub fn status_report(&self) -> Vec<ChannelReport> {
        self.channels.iter().map(|ch| ChannelReport {
            name: ch.name.clone(),
            priority: ch.priority,
            health: ch.health,
            consecutive_failures: ch.consecutive_failures,
            avg_latency_ms: ch.avg_latency_ms,
            total_sent: ch.total_bytes_sent,
            total_received: ch.total_bytes_received,
        }).collect()
    }

    /// Get number of healthy channels
    pub fn healthy_count(&self) -> usize {
        self.channels.iter()
            .filter(|c| matches!(c.health, ChannelHealth::Healthy | ChannelHealth::Unknown))
            .count()
    }

    /// Reset all channels to Unknown health (e.g., after network change)
    pub fn reset_all(&mut self) {
        for ch in &mut self.channels {
            ch.reset_health();
        }
    }

    /// Get reference to a specific channel
    pub fn channel(&self, idx: usize) -> Option<&ChannelState> {
        self.channels.get(idx)
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }
}

#[derive(Debug, Clone)]
pub struct ChannelReport {
    pub name: String,
    pub priority: u32,
    pub health: ChannelHealth,
    pub consecutive_failures: u32,
    pub avg_latency_ms: f64,
    pub total_sent: u64,
    pub total_received: u64,
}

impl std::fmt::Display for ChannelReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let health_str = match self.health {
            ChannelHealth::Healthy => "HEALTHY",
            ChannelHealth::Degraded => "DEGRADED",
            ChannelHealth::Dead => "DEAD",
            ChannelHealth::Unknown => "UNKNOWN",
        };
        write!(f, "{:<20} pri={} health={:<10} latency={:.0}ms sent={}B recv={}B",
            self.name, self.priority, health_str,
            self.avg_latency_ms, self.total_sent, self.total_received)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::channel::ChannelType;

    fn make_test_channels() -> Vec<ChannelState> {
        vec![
            ChannelState::new("doh", ChannelType::DoH {
                endpoint: "https://cloudflare-dns.com/dns-query".into(),
                wire_format: true,
            }, 1),
            ChannelState::new("dns-udp", ChannelType::DnsUdp {
                server: "8.8.8.8".into(),
                port: 53,
            }, 2),
            ChannelState::new("dot", ChannelType::DoT {
                server: "1.1.1.1:853".into(),
                tls_name: "cloudflare-dns.com".into(),
            }, 3),
        ]
    }

    #[test]
    fn test_priority_selection() {
        let chain = TransportChain::new(make_test_channels(), FailoverStrategy::Priority);
        let idx = chain.select_channel().unwrap();
        assert_eq!(idx, 0); // Lowest priority number
    }

    #[test]
    fn test_failover() {
        let mut chain = TransportChain::new(make_test_channels(), FailoverStrategy::Priority);

        // Kill the primary channel
        for _ in 0..10 {
            chain.record_failure(0);
        }

        let idx = chain.select_channel().unwrap();
        assert_eq!(idx, 1); // Should fall back to second channel
    }

    #[test]
    fn test_all_channels_failed() {
        let mut chain = TransportChain::new(make_test_channels(), FailoverStrategy::Priority);

        // Kill all channels
        for ch_idx in 0..3 {
            for _ in 0..10 {
                chain.record_failure(ch_idx);
            }
        }

        assert!(chain.select_channel().is_err());
    }

    #[test]
    fn test_status_report() {
        let mut chain = TransportChain::new(make_test_channels(), FailoverStrategy::Priority);
        chain.record_success(0, 100, 200, 50.0);

        let report = chain.status_report();
        assert_eq!(report.len(), 3);
        assert_eq!(report[0].health, ChannelHealth::Healthy);
    }

    #[test]
    fn test_healthy_count() {
        let mut chain = TransportChain::new(make_test_channels(), FailoverStrategy::Priority);
        assert_eq!(chain.healthy_count(), 3); // All Unknown counts as healthy

        chain.record_success(0, 0, 0, 0.0);
        assert_eq!(chain.healthy_count(), 3);

        for _ in 0..10 {
            chain.record_failure(1);
        }
        assert_eq!(chain.healthy_count(), 2); // One dead
    }

    #[test]
    fn test_reset_all() {
        let mut chain = TransportChain::new(make_test_channels(), FailoverStrategy::Priority);

        for _ in 0..10 {
            chain.record_failure(0);
        }
        assert_eq!(chain.channel(0).unwrap().health, ChannelHealth::Dead);

        chain.reset_all();
        assert_eq!(chain.channel(0).unwrap().health, ChannelHealth::Unknown);
    }

    #[test]
    fn test_lowest_latency_selection() {
        let mut chain = TransportChain::new(make_test_channels(), FailoverStrategy::LowestLatency);

        // Give channel 2 the lowest latency
        chain.record_success(0, 0, 0, 100.0);
        chain.record_success(1, 0, 0, 50.0);
        chain.record_success(2, 0, 0, 200.0);

        let idx = chain.select_channel().unwrap();
        assert_eq!(idx, 1); // Lowest latency
    }
}
