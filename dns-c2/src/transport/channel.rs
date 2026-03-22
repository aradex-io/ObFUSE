//! Individual transport channel definitions.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Transport channel types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelType {
    /// DNS via Cloudflare API (existing mechanism)
    DnsCloudflare {
        api_token: String,
        zone_id: String,
    },
    /// DNS-over-HTTPS queries to public resolvers
    DoH {
        endpoint: String,
        /// Use wire format (true) or JSON API (false)
        wire_format: bool,
    },
    /// DNS-over-TLS on port 853
    DoT {
        server: String,
        tls_name: String,
    },
    /// Raw DNS over UDP to a specific resolver
    DnsUdp {
        server: String,
        port: u16,
    },
    /// HTTPS with domain fronting
    HttpsFronted {
        front_domain: String,
        real_host: String,
        path: String,
    },
    /// HTTPS direct (for fallback to a regular web server)
    HttpsDirect {
        url: String,
    },
}

/// Health status of a channel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelHealth {
    /// Working normally
    Healthy,
    /// Experiencing intermittent issues
    Degraded,
    /// Not responding / blocked
    Dead,
    /// Not yet tested
    Unknown,
}

/// Runtime state for a transport channel
#[derive(Debug, Clone)]
pub struct ChannelState {
    pub channel_type: ChannelType,
    pub name: String,
    pub priority: u32,
    pub health: ChannelHealth,
    pub consecutive_failures: u32,
    pub max_failures_before_degraded: u32,
    pub max_failures_before_dead: u32,
    pub last_success: Option<std::time::Instant>,
    pub last_failure: Option<std::time::Instant>,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub avg_latency_ms: f64,
    pub timeout: Duration,
}

impl ChannelState {
    pub fn new(name: &str, channel_type: ChannelType, priority: u32) -> Self {
        Self {
            channel_type,
            name: name.to_string(),
            priority,
            health: ChannelHealth::Unknown,
            consecutive_failures: 0,
            max_failures_before_degraded: 3,
            max_failures_before_dead: 10,
            last_success: None,
            last_failure: None,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            avg_latency_ms: 0.0,
            timeout: Duration::from_secs(30),
        }
    }

    /// Record a successful operation
    pub fn record_success(&mut self, bytes_sent: u64, bytes_received: u64, latency_ms: f64) {
        self.consecutive_failures = 0;
        self.health = ChannelHealth::Healthy;
        self.last_success = Some(std::time::Instant::now());
        self.total_bytes_sent += bytes_sent;
        self.total_bytes_received += bytes_received;
        // Exponential moving average for latency
        self.avg_latency_ms = self.avg_latency_ms * 0.8 + latency_ms * 0.2;
    }

    /// Record a failed operation
    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.last_failure = Some(std::time::Instant::now());

        if self.consecutive_failures >= self.max_failures_before_dead {
            self.health = ChannelHealth::Dead;
        } else if self.consecutive_failures >= self.max_failures_before_degraded {
            self.health = ChannelHealth::Degraded;
        }
    }

    /// Check if this channel should be retried (Dead channels get a retry window)
    pub fn should_retry(&self) -> bool {
        match self.health {
            ChannelHealth::Healthy | ChannelHealth::Unknown => true,
            ChannelHealth::Degraded => true,
            ChannelHealth::Dead => {
                // Retry dead channels every 5 minutes
                self.last_failure
                    .map(|t| t.elapsed() > Duration::from_secs(300))
                    .unwrap_or(true)
            }
        }
    }

    /// Reset health status (e.g., after manual recovery)
    pub fn reset_health(&mut self) {
        self.health = ChannelHealth::Unknown;
        self.consecutive_failures = 0;
    }
}

/// Generate channel configurations for common setups
pub fn preset_stealthy(_domain: &str, cf_token: &str, cf_zone: &str) -> Vec<ChannelState> {
    vec![
        ChannelState::new("doh-cloudflare", ChannelType::DoH {
            endpoint: "https://cloudflare-dns.com/dns-query".into(),
            wire_format: true,
        }, 1),
        ChannelState::new("doh-google", ChannelType::DoH {
            endpoint: "https://dns.google/dns-query".into(),
            wire_format: true,
        }, 2),
        ChannelState::new("dot-cloudflare", ChannelType::DoT {
            server: "1.1.1.1:853".into(),
            tls_name: "cloudflare-dns.com".into(),
        }, 3),
        ChannelState::new("dns-api", ChannelType::DnsCloudflare {
            api_token: cf_token.to_string(),
            zone_id: cf_zone.to_string(),
        }, 4),
    ]
}

pub fn preset_aggressive(_domain: &str, cf_token: &str, cf_zone: &str) -> Vec<ChannelState> {
    vec![
        ChannelState::new("dns-api", ChannelType::DnsCloudflare {
            api_token: cf_token.to_string(),
            zone_id: cf_zone.to_string(),
        }, 1),
        ChannelState::new("dns-udp", ChannelType::DnsUdp {
            server: "8.8.8.8".into(),
            port: 53,
        }, 2),
        ChannelState::new("doh-cloudflare", ChannelType::DoH {
            endpoint: "https://cloudflare-dns.com/dns-query".into(),
            wire_format: true,
        }, 3),
    ]
}

pub fn preset_fronted(front_domain: &str, real_host: &str, cf_token: &str, cf_zone: &str) -> Vec<ChannelState> {
    vec![
        ChannelState::new("https-fronted", ChannelType::HttpsFronted {
            front_domain: front_domain.to_string(),
            real_host: real_host.to_string(),
            path: "/api/v1/telemetry".into(),
        }, 1),
        ChannelState::new("doh-cloudflare", ChannelType::DoH {
            endpoint: "https://cloudflare-dns.com/dns-query".into(),
            wire_format: true,
        }, 2),
        ChannelState::new("dns-api", ChannelType::DnsCloudflare {
            api_token: cf_token.to_string(),
            zone_id: cf_zone.to_string(),
        }, 3),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_health_tracking() {
        let mut ch = ChannelState::new("test", ChannelType::DnsUdp {
            server: "8.8.8.8".into(),
            port: 53,
        }, 1);

        assert_eq!(ch.health, ChannelHealth::Unknown);

        ch.record_success(100, 200, 50.0);
        assert_eq!(ch.health, ChannelHealth::Healthy);
        assert_eq!(ch.consecutive_failures, 0);

        for _ in 0..3 {
            ch.record_failure();
        }
        assert_eq!(ch.health, ChannelHealth::Degraded);

        for _ in 0..7 {
            ch.record_failure();
        }
        assert_eq!(ch.health, ChannelHealth::Dead);
    }

    #[test]
    fn test_channel_retry_logic() {
        let mut ch = ChannelState::new("test", ChannelType::DnsUdp {
            server: "8.8.8.8".into(),
            port: 53,
        }, 1);

        assert!(ch.should_retry()); // Unknown = retry

        ch.record_success(0, 0, 0.0);
        assert!(ch.should_retry()); // Healthy = retry

        for _ in 0..10 {
            ch.record_failure();
        }
        assert_eq!(ch.health, ChannelHealth::Dead);
        // Dead channel should not retry immediately
        assert!(!ch.should_retry());
    }

    #[test]
    fn test_presets() {
        let channels = preset_stealthy("test.com", "token", "zone");
        assert_eq!(channels.len(), 4);
        assert_eq!(channels[0].priority, 1);

        let channels = preset_aggressive("test.com", "token", "zone");
        assert_eq!(channels.len(), 3);
    }

    #[test]
    fn test_latency_tracking() {
        let mut ch = ChannelState::new("test", ChannelType::DnsUdp {
            server: "8.8.8.8".into(),
            port: 53,
        }, 1);

        ch.record_success(0, 0, 100.0);
        assert!((ch.avg_latency_ms - 20.0).abs() < 1.0); // 0.8*0 + 0.2*100

        ch.record_success(0, 0, 100.0);
        assert!((ch.avg_latency_ms - 36.0).abs() < 1.0); // 0.8*20 + 0.2*100
    }
}
