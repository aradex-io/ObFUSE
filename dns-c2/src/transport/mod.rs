//! Multi-channel transport layer with automatic failover.
//!
//! Provides a unified `Channel` abstraction over multiple transport mechanisms:
//! - DNS TXT records (existing, via Cloudflare API)
//! - DNS-over-HTTPS (DoH) — blends with normal encrypted DNS traffic
//! - DNS-over-TLS (DoT) — standard encrypted DNS on port 853
//! - HTTPS with domain fronting — CDN-routed covert channel
//! - Raw DNS over UDP/TCP — direct queries with custom resolver
//!
//! Channels are organized in a priority chain with automatic failover.

pub mod channel;
pub mod chain;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("channel error: {0}")]
    Channel(String),
    #[error("all channels exhausted")]
    AllChannelsFailed,
    #[error("timeout on channel {0}")]
    Timeout(String),
    #[error("channel {0} is degraded: {1}")]
    Degraded(String, String),
}
