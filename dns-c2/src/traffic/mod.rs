//! Traffic obfuscation and covert channel techniques.
//!
//! Provides domain fronting, DNS-over-HTTPS (DoH), DNS record encoding
//! tricks, traffic shaping, and protocol mimicry to make C2 traffic
//! blend with legitimate network activity.

pub mod fronting;
pub mod doh;
pub mod encoding;
pub mod shaping;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TrafficError {
    #[error("network error: {0}")]
    Network(String),
    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("fronting error: {0}")]
    Fronting(String),
}
