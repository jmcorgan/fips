//! Ethernet address parsing.

use crate::transport::TransportError;

/// Parse a colon-separated MAC string (e.g., "aa:bb:cc:dd:ee:ff") into bytes.
pub fn parse_mac_string(s: &str) -> Result<[u8; 6], TransportError> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(TransportError::InvalidAddress(format!(
            "invalid MAC format: expected 6 colon-separated hex bytes, got '{}'",
            s
        )));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| {
            TransportError::InvalidAddress(format!("invalid hex byte '{}' in MAC address", part))
        })?;
    }
    Ok(mac)
}
