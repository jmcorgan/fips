//! The STUN codec: the binding request this node sends, the binding success
//! it accepts (MAPPED-ADDRESS and XOR-MAPPED-ADDRESS, IPv4 and IPv6), and the
//! `stun:` server URL. The socket, the server lookup and the transaction id's
//! random draw stay in the shell's `stun.rs`.

use alloc::format;
use alloc::string::{String, ToString};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::error::Error;

pub mod candidates;

pub fn parse_stun_url(input: &str) -> Result<StunEndpoint, Error> {
    let raw = input.strip_prefix("stun:").unwrap_or(input);
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err(Error::Stun(format!("invalid STUN URL: {}", input)));
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| Error::Stun(format!("invalid STUN URL: {}", input)))?;
    if host.is_empty() {
        return Err(Error::Stun(format!("invalid STUN URL: {}", input)));
    }
    Ok(StunEndpoint {
        host: host.to_string(),
        port,
    })
}

pub struct StunEndpoint {
    pub host: String,
    pub port: u16,
}

pub fn create_stun_binding_request(txn_id: [u8; 12]) -> [u8; 20] {
    const STUN_BINDING_REQUEST: u16 = 0x0001;
    const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;
    let mut packet = [0u8; 20];
    packet[..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    packet[2..4].copy_from_slice(&0u16.to_be_bytes());
    packet[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    packet[8..20].copy_from_slice(&txn_id);
    packet
}

pub fn parse_stun_binding_success(packet: &[u8], txn_id: &[u8; 12]) -> Option<SocketAddr> {
    const STUN_BINDING_SUCCESS: u16 = 0x0101;
    const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;
    const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
    const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

    if packet.len() < 20 {
        return None;
    }
    if u16::from_be_bytes(packet[..2].try_into().ok()?) != STUN_BINDING_SUCCESS {
        return None;
    }
    if u32::from_be_bytes(packet[4..8].try_into().ok()?) != STUN_MAGIC_COOKIE {
        return None;
    }
    if &packet[8..20] != txn_id {
        return None;
    }

    let message_length = u16::from_be_bytes(packet[2..4].try_into().ok()?) as usize;
    let mut offset = 20usize;
    let max_offset = packet.len().min(20 + message_length);
    while offset + 4 <= max_offset {
        let attr_type = u16::from_be_bytes(packet[offset..offset + 2].try_into().ok()?);
        let attr_len = u16::from_be_bytes(packet[offset + 2..offset + 4].try_into().ok()?) as usize;
        let value_start = offset + 4;
        let value_end = value_start + attr_len;
        if value_end > packet.len() {
            break;
        }
        let value = &packet[value_start..value_end];
        let parsed = match attr_type {
            STUN_ATTR_XOR_MAPPED_ADDRESS => parse_xor_mapped_address(value, txn_id),
            STUN_ATTR_MAPPED_ADDRESS => parse_mapped_address(value),
            _ => None,
        };
        if parsed.is_some() {
            return parsed;
        }
        offset = value_end + ((4 - (attr_len % 4)) % 4);
    }
    None
}

fn parse_mapped_address(value: &[u8]) -> Option<SocketAddr> {
    match value.get(1).copied()? {
        0x01 if value.len() >= 8 => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(value[4], value[5], value[6], value[7])),
            u16::from_be_bytes([value[2], value[3]]),
        )),
        0x02 if value.len() >= 20 => {
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&value[4..20]).ok()?);
            Some(SocketAddr::new(
                IpAddr::V6(ip),
                u16::from_be_bytes([value[2], value[3]]),
            ))
        }
        _ => None,
    }
}

fn parse_xor_mapped_address(value: &[u8], txn_id: &[u8; 12]) -> Option<SocketAddr> {
    const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;
    let xored_port = u16::from_be_bytes([value.get(2).copied()?, value.get(3).copied()?])
        ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();

    match value.get(1).copied()? {
        0x01 if value.len() >= 8 => {
            let ip = Ipv4Addr::new(
                value[4] ^ cookie[0],
                value[5] ^ cookie[1],
                value[6] ^ cookie[2],
                value[7] ^ cookie[3],
            );
            Some(SocketAddr::new(IpAddr::V4(ip), xored_port))
        }
        0x02 if value.len() >= 20 => {
            let mut ip = [0u8; 16];
            for (index, byte) in ip.iter_mut().enumerate() {
                let mask = if index < 4 {
                    cookie[index]
                } else {
                    txn_id[index - 4]
                };
                *byte = value[4 + index] ^ mask;
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), xored_port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
