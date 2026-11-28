//! The address codec the record and the ceremony share: `[family][address][port]`.
//!
//! Family 0 is "no address" (the ceremony sends one on some flights), 4 is IPv4,
//! 6 is IPv6; the port is big-endian. An IPv6 address also carries its flow info
//! and scope id, because a link-local address without a scope cannot be dialed.
//! One implementation, so a port-endianness or IPv6 fix has one place to land and
//! one place to test.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Append `address` to `bytes`.
pub(crate) fn encode(bytes: &mut Vec<u8>, address: Option<SocketAddr>) {
    match address {
        None => bytes.push(0),
        Some(SocketAddr::V4(v4)) => {
            bytes.push(4);
            bytes.extend_from_slice(&v4.ip().octets());
            bytes.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            bytes.push(6);
            bytes.extend_from_slice(&v6.ip().octets());
            bytes.extend_from_slice(&v6.port().to_be_bytes());
            bytes.extend_from_slice(&v6.flowinfo().to_be_bytes());
            bytes.extend_from_slice(&v6.scope_id().to_be_bytes());
        }
    }
}

/// Read one address prefix, answering it and the bytes after it.
pub(crate) fn decode(bytes: &[u8]) -> Option<(Option<SocketAddr>, &[u8])> {
    let (&family, rest) = bytes.split_first()?;
    match family {
        0 => Some((None, rest)),
        4 => {
            let field: [u8; 6] = rest.get(..6)?.try_into().ok()?;
            let address = SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(field[0], field[1], field[2], field[3]),
                u16::from_be_bytes([field[4], field[5]]),
            ));
            Some((Some(address), &rest[6..]))
        }
        6 => {
            let field: [u8; 26] = rest.get(..26)?.try_into().ok()?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&field[..16]);
            let address = SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                u16::from_be_bytes([field[16], field[17]]),
                u32::from_be_bytes([field[18], field[19], field[20], field[21]]),
                u32::from_be_bytes([field[22], field[23], field[24], field[25]]),
            ));
            Some((Some(address), &rest[26..]))
        }
        _ => None,
    }
}

/// The first `cap` distinct addresses of `front`, in the order given.
///
/// One implementation of "distinct, in order, capped", shared by the record's list and the set a
/// punch dials, so the two cannot disagree about what a repeat or the bound does.
pub(crate) fn distinct(front: impl IntoIterator<Item = SocketAddr>, cap: usize) -> Vec<SocketAddr> {
    let mut addresses: Vec<SocketAddr> = Vec::with_capacity(cap);
    for address in front {
        if addresses.len() >= cap {
            break;
        }
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses
}
