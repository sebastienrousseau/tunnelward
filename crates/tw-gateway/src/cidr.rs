// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! IP ranges in CIDR notation, for the connector allowlist (G9).

use core::fmt;
use core::str::FromStr;
use std::net::IpAddr;

/// An IP range such as `10.0.0.0/8` or `2001:db8::/32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

/// Text that is not a CIDR range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrError(String);

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not a CIDR range: {}", self.0)
    }
}

impl std::error::Error for CidrError {}

impl Cidr {
    /// Whether `ip` is inside the range. An IPv4-mapped IPv6 address
    /// (`::ffff:a.b.c.d`) is compared as the IPv4 address it carries.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => prefix_eq(
                u128::from(u32::from(net)) << 96,
                u128::from(u32::from(ip)) << 96,
                self.prefix,
            ),
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_eq(u128::from(net), u128::from(ip), self.prefix)
            }
            _ => false,
        }
    }
}

/// Whether the top `prefix` bits of `a` and `b` agree.
fn prefix_eq(a: u128, b: u128, prefix: u8) -> bool {
    let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
    (a ^ b) & mask == 0
}

impl FromStr for Cidr {
    type Err = CidrError;

    fn from_str(text: &str) -> Result<Self, CidrError> {
        let bad = || CidrError(text.to_owned());
        let (addr, prefix) = text.split_once('/').ok_or_else(bad)?;
        let network: IpAddr = addr.parse().map_err(|_| bad())?;
        let prefix: u8 = prefix.parse().map_err(|_| bad())?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(bad());
        }
        Ok(Self { network, prefix })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]))
    }

    fn cidr(s: &str) -> Result<Cidr, CidrError> {
        s.parse()
    }

    #[test]
    fn ipv4_ranges() -> Result<(), CidrError> {
        let ten = cidr("10.0.0.0/8")?;
        assert!(ten.contains(ip("10.1.2.3")));
        assert!(!ten.contains(ip("11.0.0.1")));
        assert!(
            ten.contains(ip("::ffff:10.9.9.9")),
            "IPv4-mapped IPv6 counts"
        );
        assert!(!ten.contains(ip("2001:db8::1")));
        assert!(cidr("192.168.1.7/32")?.contains(ip("192.168.1.7")));
        assert!(!cidr("192.168.1.7/32")?.contains(ip("192.168.1.8")));
        assert!(cidr("0.0.0.0/0")?.contains(ip("8.8.8.8")));
        Ok(())
    }

    #[test]
    fn ipv6_ranges() -> Result<(), CidrError> {
        let doc = cidr("2001:db8::/32")?;
        assert!(doc.contains(ip("2001:db8:1::5")));
        assert!(!doc.contains(ip("2001:db9::5")));
        assert!(!doc.contains(ip("10.0.0.1")));
        assert!(cidr("::/0")?.contains(ip("::1")));
        Ok(())
    }

    #[test]
    fn bad_ranges_are_refused() {
        for bad in [
            "10.0.0.0",
            "10.0.0.0/33",
            "::/129",
            "x/8",
            "10.0.0.0/-1",
            "/8",
            "10.0.0.0/8/9",
        ] {
            assert!(cidr(bad).is_err(), "{bad}");
        }
    }
}
