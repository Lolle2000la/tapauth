//! Utility functions for the TapAuth configuration GUI.
//!
//! Provides privilege elevation helpers and network interface enumeration.

pub mod elevation;
pub mod system_check;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Get the local IPv4 address
#[allow(dead_code)]
pub fn get_local_ipv4() -> Option<Ipv4Addr> {
    // Get all network interfaces
    if let Ok(interfaces) = local_ip_address::list_afinet_netifas() {
        for (name, ip) in interfaces {
            // Skip loopback
            if name == "lo" || name == "lo0" {
                continue;
            }

            if let IpAddr::V4(ipv4) = ip {
                if !ipv4.is_loopback() {
                    return Some(ipv4);
                }
            }
        }
    }
    None
}

/// Get the local IPv6 address
#[allow(dead_code)]
pub fn get_local_ipv6() -> Option<Ipv6Addr> {
    if let Ok(interfaces) = local_ip_address::list_afinet_netifas() {
        for (name, ip) in interfaces {
            // Skip loopback
            if name == "lo" || name == "lo0" {
                continue;
            }

            if let IpAddr::V6(ipv6) = ip {
                if !ipv6.is_loopback() {
                    return Some(ipv6);
                }
            }
        }
    }
    None
}
