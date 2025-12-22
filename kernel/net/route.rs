//! Routing Table
//!
//! This module implements a simple IPv4 routing table for
//! next-hop determination.

use alloc::sync::Arc;
use alloc::vec::Vec;

use spin::RwLock;

use crate::net::NetError;
use crate::net::device::NetDevice;
use crate::net::ipv4::Ipv4Addr;

/// Route entry
#[derive(Clone)]
pub struct Route {
    /// Destination network
    pub dest: Ipv4Addr,
    /// Network mask
    pub netmask: Ipv4Addr,
    /// Gateway (0.0.0.0 for directly connected)
    pub gateway: Ipv4Addr,
    /// Output interface
    pub dev: Arc<NetDevice>,
    /// Route flags
    pub flags: u32,
    /// Metric (lower is better)
    pub metric: u32,
}

/// Route flags
pub mod flags {
    /// Route is up
    pub const RTF_UP: u32 = 0x0001;
    /// Destination is a gateway
    pub const RTF_GATEWAY: u32 = 0x0002;
    /// Destination is a host
    pub const RTF_HOST: u32 = 0x0004;
    /// Route is dynamic
    pub const RTF_DYNAMIC: u32 = 0x0010;
    /// Route is default
    pub const RTF_DEFAULT: u32 = 0x10000;
}

impl Route {
    /// Check if this route matches a destination
    pub fn matches(&self, dest: Ipv4Addr) -> bool {
        (dest & self.netmask) == (self.dest & self.netmask)
    }

    /// Check if destination is through a gateway
    pub fn is_gateway(&self) -> bool {
        !self.gateway.is_unspecified()
    }

    /// Get the number of bits in the prefix (for longest-prefix matching)
    fn prefix_len(&self) -> u32 {
        self.netmask.to_u32().count_ones()
    }
}

/// Global routing table
static ROUTING_TABLE: RwLock<Vec<Route>> = RwLock::new(Vec::new());

/// Initialize routing
pub fn init() {
    // Nothing to do - routes are added when interfaces come up
}

/// Add a route for a directly connected interface
pub fn add_interface_route(dest: Ipv4Addr, netmask: Ipv4Addr, dev: Arc<NetDevice>) {
    let route = Route {
        dest,
        netmask,
        gateway: Ipv4Addr::new(0, 0, 0, 0),
        dev,
        flags: flags::RTF_UP,
        metric: 0,
    };

    let mut table = ROUTING_TABLE.write();
    table.push(route);
}

/// Add a default route (gateway)
pub fn add_default_route(gateway: Ipv4Addr, dev: Arc<NetDevice>) {
    let route = Route {
        dest: Ipv4Addr::new(0, 0, 0, 0),
        netmask: Ipv4Addr::new(0, 0, 0, 0),
        gateway,
        dev,
        flags: flags::RTF_UP | flags::RTF_GATEWAY | flags::RTF_DEFAULT,
        metric: 100,
    };

    let mut table = ROUTING_TABLE.write();
    table.push(route);
}

/// Add a host route
pub fn add_host_route(dest: Ipv4Addr, gateway: Ipv4Addr, dev: Arc<NetDevice>) {
    let route = Route {
        dest,
        netmask: Ipv4Addr::new(255, 255, 255, 255),
        gateway,
        dev,
        flags: flags::RTF_UP
            | flags::RTF_HOST
            | if !gateway.is_unspecified() {
                flags::RTF_GATEWAY
            } else {
                0
            },
        metric: 0,
    };

    let mut table = ROUTING_TABLE.write();
    table.push(route);
}

/// Look up a route for a destination address
///
/// Returns the output device and next-hop address.
/// Uses longest-prefix matching for route selection.
pub fn route_lookup(dest: Ipv4Addr) -> Result<(Arc<NetDevice>, Ipv4Addr), NetError> {
    let table = ROUTING_TABLE.read();

    // Find best matching route (longest prefix)
    let mut best_route: Option<&Route> = None;
    let mut best_prefix_len = 0u32;

    for route in table.iter() {
        if route.matches(dest) {
            let prefix_len = route.prefix_len();
            if best_route.is_none() || prefix_len > best_prefix_len {
                best_route = Some(route);
                best_prefix_len = prefix_len;
            }
        }
    }

    match best_route {
        Some(route) => {
            // Next hop is gateway if present, otherwise destination
            let next_hop = if route.is_gateway() {
                route.gateway
            } else {
                dest
            };

            Ok((Arc::clone(&route.dev), next_hop))
        }
        None => Err(NetError::NoRoute),
    }
}

/// Get all routes (for debugging)
pub fn get_routes() -> Vec<Route> {
    ROUTING_TABLE.read().clone()
}

/// Clear all routes
pub fn clear_routes() {
    ROUTING_TABLE.write().clear();
}
