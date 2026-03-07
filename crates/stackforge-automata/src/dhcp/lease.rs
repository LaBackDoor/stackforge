use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// A single DHCP lease record.
#[derive(Debug, Clone)]
pub struct Lease {
    /// The MAC address of the client (first 6 bytes of chaddr).
    pub client_mac: [u8; 6],
    /// The assigned IP address.
    pub ip: Ipv4Addr,
    /// When this lease was granted.
    pub granted_at: Instant,
    /// Lease duration.
    pub duration: Duration,
    /// Hostname if provided by the client.
    pub hostname: Option<String>,
}

impl Lease {
    pub fn is_expired(&self) -> bool {
        self.granted_at.elapsed() > self.duration
    }

    pub fn remaining(&self) -> Duration {
        self.duration.saturating_sub(self.granted_at.elapsed())
    }
}

/// Configuration for the DHCP address pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Start of the IP address pool (inclusive).
    pub pool_start: Ipv4Addr,
    /// End of the IP address pool (inclusive).
    pub pool_end: Ipv4Addr,
    /// Server's own IP address.
    pub server_ip: Ipv4Addr,
    /// Subnet mask.
    pub subnet_mask: Ipv4Addr,
    /// Default gateway / router.
    pub gateway: Ipv4Addr,
    /// DNS server addresses.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Domain name.
    pub domain: Option<String>,
    /// Default lease time in seconds.
    pub lease_time: u32,
    /// Renewal time (T1) in seconds — when client should start unicast renewal.
    /// Defaults to lease_time / 2.
    pub renewal_time: Option<u32>,
    /// Rebinding time (T2) in seconds — when client should broadcast renewal.
    /// Defaults to lease_time * 7/8.
    pub rebinding_time: Option<u32>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 200),
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
            domain: None,
            lease_time: 86400, // 24 hours
            renewal_time: None,
            rebinding_time: None,
        }
    }
}

impl PoolConfig {
    /// Effective T1 (renewal time).
    pub fn effective_renewal_time(&self) -> u32 {
        self.renewal_time.unwrap_or(self.lease_time / 2)
    }

    /// Effective T2 (rebinding time).
    pub fn effective_rebinding_time(&self) -> u32 {
        self.rebinding_time.unwrap_or(self.lease_time * 7 / 8)
    }
}

/// Manages the DHCP lease table and IP address pool allocation.
pub struct LeaseTable {
    /// Active leases keyed by MAC address.
    leases_by_mac: HashMap<[u8; 6], Lease>,
    /// Reverse index: IP → MAC.
    ip_to_mac: HashMap<Ipv4Addr, [u8; 6]>,
    /// Pool configuration.
    config: PoolConfig,
    /// Set of IPs that have been declined and should not be offered.
    declined: std::collections::HashSet<Ipv4Addr>,
}

impl LeaseTable {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            leases_by_mac: HashMap::new(),
            ip_to_mac: HashMap::new(),
            config,
            declined: std::collections::HashSet::new(),
        }
    }

    /// Get the pool config.
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// Allocate (or re-offer) an IP for the given client MAC.
    ///
    /// Returns the offered IP, or None if the pool is exhausted.
    pub fn allocate(
        &mut self,
        client_mac: [u8; 6],
        requested_ip: Option<Ipv4Addr>,
    ) -> Option<Ipv4Addr> {
        // If client already has a lease (even expired), prefer the same IP
        if let Some(existing) = self.leases_by_mac.get(&client_mac) {
            let ip = existing.ip;
            if self.is_in_pool(ip) && !self.declined.contains(&ip) {
                return Some(ip);
            }
        }

        // If client requested a specific IP and it's available, grant it
        if let Some(req) = requested_ip {
            if self.is_in_pool(req)
                && self.is_available(req, &client_mac)
                && !self.declined.contains(&req)
            {
                return Some(req);
            }
        }

        // Find the first available IP in the pool
        self.find_free_ip(&client_mac)
    }

    /// Commit a lease for the given client.
    pub fn commit(&mut self, client_mac: [u8; 6], ip: Ipv4Addr, hostname: Option<String>) {
        // Remove any old lease for this MAC
        if let Some(old) = self.leases_by_mac.remove(&client_mac) {
            self.ip_to_mac.remove(&old.ip);
        }
        // Remove any old lease for this IP (in case a different client had it)
        if let Some(old_mac) = self.ip_to_mac.remove(&ip) {
            if old_mac != client_mac {
                self.leases_by_mac.remove(&old_mac);
            }
        }

        let lease = Lease {
            client_mac,
            ip,
            granted_at: Instant::now(),
            duration: Duration::from_secs(u64::from(self.config.lease_time)),
            hostname,
        };
        self.ip_to_mac.insert(ip, client_mac);
        self.leases_by_mac.insert(client_mac, lease);
    }

    /// Release a lease for the given client MAC.
    pub fn release(&mut self, client_mac: &[u8; 6]) {
        if let Some(lease) = self.leases_by_mac.remove(client_mac) {
            self.ip_to_mac.remove(&lease.ip);
        }
    }

    /// Mark an IP as declined (will not be offered again).
    pub fn decline(&mut self, ip: Ipv4Addr, client_mac: &[u8; 6]) {
        self.declined.insert(ip);
        if let Some(lease) = self.leases_by_mac.remove(client_mac) {
            if lease.ip == ip {
                self.ip_to_mac.remove(&ip);
            }
        }
    }

    /// Sweep expired leases, returning the count of leases removed.
    pub fn sweep_expired(&mut self) -> usize {
        let expired: Vec<[u8; 6]> = self
            .leases_by_mac
            .iter()
            .filter(|(_, l)| l.is_expired())
            .map(|(mac, _)| *mac)
            .collect();
        let count = expired.len();
        for mac in expired {
            if let Some(lease) = self.leases_by_mac.remove(&mac) {
                self.ip_to_mac.remove(&lease.ip);
            }
        }
        count
    }

    /// Get the current lease for a client MAC.
    pub fn get_lease(&self, client_mac: &[u8; 6]) -> Option<&Lease> {
        self.leases_by_mac.get(client_mac)
    }

    /// Get all active (non-expired) leases.
    pub fn active_leases(&self) -> Vec<&Lease> {
        self.leases_by_mac
            .values()
            .filter(|l| !l.is_expired())
            .collect()
    }

    /// Total number of leases (including expired).
    pub fn len(&self) -> usize {
        self.leases_by_mac.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leases_by_mac.is_empty()
    }

    // ---- internal helpers ----

    fn is_in_pool(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        let start = u32::from(self.config.pool_start);
        let end = u32::from(self.config.pool_end);
        ip_u32 >= start && ip_u32 <= end
    }

    fn is_available(&self, ip: Ipv4Addr, requesting_mac: &[u8; 6]) -> bool {
        match self.ip_to_mac.get(&ip) {
            None => true,
            Some(mac) => {
                mac == requesting_mac || self.leases_by_mac.get(mac).is_some_and(|l| l.is_expired())
            },
        }
    }

    fn find_free_ip(&self, requesting_mac: &[u8; 6]) -> Option<Ipv4Addr> {
        let start = u32::from(self.config.pool_start);
        let end = u32::from(self.config.pool_end);
        for ip_u32 in start..=end {
            let ip = Ipv4Addr::from(ip_u32);
            if !self.declined.contains(&ip) && self.is_available(ip, requesting_mac) {
                return Some(ip);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> PoolConfig {
        PoolConfig {
            pool_start: Ipv4Addr::new(10, 0, 0, 10),
            pool_end: Ipv4Addr::new(10, 0, 0, 20),
            server_ip: Ipv4Addr::new(10, 0, 0, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
            domain: Some("test.local".to_string()),
            lease_time: 3600,
            renewal_time: None,
            rebinding_time: None,
        }
    }

    #[test]
    fn test_allocate_first_ip() {
        let mut table = LeaseTable::new(default_config());
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ip = table.allocate(mac, None).unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 10));
    }

    #[test]
    fn test_allocate_requested_ip() {
        let mut table = LeaseTable::new(default_config());
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let requested = Ipv4Addr::new(10, 0, 0, 15);
        let ip = table.allocate(mac, Some(requested)).unwrap();
        assert_eq!(ip, requested);
    }

    #[test]
    fn test_commit_and_reuse() {
        let mut table = LeaseTable::new(default_config());
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ip = table.allocate(mac, None).unwrap();
        table.commit(mac, ip, None);

        // Same MAC should get same IP
        let ip2 = table.allocate(mac, None).unwrap();
        assert_eq!(ip, ip2);
    }

    #[test]
    fn test_different_macs_get_different_ips() {
        let mut table = LeaseTable::new(default_config());
        let mac1 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mac2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let ip1 = table.allocate(mac1, None).unwrap();
        table.commit(mac1, ip1, None);

        let ip2 = table.allocate(mac2, None).unwrap();
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_release() {
        let mut table = LeaseTable::new(default_config());
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ip = table.allocate(mac, None).unwrap();
        table.commit(mac, ip, None);
        assert_eq!(table.len(), 1);

        table.release(&mac);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_decline() {
        let mut table = LeaseTable::new(default_config());
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ip = table.allocate(mac, None).unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 10));

        table.decline(ip, &mac);

        // Next allocation should skip the declined IP
        let mac2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ip2 = table.allocate(mac2, None).unwrap();
        assert_eq!(ip2, Ipv4Addr::new(10, 0, 0, 11));
    }

    #[test]
    fn test_pool_exhaustion() {
        let config = PoolConfig {
            pool_start: Ipv4Addr::new(10, 0, 0, 10),
            pool_end: Ipv4Addr::new(10, 0, 0, 11), // only 2 IPs
            ..default_config()
        };
        let mut table = LeaseTable::new(config);

        let mac1 = [0x01; 6];
        let mac2 = [0x02; 6];
        let mac3 = [0x03; 6];

        let ip1 = table.allocate(mac1, None).unwrap();
        table.commit(mac1, ip1, None);
        let ip2 = table.allocate(mac2, None).unwrap();
        table.commit(mac2, ip2, None);

        assert!(table.allocate(mac3, None).is_none());
    }

    #[test]
    fn test_renewal_rebinding_defaults() {
        let config = default_config();
        assert_eq!(config.effective_renewal_time(), 1800); // 3600/2
        assert_eq!(config.effective_rebinding_time(), 3150); // 3600*7/8
    }

    #[test]
    fn test_active_leases() {
        let mut table = LeaseTable::new(default_config());
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ip = table.allocate(mac, None).unwrap();
        table.commit(mac, ip, Some("testhost".to_string()));

        let active = table.active_leases();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].hostname, Some("testhost".to_string()));
    }
}
