//! Per-IP request rate limiting, applied to the whole app on top of the
//! per-endpoint checks (e.g. login's own brute-force ban). Protects against
//! a compromised LAN device hammering the API rather than a single guess.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// No page load fetches more than a handful of endpoints and the UI has no
/// auto-refresh, so normal usage stays far under this even with several
/// tabs open; automated hammering is what this catches.
const WINDOW: Duration = Duration::from_secs(10);
const MAX_REQUESTS: u32 = 60;

pub(crate) struct Bucket {
    count: u32,
    window_start: Instant,
}

pub type RateLimiter = Arc<Mutex<HashMap<IpAddr, Bucket>>>;

pub fn new_rate_limiter() -> RateLimiter {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Records this request against `ip`'s budget; returns true if it should be
/// rejected with 429.
pub fn is_rate_limited(limiter: &RateLimiter, ip: IpAddr) -> bool {
    let mut map = limiter.lock();
    let now = Instant::now();
    let entry = map.entry(ip).or_insert_with(|| Bucket { count: 0, window_start: now });
    if now.duration_since(entry.window_start) >= WINDOW {
        entry.count = 0;
        entry.window_start = now;
    }
    entry.count += 1;
    entry.count > MAX_REQUESTS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn allows_requests_under_the_limit() {
        let limiter = new_rate_limiter();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        for _ in 0..MAX_REQUESTS {
            assert!(!is_rate_limited(&limiter, ip));
        }
    }

    #[test]
    fn rejects_once_the_limit_is_exceeded() {
        let limiter = new_rate_limiter();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        for _ in 0..MAX_REQUESTS {
            is_rate_limited(&limiter, ip);
        }
        assert!(is_rate_limited(&limiter, ip));
    }

    #[test]
    fn tracks_ips_independently() {
        let limiter = new_rate_limiter();
        let a = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        for _ in 0..=MAX_REQUESTS {
            is_rate_limited(&limiter, a);
        }
        assert!(!is_rate_limited(&limiter, b));
    }
}
