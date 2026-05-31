//! Safety helpers shared by the config-changing flows (Wi-Fi, DHCP).
//!
//! Two concerns live here:
//! * confirming a service actually came up after a restart, with a short
//!   retry window so a slow-starting unit is not mistaken for a failure;
//! * undoing a change — either immediately when the restart fails, or on a
//!   timer when the admin cannot confirm it (e.g. the new Wi-Fi settings cut
//!   the very link they are managing the device over).

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::file::{backup_path, restore_backup};
use crate::service::{service_restart, service_running};

/// How long to wait for a service to report running after a restart, and how
/// often to poll while waiting.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);
const VERIFY_INTERVAL: Duration = Duration::from_millis(250);

/// Poll [`service_running`] until it is true or the timeout elapses. Returns
/// as soon as the service is up, so the success path is not delayed.
pub fn wait_until_running(service: &str) -> bool {
    wait_until_running_with(service, VERIFY_TIMEOUT, VERIFY_INTERVAL, &service_running)
}

/// Testable core of [`wait_until_running`]: the poll function is injected so it
/// can be exercised without a real init system.
fn wait_until_running_with(
    service: &str,
    timeout: Duration,
    interval: Duration,
    running: &dyn Fn(&str) -> bool,
) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if running(service) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        thread::sleep(interval);
    }
}

/// Restore `path` from its `.bak` sibling and restart `service` on the
/// restored config. Best-effort: failures here are not recoverable by the
/// caller, so they are swallowed.
pub fn revert(path: &Path, service: &str) {
    let _ = restore_backup(path);
    let _ = service_restart(service);
}

/// Remove the `.bak` left by a committed edit. Best-effort.
pub fn discard_backup(path: &Path) {
    let _ = std::fs::remove_file(backup_path(path));
}

/// A pending automatic rollback. The supplied action runs once, on a
/// background thread, after `timeout` elapses — unless [`AutoRevert::confirm`]
/// cancels it first (or the guard is dropped). Used to undo a network change
/// that severs the admin's own link when they cannot reconnect to confirm it.
pub struct AutoRevert {
    state: Arc<RevertState>,
    handle: Option<JoinHandle<()>>,
}

struct RevertState {
    cancelled: Mutex<bool>,
    cvar: Condvar,
    fired: AtomicBool,
}

impl AutoRevert {
    /// Arm the timer. `action` runs after `timeout` unless cancelled first.
    pub fn arm<F>(timeout: Duration, action: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        let state = Arc::new(RevertState {
            cancelled: Mutex::new(false),
            cvar: Condvar::new(),
            fired: AtomicBool::new(false),
        });
        let st = Arc::clone(&state);
        let handle = thread::spawn(move || {
            let cancelled = st.cancelled.lock().unwrap();
            let (cancelled, wait) = st
                .cvar
                .wait_timeout_while(cancelled, timeout, |c| !*c)
                .unwrap();
            // Fire only if we waited the whole timeout without being cancelled.
            if wait.timed_out() && !*cancelled {
                st.fired.store(true, Ordering::SeqCst);
                drop(cancelled);
                action();
            }
        });
        AutoRevert {
            state,
            handle: Some(handle),
        }
    }

    /// Cancel the pending rollback. Returns `true` if it was cancelled before
    /// firing, `false` if the timer had already run the action.
    pub fn confirm(&self) -> bool {
        {
            let mut c = self.state.cancelled.lock().unwrap();
            *c = true;
        }
        self.state.cvar.notify_all();
        !self.state.fired.load(Ordering::SeqCst)
    }

    /// Whether the rollback action has already run.
    pub fn fired(&self) -> bool {
        self.state.fired.load(Ordering::SeqCst)
    }
}

impl Drop for AutoRevert {
    fn drop(&mut self) {
        // Signal the worker to stop waiting so it does not fire after the guard
        // is gone (e.g. replaced by a newer pending change), then reap it.
        {
            let mut c = self.state.cancelled.lock().unwrap();
            *c = true;
        }
        self.state.cvar.notify_all();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    #[test]
    fn wait_returns_true_as_soon_as_running() {
        let calls = AtomicUsize::new(0);
        let running = |_: &str| calls.fetch_add(1, Ordering::SeqCst) >= 2;
        let start = Instant::now();
        assert!(wait_until_running_with(
            "svc",
            Duration::from_secs(5),
            Duration::from_millis(10),
            &running,
        ));
        // Came up on the third poll, well under the timeout.
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn wait_gives_up_after_timeout() {
        let never = |_: &str| false;
        assert!(!wait_until_running_with(
            "svc",
            Duration::from_millis(60),
            Duration::from_millis(10),
            &never,
        ));
    }

    #[test]
    fn auto_revert_fires_after_timeout() {
        let fired = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&fired);
        let guard = AutoRevert::arm(Duration::from_millis(50), move || {
            f.store(true, Ordering::SeqCst);
        });
        thread::sleep(Duration::from_millis(150));
        assert!(guard.fired());
        assert!(fired.load(Ordering::SeqCst));
        // Confirming after it fired reports that it was too late.
        assert!(!guard.confirm());
    }

    #[test]
    fn confirm_cancels_before_firing() {
        let fired = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&fired);
        let guard = AutoRevert::arm(Duration::from_secs(5), move || {
            f.store(true, Ordering::SeqCst);
        });
        assert!(guard.confirm());
        thread::sleep(Duration::from_millis(50));
        assert!(!guard.fired());
        assert!(!fired.load(Ordering::SeqCst));
    }

    #[test]
    fn drop_cancels_pending_action() {
        let fired = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&fired);
        drop(AutoRevert::arm(Duration::from_secs(5), move || {
            f.store(true, Ordering::SeqCst);
        }));
        thread::sleep(Duration::from_millis(50));
        assert!(!fired.load(Ordering::SeqCst));
    }
}
