//! Which backup hosts are online. Hosts are often home computers that sleep
//! or are switched off, so the daemon checks them every few minutes. Sets that
//! back up to a host that is away wait for it instead of failing over and
//! over, and back up as soon as it is reachable again (see
//! [`Event::PeerOnline`]).

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kinvault_net::Endpoint;
use tokio::sync::broadcast;

use crate::api::Event;
use crate::worker::peer_addr;

/// How often backup hosts are checked, and how long a check waits for one.
#[derive(Clone, Copy, Debug)]
pub struct ReachabilityOptions {
    pub interval: Duration,
    pub timeout: Duration,
}

impl Default for ReachabilityOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(2 * 60),
            timeout: Duration::from_secs(15),
        }
    }
}

/// What is known about a host's reachability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HostState {
    /// `None` until it has been checked.
    pub online: Option<bool>,
    /// When it was last reachable (Unix seconds), also from before a restart.
    pub last_seen_unix: Option<i64>,
}

/// Where to reach a host.
#[derive(Clone, Debug)]
pub(crate) struct HostTarget {
    pub id: String,
    pub addrs: Vec<SocketAddr>,
    pub hosts: Vec<String>,
}

impl HostTarget {
    /// Also tries these addresses.
    pub fn add(&mut self, addrs: &[SocketAddr], hosts: &[String]) {
        for a in addrs {
            if !self.addrs.contains(a) {
                self.addrs.push(*a);
            }
        }
        for h in hosts {
            if !self.hosts.contains(h) {
                self.hosts.push(h.clone());
            }
        }
    }
}

/// Reachability of every backup host, shared by the daemon and set workers.
pub(crate) struct Hosts {
    states: Mutex<HashMap<String, HostState>>,
    /// Keeps `last_seen_unix` across restarts.
    seen_path: PathBuf,
    events: broadcast::Sender<Event>,
    pub opts: ReachabilityOptions,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl Hosts {
    pub fn new(
        seen_path: PathBuf,
        events: broadcast::Sender<Event>,
        opts: ReachabilityOptions,
    ) -> Self {
        let seen: HashMap<String, i64> = fs::read_to_string(&seen_path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        let states = seen
            .into_iter()
            .map(|(id, t)| {
                let state = HostState {
                    online: None,
                    last_seen_unix: Some(t),
                };
                (id, state)
            })
            .collect();
        Self {
            states: Mutex::new(states),
            seen_path,
            events,
            opts,
        }
    }

    pub fn get(&self, id: &str) -> HostState {
        self.states
            .lock()
            .unwrap()
            .get(id)
            .copied()
            .unwrap_or_default()
    }

    /// Whether the host is known to be offline (not just unchecked).
    pub fn is_offline(&self, id: &str) -> bool {
        self.get(id).online == Some(false)
    }

    /// Records whether a host could be reached, telling subscribers if that
    /// changed.
    pub fn record(&self, id: &str, online: bool) {
        let mut states = self.states.lock().unwrap();
        let state = states.entry(id.to_string()).or_default();
        let changed = state.online != Some(online);
        state.online = Some(online);
        if online {
            state.last_seen_unix = Some(unix_now());
        }
        if !changed {
            return;
        }
        // Only on changes, so the file isn't rewritten at every check.
        let seen: HashMap<&str, i64> = states
            .iter()
            .filter_map(|(id, s)| Some((id.as_str(), s.last_seen_unix?)))
            .collect();
        let json = serde_json::to_string(&seen);
        drop(states);
        if let Ok(json) = json
            && let Err(e) = crate::config::write_private(&self.seen_path, json.as_bytes())
        {
            tracing::debug!("couldn't save when hosts were last seen: {e:#}");
        }
        if online {
            tracing::info!(peer = %id, "backup host is online");
        } else {
            tracing::info!(peer = %id, "backup host can't be reached");
        }
        let _ = self.events.send(Event::PeerOnline {
            id: id.to_string(),
            online,
        });
    }

    /// Forgets hosts that no longer keep any backups, keeping when they were
    /// last seen.
    pub fn retain(&self, keep: impl Fn(&str) -> bool) {
        for (id, state) in self.states.lock().unwrap().iter_mut() {
            if !keep(id) {
                state.online = None;
            }
        }
    }

    /// Connects to a host to see if it's reachable, and records the result.
    pub async fn check(&self, endpoint: &Endpoint, target: &HostTarget) -> bool {
        let online = match peer_addr(&target.id, &target.addrs) {
            Ok(addr) => {
                match kinvault_net::ping(endpoint, addr, &target.hosts, self.opts.timeout).await {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::debug!(peer = %target.id, "backup host unreachable: {e}");
                        false
                    }
                }
            }
            Err(_) => false,
        };
        self.record(&target.id, online);
        online
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changes_are_announced_and_last_seen_survives_restarts() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("hosts-seen.json");
        let (tx, mut rx) = broadcast::channel(16);
        let hosts = Hosts::new(path.clone(), tx.clone(), Default::default());
        assert_eq!(hosts.get("a"), HostState::default());
        assert!(!hosts.is_offline("a"), "unchecked hosts aren't offline");

        hosts.record("a", false);
        assert!(hosts.is_offline("a"));
        assert!(matches!(
            rx.try_recv(),
            Ok(Event::PeerOnline { online: false, .. })
        ));
        hosts.record("a", false);
        assert!(rx.try_recv().is_err(), "no news is not announced");

        hosts.record("a", true);
        assert!(matches!(
            rx.try_recv(),
            Ok(Event::PeerOnline { online: true, .. })
        ));
        let seen = hosts.get("a").last_seen_unix.unwrap();
        assert!(seen > 0);

        let again = Hosts::new(path, tx, Default::default());
        assert_eq!(
            again.get("a"),
            HostState {
                online: None,
                last_seen_unix: Some(seen)
            }
        );
    }
}
