//! Resume tokens (section 8 of the extension).
//!
//! Every tunnel of a connection that negotiated RESUME has one live token.
//! While the connection holds the tunnel the token is *attached*; when the
//! connection ends without closing the tunnel, the tunnel is *parked* here
//! for the grace period with its network, addresses and flows. An `OPEN` with
//! `RESUME` takes a parked tunnel, or asks the connection that still holds it
//! to let go, which covers a client that notices an outage before the server
//! does. Tokens are single-use, bound to the principal that created them,
//! and gone once the grace period ends.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use wisp_ip::ResumeToken;

use crate::service::Tunnel;

enum Slot {
    /// Held by a connection; cancelling the token asks it to park the tunnel.
    Attached(CancellationToken),
    Parked {
        tunnel: Box<Tunnel>,
        expires: Instant,
    },
}

struct Entry {
    principal: Option<String>,
    slot: Slot,
}

#[derive(Default)]
pub(crate) struct ResumeStore {
    entries: Mutex<HashMap<ResumeToken, Entry>>,
    changed: Notify,
}

impl ResumeStore {
    pub(crate) fn attach(
        &self,
        token: ResumeToken,
        principal: Option<String>,
        steal: CancellationToken,
    ) {
        // Whatever the insert displaces is dropped after the lock is released.
        let displaced = self.entries.lock().insert(
            token,
            Entry {
                principal,
                slot: Slot::Attached(steal),
            },
        );
        drop(displaced);
    }

    /// Parks `tunnel` under `token` for `grace`, after which it is dropped
    /// and its network torn down unless resumed first.
    pub(crate) fn park(self: &Arc<Self>, token: ResumeToken, tunnel: Tunnel, grace: Duration) {
        let expires = Instant::now() + grace;
        let displaced = {
            let mut entries = self.entries.lock();
            match entries.get_mut(&token) {
                Some(entry) => Some(std::mem::replace(
                    &mut entry.slot,
                    Slot::Parked {
                        tunnel: Box::new(tunnel),
                        expires,
                    },
                )),
                // The token was forgotten meanwhile: the tunnel just ends.
                None => {
                    drop(entries);
                    drop(tunnel);
                    return;
                }
            }
        };
        drop(displaced);
        self.changed.notify_waiters();
        let store = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep_until(expires).await;
            if let Some(store) = store.upgrade() {
                store.expire(token, expires);
            }
        });
    }

    fn expire(&self, token: ResumeToken, expires: Instant) {
        let removed = {
            let mut entries = self.entries.lock();
            let stale = matches!(
                entries.get(&token),
                Some(Entry { slot: Slot::Parked { expires: at, .. }, .. }) if *at == expires
            );
            if stale {
                entries.remove(&token)
            } else {
                None
            }
        };
        if let Some(entry) = removed {
            if let Slot::Parked { tunnel, .. } = entry.slot {
                tracing::debug!(
                    tunnel = tunnel.id(),
                    "wisp-tun: resume grace over, tunnel ends"
                );
            }
        }
    }

    /// Forgets `token`, ending any tunnel parked under it. The tunnel is
    /// dropped after the lock is released, since dropping one forgets its
    /// token in turn.
    pub(crate) fn forget(&self, token: &ResumeToken) {
        let removed = self.entries.lock().remove(token);
        drop(removed);
    }

    /// Takes the tunnel `token` names for `principal`. A tunnel still held by
    /// a connection is asked to park, and waited for up to `wait`.
    pub(crate) async fn take(
        &self,
        token: &ResumeToken,
        principal: Option<&str>,
        wait: Duration,
    ) -> Option<Tunnel> {
        let deadline = Instant::now() + wait;
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut entries = self.entries.lock();
                let entry = entries.get(token)?;
                if entry.principal.as_deref() != principal {
                    return None;
                }
                match &entry.slot {
                    Slot::Parked { .. } => {
                        let entry = entries.remove(token)?;
                        let Slot::Parked { tunnel, .. } = entry.slot else {
                            return None;
                        };
                        return Some(*tunnel);
                    }
                    Slot::Attached(steal) => steal.cancel(),
                }
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return None;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().len()
    }
}
