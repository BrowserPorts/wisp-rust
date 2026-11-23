//! A backend whose networks are channels a test holds: what a tunnel lets
//! out arrives on [`MemoryNetwork::from_tunnel`], and what the test sends on
//! [`MemoryNetwork::to_tunnel`] reaches the tunnel as if the internet had
//! answered. Teardown is observable through [`MemoryNetwork::torn_down`].

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::backend::{Backend, BackendError, Device, DeviceGuard, NetworkPlan, DEVICE_QUEUE};

/// The test's end of one tunnel's network.
pub struct MemoryNetwork {
    pub plan: NetworkPlan,
    pub from_tunnel: mpsc::Receiver<Bytes>,
    pub to_tunnel: mpsc::Sender<Bytes>,
    torn_down: CancellationToken,
}

impl MemoryNetwork {
    /// Resolves once the tunnel's network has been torn down.
    pub async fn torn_down(&self) {
        self.torn_down.cancelled().await
    }

    pub fn is_torn_down(&self) -> bool {
        self.torn_down.is_cancelled()
    }
}

struct Teardown(CancellationToken);

impl Drop for Teardown {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Hands each network it builds to the receiver returned by [`Self::new`].
pub struct MemoryBackend {
    networks: mpsc::UnboundedSender<MemoryNetwork>,
    fail: parking_lot::Mutex<Option<String>>,
}

impl MemoryBackend {
    pub fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<MemoryNetwork>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                networks: tx,
                fail: parking_lot::Mutex::new(None),
            }),
            rx,
        )
    }

    /// Makes the next network fail to build with `reason`.
    pub fn fail_next(&self, reason: &str) {
        *self.fail.lock() = Some(reason.to_owned());
    }
}

#[async_trait]
impl Backend for MemoryBackend {
    async fn create(&self, plan: NetworkPlan) -> Result<Device, BackendError> {
        if let Some(reason) = self.fail.lock().take() {
            return Err(BackendError::Setup(reason));
        }
        let (to_network, from_tunnel) = mpsc::channel(DEVICE_QUEUE);
        let (to_tunnel, from_network) = mpsc::channel(DEVICE_QUEUE);
        let torn_down = CancellationToken::new();
        let _ = self.networks.send(MemoryNetwork {
            plan,
            from_tunnel,
            to_tunnel,
            torn_down: torn_down.clone(),
        });
        Ok(Device {
            to_network,
            from_network,
            guard: DeviceGuard::new(Teardown(torn_down)),
        })
    }

    fn name(&self) -> &'static str {
        "memory"
    }
}
