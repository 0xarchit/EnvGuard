use env_guard_core::env_guard::envGuard;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct VaultState {
    pub inner: Arc<Mutex<Option<envGuard>>>,
}

impl Default for VaultState {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
        }
    }
}
