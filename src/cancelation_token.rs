use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}
pub struct CancellationGuard {
    token: CancellationToken,
}

impl CancellationGuard {
    pub fn new() -> (CancellationToken, Self) {
        let token = CancellationToken::new();
        let guard = Self {
            token: token.clone(),
        };
        (token, guard)
    }
}

impl Drop for CancellationGuard {
    fn drop(&mut self) {
        self.token.cancel();
    }
}
