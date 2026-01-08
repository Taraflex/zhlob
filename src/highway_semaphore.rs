use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::oneshot;

pub type SemaphoreResult<T> = std::result::Result<T, &'static str>;

struct State {
    available: usize,
    high_queue: VecDeque<oneshot::Sender<()>>,
    low_queue: VecDeque<oneshot::Sender<()>>,
}

pub struct HighwaySemaphore {
    state: Arc<Mutex<State>>,
}

pub struct HighwayPermit {
    state: Arc<Mutex<State>>,
}

impl HighwaySemaphore {
    pub fn new(permits: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                available: permits,
                high_queue: VecDeque::new(),
                low_queue: VecDeque::new(),
            })),
        }
    }

    pub async fn acquire(&self, is_high: bool) -> SemaphoreResult<HighwayPermit> {
        let rx = {
            let mut state = self.state.lock();

            let can_take = if is_high {
                state.available > 0
            } else {
                state.available > 0 && state.high_queue.is_empty()
            };

            if can_take {
                state.available -= 1;
                return Ok(HighwayPermit {
                    state: Arc::clone(&self.state),
                });
            }

            let (tx, rx) = oneshot::channel();
            if is_high {
                state.high_queue.push_back(tx);
            } else {
                state.low_queue.push_back(tx);
            }
            rx
        };

        match rx.await {
            Ok(_) => Ok(HighwayPermit {
                state: Arc::clone(&self.state),
            }),
            Err(_) => {
                self.release_and_notify();
                Err("Semaphore acquire cancelled")
            }
        }
    }

    fn release_and_notify(&self) {
        let mut state = self.state.lock();
        state.available += 1;
        Self::notify_next(&mut state);
    }

    fn notify_next(state: &mut State) {
        while state.available > 0 {
            let waiter = state
                .high_queue
                .pop_front()
                .or_else(|| state.low_queue.pop_front());

            match waiter {
                Some(tx) => {
                    if tx.send(()).is_ok() {
                        state.available -= 1;
                    }
                }
                None => break,
            }
        }
    }
}

impl Drop for HighwayPermit {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        state.available += 1;
        HighwaySemaphore::notify_next(&mut state);
    }
}
