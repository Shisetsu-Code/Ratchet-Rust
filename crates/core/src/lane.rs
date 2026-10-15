use crate::error::DomainError;
use futures_channel::oneshot;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
};

#[derive(Default)]
struct Inner {
    active: Cell<bool>,
    queue: RefCell<VecDeque<oneshot::Sender<LaneGuard>>>,
}
#[derive(Default)]
pub struct FifoLane {
    inner: Rc<Inner>,
}
pub struct LaneGuard {
    inner: Option<Rc<Inner>>,
}

impl FifoLane {
    pub fn new() -> Self {
        Self::default()
    }
    pub async fn enter(&self) -> Result<LaneGuard, DomainError> {
        if !self.inner.active.replace(true) {
            return Ok(LaneGuard {
                inner: Some(self.inner.clone()),
            });
        }
        let (sender, receiver) = oneshot::channel();
        self.inner.queue.borrow_mut().push_back(sender);
        receiver
            .await
            .map_err(|_| DomainError::new("SEND_LANE_CLOSED", 503))
    }
}

impl Drop for LaneGuard {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        loop {
            let next = inner.queue.borrow_mut().pop_front();
            let Some(sender) = next else {
                inner.active.set(false);
                return;
            };
            let guard = LaneGuard {
                inner: Some(inner.clone()),
            };
            match sender.send(guard) {
                Ok(()) => return,
                // Avoid recursive drops when many cancelled callers are queued.
                Err(mut cancelled) => {
                    cancelled.inner.take();
                }
            }
        }
    }
}
