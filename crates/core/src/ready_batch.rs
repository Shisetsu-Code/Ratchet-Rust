//! Runtime-independent FIFO batching and bounded concurrent preparation.
use std::{
    cell::RefCell,
    collections::VecDeque,
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll, Waker},
};

enum Slot<T> {
    Pending,
    Ready(T),
    Cancelled,
}
type Slots<T> = Rc<RefCell<VecDeque<Rc<RefCell<Slot<T>>>>>>;
type Notify = Rc<RefCell<Option<Rc<dyn Fn()>>>>;
fn notify_change(notify: &Notify) {
    let callback = notify.borrow().clone();
    if let Some(callback) = callback {
        callback();
    }
}

/// A reservation-ordered queue. Reserve synchronously before any preparation await.
pub struct ReadyBatchQueue<T> {
    slots: Slots<T>,
    notify: Notify,
}
impl<T> Clone for ReadyBatchQueue<T> {
    fn clone(&self) -> Self {
        Self {
            slots: self.slots.clone(),
            notify: self.notify.clone(),
        }
    }
}
impl<T> Default for ReadyBatchQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}
impl<T> ReadyBatchQueue<T> {
    /// Installs a synchronous change notification; avoid capturing the queue strongly.
    pub fn set_notify(&self, callback: Rc<dyn Fn()>) {
        let previous = self.notify.borrow_mut().replace(callback);
        drop(previous);
    }
    pub fn new() -> Self {
        Self {
            slots: Rc::new(RefCell::new(VecDeque::new())),
            notify: Rc::new(RefCell::new(None)),
        }
    }
    pub fn reserve(&self) -> Ticket<T> {
        let slot = Rc::new(RefCell::new(Slot::Pending));
        self.slots.borrow_mut().push_back(slot.clone());
        Ticket {
            slot: Some(slot),
            owner: self.slots.clone(),
            notify: self.notify.clone(),
        }
    }
    /// Publishes a prepared result. A ticket belongs to exactly one queue.
    pub fn ready(&self, mut ticket: Ticket<T>, value: T) {
        assert!(
            Rc::ptr_eq(&self.slots, &ticket.owner),
            "ticket belongs to another queue"
        );
        let Some(slot) = ticket.slot.take() else {
            unreachable!("ticket already completed")
        };
        *slot.borrow_mut() = Slot::Ready(value);
        notify_change(&self.notify);
    }
    /// Takes a contiguous ready prefix immediately; pending heads never get overtaken.
    pub fn take_ready(&self, max: usize) -> Vec<T> {
        let mut result = Vec::new();
        let mut slots = self.slots.borrow_mut();
        while result.len() < max {
            let Some(front) = slots.front() else { break };
            if matches!(*front.borrow(), Slot::Pending) {
                break;
            }
            let Some(slot) = slots.pop_front() else {
                unreachable!("front exists")
            };
            let state = std::mem::replace(&mut *slot.borrow_mut(), Slot::Cancelled);
            if let Slot::Ready(value) = state {
                result.push(value)
            }
        }
        result
    }
}
/// Dropping an unfinished reservation cancels it without blocking later entries.
pub struct Ticket<T> {
    slot: Option<Rc<RefCell<Slot<T>>>>,
    owner: Slots<T>,
    notify: Notify,
}
impl<T> Drop for Ticket<T> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            *slot.borrow_mut() = Slot::Cancelled;
            notify_change(&self.notify);
        }
    }
}

struct Waiter {
    waker: Option<Waker>,
}
struct WindowState {
    limit: usize,
    active: usize,
    waiters: VecDeque<Rc<RefCell<Waiter>>>,
}
impl WindowState {
    fn next_waker(&self) -> Option<Waker> {
        if self.active < self.limit {
            self.waiters.front().and_then(|w| w.borrow().waker.clone())
        } else {
            None
        }
    }
}
/// Limits preparation plus persistence. Keep the permit until durable completion.
#[derive(Clone)]
pub struct PreparationWindow {
    state: Rc<RefCell<WindowState>>,
}
impl PreparationWindow {
    pub fn new(limit: usize) -> Self {
        assert!(limit > 0, "preparation window must have positive capacity");
        Self {
            state: Rc::new(RefCell::new(WindowState {
                limit,
                active: 0,
                waiters: VecDeque::new(),
            })),
        }
    }
    /// Reserves FIFO position immediately, even before this future is first polled.
    pub fn acquire(&self) -> Acquire {
        let waiter = Rc::new(RefCell::new(Waiter { waker: None }));
        self.state.borrow_mut().waiters.push_back(waiter.clone());
        Acquire {
            state: self.state.clone(),
            waiter: Some(waiter),
        }
    }
}
pub struct Acquire {
    state: Rc<RefCell<WindowState>>,
    waiter: Option<Rc<RefCell<Waiter>>>,
}
impl Future for Acquire {
    type Output = PreparationPermit;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let Some(waiter) = this.waiter.as_ref() else {
            panic!("acquisition polled after completion")
        };
        let mut state = this.state.borrow_mut();
        let is_head = state
            .waiters
            .front()
            .is_some_and(|head| Rc::ptr_eq(head, waiter));
        if state.active < state.limit && is_head {
            state.waiters.pop_front();
            state.active += 1;
            let wake = state.next_waker();
            drop(state);
            this.waiter = None;
            if let Some(waker) = wake {
                waker.wake()
            }
            Poll::Ready(PreparationPermit {
                state: this.state.clone(),
            })
        } else {
            waiter.borrow_mut().waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
impl Drop for Acquire {
    fn drop(&mut self) {
        if let Some(waiter) = self.waiter.take() {
            let wake = {
                let mut state = self.state.borrow_mut();
                state.waiters.retain(|w| !Rc::ptr_eq(w, &waiter));
                state.next_waker()
            };
            if let Some(waker) = wake {
                waker.wake()
            }
        }
    }
}
pub struct PreparationPermit {
    state: Rc<RefCell<WindowState>>,
}
impl Drop for PreparationPermit {
    fn drop(&mut self) {
        let wake = {
            let mut state = self.state.borrow_mut();
            state.active -= 1;
            state.next_waker()
        };
        if let Some(waker) = wake {
            waker.wake()
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll, Waker},
    };
    fn poll<F: Future + Unpin>(f: &mut F) -> Poll<F::Output> {
        Pin::new(f).poll(&mut Context::from_waker(Waker::noop()))
    }
    #[test]
    fn slow_head_blocks_fast_followers() {
        let q = ReadyBatchQueue::new();
        let first = q.reserve();
        let second = q.reserve();
        q.ready(second, 2);
        assert!(q.take_ready(16).is_empty());
        q.ready(first, 1);
        assert_eq!(q.take_ready(16), vec![1, 2]);
    }
    #[test]
    fn cancellation_unblocks_and_batches_are_immediate_and_bounded() {
        let q = ReadyBatchQueue::new();
        let cancelled = q.reserve();
        for i in 0..33 {
            let t = q.reserve();
            q.ready(t, i);
        }
        assert!(q.take_ready(16).is_empty());
        drop(cancelled);
        assert_eq!(q.take_ready(16), (0..16).collect::<Vec<_>>());
        assert_eq!(q.take_ready(16), (16..32).collect::<Vec<_>>());
        assert_eq!(q.take_ready(16), vec![32]);
        assert!(q.take_ready(16).is_empty());
    }
    #[test]
    fn thousand_out_of_order_completions_preserve_order() {
        let q = ReadyBatchQueue::new();
        let tickets: Vec<_> = (0..1000).map(|i| (i, q.reserve())).collect();
        for (i, t) in tickets.into_iter().rev() {
            q.ready(t, i);
        }
        let mut all = Vec::new();
        loop {
            let batch = q.take_ready(16);
            if batch.is_empty() {
                break;
            }
            all.extend(batch);
        }
        assert_eq!(all, (0..1000).collect::<Vec<_>>());
    }
    #[test]
    fn window_allows_64_and_releases_fifo_even_when_waiters_cancel() {
        let w = PreparationWindow::new(64);
        let mut permits = Vec::new();
        for _ in 0..64 {
            let mut f = w.acquire();
            match poll(&mut f) {
                Poll::Ready(p) => permits.push(p),
                _ => panic!("serialized preparation"),
            }
        }
        let mut first = w.acquire();
        let mut second = w.acquire();
        let mut third = w.acquire();
        assert!(poll(&mut second).is_pending());
        assert!(poll(&mut first).is_pending());
        drop(first);
        drop(permits.pop());
        assert!(poll(&mut third).is_pending());
        let p = match poll(&mut second) {
            Poll::Ready(p) => p,
            _ => panic!("leaked capacity"),
        };
        drop(p);
        assert!(poll(&mut third).is_ready());
        drop(permits);
        for _ in 0..64 {
            let mut f = w.acquire();
            assert!(poll(&mut f).is_ready());
        }
    }
    #[test]
    fn ready_and_cancellation_notify_outside_borrows() {
        let q = ReadyBatchQueue::new();
        let batches = Rc::new(RefCell::new(Vec::new()));
        let drain_queue = q.clone();
        let collected = batches.clone();
        q.set_notify(Rc::new(move || {
            collected.borrow_mut().extend(drain_queue.take_ready(16));
        }));
        let head = q.reserve();
        let next = q.reserve();
        q.ready(next, 2);
        assert!(batches.borrow().is_empty());
        drop(head);
        assert_eq!(*batches.borrow(), vec![2]);
        let last = q.reserve();
        q.ready(last, 3);
        assert_eq!(*batches.borrow(), vec![2, 3]);
        q.set_notify(Rc::new(|| {})); // Break the deliberate reentrant test capture.
    }
}
