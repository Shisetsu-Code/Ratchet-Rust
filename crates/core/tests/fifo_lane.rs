use ratchet_core::lane::FifoLane;
use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

#[test]
fn grants_are_fifo_instead_of_mutex_wakeup_order() {
    let lane = FifoLane::new();
    let mut cx = Context::from_waker(Waker::noop());
    let mut first = pin!(lane.enter());
    let initial = match first.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(guard)) => guard,
        _ => panic!("first turn"),
    };
    let mut second = pin!(lane.enter());
    let mut third = pin!(lane.enter());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    assert!(third.as_mut().poll(&mut cx).is_pending());
    drop(initial);
    assert!(third.as_mut().poll(&mut cx).is_pending());
    let next = match second.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(guard)) => guard,
        _ => panic!("second turn"),
    };
    assert!(third.as_mut().poll(&mut cx).is_pending());
    drop(next);
    assert!(matches!(third.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
}

#[test]
fn cancelling_an_already_notified_waiter_does_not_block_the_queue() {
    let lane = FifoLane::new();
    let mut cx = Context::from_waker(Waker::noop());
    let mut first = Box::pin(lane.enter());
    let guard = match first.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(g)) => g,
        _ => panic!("first"),
    };
    let mut cancelled = Box::pin(lane.enter());
    let mut next = Box::pin(lane.enter());
    assert!(cancelled.as_mut().poll(&mut cx).is_pending());
    assert!(next.as_mut().poll(&mut cx).is_pending());
    drop(guard);
    drop(cancelled);
    assert!(matches!(next.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
}

#[test]
fn a_thousand_waiters_are_released_in_order() {
    let lane = FifoLane::new();
    let mut cx = Context::from_waker(Waker::noop());
    let mut first = Box::pin(lane.enter());
    let guard = match first.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(g)) => g,
        _ => panic!("first"),
    };
    let mut pending = (0..1000)
        .map(|_| Box::pin(lane.enter()))
        .collect::<Vec<_>>();
    for future in &mut pending {
        assert!(future.as_mut().poll(&mut cx).is_pending());
    }
    drop(guard);
    for future in &mut pending {
        let guard = match future.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(g)) => g,
            _ => panic!("FIFO turn"),
        };
        drop(guard);
    }
}
