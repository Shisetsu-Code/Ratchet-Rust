import { useEffect, useRef, type TouchEvent } from 'react';
import { navigationSwipe, type SwipePoint } from './navigation-swipe';

export function useMobileNavigation(open: boolean, onOpen: () => void, onClose: () => void) {
  const start = useRef<SwipePoint | null>(null);
  const callbacks = useRef({ onOpen, onClose });
  const pendingBack = useRef<Promise<void> | null>(null);
  callbacks.current = { onOpen, onClose };
  useEffect(() => {
    // React touch listeners are passive. Claim only our horizontal navigation
    // gesture before Chrome interprets the same edge swipe as browser Back.
    const claimSwipe = (event: globalThis.TouchEvent) => {
      const from = start.current;
      const touch = event.touches[0];
      if (!from || !touch || event.touches.length !== 1) return;
      const dx = touch.clientX - from.x;
      const dy = touch.clientY - from.y;
      if ((open || from.x <= 28) && Math.abs(dx) > 8 && Math.abs(dx) > Math.abs(dy) * 1.5 && event.cancelable) event.preventDefault();
    };
    document.addEventListener('touchmove', claimSwipe, { passive: false });
    return () => document.removeEventListener('touchmove', claimSwipe);
  }, [open]);
  // A transient history entry lets Android/browser back close the active screen.
  useEffect(() => {
    if (!open || !window.matchMedia('(max-width: 760px)').matches) return;
    const marker = crypto.randomUUID();
    let cancelled = false;
    let active = false;
    const onBack = () => {
      if (history.state?.ratchetScreen !== marker) callbacks.current.onClose();
    };
    const activate = () => {
      if (cancelled) return;
      history.pushState({ ...history.state, ratchetScreen: marker }, '');
      window.addEventListener('popstate', onBack);
      active = true;
    };
    // A preceding close may still be traversing history. Reopening must not
    // push a new entry until that traversal finishes, or its pop closes this screen.
    if (pendingBack.current) void pendingBack.current.then(activate);
    else activate();
    return () => {
      cancelled = true;
      window.removeEventListener('popstate', onBack);
      if (active && history.state?.ratchetScreen === marker) {
        const traversal = new Promise<void>((resolve) => {
          window.addEventListener('popstate', () => resolve(), { once: true });
          history.back();
        });
        pendingBack.current = traversal;
        void traversal.then(() => {
          if (pendingBack.current === traversal) pendingBack.current = null;
        });
      }
    };
  }, [open]);
  return {
    onTouchStart: (event: TouchEvent<HTMLElement>) => {
      start.current = null;
      if (!window.matchMedia('(max-width: 760px)').matches || event.touches.length !== 1) return;
      if (event.target instanceof Element && event.target.closest('input,textarea,select,button,a,label,[data-no-navigation-gesture]')) return;
      const touch = event.touches[0];
      if (!touch) return;
      start.current = { x: touch.clientX, y: touch.clientY, time: event.timeStamp };
    },
    onTouchEnd: (event: TouchEvent<HTMLElement>) => {
      const from = start.current;
      start.current = null;
      if (!from || event.changedTouches.length !== 1) return;
      const touch = event.changedTouches[0];
      if (!touch) return;
      const result = navigationSwipe(from, { x: touch.clientX, y: touch.clientY, time: event.timeStamp }, open);
      if (result === 'open') callbacks.current.onOpen();
      if (result === 'close') callbacks.current.onClose();
    },
    onTouchCancel: () => { start.current = null; },
  };
}
