import { useEffect, useRef, type TouchEvent } from 'react';
import { navigationSwipe, type SwipePoint } from './navigation-swipe';

export function useMobileNavigation(open: boolean, onOpen: () => void, onClose: () => void) {
  const start = useRef<SwipePoint | null>(null);
  const callbacks = useRef({ onOpen, onClose });
  callbacks.current = { onOpen, onClose };
  // A transient history entry lets Android/browser back close the active screen.
  useEffect(() => {
    if (!open || !window.matchMedia('(max-width: 760px)').matches) return;
    const marker = crypto.randomUUID();
    history.pushState({ ...history.state, ratchetScreen: marker }, '');
    const onBack = () => {
      if (history.state?.ratchetScreen !== marker) callbacks.current.onClose();
    };
    window.addEventListener('popstate', onBack);
    return () => {
      window.removeEventListener('popstate', onBack);
      if (history.state?.ratchetScreen === marker) history.back();
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
