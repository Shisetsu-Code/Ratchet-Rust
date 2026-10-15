export type SwipePoint = { x: number; y: number; time: number };

export function navigationSwipe(start: SwipePoint, end: SwipePoint, listOpen: boolean): 'open' | 'close' | null {
  const dx = end.x - start.x;
  const dy = Math.abs(end.y - start.y);
  if (end.time - start.time > 700 || Math.abs(dx) < 72 || Math.abs(dx) < dy * 2) return null;
  if (listOpen && dx < 0) return 'close';
  if (!listOpen && start.x <= 28 && dx > 0) return 'open';
  return null;
}
