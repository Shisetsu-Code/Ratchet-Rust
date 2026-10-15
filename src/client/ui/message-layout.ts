/** Measure real sizes before allowing the browser to skip offscreen contents.
 * Estimates shift the scroll position for variable-height chat bubbles.
 * One observer handles all rows; unsupported browsers retain normal layout.
 */
export function observeMessageLayout(container: HTMLElement): () => void {
  if (!('ResizeObserver' in window) || !CSS.supports('content-visibility', 'auto')) return () => {};
  const pending = new Set<HTMLElement>();
  const rows = new Set<HTMLElement>();
  let width = container.clientWidth;
  let frame = 0;
  let viewportFrame = 0;
  const measured = new Map<HTMLElement, DOMRectReadOnly>();
  const measure = (row: HTMLElement) => {
    measured.delete(row);
    row.style.contentVisibility = 'visible';
    row.style.removeProperty('contain-intrinsic-size');
    pending.add(row);
    sizes.observe(row);
  };
  const sizes = new ResizeObserver(entries => {
    for (const entry of entries) {
      const row = entry.target as HTMLElement;
      if (!pending.delete(row)) continue;
      sizes.unobserve(row);
      measured.set(row, entry.contentRect);
    }
    if (!frame) frame = requestAnimationFrame(() => {
      frame = 0;
      for (const [row, rect] of measured) {
        if (row.parentElement !== container) continue;
        row.style.containIntrinsicSize = 'auto ' + rect.width + 'px auto ' + rect.height + 'px';
        row.style.contentVisibility = 'auto';
      }
      measured.clear();
    });
  });
  const discover = () => {
    for (const row of rows) if (row.parentElement !== container) { rows.delete(row); pending.delete(row); sizes.unobserve(row); }
    for (const child of container.children) {
      if (!(child instanceof HTMLElement) || !child.classList.contains('bubble') || rows.has(child)) continue;
      rows.add(child); measure(child);
    }
  };
  const additions = new MutationObserver(discover);
  additions.observe(container, {childList:true});
  const viewport = new ResizeObserver(() => {
    if (container.clientWidth === width) return;
    width = container.clientWidth;
    cancelAnimationFrame(viewportFrame);
    viewportFrame = requestAnimationFrame(() => { for (const row of rows) measure(row); });
  });
  viewport.observe(container);
  discover();
  return () => {
    cancelAnimationFrame(frame); cancelAnimationFrame(viewportFrame); measured.clear();
    additions.disconnect(); viewport.disconnect(); sizes.disconnect();
    for (const row of rows) { row.style.removeProperty('content-visibility'); row.style.removeProperty('contain-intrinsic-size'); }
    rows.clear(); pending.clear();
  };
}
