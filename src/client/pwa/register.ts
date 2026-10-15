export async function registerPwaServiceWorker(): Promise<ServiceWorkerRegistration | null> {
  if (!('serviceWorker' in navigator) || !window.isSecureContext) return null;
  try {
    return await navigator.serviceWorker.register('/sw.js', { scope: '/', updateViaCache: 'none' });
  } catch (error) {
    console.warn('Service worker registration failed', error);
    return null;
  }
}
