const CACHE = 'ratchet-shell-v4';
const SHELL = ['/', '/manifest.webmanifest', '/app-icon.svg'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(Promise.all([
    caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key)))),
    self.clients.claim(),
  ]));
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || request.method !== 'GET') return;

  // API authority is always the server. Never satisfy an API read from CacheStorage.
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(request));
    return;
  }

  // Navigations are network-first so a newly deployed index immediately points
  // at the current content-hashed application bundles.
  if (request.mode === 'navigate') {
    event.respondWith(fetch(request).then(async (response) => {
      if (response.ok) (await caches.open(CACHE)).put('/', response.clone());
      return response;
    }).catch(async () => (await caches.match('/')) || new Response('Offline', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } })));
    return;
  }

  // Cache only the public application shell and build assets.
  // Vite uses /@fs/ for its env module when node_modules is a symlink or junction.
  // Allow only that public runtime module, never arbitrary filesystem URLs.
  const viteEnvironmentModule = url.pathname.startsWith('/@fs/')
    && url.pathname.endsWith('/node_modules/vite/dist/client/env.mjs');
  const localDevelopmentAsset = ['localhost', '127.0.0.1'].includes(url.hostname)
    && (viteEnvironmentModule || ['/src/', '/node_modules/.vite/', '/node_modules/vite/dist/client/env.mjs', '/@vite/', '/@react-refresh'].some(prefix => url.pathname.startsWith(prefix)));
  if (!SHELL.includes(url.pathname) && !url.pathname.startsWith('/assets/') && !localDevelopmentAsset) return;

  // Executable/style assets are also network-first. An already-open tab may of
  // course keep its currently executing JS until reload, but a reload after a
  // deployment must not be held on an older cached application bundle.
  if (request.destination === 'script' || request.destination === 'style' || request.destination === 'worker') {
    event.respondWith(fetch(request).then(async (response) => {
      if (response.ok && response.type === 'basic') (await caches.open(CACHE)).put(request, response.clone());
      return response;
    }).catch(async () => (await caches.match(request)) || new Response('', { status: 503 })));
    return;
  }

  event.respondWith(caches.match(request).then(async (cached) => {
    if (cached) return cached;
    const response = await fetch(request);
    if (response.ok && response.type === 'basic') (await caches.open(CACHE)).put(request, response.clone());
    return response;
  }));
});

self.addEventListener('push', (event) => {
  event.waitUntil(self.registration.showNotification('Nueva actividad', {
    body: 'Abrí Ratchet para sincronizar los cambios de forma segura.',
    icon: '/app-icon.svg',
    badge: '/app-icon.svg',
    tag: 'ratchet-change',
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = '/';
  event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(async (clients) => {
    for (const client of clients) {
      if ('focus' in client) {
        await client.focus();
        if ('navigate' in client) await client.navigate(target);
        return;
      }
    }
    if (self.clients.openWindow) await self.clients.openWindow(target);
  }));
});
