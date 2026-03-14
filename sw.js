/*
  Controle service worker

  Scope: app root (sw.js is served from /)

  Goals (v1):
   - cache static assets for faster load
   - allow basic shell to load offline
   - keep API requests network-first
*/

const CACHE = 'controle-v13';

const ASSETS = [
  './',
  './index.php',
  './login.php',
  './assets/base.css',
  './assets/app.css',
  './assets/auth.css',
  './assets/app.js',
  './assets/theme.js',
  './assets/security.js',
  './assets/security_page.css',
  './assets/admin_shared.js',
  './assets/admin_users.js',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys.map((k) => (k === CACHE ? null : caches.delete(k)))
    )).then(() => self.clients.claim())
  );
});

function isHtmlRequest(req){
  return req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html');
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  if (url.origin !== self.location.origin) return;

  // Never cache API responses.
  if (url.pathname.startsWith('/api/')) return;

  // Stale-while-revalidate for static assets.
  // This avoids users being stuck on old CSS/JS after deploys.
  if (url.pathname.startsWith('/assets/')) {
    event.respondWith(
      caches.open(CACHE).then(async (cache) => {
        const cached = await cache.match(req);

        const network = fetch(req).then((res) => {
          try{ if (res && res.ok) cache.put(req, res.clone()); }catch{}
          return res;
        });

        if (cached) {
          event.waitUntil(network.catch(()=>{}));
          return cached;
        }
        return network;
      })
    );
    return;
  }

  // Network-first for HTML navigations; fallback to cached shell.
  if (isHtmlRequest(req)) {
    event.respondWith(
      fetch(req).then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy));
        return res;
      }).catch(() => caches.match(req).then((hit) => hit || caches.match('./')))
    );
  }
});
