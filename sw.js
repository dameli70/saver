/*
  Controle service worker

  Scope: app root (sw.js is served from /)

  Goals (v1):
   - cache static assets for faster load
   - allow basic shell to load offline
   - keep API requests network-first
*/

const CACHE = 'controle-v16';

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
  // (Use includes('/api/') so this works for subdirectory installs too.)
  if (url.pathname.includes('/api/')) return;

  // For a few critical assets, prefer network-first so UI fixes land immediately.
  const criticalAsset = (
    url.pathname.endsWith('/assets/app.css') ||
    url.pathname.endsWith('/assets/base.css') ||
    url.pathname.endsWith('/assets/app.js')
  );

  if (url.pathname.includes('/assets/') && criticalAsset) {
    event.respondWith(
      caches.open(CACHE).then(async (cache) => {
        try{
          const res = await fetch(req);
          if (res && res.ok) cache.put(req, res.clone());
          return res;
        }catch{
          const cached = await cache.match(req);
          if (cached) return cached;
          throw new Error('offline');
        }
      })
    );
    return;
  }

  // Stale-while-revalidate for other static assets.
  // This avoids users being stuck on old CSS/JS after deploys.
  if (url.pathname.includes('/assets/')) {
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
