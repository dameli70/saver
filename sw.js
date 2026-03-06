/* LOCKSMITH PWA service worker

   This is intentionally conservative:
   - No caching of /api responses
   - No caching of authenticated HTML pages
*/

const CACHE = 'locksmith-static-v1';

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((c) => c.addAll([
      '/',
      '/index.php',
      '/faq.php',
      '/manifest.webmanifest',
      '/assets/icon-192.svg',
      '/assets/icon-512.svg',
    ])).catch(() => {})
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.map((k) => (k === CACHE ? null : caches.delete(k))))).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  if (req.method !== 'GET') return;
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return;

  // Avoid caching authenticated pages.
  const isDynamicPage = url.pathname.endsWith('.php');
  const isPublicPage = url.pathname === '/' || url.pathname === '/index.php' || url.pathname === '/faq.php';

  if (isDynamicPage && !isPublicPage) return;

  event.respondWith(
    caches.match(req).then((cached) => {
      const fetchPromise = fetch(req)
        .then((resp) => {
          if (resp.ok) {
            const copy = resp.clone();
            caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
          }
          return resp;
        })
        .catch(() => cached || Response.error());

      return cached || fetchPromise;
    })
  );
});
