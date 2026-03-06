/* LOCKSMITH PWA service worker

   This is intentionally conservative:
   - No caching of /api responses
   - Cache only static assets (no authenticated HTML)
*/

const CACHE = 'locksmith-static-v1';
const SCOPE_PATH = new URL(self.registration.scope).pathname; // e.g. "/" or "/locksmith/"
const SCOPE_PREFIX = SCOPE_PATH.endsWith('/') ? SCOPE_PATH : (SCOPE_PATH + '/');
const ASSETS_PREFIX = SCOPE_PREFIX + 'assets/';
const MANIFEST_PATH = SCOPE_PREFIX + 'manifest.webmanifest';
const API_PREFIX = SCOPE_PREFIX + 'api/';

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((c) => c.addAll([
      'manifest.webmanifest',
      'assets/icon-192.svg',
      'assets/icon-512.svg',
    ])).catch(() => {})
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.map((k) => (k === CACHE ? null : caches.delete(k)))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  if (req.method !== 'GET') return;
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith(API_PREFIX)) return;

  const isAsset = url.pathname.startsWith(ASSETS_PREFIX);
  const isManifest = url.pathname === MANIFEST_PATH;

  if (!isAsset && !isManifest) return;

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
