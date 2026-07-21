// Service worker — Golden Ticket
// Stratégie simple : cache-first pour l'app shell, avec repli réseau si absent du cache.
// Bump CACHE_NAME à chaque déploiement pour invalider l'ancien cache.
const CACHE_NAME = 'golden-ticket-v5';
const APP_SHELL = [
  './',
  './index.html',
  './css/style.css',
  './js/graph.js',
  './js/scenarios.js',
  './js/domaingen.js',
  './js/terminal.js',
  './js/main.js',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request)
        .then((response) => {
          // met en cache les réponses valides du même site pour la prochaine visite hors-ligne
          if (response && response.ok && event.request.url.startsWith(self.location.origin)) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
          }
          return response;
        })
        .catch(() => {
          // hors-ligne et pas en cache : repli sur la page d'accueil pour une navigation
          if (event.request.mode === 'navigate') return caches.match('./index.html');
          return undefined;
        });
    })
  );
});
