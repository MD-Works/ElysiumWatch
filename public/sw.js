// Minimal stub — required for PWA installability.
// Push event handling (VAPID) gets added here later, same pattern as PAS.

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(clients.claim()));

// Placeholder — no offline caching yet. Add a fetch handler here if/when
// you want cached map tiles or offline report queuing.
