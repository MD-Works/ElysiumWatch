// ElysiumWatch Admin — Service Worker
// Handles Web Push notifications for new reports.
// Also registers a fetch handler (required for PWA installability).

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(clients.claim()));

// Minimal fetch handler — required for the browser to consider this a PWA.
// No offline caching yet; all requests pass through to the network.
self.addEventListener('fetch', () => {});

// ── Push handler ──
self.addEventListener('push', event => {
  let data = { title: 'New report', body: 'A new report is waiting for review.', category: '' };

  if (event.data) {
    try { data = { ...data, ...event.data.json() }; }
    catch { data.body = event.data.text() || data.body; }
  }

  const catEmoji = {
    suspicious: '🔴',
    fire:       '🔥',
    flood:      '💧',
    electrical: '⚡',
    water:      '🚰',
    other:      '📋',
  }[data.category] || '📋';

  event.waitUntil(
    self.registration.showNotification(`${catEmoji} ${data.title}`, {
      body:     data.body,
      icon:     '/admin/icons/icon-192.png',
      badge:    '/admin/icons/icon-192.png',
      tag:      'new-report',   // replaces previous unread notification
      renotify: true,           // still vibrate/sound even if replacing
      data:     { url: data.url || self.registration.scope },
    }).then(() =>
      // Tell any open admin tab to play the alert sound AND refresh the queue.
      // Background contexts can't play audio directly — the page has to do it.
      clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
        for (const c of list) {
          if (c.url.includes('/admin')) {
            c.postMessage({ type: 'PLAY_ALERT' });
            c.postMessage({ type: 'REFRESH_QUEUE' });
          }
        }
      })
    )
  );
});

// ── Notification click — focus or open the admin tab, then refresh queue ──
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const target = event.notification.data?.url || self.registration.scope;

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(async list => {
      let adminClient = null;

      // If admin tab already open, focus it
      for (const c of list) {
        if (c.url.includes('/admin')) {
          await c.focus();
          adminClient = c;
          break;
        }
      }

      // Otherwise open a new tab and wait for it to be ready
      if (!adminClient && clients.openWindow) {
        adminClient = await clients.openWindow(target);
      }

      // Give the page a moment to load if it was just opened, then trigger refresh
      if (adminClient) {
        setTimeout(() => {
          adminClient.postMessage({ type: 'REFRESH_QUEUE' });
        }, 800);
      }
    })
  );
});
