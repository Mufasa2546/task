// Task service worker: offline cache + reminder notifications.
const CACHE = "task-v31";
const SHELL = ["./", "index.html", "manifest.webmanifest", "icon.svg", "icon-192.png", "icon-512.png", "icon-maskable-512.png", "apple-touch-icon.png"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});

// App files: network first so updates arrive, cache when offline.
// Fonts and libraries: cache first.
self.addEventListener("fetch", e => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.hostname === "api.anthropic.com") return;
  if (url.origin === location.origin && url.pathname.startsWith("/api/")) return; // accounts and sync: always live
  if (url.origin === location.origin) {
    e.respondWith(fetch(req).then(res => { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); return res; })
      .catch(() => caches.match(req).then(r => r || caches.match("index.html"))));
  } else if (/fonts\.(googleapis|gstatic)\.com|cdn\.jsdelivr\.net/.test(url.hostname)) {
    e.respondWith(caches.match(req).then(r => r || fetch(req).then(res => { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); return res; })));
  }
});

// Reminders while the app is closed (Android Chrome, installed app, when the browser allows it).
function idb() { return new Promise((res, rej) => { const r = indexedDB.open("task-app", 1); r.onupgradeneeded = () => r.result.createObjectStore("kv"); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); }
const get = (db, k) => new Promise(res => { const q = db.transaction("kv").objectStore("kv").get(k); q.onsuccess = () => res(q.result); q.onerror = () => res(undefined); });
const set = (db, k, v) => new Promise(res => { const tx = db.transaction("kv", "readwrite"); tx.objectStore("kv").put(v, k); tx.oncomplete = res; tx.onerror = res; });

async function checkDue() {
  const db = await idb();
  const reminders = (await get(db, "reminders")) || [];
  const sent = new Set((await get(db, "sent")) || []);
  const open = await self.clients.matchAll({type: "window"});
  if (open.some(c => c.visibilityState === "visible")) return; // the open app handles it
  for (const r of reminders) {
    if (r.due <= Date.now() && !sent.has(r.id)) {
      await self.registration.showNotification("Task reminder", {body: r.title, tag: r.id, icon: "icon-192.png", badge: "icon-192.png", requireInteraction: true, data: {id: r.id}});
      sent.add(r.id);
      open.forEach(c => c.postMessage({type: "notified", id: r.id}));
    }
  }
  await set(db, "sent", [...sent].slice(-500));
}
self.addEventListener("periodicsync", e => { if (e.tag === "task-reminders") e.waitUntil(checkDue()); });
self.addEventListener("push", e => e.waitUntil(checkDue()));

self.addEventListener("notificationclick", e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({type: "window"}).then(cs => cs.length ? cs[0].focus() : self.clients.openWindow("./")));
});
