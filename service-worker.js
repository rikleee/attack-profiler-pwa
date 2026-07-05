const CACHE_NAME='attack-profiler-pwa-v8-cti-platform';
const APP_SHELL=['./','./index.html','./styles.css','./cti.css','./app.js','./cti.js','./site.js','./manifest.json','./manifest.webmanifest','./icon.svg','./icons/icon-192.png','./icons/icon-512.png'];
self.addEventListener('install',event=>{event.waitUntil(caches.open(CACHE_NAME).then(cache=>cache.addAll(APP_SHELL)).then(()=>self.skipWaiting()))});
self.addEventListener('activate',event=>{event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE_NAME).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',event=>{const req=event.request;if(req.method!=='GET')return;const url=new URL(req.url);if(url.pathname.includes('/api/analyze'))return;event.respondWith(caches.match(req).then(cached=>cached||fetch(req).then(res=>{if(res.ok&&url.origin===self.location.origin)caches.open(CACHE_NAME).then(c=>c.put(req,res.clone()));return res}).catch(()=>caches.match('./index.html'))))});
