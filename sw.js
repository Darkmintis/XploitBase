// Service Worker for XploitBase - Offline Support

const CACHE_NAME = 'xploitbase-v1';
const urlsToCache = [
    './',
    './index.html',
    './search.html',
    './help.html',
    './css/styles.css',
    './css/command-enhancements.css',
    './css/enhanced-features.css',
    './js/data.js',
    './js/main.js',
    './js/category.js',
    './js/search.js',
    './js/shortcuts.js',
    './js/favorites.js',
    './js/timer.js',
    './js/notes.js',
    './categories/web.html',
    './categories/reverse.html',
    './categories/binary.html',
    './categories/crypto.html',
    './categories/forensics.html',
    './categories/osint.html',
    './categories/stego.html',
    './categories/mobile.html',
    './categories/network.html',
    './categories/misc.html',
    './categories/idor.html',
    './categories/privesc.html',
    './categories/activedir.html',
    './categories/system.html',
    './categories/malware.html',
    './categories/realworld.html',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css'
];

// Install event - cache resources
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('XploitBase: Caching app resources');
                return cache.addAll(urlsToCache);
            })
            .then(() => self.skipWaiting())
    );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cacheName => {
                    if (cacheName !== CACHE_NAME) {
                        console.log('XploitBase: Deleting old cache:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        }).then(() => self.clients.claim())
    );
});

// Fetch event - serve from cache, fallback to network
self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request)
            .then(response => {
                // Cache hit - return response
                if (response) {
                    return response;
                }

                // Clone the request
                const fetchRequest = event.request.clone();

                return fetch(fetchRequest).then(response => {
                    // Check if valid response
                    if (!response || response.status !== 200 || response.type !== 'basic') {
                        return response;
                    }

                    // Clone the response
                    const responseToCache = response.clone();

                    caches.open(CACHE_NAME)
                        .then(cache => {
                            cache.put(event.request, responseToCache);
                        });

                    return response;
                });
            }).catch(() => {
                // If both cache and network fail, show offline page
                return caches.match('./index.html');
            })
    );
});
