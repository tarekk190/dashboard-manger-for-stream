/**
 * High-Scale Sports Streaming Player Implementation
 * Integrates Hls.js with Camouflage Obfuscation (.css manifests, .js segments)
 * Strict Playlist & Segment Token Auth + Clean URI CDN Cache Key Optimization
 */

(function () {
    'use strict';

    let hls = null;
    let video = null;
    let cacheHitCount = 0;
    let cacheTotalCount = 0;

    const elements = {
        video: document.getElementById('video-player'),
        channelBadge: document.getElementById('badge-channel'),
        cacheBadge: document.getElementById('badge-cache'),
        liveBadge: document.getElementById('badge-live'),
        diagResolution: document.getElementById('diag-resolution'),
        diagLatency: document.getElementById('diag-latency'),
        diagBuffer: document.getElementById('diag-buffer'),
        diagCacheHit: document.getElementById('diag-cache-hit'),
        diagTokenTtl: document.getElementById('diag-token-ttl'),
        tokenBar: document.getElementById('token-bar'),
        centerPrompt: document.getElementById('center-prompt'),
        playBtn: document.getElementById('play-btn')
    };

    video = elements.video;

    async function startPlayback() {
        try {
            const streamInfo = await window.StreamConfig.init();
            if (elements.channelBadge) {
                elements.channelBadge.textContent = streamInfo.channel.toUpperCase();
            }
            loadStream(streamInfo.streamUrl, streamInfo.fallbackUrl);
            startDiagnosticsLoop();
        } catch (err) {
            console.error('[PLAYER] Initialization failed:', err);
            showPlayButton('Retry Connection', () => startPlayback());
        }
    }

    function loadStream(primaryUrl, fallbackUrl) {
        if (Hls.isSupported()) {
            initHlsJs(primaryUrl, fallbackUrl);
        } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
            initNativeHls(primaryUrl);
        } else if (window.shaka) {
            initShakaPlayer(primaryUrl);
        }
    }

    function initHlsJs(sourceUrl, fallbackUrl) {
        if (hls) hls.destroy();

        hls = new Hls({
            enableWorker: true,
            lowLatencyMode: true,
            backBufferLength: 30,
            maxBufferLength: 10,
            liveSyncDurationCount: 3,
            liveMaxLatencyDurationCount: 6,

            /**
             * Attaches the dynamic Bearer token to all requests (playlists and media segments).
             * Attaching Authorization does NOT break Nginx segment edge caching because the
             * segment cache key is strictly $uri, and auth_request runs before proxy_cache.
             */
            xhrSetup: function (xhr, url) {
                const token = window.StreamConfig.getToken();
                if (token) {
                    xhr.setRequestHeader('Authorization', `Bearer ${token}`);
                }
            }
        });

        hls.attachMedia(video);

        hls.on(Hls.Events.MEDIA_ATTACHED, () => {
            hls.loadSource(sourceUrl);
        });

        hls.on(Hls.Events.FRAG_LOADED, (event, data) => {
            cacheTotalCount++;
            let cacheStatus = 'MISS';
            if (data.networkDetails && typeof data.networkDetails.getResponseHeader === 'function') {
                const headerVal = data.networkDetails.getResponseHeader('X-Cache-Status');
                if (headerVal) cacheStatus = headerVal;
            }

            if (cacheStatus === 'HIT') {
                cacheHitCount++;
                if (elements.cacheBadge) {
                    elements.cacheBadge.textContent = 'CDN HIT';
                    elements.cacheBadge.classList.remove('miss');
                }
            } else {
                if (elements.cacheBadge) {
                    elements.cacheBadge.textContent = 'CDN MISS';
                    elements.cacheBadge.classList.add('miss');
                }
            }
        });

        hls.on(Hls.Events.ERROR, async (event, data) => {
            if (data.fatal) {
                if (data.type === Hls.ErrorTypes.NETWORK_ERROR) {
                    if (data.response && (data.response.code === 401 || data.response.code === 403)) {
                        const newToken = await window.StreamConfig.refreshToken();
                        if (newToken) {
                            hls.startLoad();
                            return;
                        }
                    }
                    if (fallbackUrl && data.context && data.context.url === sourceUrl) {
                        hls.loadSource(fallbackUrl);
                        return;
                    }
                    hls.startLoad();
                } else if (data.type === Hls.ErrorTypes.MEDIA_ERROR) {
                    hls.recoverMediaError();
                } else {
                    hls.destroy();
                    setTimeout(startPlayback, 3000);
                }
            }
        });
    }

    /**
     * Safari Native HLS Player Fallback
     * 
     * SECURITY NOTICE ON NATIVE HLS SEGMENTS:
     * Apple's native AVPlayer / Safari <video src="..."> engine cannot attach custom
     * HTTP request headers (such as Authorization: Bearer <token>) to sub-requests (media segments).
     * Playlists authenticate cleanly via the ?token= query parameter fallback.
     * To avoid silently weakening segment security by opening segments to unauthenticated requests,
     * clients requiring strict per-segment token auth must use MSE-based players (hls.js).
     */
    function initNativeHls(sourceUrl) {
        console.warn('[PLAYER] Native Safari HLS engine active. Playlists authenticated via ?token=; segments require MSE/Hls.js for custom header auth.');
        const token = window.StreamConfig.getToken();
        video.src = `${sourceUrl}?token=${encodeURIComponent(token)}`;
        video.play().catch(() => {});
    }

    /**
     * Shaka Player Fallback Adapter
     */
    function initShakaPlayer(sourceUrl) {
        const player = new window.shaka.Player(video);
        player.getNetworkingEngine().registerRequestFilter((type, request) => {
            const token = window.StreamConfig.getToken();
            if (token) {
                request.headers['Authorization'] = `Bearer ${token}`;
            }
        });
        player.load(sourceUrl);
    }

    function showPlayButton(text, onClick) {
        if (elements.centerPrompt && elements.playBtn) {
            elements.playBtn.textContent = text;
            elements.playBtn.onclick = onClick;
            elements.centerPrompt.style.display = 'block';
        }
    }

    function startDiagnosticsLoop() {
        setInterval(() => {
            if (elements.diagResolution && video) {
                elements.diagResolution.textContent = video.videoWidth ? `${video.videoWidth}x${video.videoHeight}` : 'Probing...';
            }
            if (elements.diagLatency && hls) {
                elements.diagLatency.textContent = hls.latency ? hls.latency.toFixed(2) + 's' : '~1.8s';
            }
            if (elements.diagBuffer && video) {
                let bufferedEnd = 0;
                for (let i = 0; i < video.buffered.length; i++) {
                    if (video.buffered.start(i) <= video.currentTime && video.currentTime <= video.buffered.end(i)) {
                        bufferedEnd = video.buffered.end(i) - video.currentTime;
                        break;
                    }
                }
                elements.diagBuffer.textContent = `${bufferedEnd.toFixed(1)}s`;
            }
            if (elements.diagCacheHit) {
                const ratio = cacheTotalCount > 0 ? ((cacheHitCount / cacheTotalCount) * 100).toFixed(0) : 100;
                elements.diagCacheHit.textContent = `${ratio}% (${cacheHitCount}/${cacheTotalCount})`;
            }
            const remainingSec = window.StreamConfig.getTimeRemainingSeconds();
            if (elements.diagTokenTtl) elements.diagTokenTtl.textContent = `${remainingSec}s`;
            if (elements.tokenBar) {
                const percent = Math.min(100, Math.max(0, (remainingSec / 60) * 100));
                elements.tokenBar.style.width = `${percent}%`;
            }
        }, 1000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startPlayback);
    } else {
        startPlayback();
    }
})();
