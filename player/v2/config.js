/**
 * Dynamic Stream Configuration & Token Lifecycle Manager
 * Handles dynamic stream routing from /api/stream and continuous
 * background JWT renewal via /api/token without interrupting video playback.
 */

(function (window) {
    'use strict';

    const API_BASE = '/api';
    const STREAM_ENDPOINT = `${API_BASE}/stream`;
    const TOKEN_ENDPOINT = `${API_BASE}/token`;

    // State
    let currentChannel = 'test';
    let currentToken = null;
    let streamUrl = null;
    let fallbackUrl = null;
    let tokenExpiresAt = 0;
    let refreshTimer = null;
    const tokenListeners = [];

    /**
     * Parse query parameters from current window location
     */
    function getQueryParam(name, defaultValue) {
        const params = new URLSearchParams(window.location.search);
        return params.get(name) || defaultValue;
    }

    /**
     * Fetch stream URL and initial token from dynamic auth microservice
     */
    async function initSession() {
        currentChannel = getQueryParam('channel', 'test');
        console.log(`[STREAM-CONFIG] Initializing streaming session for channel: ${currentChannel}`);

        try {
            const response = await fetch(`${STREAM_ENDPOINT}?channel=${encodeURIComponent(currentChannel)}`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`Failed to initialize stream: HTTP ${response.status} ${response.statusText}`);
            }

            const data = await response.json();
            if (data.status !== 'success' || !data.token) {
                throw new Error(data.message || 'Malformed stream API response');
            }

            currentToken = data.token;
            streamUrl = data.streamUrl;
            fallbackUrl = data.fallbackUrl;
            tokenExpiresAt = Date.now() + (data.expiresIn * 1000);

            console.log(`[STREAM-CONFIG] Session acquired. Stream: ${streamUrl} | Token TTL: ${data.expiresIn}s`);

            // Schedule background token auto-renewal
            scheduleTokenRefresh(data.refreshIntervalMs || 45000);

            // Notify listeners
            notifyTokenUpdated(currentToken, tokenExpiresAt);

            return {
                channel: currentChannel,
                streamUrl: streamUrl,
                fallbackUrl: fallbackUrl,
                token: currentToken,
                expiresIn: data.expiresIn
            };
        } catch (error) {
            console.error('[STREAM-CONFIG] Stream initialization error:', error);
            throw error;
        }
    }

    /**
     * Auto-renew viewer JWT token via /api/token
     */
    async function renewToken() {
        if (!currentToken) {
            console.warn('[STREAM-CONFIG] Cannot renew: no active token present');
            return null;
        }

        try {
            const response = await fetch(TOKEN_ENDPOINT, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${currentToken}`
                },
                body: JSON.stringify({
                    channel: currentChannel,
                    token: currentToken
                })
            });

            if (!response.ok) {
                throw new Error(`Token refresh failed: HTTP ${response.status}`);
            }

            const data = await response.json();
            if (data.status === 'success' && data.token) {
                currentToken = data.token;
                tokenExpiresAt = Date.now() + (data.expiresIn * 1000);
                console.log(`[STREAM-CONFIG] Token auto-renewed successfully. Valid for another ${data.expiresIn}s`);

                // Reschedule next refresh
                scheduleTokenRefresh(data.refreshIntervalMs || 45000);

                // Notify listeners
                notifyTokenUpdated(currentToken, tokenExpiresAt);
                return currentToken;
            } else {
                throw new Error(data.message || 'Token refresh failed');
            }
        } catch (error) {
            console.error('[STREAM-CONFIG] Token renewal failed:', error);
            // Retry in 5 seconds on transient failure
            scheduleTokenRefresh(5000);
            return null;
        }
    }

    /**
     * Schedule next background token refresh
     */
    function scheduleTokenRefresh(delayMs) {
        if (refreshTimer) {
            clearTimeout(refreshTimer);
        }
        refreshTimer = setTimeout(() => {
            renewToken();
        }, delayMs);
    }

    /**
     * Register listeners for token renewal events
     */
    function onTokenRefresh(callback) {
        if (typeof callback === 'function') {
            tokenListeners.push(callback);
        }
    }

    function notifyTokenUpdated(token, expiresAt) {
        tokenListeners.forEach(cb => {
            try {
                cb({ token, expiresAt, channel: currentChannel });
            } catch (e) {
                console.error('[STREAM-CONFIG] Listener error:', e);
            }
        });
    }

    // Public API
    window.StreamConfig = {
        init: initSession,
        refreshToken: renewToken,
        getToken: () => currentToken,
        getStreamUrl: () => streamUrl,
        getFallbackUrl: () => fallbackUrl,
        getChannel: () => currentChannel,
        getExpiresAt: () => tokenExpiresAt,
        getTimeRemainingSeconds: () => Math.max(0, Math.floor((tokenExpiresAt - Date.now()) / 1000)),
        onTokenRefresh: onTokenRefresh
    };

})(window);
