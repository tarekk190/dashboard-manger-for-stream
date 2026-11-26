'use strict';

// ==============================================================================
// Viewer security helpers (no Express, no JWT: pure functions, unit-tested in test/)
//   ipPrefix               network a client is on (/24 IPv4, /48 IPv6) for token binding
//   segment signatures     ?e=&s= on origin-path segment URLs, shared by all viewers of a
//                          channel within one window so nginx and Cloudflare still cache them
//   createRevocationStore  viewer sessions revoked before they expire (DevTools guard)
//   verifyTurnstile        Cloudflare Turnstile siteverify call
// ==============================================================================

const crypto = require('crypto');
const net = require('net');

// --- IP prefix ---------------------------------------------------------------

// "2001:db8::1" -> [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]; null if not an IPv6 address
function expandIPv6(address) {
    let ip = address;
    if (ip.includes('.')) {
        // Embedded IPv4 tail (::ffff:1.2.3.4, 64:ff9b::1.2.3.4)
        const cut = ip.lastIndexOf(':');
        const v4 = ip.slice(cut + 1);
        if (!net.isIPv4(v4)) return null;
        const o = v4.split('.').map(Number);
        ip = `${ip.slice(0, cut + 1)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
    }
    const halves = ip.split('::');
    if (halves.length > 2) return null;
    const head = halves[0] ? halves[0].split(':') : [];
    const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    const missing = 8 - head.length - tail.length;
    if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
    const groups = [...head, ...new Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
    if (groups.some(g => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
    return groups.map(g => parseInt(g, 16));
}

// Canonical network of an address: "4:203.0.113.0/24", "6:2001:db8:1:0:0:0:0:0/48".
// Binding a token to the network instead of the exact address keeps playback alive when a
// carrier or IPv6 privacy extensions change the last part of the address, while a token
// copied to another ISP or country stops working. '' for anything unparseable.
function ipPrefix(address, { v4Bits = 24, v6Bits = 48 } = {}) {
    let ip = String(address || '').trim();
    const zone = ip.indexOf('%');
    if (zone >= 0) ip = ip.slice(0, zone);
    const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
    if (mapped) ip = mapped[1];

    if (net.isIPv4(ip)) {
        const bits = Math.min(Math.max(v4Bits, 0), 32);
        const n = ip.split('.').reduce((acc, o) => acc * 256 + Number(o), 0);
        const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
        const masked = (n & mask) >>> 0;
        return `4:${[24, 16, 8, 0].map(s => (masked >>> s) & 255).join('.')}/${bits}`;
    }
    if (net.isIPv6(ip)) {
        const groups = expandIPv6(ip);
        if (!groups) return '';
        const bits = Math.min(Math.max(v6Bits, 0), 128);
        const masked = groups.map((g, i) => {
            const keep = Math.min(Math.max(bits - i * 16, 0), 16);
            return keep === 0 ? 0 : g & ((0xFFFF << (16 - keep)) & 0xFFFF);
        });
        return `6:${masked.map(g => g.toString(16)).join(':')}/${bits}`;
    }
    return '';
}

// --- Signed segment URLs (origin path) ----------------------------------------

function hmac(key, text) {
    return crypto.createHmac('sha256', key).update(text).digest('base64url');
}

// Key for segment signatures, derived so the JWT secret itself never signs URLs
function deriveSegmentKey(viewerSecret) {
    return hmac(viewerSecret, 'pxl-edge-seg-key|1');
}

// End of the NEXT window: a signature handed out in window w works until (w + 2) * window,
// i.e. between 1x and 2x the window length. Every viewer of a channel gets the same value
// within a window, so the signed URL stays one cache entry per segment and window.
function segmentExpiry(nowSeconds, windowSeconds) {
    return (Math.floor(nowSeconds / windowSeconds) + 2) * windowSeconds;
}

function segmentSignature(key, channel, expiry) {
    return hmac(key, `pxl-edge-seg|1|${channel}|${expiry}`).slice(0, 22);
}

// Query string appended to every segment in the playlist: "e={expiry}&s={signature}"
function segmentQuery(key, channel, nowSeconds, windowSeconds) {
    const e = segmentExpiry(nowSeconds, windowSeconds);
    return `e=${e}&s=${segmentSignature(key, channel, e)}`;
}

function safeEqualText(a, b) {
    const x = Buffer.from(String(a));
    const y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// True when e/s are a valid, unexpired signature for this channel. An expiry further ahead
// than an honest issuer could have produced (2 windows + 5 s clock slack) is refused as well.
function verifySegmentQuery(key, channel, e, s, nowSeconds, windowSeconds) {
    if (typeof e !== 'string' || !/^\d{1,12}$/.test(e)) return false;
    if (typeof s !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(s)) return false;
    const expiry = Number(e);
    if (expiry <= nowSeconds || expiry > nowSeconds + 2 * windowSeconds + 5) return false;
    return safeEqualText(s, segmentSignature(key, channel, expiry));
}

// --- Session revocation ---------------------------------------------------------

// In-memory list of revoked session ids, each kept until the session would have expired
// anyway. One backend process serves every viewer, so no shared store is needed. The size
// cap bounds memory: every entry needs a signed session (i.e. a passed Turnstile check).
function createRevocationStore({ max = 200000, now = () => Date.now() } = {}) {
    const entries = new Map();   // sid -> revoked until (ms)
    function sweep() {
        const t = now();
        for (const [sid, until] of entries) if (until <= t) entries.delete(sid);
    }
    return {
        revoke(sid, untilMs) {
            if (!sid) return;
            if (entries.size >= max) sweep();
            if (entries.size >= max) entries.delete(entries.keys().next().value);  // oldest first
            entries.set(String(sid), Number(untilMs) || now() + 3600 * 1000);
        },
        isRevoked(sid) {
            const until = entries.get(String(sid));
            if (until === undefined) return false;
            if (until <= now()) {
                entries.delete(String(sid));
                return false;
            }
            return true;
        },
        sweep,
        get size() { return entries.size; }
    };
}

// --- Cloudflare Turnstile ---------------------------------------------------------

const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

// Resolves { ok, hostname, action, codes }. Fails closed: a missing token, a timeout or an
// unreachable Cloudflare all give ok: false.
async function verifyTurnstile({ secret, token, remoteip, fetchImpl = globalThis.fetch, timeoutMs = 5000 }) {
    if (typeof token !== 'string' || !token || token.length > 2048) {
        return { ok: false, codes: ['missing-input-response'] };
    }
    const body = new URLSearchParams({ secret, response: token });
    if (remoteip) body.set('remoteip', remoteip);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const res = await fetchImpl(TURNSTILE_VERIFY_URL, { method: 'POST', body, signal: controller.signal });
        const data = await res.json();
        return {
            ok: data && data.success === true,
            hostname: String((data && data.hostname) || '').toLowerCase(),
            action: String((data && data.action) || ''),
            codes: Array.isArray(data && data['error-codes']) ? data['error-codes'] : []
        };
    } catch (err) {
        return { ok: false, codes: [controller.signal.aborted ? 'timeout' : 'unreachable'] };
    } finally {
        clearTimeout(timer);
    }
}

// --- User-Agent helpers --------------------------------------------------------------

// Apple devices whose browser may lack hls.js support and play HLS natively (iPhone, iPad,
// iPadOS reporting as Macintosh, Safari on macOS). Desktop Chrome/Firefox/Edge on a Mac
// always have hls.js, so they never need the long-lived native key.
function mayUseNativeHls(userAgent) {
    const ua = String(userAgent || '');
    return /(iPhone|iPad|iPod|Macintosh)/.test(ua) && !/(Chrome|Chromium|Edg|Firefox|Android)\//.test(ua);
}

module.exports = {
    ipPrefix,
    deriveSegmentKey,
    segmentExpiry,
    segmentSignature,
    segmentQuery,
    verifySegmentQuery,
    createRevocationStore,
    verifyTurnstile,
    TURNSTILE_VERIFY_URL,
    mayUseNativeHls
};
