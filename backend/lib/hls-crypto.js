'use strict';

// ==============================================================================
// HLS segment encryption (Phase 3): AES-128 (HLS METHOD=AES-128, i.e. AES-128-CBC + PKCS#7
// over the whole segment) with keys that are never stored anywhere.
//
//   key(scope, idx)   = first 16 bytes of HMAC-SHA256(HLS_KEY_SECRET, "pxl-aes|1|{scope}|{idx}")
//   idx               = floor(unix time / rotateSeconds) when the segment is first seen, so every
//                       viewer, both delivery paths and a restarted backend agree on it
//   IV                = the segment number (seg_00042 -> 0x...2a), written explicitly into the
//                       playlist next to every segment
//   scope             = "r:{r2 slug}" (R2 path, SD and HD share it) or "o:{stream key}" (origin)
//
// The key server hands out only keys whose idx is near "now" (indexAllowed), so a credential
// that leaks cannot be used to fetch keys for later parts of the match ahead of time.
// Native HLS (old iOS without MediaSource) cannot attach headers to key requests: its R2
// playlists carry a "native ticket" per scope and idx in the key URI instead (nativeTicket).
// ==============================================================================

const crypto = require('crypto');

const KEY_BYTES = 16;
const SEQ_RE = /(\d{1,30})$/;

function createHlsCrypto({ secret, rotateSeconds = 300, now = () => Date.now() } = {}) {
    if (!secret || String(secret).length < 32) throw new Error('hls-crypto: secret must be at least 32 characters');
    const rotate = Math.max(30, Math.floor(rotateSeconds));

    function hmac(text) {
        return crypto.createHmac('sha256', String(secret)).update(text).digest();
    }

    function currentIndex(nowMs = now()) {
        return Math.floor(nowMs / 1000 / rotate);
    }

    function deriveKey(scope, idx) {
        return hmac(`pxl-aes|1|${scope}|${idx}`).subarray(0, KEY_BYTES);
    }

    // Keys the key server may release now: one period back (segments buffered behind the live
    // edge) to two ahead (inline keys must outlast the player's renewal interval)
    function indexAllowed(idx, nowMs = now()) {
        const cur = currentIndex(nowMs);
        return Number.isSafeInteger(idx) && idx >= cur - 2 && idx <= cur + 2;
    }

    // { "<idx>": "<base64 key>" } for the player (delivered inline with /api/r2 and /api/stream)
    function inlineKeys(scope, nowMs = now()) {
        const cur = currentIndex(nowMs);
        const keys = {};
        for (let idx = cur - 1; idx <= cur + 2; idx++) keys[idx] = deriveKey(scope, idx).toString('base64');
        return keys;
    }

    // 16-byte IV from the trailing number of a segment base name (seg_00042 -> 42), or a hash
    // of the name when it carries none. Never secret, only unique per segment.
    function ivFor(base) {
        const m = SEQ_RE.exec(String(base));
        if (!m) return crypto.createHash('sha256').update(String(base)).digest().subarray(0, KEY_BYTES);
        const iv = Buffer.alloc(KEY_BYTES);
        let n = BigInt(m[1]);
        for (let i = KEY_BYTES - 1; i >= 0 && n > 0n; i--) {
            iv[i] = Number(n & 0xffn);
            n >>= 8n;
        }
        return iv;
    }

    function encryptSegment(plain, scope, idx, base) {
        const cipher = crypto.createCipheriv('aes-128-cbc', deriveKey(scope, idx), ivFor(base));
        return Buffer.concat([cipher.update(plain), cipher.final()]);
    }

    function decryptSegment(data, scope, idx, base) {
        const decipher = crypto.createDecipheriv('aes-128-cbc', deriveKey(scope, idx), ivFor(base));
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }

    function nativeTicket(scope, idx) {
        return hmac(`pxl-nt|1|${scope}|${idx}`).toString('base64url').slice(0, 22);
    }

    function verifyNativeTicket(scope, idx, ticket) {
        const expected = Buffer.from(nativeTicket(scope, idx));
        const given = Buffer.from(String(ticket || ''));
        return given.length === expected.length && crypto.timingSafeEqual(given, expected);
    }

    function keyTag(uri, base) {
        return `#EXT-X-KEY:METHOD=AES-128,URI="${uri}",IV=0x${ivFor(base).toString('hex')}`;
    }

    /**
     * Rewrites a plain media playlist for encrypted segments.
     *   segment(base, line) -> { uri, idx }   new URI line and key index of one segment
     *   keyUri(idx)         -> string         key URI for that index
     * An EXT-X-KEY tag (with the segment's explicit IV) goes in front of every #EXTINF, existing
     * EXT-X-KEY tags are dropped, everything else is kept. Master playlists are returned as is.
     */
    function rewritePlaylist(text, { segment, keyUri }) {
        if (/#EXT-X-STREAM-INF/.test(text)) return text;
        const lines = String(text).split(/\r?\n/);
        const out = [];
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const s = line.trim();
            if (/^#EXT-X-KEY:/.test(s)) continue;
            if (/^#EXTINF:/.test(s)) {
                let j = i + 1;
                while (j < lines.length && (!lines[j].trim() || lines[j].trim().startsWith('#'))) j++;
                if (j < lines.length) {
                    const uriLine = lines[j].trim();
                    const base = uriLine.split('?')[0].split('/').pop().replace(/\.[^.]*$/, '');
                    const seg = segment(base, uriLine);
                    out.push(keyTag(keyUri(seg.idx), base));
                    out.push(line);
                    for (let k = i + 1; k < j; k++) if (!/^#EXT-X-KEY:/.test(lines[k].trim())) out.push(lines[k]);
                    out.push(seg.uri);
                    i = j;
                    continue;
                }
            }
            out.push(line);
        }
        return out.join('\n');
    }

    return {
        rotateSeconds: rotate,
        currentIndex,
        deriveKey,
        indexAllowed,
        inlineKeys,
        ivFor,
        encryptSegment,
        decryptSegment,
        nativeTicket,
        verifyNativeTicket,
        keyTag,
        rewritePlaylist
    };
}

// Key index per segment, fixed the first time a segment is seen (by the R2 uploader or the
// origin encryptor, whichever comes first) so its name, key and playlist entry always agree.
function createIndexMap({ indexNow, maxEntries = 20000 } = {}) {
    const map = new Map();
    return {
        get(id) {
            let idx = map.get(id);
            if (idx === undefined) {
                if (map.size >= maxEntries) map.delete(map.keys().next().value);
                idx = indexNow();
                map.set(id, idx);
            }
            return idx;
        },
        peek(id) { return map.get(id); },
        delete(id) { map.delete(id); },
        get size() { return map.size; }
    };
}

module.exports = { createHlsCrypto, createIndexMap, KEY_BYTES };
