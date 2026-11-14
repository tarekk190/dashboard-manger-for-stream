/**
 * ==============================================================================
 * Live Streaming Server & Restreaming Dashboard Backend
 * 
 * Core Functionalities:
 * 1. Admin Authentication & Session Security (JWT)
 * 2. Channel Management & Slug Randomization
 * 3. FFmpeg Process Manager (Background Pull Restreaming, Telemetry & Live Logs)
 * 4. Real-Time Cloudflare R2 Zero-Egress Watcher, Manifest Rewriter & Pruner
 * 5. Edge Viewer Token Issuance & Nginx Auth Subrequest Handler (/auth)
 * ==============================================================================
 */

'use strict';

require('dotenv').config();
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const net = require('net');
const dns = require('dns').promises;
const { spawn } = require('child_process');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const chokidar = require('chokidar');
const {
    S3Client,
    PutObjectCommand,
    ListObjectsV2Command,
    DeleteObjectsCommand
} = require('@aws-sdk/client-s3');

// ------------------------------------------------------------------------------
// Configuration & Environment Variables
// ------------------------------------------------------------------------------
function fatal(message) {
    console.error(`[FATAL] ${message} Refusing to start.`);
    process.exit(1);
}

// SHA-256 of placeholder passwords that shipped in earlier .env/.env.example files.
// Stored as hashes so the literal placeholder strings do not live in the source tree.
const KNOWN_PLACEHOLDER_PASSWORD_HASHES = new Set([
    'ac0e7d037817094e9e0b4441f9bae3209d67b02fa484917065f71b16109a1a78', // old compose default
    '299bd1a5420db43c61a00a05bee485c27f0129c3f014bb9b53bf9c5791b1a37f', // old .env.example
    'a122649a4ff9430be08e9d697b748df8838fd3a10b3fbda6ee94ef3fd33d453a'  // old backend/.env.example
]);
const sha256 = (value) => crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');

const PORT = parseInt(process.env.PORT || '3000', 10);
const NODE_ENV = process.env.NODE_ENV || 'production';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET;
const VIEWER_JWT_SECRET = process.env.VIEWER_JWT_SECRET;

if (!ADMIN_JWT_SECRET || ADMIN_JWT_SECRET.trim().length < 32) {
    fatal('ADMIN_JWT_SECRET is missing or shorter than 32 characters (generate with: openssl rand -hex 48).');
}
if (!VIEWER_JWT_SECRET || VIEWER_JWT_SECRET.trim().length < 32) {
    fatal('VIEWER_JWT_SECRET is missing or shorter than 32 characters (generate with: openssl rand -hex 48).');
}
if (ADMIN_JWT_SECRET === VIEWER_JWT_SECRET) {
    fatal('ADMIN_JWT_SECRET and VIEWER_JWT_SECRET must be different values.');
}
if (!ADMIN_USERNAME || !ADMIN_USERNAME.trim()) {
    fatal('ADMIN_USERNAME is missing.');
}
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) {
    fatal('ADMIN_PASSWORD is missing or shorter than 12 characters.');
}
if (KNOWN_PLACEHOLDER_PASSWORD_HASHES.has(sha256(ADMIN_PASSWORD))) {
    fatal('ADMIN_PASSWORD is a known placeholder value. Set a real password.');
}

const SERVER_IP = process.env.SERVER_IP || '127.0.0.1';
const EDGE_DOMAIN = process.env.EDGE_DOMAIN || 'localhost';
const R2_CUSTOM_DOMAIN = process.env.R2_CUSTOM_DOMAIN || 'r2-custom-domain.shop';
const MEDIAMTX_RTMP_HOST = process.env.MEDIAMTX_RTMP_HOST || 'mediamtx';
const MEDIAMTX_RTMP_PORT = parseInt(process.env.MEDIAMTX_RTMP_PORT || '1935', 10);
const HLS_DIR = path.resolve(process.env.HLS_DIR || '/hls');
const DATA_FILE = path.resolve(process.env.DATA_FILE || path.join(__dirname, 'data', 'channels.json'));
const MAX_SEGMENT_AGE_SECONDS = parseInt(process.env.MAX_SEGMENT_AGE_SECONDS || '120', 10);
// Viewer auth on edge playlists AND segments. Enabled unless explicitly set to 'false'.
const ENABLE_AUTH_ON_PLAYLISTS = process.env.ENABLE_AUTH_ON_PLAYLISTS !== 'false';
const TOKEN_EXPIRATION_SECONDS = parseInt(process.env.TOKEN_EXPIRATION_SECONDS || '60', 10);
const TOKEN_RENEW_GRACE_SECONDS = parseInt(process.env.TOKEN_RENEW_GRACE_SECONDS || '15', 10);
const ADMIN_TOKEN_TTL = '12h';
const JWT_ALGORITHMS = ['HS256'];

// Cross-origin access for the public viewer API only (/api/stream, /api/token).
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
if (NODE_ENV === 'production' && ALLOWED_ORIGINS.includes('*')) {
    fatal('ALLOWED_ORIGINS="*" is not allowed when NODE_ENV=production. List explicit origins.');
}

if (!ENABLE_AUTH_ON_PLAYLISTS) {
    console.warn('[SECURITY] ENABLE_AUTH_ON_PLAYLISTS=false: /auth allows every edge request. Do not use in production.');
}

// Restream source URL policy
const ALLOWED_SOURCE_PROTOCOLS = new Set(['http:', 'https:', 'rtmp:', 'rtmps:', 'rtsp:', 'srt:']);
const BLOCKED_SOURCE_HOSTS = new Set([
    'localhost', 'mediamtx', 'backend', 'nginx',
    'stream_mediamtx', 'stream_backend', 'stream_nginx', 'host.docker.internal'
]);
// Passed to FFmpeg so HLS playlists / redirects can never pull in file:, pipe:, concat:, data: etc.
const FFMPEG_PROTOCOL_WHITELIST = 'http,https,tcp,tls,crypto,rtmp,rtmps,rtmpt,rtmpts,rtp,srtp,udp,srt';

// Cloudflare R2 S3 Config
const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID || '';
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID || '';
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY || '';
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME || 'live-streams';
const R2_ENDPOINT = process.env.R2_ENDPOINT || (R2_ACCOUNT_ID ? `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com` : '');

// ------------------------------------------------------------------------------
// S3 Client Initialization (Cloudflare R2)
// ------------------------------------------------------------------------------
let s3Client = null;
const isR2Configured = Boolean(R2_ENDPOINT && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY);

if (isR2Configured) {
    s3Client = new S3Client({
        region: 'auto',
        endpoint: R2_ENDPOINT,
        credentials: {
            accessKeyId: R2_ACCESS_KEY_ID,
            secretAccessKey: R2_SECRET_ACCESS_KEY
        }
    });
    console.log('[R2-STORAGE] Cloudflare R2 S3 client initialized successfully.');
} else {
    console.warn('[R2-STORAGE] R2 credentials not fully specified. Running in DRY-RUN / local watcher mode.');
}

// ------------------------------------------------------------------------------
// Channel Store & Persistence Manager
// ------------------------------------------------------------------------------
class ChannelManager {
    constructor(filePath) {
        this.filePath = filePath;
        this.channels = new Map();
        this.init();
    }

    init() {
        try {
            const dir = path.dirname(this.filePath);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            if (fs.existsSync(this.filePath)) {
                const raw = fs.readFileSync(this.filePath, 'utf8');
                const list = JSON.parse(raw);
                if (Array.isArray(list)) {
                    list.forEach(c => this.channels.set(c.id, c));
                }
                // Migration: every channel needs a secret RTMP publish key distinct from its public streamKey
                let migrated = 0;
                for (const channel of this.channels.values()) {
                    if (!channel.publishKey) {
                        channel.publishKey = ChannelManager.generatePublishKey();
                        migrated++;
                    }
                }
                if (migrated > 0) {
                    console.log(`[CHANNELS] Generated publishKey for ${migrated} existing channel(s).`);
                    this.save();
                }
            } else {
                // Initialize default demo channel
                const defaultChannel = {
                    id: 'ch_match1',
                    name: 'Match 1 Primary Feed',
                    streamKey: 'match1',
                    publishKey: ChannelManager.generatePublishKey(),
                    r2_slug: this.generateRandomSlug(12),
                    sourceUrl: '',
                    createdAt: new Date().toISOString()
                };
                this.channels.set(defaultChannel.id, defaultChannel);
                this.save();
            }
            console.log(`[CHANNELS] Loaded ${this.channels.size} channel(s) from ${this.filePath}`);
        } catch (err) {
            console.error('[CHANNELS-ERROR] Failed to load channels file:', err.message);
        }
    }

    save() {
        // Atomic write: a crash mid-write can never leave a truncated channels.json behind
        const tmpPath = `${this.filePath}.${process.pid}.tmp`;
        try {
            const list = Array.from(this.channels.values());
            fs.writeFileSync(tmpPath, JSON.stringify(list, null, 2), 'utf8');
            fs.renameSync(tmpPath, this.filePath);
        } catch (err) {
            try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
            console.error('[CHANNELS-ERROR] Failed to save channels:', err.message);
        }
    }

    static generatePublishKey() {
        return crypto.randomBytes(16).toString('hex'); // 32 hex chars
    }

    generateRandomSlug(length = 12) {
        const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        const bytes = crypto.randomBytes(length);
        for (let i = 0; i < length; i++) {
            result += chars[bytes[i] % chars.length];
        }
        return result;
    }

    getAll() {
        return Array.from(this.channels.values());
    }

    getById(id) {
        return this.channels.get(id);
    }

    getByStreamKey(streamKey) {
        const clean = streamKey.trim().toLowerCase();
        for (const channel of this.channels.values()) {
            if (channel.streamKey.toLowerCase() === clean) {
                return channel;
            }
        }
        return null;
    }

    getByR2Slug(slug) {
        const clean = slug.trim().toLowerCase();
        for (const channel of this.channels.values()) {
            if (channel.r2_slug.toLowerCase() === clean) {
                return channel;
            }
        }
        return null;
    }

    create({ name, streamKey, r2_slug, sourceUrl = '' }) {
        const cleanKey = (streamKey || name).trim().toLowerCase().replace(/[^a-z0-9_-]/g, '_');
        if (this.getByStreamKey(cleanKey)) {
            throw new Error(`Stream key '${cleanKey}' is already in use.`);
        }

        const id = 'ch_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex');
        const channel = {
            id,
            name: name.trim() || `Channel ${cleanKey}`,
            streamKey: cleanKey,
            publishKey: ChannelManager.generatePublishKey(),
            r2_slug: (r2_slug || this.generateRandomSlug(12)).trim().toLowerCase().replace(/[^a-z0-9]/g, ''),
            sourceUrl: sourceUrl.trim(),
            createdAt: new Date().toISOString()
        };

        this.channels.set(id, channel);
        this.save();
        return channel;
    }

    update(id, updates) {
        const channel = this.channels.get(id);
        if (!channel) return null;

        if (updates.name) channel.name = updates.name.trim();
        if (updates.sourceUrl !== undefined) channel.sourceUrl = updates.sourceUrl.trim();
        if (updates.r2_slug) channel.r2_slug = updates.r2_slug.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
        // Desired restream state ('running' | 'stopped'), resumed on backend start
        if (updates.desiredState) channel.desiredState = updates.desiredState;

        this.channels.set(id, channel);
        this.save();
        return channel;
    }

    delete(id) {
        const channel = this.channels.get(id);
        if (!channel) return false;
        this.channels.delete(id);
        this.save();
        return true;
    }
}

const channelManager = new ChannelManager(DATA_FILE);

// ------------------------------------------------------------------------------
// Restream Source URL Validation (SSRF / local file protection)
// ------------------------------------------------------------------------------
class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.status = 400;
    }
}

const PRIVATE_NETWORKS = new net.BlockList();
[
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
    ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
    ['224.0.0.0', 4], ['240.0.0.0', 4]
].forEach(([addr, prefix]) => PRIVATE_NETWORKS.addSubnet(addr, prefix, 'ipv4'));
[
    ['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]
].forEach(([addr, prefix]) => PRIVATE_NETWORKS.addSubnet(addr, prefix, 'ipv6'));

function isPrivateAddress(address) {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
    if (mapped) address = mapped[1];
    const family = net.isIPv6(address) ? 'ipv6' : 'ipv4';
    return PRIVATE_NETWORKS.check(address, family);
}

/**
 * Validates an external restream source URL. Throws ValidationError (HTTP 400) on rejection.
 * Returns the normalized URL string.
 */
async function validateSourceUrl(rawUrl) {
    const value = String(rawUrl || '').trim();
    if (!value) throw new ValidationError('Source URL is required for pull restreaming');

    let parsed;
    try {
        parsed = new URL(value);
    } catch {
        throw new ValidationError('Source URL is not a valid absolute URL');
    }

    if (!ALLOWED_SOURCE_PROTOCOLS.has(parsed.protocol)) {
        throw new ValidationError(`Source URL scheme '${parsed.protocol}' is not allowed (use http, https, rtmp, rtmps, rtsp or srt)`);
    }

    const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (!host) throw new ValidationError('Source URL must include a host');
    if (BLOCKED_SOURCE_HOSTS.has(host) || host.endsWith('.localhost') || host.endsWith('.internal')) {
        throw new ValidationError(`Source host '${host}' is not allowed`);
    }

    let addresses;
    if (net.isIP(host)) {
        addresses = [host];
    } else {
        try {
            addresses = (await dns.lookup(host, { all: true, verbatim: true })).map(a => a.address);
        } catch {
            throw new ValidationError(`Source host '${host}' could not be resolved`);
        }
    }
    if (addresses.length === 0 || addresses.some(isPrivateAddress)) {
        throw new ValidationError(`Source host '${host}' resolves to a loopback, link-local or private address`);
    }

    return value;
}

// ------------------------------------------------------------------------------
// FFmpeg Process & Restream Manager (supervised)
// - Auto-restarts on unexpected exit with exponential backoff (2s -> 60s cap)
// - Desired state ('running' | 'stopped') persisted per channel and resumed on boot
// - stop() is awaitable and escalates SIGINT -> SIGKILL after 5s
// ------------------------------------------------------------------------------
// Auto-restart: an unexpected FFmpeg exit is retried after 3s; after RESTREAM_FAST_RETRIES
// consecutive failures (source down for ~1 min) the delay grows to 30s so a dead source
// does not hammer the server. A run that stays up 60s resets the counter.
const RESTREAM_RETRY_DELAY_MS = 3000;
const RESTREAM_SLOW_RETRY_DELAY_MS = 30000;
const RESTREAM_FAST_RETRIES = 20;
const RESTREAM_STOP_TIMEOUT_MS = 5000;
// A run lasting this long counts as healthy and resets the retry counter
const RESTREAM_STABLE_RUN_MS = 60000;
// Consecutive failed restarts before giving up (0 = retry forever, the default)
const RESTREAM_MAX_RETRIES = parseInt(process.env.RESTREAM_MAX_RETRIES || '0', 10);
// A source that sends nothing for this long makes FFmpeg exit, so the supervisor reconnects it
const RESTREAM_RW_TIMEOUT_US = 15 * 1000 * 1000;
// Output profile: '480p' (default) transcodes every restream to 854x480 H.264 + AAC,
// 'copy' relays the source untouched (video copy, audio AAC unless RESTREAM_COPY_AUDIO=true).
const RESTREAM_PROFILE = String(process.env.RESTREAM_PROFILE || '480p').toLowerCase();
if (!['480p', 'copy'].includes(RESTREAM_PROFILE)) {
    fatal(`RESTREAM_PROFILE must be "480p" or "copy" (got "${RESTREAM_PROFILE}").`);
}
const RESTREAM_TARGET_HEIGHT = 480;
const RESTREAM_VIDEO_KBPS = Math.min(Math.max(parseInt(process.env.RESTREAM_VIDEO_KBPS || '900', 10) || 900, 300), 4000);
const X264_PRESETS = ['ultrafast', 'superfast', 'veryfast', 'faster', 'fast', 'medium'];
const RESTREAM_X264_PRESET = X264_PRESETS.includes(process.env.RESTREAM_X264_PRESET) ? process.env.RESTREAM_X264_PRESET : 'veryfast';
// true = pure `-c copy` in 'copy' profile (source audio must already be AAC/MP3)
const RESTREAM_COPY_AUDIO = String(process.env.RESTREAM_COPY_AUDIO || 'false').toLowerCase() === 'true';
// ONLINE only while the frame counter advances; FFmpeg keeps printing progress lines while stalled
const RESTREAM_PROGRESS_STALE_MS = 10 * 1000;
// Watchdog: FFmpeg alive but no new frame for this long -> kill it so the supervisor restarts it
const RESTREAM_STALL_TIMEOUT_MS = 30 * 1000;
// A looped (frozen) HLS source is re-checked this often; when it is live again we switch back
const RESTREAM_FROZEN_RECHECK_MS = 5 * 60 * 1000;

// ------------------------------------------------------------------------------
// Source probing: decides HOW FFmpeg reads a source
// - hls-live   : live playlist, followed normally (only the chosen variant is downloaded)
// - hls-vod    : playlist with #EXT-X-ENDLIST          -> looped forever at real-time speed
// - hls-frozen : "live" playlist that stopped updating -> looped (re-checked every 5 min)
// - file       : finite HTTP file (mp4/ts with a size) -> looped forever at real-time speed
// - stream     : endless HTTP stream (IPTV .ts)        -> reconnect at EOF
// - live       : rtmp/rtsp/srt                         -> read as-is
// Every redirect and every segment host passes validateSourceUrl (SSRF protection).
// ------------------------------------------------------------------------------
const LOOP_PLAYLIST_DIR = path.join(require('os').tmpdir(), 'restream-loops');
const PROBE_TIMEOUT_MS = 8000;
const PROBE_MAX_BYTES = 512 * 1024;
const HLS_FROZEN_MIN_AGE_MS = 60 * 1000;
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

async function fetchLimited(url) {
    let current = url;
    for (let hop = 0; hop < 4; hop++) {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), PROBE_TIMEOUT_MS);
        try {
            const res = await fetch(current, {
                redirect: 'manual',
                signal: ctrl.signal,
                headers: { 'User-Agent': 'Mozilla/5.0 (StreamOps restreamer)' }
            });
            const location = res.headers.get('location');
            if (res.status >= 300 && res.status < 400 && location) {
                try { await res.body?.cancel(); } catch { /* ignore */ }
                current = await validateSourceUrl(new URL(location, current).href);
                continue;
            }
            const chunks = [];
            let size = 0;
            if (res.body) {
                const reader = res.body.getReader();
                while (size < PROBE_MAX_BYTES) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    chunks.push(value);
                    size += value.length;
                }
                try { await reader.cancel(); } catch { /* ignore */ }
            }
            return { url: current, status: res.status, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') };
        } finally {
            clearTimeout(timer);
        }
    }
    throw new Error('Too many redirects');
}

function parseHlsAttributes(attrText) {
    const attrs = {};
    attrText.replace(/([A-Z0-9-]+)=("[^"]*"|[^,]*)/g, (_, key, value) => {
        attrs[key] = value.replace(/^"|"$/g, '');
        return '';
    });
    return attrs;
}

function hlsFingerprint(text) {
    const seq = (text.match(/#EXT-X-MEDIA-SEQUENCE:(\d+)/) || [])[1] || '';
    const uris = text.split(/\r?\n/).filter(l => l.trim() && !l.startsWith('#'));
    return `${seq}|${uris[uris.length - 1] || ''}|${uris.length}`;
}

// Rewrites a media playlist to absolute http(s) URLs and appends #EXT-X-ENDLIST so that
// FFmpeg treats it as VOD and `-stream_loop -1` can loop it.
async function buildLoopPlaylist(text, baseUrl) {
    const origins = new Set();
    const absolutize = (uri) => {
        const abs = new URL(uri.trim(), baseUrl);
        if (abs.protocol !== 'http:' && abs.protocol !== 'https:') {
            throw new ValidationError(`Playlist entry uses a forbidden scheme '${abs.protocol}'`);
        }
        origins.add(abs.origin);
        return abs.href;
    };
    let segments = 0;
    const out = text.split(/\r?\n/).filter(l => !/^#EXT-X-ENDLIST/.test(l)).map(line => {
        if (!line.trim()) return line;
        if (line.startsWith('#')) {
            return line.replace(/URI="([^"]+)"/g, (_, uri) => `URI="${absolutize(uri)}"`);
        }
        segments++;
        return absolutize(line);
    });
    if (segments === 0) throw new Error('Playlist has no segments');
    for (const origin of origins) await validateSourceUrl(`${origin}/`);
    return { content: `${out.join('\n')}\n#EXT-X-ENDLIST\n`, segments };
}

function fallbackSourceKind(url) {
    if (!/^https?:/i.test(url)) return 'live';
    return /\.m3u8?(\?|$)/i.test(new URL(url).pathname) ? 'hls-live' : 'stream';
}

async function probeSource(sourceUrl) {
    if (!/^https?:/i.test(sourceUrl)) return { kind: 'live', inputUrl: sourceUrl, note: '' };

    let res = await fetchLimited(sourceUrl);
    if (res.status >= 400) throw new Error(`source answered HTTP ${res.status}`);
    let text = res.text.replace(/^﻿/, '');

    if (!text.startsWith('#EXTM3U')) {
        const type = (res.headers.get('content-type') || '').toLowerCase();
        const length = parseInt(res.headers.get('content-length') || '0', 10);
        // A fixed-size response is a file; endless IPTV streams have no Content-Length
        if (length > 0 && !type.includes('mpegurl')) {
            return { kind: 'file', inputUrl: res.url, note: `${(length / 1048576).toFixed(1)} MB` };
        }
        return { kind: 'stream', inputUrl: res.url, note: '' };
    }

    const notes = [];
    if (text.includes('#EXT-X-STREAM-INF')) {
        // Master playlist: pick ONE variant (FFmpeg would otherwise download all of them)
        const lines = text.split(/\r?\n/);
        const variants = [];
        for (let i = 0; i < lines.length; i++) {
            if (!lines[i].startsWith('#EXT-X-STREAM-INF')) continue;
            const attrs = parseHlsAttributes(lines[i].slice(lines[i].indexOf(':') + 1));
            const uri = lines.slice(i + 1).find(l => l.trim() && !l.startsWith('#'));
            if (!uri) continue;
            variants.push({
                uri: uri.trim(),
                height: parseInt((attrs.RESOLUTION || '').split('x')[1] || '0', 10),
                bandwidth: parseInt(attrs.BANDWIDTH || '0', 10)
            });
        }
        if (variants.length === 0) throw new Error('master playlist has no variants');
        const known = variants.filter(v => v.height > 0);
        let pick;
        if (RESTREAM_PROFILE === '480p' && known.length) {
            // Smallest variant that is still >= 480p (less download + decode), else the largest
            pick = known.filter(v => v.height >= RESTREAM_TARGET_HEIGHT).sort((a, b) => a.height - b.height || a.bandwidth - b.bandwidth)[0]
                || known.sort((a, b) => b.height - a.height)[0];
        } else {
            pick = variants.slice().sort((a, b) => b.bandwidth - a.bandwidth)[0];
        }
        const variantUrl = await validateSourceUrl(new URL(pick.uri, res.url).href);
        notes.push(`variant ${pick.height ? pick.height + 'p' : pick.uri} (${variants.length} available)`);
        res = await fetchLimited(variantUrl);
        if (res.status >= 400) throw new Error(`variant playlist answered HTTP ${res.status}`);
        text = res.text.replace(/^﻿/, '');
        if (!text.startsWith('#EXTM3U')) throw new Error('variant is not an HLS playlist');
    }

    const targetSec = parseFloat((text.match(/#EXT-X-TARGETDURATION:(\d+(?:\.\d+)?)/) || [])[1] || '4');
    let kind = 'hls-live';
    if (/#EXT-X-ENDLIST|#EXT-X-PLAYLIST-TYPE:VOD/.test(text)) {
        kind = 'hls-vod';
    } else {
        // Frozen = a "live" playlist that is no longer updated (no ENDLIST, no new segments)
        const lastModified = Date.parse(res.headers.get('last-modified') || '');
        const serverNow = Date.parse(res.headers.get('date') || '') || Date.now();
        if (!Number.isNaN(lastModified)) {
            const age = serverNow - lastModified;
            if (age > Math.max(HLS_FROZEN_MIN_AGE_MS, targetSec * 6000)) {
                kind = 'hls-frozen';
                notes.push(`playlist not updated for ${Math.round(age / 60000)} min`);
            }
        } else {
            await sleep(Math.min(Math.max(targetSec, 2) * 1.5, 10) * 1000);
            const again = await fetchLimited(res.url);
            if (again.status < 400 && hlsFingerprint(again.text) === hlsFingerprint(text)) {
                kind = 'hls-frozen';
                notes.push('playlist did not advance');
            }
        }
    }

    if (kind === 'hls-live') return { kind, inputUrl: res.url, note: notes.join(', ') };
    const loop = await buildLoopPlaylist(text, res.url);
    notes.push(`${loop.segments} segments looped`);
    return { kind, inputUrl: res.url, loopPlaylist: loop.content, note: notes.join(', ') };
}

const SOURCE_KIND_LABELS = {
    'hls-live': 'Live HLS',
    'hls-vod': 'HLS VOD (looping)',
    'hls-frozen': 'Frozen live HLS (looping its last segments)',
    file: 'Finite file (looping)',
    stream: 'Continuous HTTP stream',
    live: 'Live stream'
};

class FFmpegRestreamManager {
    constructor() {
        // Map of channelId -> RestreamJob
        this.jobs = new Map();
        // Per-channel promise chain so start/stop/restart never interleave
        this.locks = new Map();
        // Stall watchdog + periodic re-check of looped (frozen) sources
        setInterval(() => this.checkStalls(), 5000).unref();
    }

    withLock(channelId, fn) {
        const prev = this.locks.get(channelId) || Promise.resolve();
        const next = prev.catch(() => {}).then(fn);
        this.locks.set(channelId, next);
        return next.finally(() => {
            if (this.locks.get(channelId) === next) this.locks.delete(channelId);
        });
    }

    start(channelId, sourceUrl) {
        return this.withLock(channelId, () => this._start(channelId, sourceUrl));
    }

    stop(channelId, options = {}) {
        return this.withLock(channelId, () => this._stop(channelId, options));
    }

    restart(channelId) {
        return this.withLock(channelId, () => {
            const job = this.jobs.get(channelId);
            const sourceUrl = job ? job.sourceUrl : (channelManager.getById(channelId)?.sourceUrl || '');
            if (!sourceUrl) {
                throw new Error('No source URL available to restart restream.');
            }
            return this._start(channelId, sourceUrl);
        });
    }

    async _start(channelId, sourceUrl) {
        const channel = channelManager.getById(channelId);
        if (!channel) throw new Error('Channel not found');
        if (!sourceUrl || !sourceUrl.trim()) throw new Error('Source URL is required for pull restreaming');

        // Wait for any previous process to fully exit before spawning a new one
        const previous = this.jobs.get(channelId);
        await this._stop(channelId, { persist: false });

        const job = {
            channelId,
            streamKey: channel.streamKey,
            sourceUrl: sourceUrl.trim(),
            status: 'starting',
            pid: null,
            startedAt: new Date().toISOString(),
            metrics: {
                fps: 0,
                bitrate: '0kbits/s',
                speed: '0x',
                frame: 0,
                time: '00:00:00.00',
                lastUpdate: 0 // set by FFmpeg progress lines only
            },
            logs: previous ? previous.logs : [],
            process: null,
            exited: true,
            exitPromise: Promise.resolve(),
            stopRequested: false,
            retries: 0,
            restartTimer: null
        };
        this.jobs.set(channelId, job);

        // Persist desired state + source so the job resumes after a backend restart
        channelManager.update(channelId, { sourceUrl: job.sourceUrl, desiredState: 'running' });

        this.launch(job);
        return this.getStatus(channelId);
    }

    // spawnProcess is async (it probes the source first); never leave its promise unhandled
    launch(job) {
        this.spawnProcess(job).catch(err => {
            this.appendLog(job, `[ERROR] ${err.message}`);
            console.error(`[RESTREAMER-ERROR] Channel ${job.streamKey}:`, err.message);
        });
    }

    buildArgs(channel, probe, inputPath) {
        // Publish with the channel's secret key; MediaMTX validates it via POST /internal/mediamtx-auth
        const rtmpTarget = `rtmp://${MEDIAMTX_RTMP_HOST}:${MEDIAMTX_RTMP_PORT}/live/${channel.streamKey}` +
            `?user=publish&pass=${channel.publishKey}`;

        // Input side (depends on what probeSource found):
        // - -rw_timeout (microseconds, any protocol): a source that sends nothing for 15s makes
        //   FFmpeg exit. NOT -timeout: on RTMP inputs it implies -rtmp_listen 1.
        // - Live HLS: NO -reconnect_at_eof. The playlist is a small file that ends after every
        //   download; with at_eof FFmpeg re-reads it forever instead of advancing (stall bug).
        //   -m3u8_hold_counters 10: a playlist that stops advancing ends the run (restart + re-probe).
        // - VOD / frozen HLS and finite files: real-time pacing + -stream_loop -1 (endless).
        //   Pacing is -readrate 1 with an 8s initial burst and 1.5x catch-up, NOT -re: with -re,
        //   time spent downloading each segment is never made up (measured 0.8x = constant stalls).
        //   Looped HLS is read from a local rewritten playlist, hence 'file' in its whitelist.
        // - Endless HTTP streams (IPTV .ts): reconnect at EOF.
        // Many HLS sources disguise segments (.zst, .jpg, .html, no extension, presigned URLs);
        // FFmpeg 8 rejects unknown segment extensions by default ("not in allowed_segment_extensions").
        // Safe to open up: the protocol whitelist and validateSourceUrl still apply.
        const anySegmentExt = ['-allowed_segment_extensions', 'ALL', '-extension_picky', '0'];
        const realtimeLoop = ['-readrate', '1', '-readrate_initial_burst', '8', '-readrate_catchup', '1.5', '-stream_loop', '-1'];
        const httpReconnect = ['-reconnect', '1', '-reconnect_streamed', '1', '-reconnect_on_network_error', '1', '-reconnect_delay_max', '5'];
        let input;
        switch (probe.kind) {
            case 'hls-live':
                input = ['-protocol_whitelist', FFMPEG_PROTOCOL_WHITELIST, ...httpReconnect, ...anySegmentExt,
                    '-live_start_index', '-3', '-m3u8_hold_counters', '10', '-seg_max_retry', '3'];
                break;
            case 'hls-vod':
            case 'hls-frozen':
                input = ['-protocol_whitelist', 'file,http,https,tcp,tls,crypto',
                    '-allowed_extensions', 'ALL', ...anySegmentExt, '-seg_max_retry', '3',
                    ...realtimeLoop];
                break;
            case 'file':
                input = ['-protocol_whitelist', FFMPEG_PROTOCOL_WHITELIST, ...httpReconnect, ...realtimeLoop];
                break;
            case 'stream':
                input = ['-protocol_whitelist', FFMPEG_PROTOCOL_WHITELIST, ...httpReconnect, '-reconnect_at_eof', '1'];
                break;
            default:
                input = ['-protocol_whitelist', FFMPEG_PROTOCOL_WHITELIST];
        }

        // Output side:
        // - 480p profile: scale to 480 lines (width keeps aspect, even), max 30 fps, H.264 main,
        //   ~RESTREAM_VIDEO_KBPS, keyframe every 2s (clean 2s HLS segments), AAC 128k stereo.
        // - copy profile: video copied; audio AAC unless RESTREAM_COPY_AUDIO (FLV only carries AAC/MP3).
        let codecs;
        if (RESTREAM_PROFILE === 'copy') {
            codecs = RESTREAM_COPY_AUDIO
                ? ['-c', 'copy']
                : ['-c:v', 'copy', '-c:a', 'aac', '-b:a', '128k', '-ar', '44100'];
        } else {
            codecs = [
                '-vf', `scale=-2:${RESTREAM_TARGET_HEIGHT}:flags=bicubic,format=yuv420p`,
                '-fpsmax', '30',
                '-c:v', 'libx264', '-preset', RESTREAM_X264_PRESET, '-tune', 'zerolatency', '-profile:v', 'main',
                '-b:v', `${RESTREAM_VIDEO_KBPS}k`,
                '-maxrate', `${Math.round(RESTREAM_VIDEO_KBPS * 1.1)}k`,
                '-bufsize', `${RESTREAM_VIDEO_KBPS * 2}k`,
                '-force_key_frames', 'expr:gte(t,n_forced*2)', '-sc_threshold', '0',
                '-c:a', 'aac', '-b:a', '128k', '-ar', '44100', '-ac', '2'
            ];
        }

        return [
            '-nostdin', '-hide_banner', '-loglevel', 'info',
            '-rw_timeout', String(RESTREAM_RW_TIMEOUT_US),
            ...input,
            // nobuffer: no extra input buffering for live sources (looped ones are paced by -readrate)
            '-fflags', probe.loopPlaylist || probe.kind === 'file' ? '+genpts+discardcorrupt' : '+genpts+discardcorrupt+nobuffer',
            '-i', inputPath,
            '-map', '0:v:0?', '-map', '0:a:0?',
            ...codecs,
            '-f', 'flv', rtmpTarget
        ];
    }

    async spawnProcess(job) {
        const channel = channelManager.getById(job.channelId);
        if (!channel) {
            job.status = 'stopped';
            return;
        }

        // Probe the source on every (re)start: a live source may have frozen or resumed meanwhile
        let probe;
        try {
            probe = await probeSource(job.sourceUrl);
        } catch (err) {
            if (err instanceof ValidationError) {
                // e.g. a redirect or segment host pointing into a private network: never start
                job.status = 'failed';
                this.appendLog(job, `[ERROR] Source rejected: ${err.message}`);
                return;
            }
            probe = { kind: fallbackSourceKind(job.sourceUrl), inputUrl: job.sourceUrl, note: `probe failed: ${err.message}` };
        }
        // Stopped or replaced while probing
        if (job.stopRequested || this.jobs.get(job.channelId) !== job) return;

        job.sourceKind = probe.kind;
        job.probedAt = Date.now();
        this.appendLog(job, `[SOURCE] ${SOURCE_KIND_LABELS[probe.kind] || probe.kind}${probe.note ? ` (${probe.note})` : ''}`);

        let inputPath = probe.inputUrl;
        if (probe.loopPlaylist) {
            await fsp.mkdir(LOOP_PLAYLIST_DIR, { recursive: true });
            inputPath = this.loopPlaylistPath(job.channelId);
            await fsp.writeFile(inputPath, probe.loopPlaylist, 'utf8');
        }
        if (job.stopRequested || this.jobs.get(job.channelId) !== job) return;

        const args = this.buildArgs(channel, probe, inputPath);
        console.log(`[RESTREAMER] Starting FFmpeg restream: ${channel.name} (${job.sourceUrl} -> live/${channel.streamKey}, ${probe.kind}, profile ${RESTREAM_PROFILE})`);

        const proc = spawn('ffmpeg', args, { stdio: ['ignore', 'pipe', 'pipe'] });
        const spawnedAt = Date.now();
        job.process = proc;
        job.pid = proc.pid || null;
        job.exited = false;
        job.status = 'running';
        job.startedAt = new Date().toISOString();
        job.metrics.lastUpdate = 0; // ONLINE again only once this process delivers new frames
        job.lastFrame = -1;
        job.lastProgressAt = spawnedAt;
        job.stallKilled = false;

        let resolveExit;
        job.exitPromise = new Promise(resolve => { resolveExit = resolve; });

        let finished = false;
        const finish = (code, signal) => {
            if (finished) return;
            finished = true;
            job.exited = true;
            job.pid = null;
            resolveExit();
            this.appendLog(job, `[SYSTEM] Process exited with code ${code}, signal ${signal}`);
            console.log(`[RESTREAMER] Channel ${job.streamKey} restream exited (${code}, ${signal})`);
            this.onProcessExit(job, proc, Date.now() - spawnedAt);
        };

        this.appendLog(job, `[SYSTEM] Spawned FFmpeg process PID ${proc.pid}`);
        this.appendLog(job, `[COMMAND] ffmpeg ${args.join(' ')}`);

        // Process stderr output for status & telemetry
        proc.stderr.on('data', (chunk) => this.handleOutput(job, chunk.toString()));
        proc.stdout.on('data', (chunk) => this.appendLog(job, chunk.toString().trim()));

        proc.on('error', (err) => {
            this.appendLog(job, `[ERROR] Process error: ${err.message}`);
            console.error(`[RESTREAMER-ERROR] Channel ${job.streamKey}:`, err.message);
            // Spawn failures (e.g. ENOENT) never emit 'close'
            if (!proc.pid) finish(null, null);
        });

        proc.on('close', (code, signal) => finish(code, signal));
    }

    onProcessExit(job, proc, runMs) {
        // Ignore exits of processes that were replaced by a newer one
        if (job.process !== proc || this.jobs.get(job.channelId) !== job) return;

        if (job.stopRequested) {
            job.status = 'stopped';
            return;
        }

        if (runMs >= RESTREAM_STABLE_RUN_MS) job.retries = 0;

        if (RESTREAM_MAX_RETRIES > 0 && job.retries >= RESTREAM_MAX_RETRIES) {
            job.status = 'failed';
            this.appendLog(job, `[SYSTEM] Giving up after ${job.retries} consecutive restart attempts (RESTREAM_MAX_RETRIES).`);
            return;
        }

        const delay = job.retries < RESTREAM_FAST_RETRIES ? RESTREAM_RETRY_DELAY_MS : RESTREAM_SLOW_RETRY_DELAY_MS;
        job.retries++;
        job.status = 'restarting';
        this.appendLog(job, `[SYSTEM] Unexpected exit. Restart attempt ${job.retries} in ${delay / 1000}s...`);
        job.restartTimer = setTimeout(() => {
            job.restartTimer = null;
            if (!job.stopRequested && this.jobs.get(job.channelId) === job) {
                this.launch(job);
            }
        }, delay);
    }

    /**
     * Stops the channel's restream and resolves once the FFmpeg process has exited.
     * persist=true records desiredState 'stopped' (explicit Stop); false keeps it (restart/shutdown).
     */
    async _stop(channelId, { persist = true } = {}) {
        if (persist && channelManager.getById(channelId)) {
            channelManager.update(channelId, { desiredState: 'stopped' });
        }

        const job = this.jobs.get(channelId);
        if (!job) return false;

        job.stopRequested = true;
        if (job.restartTimer) {
            clearTimeout(job.restartTimer);
            job.restartTimer = null;
        }

        if (job.process && !job.exited) {
            this.appendLog(job, '[SYSTEM] Stopping restream process...');
            try {
                job.process.kill('SIGINT');
            } catch (err) {
                console.error('[RESTREAMER-STOP-ERROR]', err.message);
            }
            // `process.killed` turns true as soon as a signal is sent, so track the real exit instead
            const killTimer = setTimeout(() => {
                if (!job.exited) {
                    this.appendLog(job, `[SYSTEM] No exit after ${RESTREAM_STOP_TIMEOUT_MS / 1000}s, sending SIGKILL`);
                    try { job.process.kill('SIGKILL'); } catch { /* already gone */ }
                }
            }, RESTREAM_STOP_TIMEOUT_MS);
            await job.exitPromise;
            clearTimeout(killTimer);
        }

        job.status = 'stopped';
        fsp.unlink(this.loopPlaylistPath(channelId)).catch(() => {});
        return true;
    }

    loopPlaylistPath(channelId) {
        return path.join(LOOP_PLAYLIST_DIR, `${String(channelId).replace(/[^a-zA-Z0-9_-]/g, '_')}.m3u8`);
    }

    // FFmpeg keeps running (and printing the same frame number) when a source silently stops
    // delivering media. Kill such processes so the supervisor restarts and re-probes the source.
    checkStalls() {
        const now = Date.now();
        for (const job of this.jobs.values()) {
            if (!job.process || job.exited || job.stopRequested) continue;

            if (!job.stallKilled && now - (job.lastProgressAt || now) > RESTREAM_STALL_TIMEOUT_MS) {
                job.stallKilled = true;
                this.appendLog(job, `[SYSTEM] No new frames for ${RESTREAM_STALL_TIMEOUT_MS / 1000}s (source stalled). Restarting FFmpeg...`);
                try { job.process.kill('SIGKILL'); } catch { /* already gone */ }
                continue;
            }

            if (job.sourceKind === 'hls-frozen' && !job.reprobing && now - (job.probedAt || now) > RESTREAM_FROZEN_RECHECK_MS) {
                job.reprobing = true;
                const proc = job.process;
                probeSource(job.sourceUrl)
                    .then(result => {
                        if (result.kind === 'hls-live' && job.process === proc && !job.exited) {
                            this.appendLog(job, '[SOURCE] Source is live again: switching from loop to live.');
                            proc.kill('SIGTERM');
                        }
                    })
                    .catch(() => { /* keep looping */ })
                    .finally(() => { job.probedAt = Date.now(); job.reprobing = false; });
            }
        }
    }

    // Resume every channel whose persisted desired state is 'running'
    async resumeAll() {
        for (const channel of channelManager.getAll()) {
            if (channel.desiredState !== 'running' || !channel.sourceUrl) continue;
            try {
                const url = await validateSourceUrl(channel.sourceUrl);
                await this.start(channel.id, url);
                console.log(`[RESTREAMER] Resumed restream for channel ${channel.streamKey}`);
            } catch (err) {
                console.error(`[RESTREAMER] Could not resume channel ${channel.streamKey}: ${err.message}`);
            }
        }
    }

    getStatus(channelId) {
        const job = this.jobs.get(channelId);
        const channel = channelManager.getById(channelId);
        if (!job) {
            return {
                channelId,
                status: 'idle',
                pid: null,
                metrics: { fps: 0, bitrate: '0kbits/s', speed: '0x', time: '00:00:00' },
                sourceUrl: channel?.sourceUrl || '',
                desiredState: channel?.desiredState || 'stopped',
                state: 'OFFLINE'
            };
        }

        return {
            channelId: job.channelId,
            status: job.status,
            pid: job.pid,
            startedAt: job.startedAt,
            metrics: job.metrics,
            sourceUrl: job.sourceUrl,
            retries: job.retries,
            desiredState: channel?.desiredState || 'stopped',
            sourceKind: job.sourceKind || null,
            profile: RESTREAM_PROFILE,
            state: FFmpegRestreamManager.panelState(job)
        };
    }

    /**
     * Panel state: ONLINE = FFmpeg is alive and reported progress (frames pushed) in the last
     * RESTREAM_PROGRESS_STALE_MS; CONNECTING = started/restarting but no frames yet;
     * FAILED = gave up after RESTREAM_MAX_RETRIES; OFFLINE = stopped/idle.
     */
    static panelState(job) {
        if (job.status === 'failed') return 'FAILED';
        if (job.status === 'stopped' || job.stopRequested) return 'OFFLINE';
        const fresh = job.metrics.lastUpdate > 0 && Date.now() - job.metrics.lastUpdate < RESTREAM_PROGRESS_STALE_MS;
        if (job.status === 'running' && !job.exited && fresh) return 'ONLINE';
        return 'CONNECTING';
    }

    getLogs(channelId, limit = 100) {
        const job = this.jobs.get(channelId);
        if (!job) return [];
        return job.logs.slice(-limit);
    }

    handleOutput(job, text) {
        const lines = text.split(/\r\n|\n|\r/);
        for (const line of lines) {
            if (!line.trim()) continue;
            this.appendLog(job, line);

            // Parse live FFmpeg metrics:
            // frame= 1240 fps= 60 q=-1.0 size= 1234kB time=00:00:20.40 bitrate=2450.1kbits/s speed=1.00x
            if (line.includes('frame=') || line.includes('fps=') || line.includes('bitrate=')) {
                const fpsMatch = line.match(/fps=\s*([\d.]+)/);
                const bitrateMatch = line.match(/bitrate=\s*([\d.]+\s*[kKmM]?bits\/s)/);
                const speedMatch = line.match(/speed=\s*([\d.]+)x/);
                const timeMatch = line.match(/time=\s*([\d:.]+)/);
                const frameMatch = line.match(/frame=\s*(\d+)/);

                if (fpsMatch) job.metrics.fps = parseFloat(fpsMatch[1]) || 0;
                if (bitrateMatch) job.metrics.bitrate = bitrateMatch[1].trim();
                if (speedMatch) job.metrics.speed = speedMatch[1] + 'x';
                if (timeMatch) job.metrics.time = timeMatch[1];
                if (frameMatch) {
                    const frame = parseInt(frameMatch[1], 10);
                    job.metrics.frame = frame;
                    // Progress = the frame counter moved (FFmpeg repeats the same line while stalled)
                    if (frame > (job.lastFrame ?? -1)) {
                        job.lastFrame = frame;
                        job.lastProgressAt = Date.now();
                        job.metrics.lastUpdate = job.lastProgressAt;
                    }
                }
            }
        }
    }

    appendLog(job, message) {
        const timestamp = new Date().toISOString().substring(11, 19);
        // Never expose the RTMP publish key in logs (logs are streamed to the dashboard)
        const safe = String(message).replace(/([?&]pass=)[^&\s]+/g, '$1***');
        job.logs.push(`[${timestamp}] ${safe}`);
        if (job.logs.length > 200) {
            job.logs.shift();
        }
    }

    // Shutdown: stop every process but keep desiredState so jobs resume on next start
    async shutdownAll() {
        console.log('[RESTREAMER] Terminating all active FFmpeg restream processes...');
        await Promise.all(Array.from(this.jobs.keys()).map(id => this._stop(id, { persist: false })));
    }
}

const restreamManager = new FFmpegRestreamManager();

// ------------------------------------------------------------------------------
// Real-Time Cloudflare R2 Watcher & Uploader
// - Segments are always uploaded BEFORE any playlist that references them
// - Async fs, streamed segment uploads, bounded concurrency, retries
// ------------------------------------------------------------------------------
const R2_UPLOAD_CONCURRENCY = 4;
const R2_UPLOAD_RETRIES = 3;          // retries after the first attempt
const R2_DELETE_BATCH_SIZE = 1000;    // S3 DeleteObjects hard limit
const PLAYLIST_CACHE_CONTROL = 'no-store, no-cache, must-revalidate, max-age=0';
// Long-lived segment caching is only safe because segment names are never reused
// (mediamtx.yml: -hls_start_number_source epoch).
const SEGMENT_CACHE_CONTROL = 'public, max-age=3600, immutable';

class R2PipelineManager {
    constructor() {
        this.watcher = null;
        this.pruneInterval = null;
        this.stats = {
            uploadedSegments: 0,
            uploadedPlaylists: 0,
            deletedSegments: 0,
            failedUploads: 0,
            lastPruneTime: null
        };
        // R2 keys of segments uploaded successfully (dropped once the local file is deleted)
        this.uploadedSegments = new Set();
        // Latest not-yet-uploaded playlist per R2 prefix, waiting for its segments
        this.pendingPlaylists = new Map();
        this.flushingPlaylists = new Set();
        // Upload concurrency limiter
        this.activeUploads = 0;
        this.uploadWaiters = [];
    }

    start() {
        if (!fs.existsSync(HLS_DIR)) {
            try {
                fs.mkdirSync(HLS_DIR, { recursive: true });
            } catch (err) {
                console.error('[R2-PIPELINE-ERROR] Failed to create HLS dir:', err.message);
            }
        }

        console.log(`[R2-PIPELINE] Initializing watcher on directory: ${HLS_DIR}`);

        // Chokidar watcher monitoring /hls
        this.watcher = chokidar.watch(HLS_DIR, {
            ignored: /(^|[\/\\])\../, // ignore dotfiles
            persistent: true,
            ignoreInitial: false,
            awaitWriteFinish: {
                stabilityThreshold: 150,
                pollInterval: 50
            }
        });

        this.watcher.on('add', (filePath) => this.processFile(filePath));
        this.watcher.on('change', (filePath) => this.processFile(filePath));
        this.watcher.on('unlink', (filePath) => this.forgetFile(filePath));
        this.watcher.on('error', (err) => console.error('[R2-WATCHER-ERROR]', err));

        // Start pruning loop for R2 bucket
        this.pruneInterval = setInterval(() => this.pruneOldSegments(), 20000);
    }

    // Maps /hls/live/{streamKey}/{file} (or /hls/{streamKey}/{file}) to { r2Prefix, fileName }
    resolveTarget(filePath) {
        const relativePath = path.relative(HLS_DIR, filePath).replace(/\\/g, '/');
        const parts = relativePath.split('/');

        let streamKey = '';
        let fileName = '';
        if (parts.length >= 3 && parts[0] === 'live') {
            streamKey = parts[1];
            fileName = parts.slice(2).join('/');
        } else if (parts.length >= 2) {
            streamKey = parts[0];
            fileName = parts.slice(1).join('/');
        } else {
            return null;
        }

        // Map stream key to randomized R2 folder slug
        const channel = channelManager.getByStreamKey(streamKey);
        const folderSlug = channel ? channel.r2_slug : streamKey;
        return { r2Prefix: `hd/${folderSlug}`, fileName };
    }

    segmentKey(r2Prefix, fileName) {
        // Camouflage segment extension: seg_001.ts -> seg_001.js
        return `${r2Prefix}/${fileName.replace(/\.ts$/i, '.js')}`;
    }

    async processFile(filePath) {
        const ext = path.extname(filePath).toLowerCase();
        if (ext !== '.ts' && ext !== '.m3u8') return;

        const target = this.resolveTarget(filePath);
        if (!target) return;

        if (ext === '.ts') {
            await this.handleSegment(filePath, target.r2Prefix, target.fileName);
        } else {
            await this.handlePlaylist(filePath, target.r2Prefix);
        }
    }

    forgetFile(filePath) {
        if (path.extname(filePath).toLowerCase() !== '.ts') return;
        const target = this.resolveTarget(filePath);
        // A deleted local segment is no longer in any current playlist
        if (target) this.uploadedSegments.delete(this.segmentKey(target.r2Prefix, target.fileName));
    }

    async handleSegment(filePath, r2Prefix, fileName) {
        const r2Key = this.segmentKey(r2Prefix, fileName);
        try {
            const stat = await fsp.stat(filePath).catch(() => null);
            if (!stat || stat.size === 0) return;

            await this.uploadObject(
                r2Key,
                () => fs.createReadStream(filePath), // fresh stream per attempt
                stat.size,
                'application/javascript',
                SEGMENT_CACHE_CONTROL
            );
            this.uploadedSegments.add(r2Key);
            this.stats.uploadedSegments++;
            // A playlist may have been waiting for exactly this segment
            this.flushPlaylist(r2Prefix);
        } catch (err) {
            console.error(`[R2-SEGMENT-ERROR] Failed to upload ${filePath}:`, err.message);
        }
    }

    async handlePlaylist(filePath, r2Prefix) {
        let content;
        try {
            content = await fsp.readFile(filePath, 'utf8');
        } catch {
            return; // rotated away between event and read
        }
        if (!content || !content.includes('#EXTM3U')) return;

        const segmentKeys = content
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(line => line && !line.startsWith('#') && /\.ts$/i.test(line))
            .map(line => this.segmentKey(r2Prefix, path.posix.basename(line)));

        // Rewrite manifest internal segment links: .ts -> .js
        const rewritten = content.replace(/([a-zA-Z0-9_\-]+)\.ts/g, '$1.js');

        // Newest playlist wins; older pending versions are superseded
        this.pendingPlaylists.set(r2Prefix, { body: Buffer.from(rewritten, 'utf8'), segmentKeys });
        await this.flushPlaylist(r2Prefix);
    }

    /**
     * Uploads the pending playlist for a prefix once every segment it lists is in R2.
     * Otherwise it stays pending and is retried after each successful segment upload.
     */
    async flushPlaylist(r2Prefix) {
        if (this.flushingPlaylists.has(r2Prefix)) return; // re-checked when the current flush ends
        const pending = this.pendingPlaylists.get(r2Prefix);
        if (!pending || !pending.segmentKeys.every(k => this.uploadedSegments.has(k))) return;

        this.pendingPlaylists.delete(r2Prefix);
        this.flushingPlaylists.add(r2Prefix);
        try {
            const size = pending.body.length;
            // 1. Upload as index.html (Direct browser and player friendly)
            // 2. Upload as index.css (Camouflaged stylesheet delivery)
            await Promise.all([
                this.uploadObject(`${r2Prefix}/index.html`, () => pending.body, size, 'text/html; charset=utf-8', PLAYLIST_CACHE_CONTROL),
                this.uploadObject(`${r2Prefix}/index.css`, () => pending.body, size, 'text/css; charset=utf-8', PLAYLIST_CACHE_CONTROL)
            ]);
            this.stats.uploadedPlaylists++;
        } catch (err) {
            console.error(`[R2-PLAYLIST-ERROR] Failed to upload playlist for ${r2Prefix}:`, err.message);
        } finally {
            this.flushingPlaylists.delete(r2Prefix);
        }
        // A newer playlist may have arrived while uploading
        if (this.pendingPlaylists.has(r2Prefix)) await this.flushPlaylist(r2Prefix);
    }

    async acquireUploadSlot() {
        if (this.activeUploads < R2_UPLOAD_CONCURRENCY) {
            this.activeUploads++;
            return;
        }
        await new Promise(resolve => this.uploadWaiters.push(resolve));
    }

    releaseUploadSlot() {
        const next = this.uploadWaiters.shift();
        if (next) next(); // hand the slot over directly
        else this.activeUploads--;
    }

    /**
     * Uploads with bounded concurrency and up to R2_UPLOAD_RETRIES retries.
     * makeBody() must return a fresh Body (stream or buffer) for every attempt. Throws on final failure.
     */
    async uploadObject(r2Key, makeBody, contentLength, contentType, cacheControl) {
        if (!s3Client) {
            // DRY-RUN mode
            return;
        }

        await this.acquireUploadSlot();
        try {
            for (let attempt = 0; ; attempt++) {
                try {
                    await s3Client.send(new PutObjectCommand({
                        Bucket: R2_BUCKET_NAME,
                        Key: r2Key,
                        Body: makeBody(),
                        ContentLength: contentLength,
                        ContentType: contentType,
                        CacheControl: cacheControl
                    }));
                    return;
                } catch (err) {
                    if (attempt >= R2_UPLOAD_RETRIES) {
                        this.stats.failedUploads++;
                        console.error(`[R2-UPLOAD-FAIL] Failed to upload ${r2Key} after ${attempt + 1} attempts:`, err.message);
                        throw err;
                    }
                    await new Promise(resolve => setTimeout(resolve, 500 * 2 ** attempt));
                }
            }
        } finally {
            this.releaseUploadSlot();
        }
    }

    async pruneOldSegments() {
        if (!s3Client) return;

        try {
            const now = Date.now();
            const maxAgeMs = MAX_SEGMENT_AGE_SECONDS * 1000;
            const toDelete = [];

            // Paginate until the listing is complete
            let continuationToken;
            do {
                const listResponse = await s3Client.send(new ListObjectsV2Command({
                    Bucket: R2_BUCKET_NAME,
                    Prefix: 'hd/',
                    ContinuationToken: continuationToken
                }));

                for (const item of listResponse.Contents || []) {
                    // Never delete playlist manifests
                    if (item.Key.endsWith('index.html') || item.Key.endsWith('index.css') || item.Key.endsWith('.m3u8')) {
                        continue;
                    }

                    // Delete .js segments older than MAX_SEGMENT_AGE_SECONDS
                    if (item.Key.endsWith('.js') && item.LastModified) {
                        const age = now - new Date(item.LastModified).getTime();
                        if (age > maxAgeMs) {
                            toDelete.push({ Key: item.Key });
                        }
                    }
                }

                continuationToken = listResponse.IsTruncated ? listResponse.NextContinuationToken : undefined;
            } while (continuationToken);

            for (let i = 0; i < toDelete.length; i += R2_DELETE_BATCH_SIZE) {
                const batch = toDelete.slice(i, i + R2_DELETE_BATCH_SIZE);
                await s3Client.send(new DeleteObjectsCommand({
                    Bucket: R2_BUCKET_NAME,
                    Delete: { Objects: batch, Quiet: true }
                }));
                batch.forEach(obj => this.uploadedSegments.delete(obj.Key));
                this.stats.deletedSegments += batch.length;
            }

            if (toDelete.length > 0) {
                this.stats.lastPruneTime = new Date().toISOString();
                console.log(`[R2-PRUNE] Cleaned ${toDelete.length} expired segment(s) from R2 bucket.`);
            }
        } catch (err) {
            console.error('[R2-PRUNE-ERROR] Error while pruning old segments:', err.message);
        }
    }

    stop() {
        if (this.watcher) this.watcher.close();
        if (this.pruneInterval) clearInterval(this.pruneInterval);
    }
}

const r2Pipeline = new R2PipelineManager();
r2Pipeline.start();

// ------------------------------------------------------------------------------
// Local /hls janitor: removes files older than 5 minutes (e.g. leftovers of an ended stream).
// Live files are rewritten/rotated every few seconds and are never that old. Channel
// directories are chowned to uid 1000 by the packaging hook (mediamtx.yml) so this can delete.
// ------------------------------------------------------------------------------
const LOCAL_HLS_MAX_AGE_MS = 5 * 60 * 1000;
const LOCAL_HLS_SWEEP_INTERVAL_MS = 60 * 1000;

async function pruneLocalHls(dir = HLS_DIR) {
    let removed = 0;
    let failed = 0;
    let entries;
    try {
        entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
        return { removed, failed };
    }
    const cutoff = Date.now() - LOCAL_HLS_MAX_AGE_MS;
    for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            const sub = await pruneLocalHls(full);
            removed += sub.removed;
            failed += sub.failed;
        } else if (entry.isFile()) {
            try {
                const stat = await fsp.stat(full);
                if (stat.mtimeMs < cutoff) {
                    await fsp.unlink(full);
                    removed++;
                }
            } catch (err) {
                if (err.code !== 'ENOENT') failed++;
            }
        }
    }
    return { removed, failed };
}

setInterval(async () => {
    const { removed, failed } = await pruneLocalHls();
    if (removed > 0) console.log(`[HLS-JANITOR] Removed ${removed} stale local file(s) older than 5 minutes.`);
    if (failed > 0) console.warn(`[HLS-JANITOR] Could not remove ${failed} stale file(s) (permissions?).`);
}, LOCAL_HLS_SWEEP_INTERVAL_MS).unref();

// ------------------------------------------------------------------------------
// Express App & Routing Setup
// ------------------------------------------------------------------------------
const app = express();

// Nginx is the single trusted hop in front of the backend; req.ip = the client address nginx saw.
app.set('trust proxy', 1);

// Security Middlewares
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    // HSTS is set once by nginx (plain max-age); helmet's default would add a second,
    // conflicting header with includeSubDomains
    strictTransportSecurity: false
}));

// CORS for the public viewer API only. Admin routes get no CORS headers (same-origin only).
const viewerCors = cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, false);
        if (ALLOWED_ORIGINS.includes('*')) return callback(null, true); // non-production only
        let normalized;
        try { normalized = new URL(origin).origin.toLowerCase(); } catch { return callback(null, false); }
        const allowed = ALLOWED_ORIGINS.some(a => {
            try { return new URL(a).origin.toLowerCase() === normalized; } catch { return false; }
        });
        callback(null, allowed);
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type'],
    maxAge: 86400,
    // Lets allow-listed third-party pages receive/send the stream_auth cookie (never with '*' in production)
    credentials: true
});
app.use(['/api/stream', '/api/token'], viewerCors);

// Admin endpoints: same-origin, plus the external control panels listed in ADMIN_ALLOWED_ORIGINS.
// Entries are exact origins ("https://panel.example.com") or "scheme://host:*" for any port
// ("http://localhost:*"). Admin auth is a Bearer header (no cookies), so CORS here never sends
// credentials; the allow-list only limits which web pages may drive the admin API.
const ADMIN_ALLOWED_ORIGINS = (process.env.ADMIN_ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
if (ADMIN_ALLOWED_ORIGINS.includes('*')) {
    fatal('ADMIN_ALLOWED_ORIGINS="*" is not allowed. List explicit origins, e.g. http://localhost:*');
}

function isAdminOriginAllowed(origin) {
    let o;
    try { o = new URL(origin); } catch { return false; }
    return ADMIN_ALLOWED_ORIGINS.some(entry => {
        const anyPort = entry.endsWith(':*');
        let e;
        try { e = new URL(anyPort ? entry.slice(0, -2) : entry); } catch { return false; }
        if (e.protocol !== o.protocol || e.hostname.toLowerCase() !== o.hostname.toLowerCase()) return false;
        return anyPort || e.port === o.port;
    });
}

const adminCors = cors({
    origin: (origin, callback) => callback(null, Boolean(origin) && isAdminOriginAllowed(origin)),
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type'],
    maxAge: 600,
    credentials: false
});

// Reject cross-origin browser requests to admin endpoints unless the origin is allow-listed.
function sameOriginOnly(req, res, next) {
    const origin = req.headers.origin;
    if (!origin) return next();
    try {
        if (new URL(origin).host.toLowerCase() === String(req.headers.host || '').toLowerCase()) return next();
    } catch { /* fall through */ }
    if (isAdminOriginAllowed(origin)) return next();
    return res.status(403).json({ success: false, error: 'Forbidden: cross-origin admin request' });
}
app.use(['/api/admin', '/api/channels', '/api/stats', '/api/config'], adminCors, sameOriginOnly);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve Static Admin Frontend Dashboard
const publicDir = path.join(__dirname, 'public');
app.use('/admin', express.static(publicDir));
app.get('/admin', (req, res) => {
    res.sendFile(path.join(publicDir, 'admin.html'));
});

// ------------------------------------------------------------------------------
// Authentication Helpers & Middleware
// ------------------------------------------------------------------------------
function generateAdminToken(username) {
    return jwt.sign(
        { role: 'admin', username },
        ADMIN_JWT_SECRET,
        { algorithm: 'HS256', expiresIn: ADMIN_TOKEN_TTL }
    );
}

// Constant-time string comparison: hash both sides so lengths always match.
function safeEqual(a, b) {
    const ha = crypto.createHash('sha256').update(String(a), 'utf8').digest();
    const hb = crypto.createHash('sha256').update(String(b), 'utf8').digest();
    return crypto.timingSafeEqual(ha, hb);
}

// In-memory admin login rate limiter: LOGIN_MAX_FAILURES failed attempts per LOGIN_WINDOW_MS per IP.
const LOGIN_MAX_FAILURES = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const loginFailures = new Map(); // ip -> { count, firstAt }

function loginBlockedFor(ip) {
    const entry = loginFailures.get(ip);
    if (!entry) return 0;
    const elapsed = Date.now() - entry.firstAt;
    if (elapsed > LOGIN_WINDOW_MS) {
        loginFailures.delete(ip);
        return 0;
    }
    return entry.count >= LOGIN_MAX_FAILURES ? Math.ceil((LOGIN_WINDOW_MS - elapsed) / 1000) : 0;
}

function recordLoginFailure(ip) {
    const entry = loginFailures.get(ip);
    if (!entry || Date.now() - entry.firstAt > LOGIN_WINDOW_MS) {
        loginFailures.set(ip, { count: 1, firstAt: Date.now() });
    } else {
        entry.count++;
    }
}

setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of loginFailures) {
        if (now - entry.firstAt > LOGIN_WINDOW_MS) loginFailures.delete(ip);
    }
}, 60 * 1000).unref();

function verifyAdminAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, error: 'Unauthorized: Missing or malformed token' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, ADMIN_JWT_SECRET, { algorithms: JWT_ALGORITHMS });
        if (decoded.role !== 'admin') {
            return res.status(403).json({ success: false, error: 'Forbidden: Admin privilege required' });
        }
        req.admin = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, error: 'Unauthorized: Invalid or expired token' });
    }
}

// ------------------------------------------------------------------------------
// REST API Endpoints
// ------------------------------------------------------------------------------

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        r2Connected: isR2Configured
    });
});

// System Public Configuration for Dashboard Links
app.get('/api/config', (req, res) => {
    const hostHeader = req.headers.host || '';
    const currentDomain = hostHeader.split(':')[0] || EDGE_DOMAIN;

    res.json({
        serverIp: SERVER_IP,
        edgeDomain: EDGE_DOMAIN || currentDomain,
        r2CustomDomain: R2_CUSTOM_DOMAIN,
        rtmpPort: 1935,
        r2Configured: isR2Configured,
        r2Bucket: R2_BUCKET_NAME,
        enableAuthOnPlaylists: ENABLE_AUTH_ON_PLAYLISTS,
        maxSegmentAgeSeconds: MAX_SEGMENT_AGE_SECONDS
    });
});

// Admin Login
app.post('/api/admin/login', (req, res) => {
    const ip = req.ip || 'unknown';
    const retryAfter = loginBlockedFor(ip);
    if (retryAfter > 0) {
        res.set('Retry-After', String(retryAfter));
        return res.status(429).json({ success: false, error: 'Too many failed login attempts. Try again later.' });
    }

    const { username, password } = req.body || {};
    if (!username || !password) {
        return res.status(400).json({ success: false, error: 'Username and password are required' });
    }

    // Evaluate both comparisons (no short-circuit) to keep timing independent of which one failed
    const userOk = safeEqual(username, ADMIN_USERNAME);
    const passOk = safeEqual(password, ADMIN_PASSWORD);
    if (userOk & passOk) {
        loginFailures.delete(ip);
        const token = generateAdminToken(ADMIN_USERNAME);
        return res.json({
            success: true,
            token,
            user: { username: ADMIN_USERNAME, role: 'admin' }
        });
    }

    recordLoginFailure(ip);
    return res.status(401).json({ success: false, error: 'Invalid admin credentials' });
});

// Verify Current Admin Token
app.get('/api/admin/verify', verifyAdminAuth, (req, res) => {
    res.json({ success: true, user: req.admin });
});

// Admin-only link set. obsStreamKey embeds the secret publish key; never return it from public endpoints.
function buildChannelLinks(channel) {
    return {
        obsRtmpUrl: `rtmp://${SERVER_IP}:${MEDIAMTX_RTMP_PORT}/live`,
        obsStreamKey: `${channel.streamKey}?user=publish&pass=${channel.publishKey}`,
        edgeCamouflagedUrl: `https://${EDGE_DOMAIN}/live/${channel.streamKey}/index.css`,
        r2DirectHtmlUrl: `https://${R2_CUSTOM_DOMAIN}/hd/${channel.r2_slug}/index.html`,
        r2DirectCssUrl: `https://${R2_CUSTOM_DOMAIN}/hd/${channel.r2_slug}/index.css`,
        iframeEmbedUrl: `https://${EDGE_DOMAIN}/player/?channel=${channel.streamKey}`,
        iframeR2EmbedUrl: `https://${EDGE_DOMAIN}/player/?r2=${channel.r2_slug}`
    };
}

// List All Channels with Dynamic Restream Status
app.get('/api/channels', verifyAdminAuth, (req, res) => {
    const channels = channelManager.getAll();
    const enriched = channels.map(channel => {
        const restreamStatus = restreamManager.getStatus(channel.id);
        return {
            ...channel,
            restream: restreamStatus,
            links: buildChannelLinks(channel)
        };
    });

    res.json({ success: true, channels: enriched });
});

// Create New Channel
app.post('/api/channels', verifyAdminAuth, async (req, res) => {
    try {
        const { name, streamKey, r2_slug } = req.body;
        let { sourceUrl } = req.body;
        if (!name && !streamKey) {
            return res.status(400).json({ success: false, error: 'Channel name or stream key is required' });
        }
        sourceUrl = sourceUrl && String(sourceUrl).trim() ? await validateSourceUrl(sourceUrl) : '';

        const channel = channelManager.create({ name, streamKey, r2_slug, sourceUrl });
        const restreamStatus = restreamManager.getStatus(channel.id);

        res.status(201).json({
            success: true,
            channel: {
                ...channel,
                restream: restreamStatus,
                links: buildChannelLinks(channel)
            }
        });
    } catch (err) {
        res.status(400).json({ success: false, error: err.message });
    }
});

// ------------------------------------------------------------------------------
// Name-based Restream API (GO Match panel): { channelName, sourceUrl }
// Thin wrappers over the id-based routes below: same validation, supervisor, locking,
// persistence (desiredState in channels.json) and resume-after-restart.
// ------------------------------------------------------------------------------
function channelKeyFromName(channelName) {
    const key = String(channelName || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '_');
    return CHANNEL_RE.test(key) ? key : null;
}

function panelChannelView(channel) {
    const status = restreamManager.getStatus(channel.id);
    return {
        id: channel.id,
        channelName: channel.name,
        streamKey: channel.streamKey,
        state: status.state,          // ONLINE | CONNECTING | OFFLINE | FAILED
        status: status.status,        // supervisor detail: idle | running | restarting | stopped | failed
        pid: status.pid,
        retries: status.retries || 0,
        startedAt: status.startedAt || null,
        sourceUrl: status.sourceUrl,
        metrics: status.metrics,
        links: buildChannelLinks(channel)
    };
}

// Start (creates the channel on first use; restarts with the new source if already running)
app.post('/api/channels/start', verifyAdminAuth, async (req, res) => {
    const { channelName, sourceUrl } = req.body || {};
    const key = channelKeyFromName(channelName);
    if (!key) {
        return res.status(400).json({ success: false, error: 'channelName is required (letters, digits, _ or -, max 64)' });
    }
    try {
        let channel = channelManager.getByStreamKey(key);
        const effectiveUrl = String(sourceUrl || channel?.sourceUrl || '').trim();
        if (!effectiveUrl) {
            return res.status(400).json({ success: false, error: 'sourceUrl is required' });
        }
        const validUrl = await validateSourceUrl(effectiveUrl);

        const created = !channel;
        if (created) {
            channel = channelManager.create({ name: String(channelName).trim(), streamKey: key, sourceUrl: validUrl });
        }
        await restreamManager.start(channel.id, validUrl);
        res.status(created ? 201 : 200).json({ success: true, created, channel: panelChannelView(channel) });
    } catch (err) {
        res.status(err.status || 500).json({ success: false, error: err.message });
    }
});

// Stop (waits for FFmpeg to exit; SIGKILL after 5s)
app.post('/api/channels/stop', verifyAdminAuth, async (req, res) => {
    const key = channelKeyFromName((req.body || {}).channelName);
    const channel = key && channelManager.getByStreamKey(key);
    if (!channel) {
        return res.status(404).json({ success: false, error: 'Channel not found' });
    }
    await restreamManager.stop(channel.id);
    res.json({ success: true, channel: panelChannelView(channel) });
});

// Status: one channel (?channelName=match1) or all channels
app.get('/api/channels/status', verifyAdminAuth, (req, res) => {
    if (req.query.channelName !== undefined) {
        const key = channelKeyFromName(req.query.channelName);
        const channel = key && channelManager.getByStreamKey(key);
        if (!channel) {
            return res.status(404).json({ success: false, error: 'Channel not found' });
        }
        return res.json({ success: true, channel: panelChannelView(channel) });
    }
    res.json({ success: true, channels: channelManager.getAll().map(panelChannelView) });
});

// Update Channel
app.put('/api/channels/:id', verifyAdminAuth, async (req, res) => {
    const { id } = req.params;
    const { name, r2_slug } = req.body;
    let { sourceUrl } = req.body;

    try {
        if (sourceUrl !== undefined) {
            sourceUrl = String(sourceUrl).trim() ? await validateSourceUrl(sourceUrl) : '';
        }
    } catch (err) {
        return res.status(err.status || 400).json({ success: false, error: err.message });
    }

    const channel = channelManager.update(id, { name, sourceUrl, r2_slug });
    if (!channel) {
        return res.status(404).json({ success: false, error: 'Channel not found' });
    }

    res.json({ success: true, channel });
});

// Delete Channel
app.delete('/api/channels/:id', verifyAdminAuth, async (req, res) => {
    const { id } = req.params;
    await restreamManager.stop(id);
    const deleted = channelManager.delete(id);
    if (!deleted) {
        return res.status(404).json({ success: false, error: 'Channel not found' });
    }
    res.json({ success: true, message: 'Channel deleted successfully' });
});

// Pull Restreaming: Start
app.post('/api/channels/:id/restream/start', verifyAdminAuth, async (req, res) => {
    const { id } = req.params;
    const { sourceUrl } = req.body;

    try {
        const channel = channelManager.getById(id);
        if (!channel) {
            return res.status(404).json({ success: false, error: 'Channel not found' });
        }

        const effectiveUrl = (sourceUrl || channel.sourceUrl || '').trim();
        if (!effectiveUrl) {
            return res.status(400).json({ success: false, error: 'External source URL is required' });
        }

        const validUrl = await validateSourceUrl(effectiveUrl);
        const status = await restreamManager.start(id, validUrl);
        res.json({ success: true, status });
    } catch (err) {
        res.status(err.status || 500).json({ success: false, error: err.message });
    }
});

// Pull Restreaming: Stop
app.post('/api/channels/:id/restream/stop', verifyAdminAuth, async (req, res) => {
    const { id } = req.params;
    await restreamManager.stop(id);
    res.json({ success: true, status: restreamManager.getStatus(id) });
});

// Pull Restreaming: Restart
app.post('/api/channels/:id/restream/restart', verifyAdminAuth, async (req, res) => {
    const { id } = req.params;
    try {
        const job = restreamManager.jobs.get(id);
        const sourceUrl = job ? job.sourceUrl : (channelManager.getById(id)?.sourceUrl || '');
        if (sourceUrl) await validateSourceUrl(sourceUrl);
        const status = await restreamManager.restart(id);
        res.json({ success: true, status });
    } catch (err) {
        res.status(err.status || 500).json({ success: false, error: err.message });
    }
});

// Pull Restreaming: Status
app.get('/api/channels/:id/restream/status', verifyAdminAuth, (req, res) => {
    const { id } = req.params;
    res.json({ success: true, status: restreamManager.getStatus(id) });
});

// Pull Restreaming: Live Logs Polling
app.get('/api/channels/:id/restream/logs', verifyAdminAuth, (req, res) => {
    const { id } = req.params;
    const limit = parseInt(req.query.limit || '100', 10);
    const logs = restreamManager.getLogs(id, limit);
    res.json({ success: true, logs });
});

// Pull Restreaming: Server-Sent Events (SSE) Live Log Streaming
app.get('/api/channels/:id/restream/logs/stream', verifyAdminAuth, (req, res) => {
    const { id } = req.params;
    
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const interval = setInterval(() => {
        const logs = restreamManager.getLogs(id, 20);
        const status = restreamManager.getStatus(id);
        res.write(`data: ${JSON.stringify({ status, logs })}\n\n`);
    }, 1000);

    req.on('close', () => {
        clearInterval(interval);
    });
});

// Pipeline Statistics
app.get('/api/stats', verifyAdminAuth, (req, res) => {
    res.json({
        success: true,
        stats: {
            ...r2Pipeline.stats,
            activeRestreams: Array.from(restreamManager.jobs.values()).filter(j => j.status === 'running').length,
            totalChannels: channelManager.getAll().length
        }
    });
});

// ------------------------------------------------------------------------------
// Edge Viewer Token & Nginx Auth Subrequest Handler (/auth)
// ------------------------------------------------------------------------------

const CHANNEL_RE = /^[a-z0-9_-]{1,64}$/;

function signViewerToken(channelKey) {
    return jwt.sign(
        { sub: crypto.randomBytes(8).toString('hex'), channel: channelKey, role: 'viewer' },
        VIEWER_JWT_SECRET,
        { algorithm: 'HS256', expiresIn: TOKEN_EXPIRATION_SECONDS }
    );
}

// Viewer token cookie for playlist auth (needed by native Safari HLS, which reloads the same
// playlist URL and cannot attach headers). Scoped per channel (Path=/live/{channel}/) so two
// channels open in one browser never overwrite each other. SameSite=None + Partitioned so it
// also works inside cross-site iframe embeds where the browser allows (partitioned) third-party
// cookies; Safari/Brave block those by default, so embeds there rely on hls.js + Bearer header.
const VIEWER_COOKIE = 'stream_auth';

function setViewerCookie(res, channelKey, token) {
    res.cookie(VIEWER_COOKIE, token, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        partitioned: true,
        path: `/live/${channelKey}/`,
        maxAge: TOKEN_EXPIRATION_SECONDS * 1000
    });
}

function cookieToken(req) {
    const header = req.headers.cookie;
    if (!header) return null;
    for (const part of header.split(';')) {
        const eq = part.indexOf('=');
        if (eq > 0 && part.slice(0, eq).trim() === VIEWER_COOKIE) {
            try {
                return decodeURIComponent(part.slice(eq + 1).trim()) || null;
            } catch {
                return null;
            }
        }
    }
    return null;
}

function bearerToken(req) {
    const header = req.headers.authorization || '';
    return header.startsWith('Bearer ') ? header.slice(7).trim() : null;
}

// Channel segment of an edge URI: /live/{channel}/index.css, /live/{channel}.css, /live/{channel}/seg_1.js
function extractChannelFromUri(uri) {
    const match = /^\/(?:live|hls)\/([A-Za-z0-9_-]+)/.exec(String(uri || '').split('?')[0]);
    return match ? match[1].toLowerCase() : null;
}

function tokenFromOriginalUri(uri) {
    if (!uri || !uri.includes('?')) return null;
    try {
        return new URL(uri, 'http://localhost').searchParams.get('token');
    } catch {
        return null;
    }
}

// Generate dynamic viewer token for Edge CDN playback
app.get('/api/stream', (req, res) => {
    const requested = String(req.query.channel || '').trim().toLowerCase();
    if (!requested) {
        return res.status(400).json({ error: 'channel query parameter is required' });
    }
    if (!CHANNEL_RE.test(requested)) {
        return res.status(400).json({ error: 'channel may only contain a-z, 0-9, _ and -' });
    }
    const channel = channelManager.getByStreamKey(requested);
    if (!channel) {
        return res.status(404).json({ error: 'Channel not found' });
    }

    const token = signViewerToken(channel.streamKey);
    setViewerCookie(res, channel.streamKey, token);
    res.json({
        channel: channel.streamKey,
        token,
        expiresIn: TOKEN_EXPIRATION_SECONDS,
        streamUrl: `https://${EDGE_DOMAIN}/live/${channel.streamKey}/index.css?token=${token}`
    });
});

// Token Renewal: accepts a valid token or one expired by at most TOKEN_RENEW_GRACE_SECONDS
app.post('/api/token', (req, res) => {
    const token = (req.body && req.body.token) || bearerToken(req);
    if (!token) {
        return res.status(400).json({ error: 'Token is required' });
    }

    let decoded;
    try {
        decoded = jwt.verify(token, VIEWER_JWT_SECRET, {
            algorithms: JWT_ALGORITHMS,
            clockTolerance: TOKEN_RENEW_GRACE_SECONDS
        });
    } catch (err) {
        return res.status(401).json({ error: err.name === 'TokenExpiredError' ? 'Token expired beyond renewal window' : 'Invalid token' });
    }

    if (decoded.role !== 'viewer' || !decoded.channel || !channelManager.getByStreamKey(decoded.channel)) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    const renewed = signViewerToken(decoded.channel);
    setViewerCookie(res, decoded.channel, renewed);
    res.json({ token: renewed, expiresIn: TOKEN_EXPIRATION_SECONDS });
});

// Internal Nginx auth_request endpoint. 200 = allow, 401 = missing/invalid/expired, 403 = channel mismatch
function handleEdgeAuth(req, res) {
    if (!ENABLE_AUTH_ON_PLAYLISTS) {
        return res.status(200).send('OK');
    }

    const originalUri = req.headers['x-original-uri'] || '';
    // Precedence: Authorization header, then ?token= from the original URI, then the stream_auth cookie
    const token = bearerToken(req) || tokenFromOriginalUri(originalUri) || cookieToken(req);
    if (!token) {
        return res.status(401).set('WWW-Authenticate', 'Bearer error="token_missing"').send('Unauthorized: Token missing');
    }

    let decoded;
    try {
        decoded = jwt.verify(token, VIEWER_JWT_SECRET, { algorithms: JWT_ALGORITHMS });
    } catch (err) {
        const reason = err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
        return res.status(401).set('WWW-Authenticate', `Bearer error="${err.name}"`).send(`Unauthorized: ${reason}`);
    }

    const requestedChannel = extractChannelFromUri(originalUri);
    if (decoded.role !== 'viewer' || !requestedChannel || typeof decoded.channel !== 'string' ||
        decoded.channel.toLowerCase() !== requestedChannel) {
        return res.status(403).send('Forbidden: Token not valid for requested channel');
    }

    return res.status(200).send('OK');
}
app.get('/auth', handleEdgeAuth);
app.head('/auth', handleEdgeAuth);

// ------------------------------------------------------------------------------
// MediaMTX HTTP auth hook (authMethod: http). Reachable only on the docker network;
// nginx does not proxy /internal/.
// ------------------------------------------------------------------------------
const LOOPBACK_IPS = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

app.post('/internal/mediamtx-auth', (req, res) => {
    const { action, path: mtxPath, ip, password } = req.body || {};

    // Only the packaging FFmpeg running inside the MediaMTX container may read streams
    if (action === 'read') {
        return LOOPBACK_IPS.has(ip) ? res.sendStatus(200) : res.sendStatus(403);
    }

    if (action === 'publish') {
        const match = /^live\/([a-z0-9_-]+)$/.exec(String(mtxPath || ''));
        const channel = match && channelManager.getByStreamKey(match[1]);
        if (channel && password && safeEqual(password, channel.publishKey)) {
            return res.sendStatus(200);
        }
        console.warn(`[MEDIAMTX-AUTH] Rejected publish to '${mtxPath}' from ${ip}`);
        return res.sendStatus(401);
    }

    // playback, api, metrics, pprof: not used by this stack
    return res.sendStatus(403);
});

// ------------------------------------------------------------------------------
// Process Termination Handling
// ------------------------------------------------------------------------------
let shuttingDown = false;
async function gracefulShutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[SYSTEM] ${signal} received. Gracefully shutting down...`);
    r2Pipeline.stop();
    // Desired states stay 'running' so restreams resume when the backend starts again.
    // Each process gets SIGINT, then SIGKILL after 5s (inside docker stop's 10s grace period).
    await restreamManager.shutdownAll();
    process.exit(0);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ------------------------------------------------------------------------------
// Start Express HTTP Server
// ------------------------------------------------------------------------------
app.listen(PORT, '0.0.0.0', () => {
    console.log('==============================================================');
    console.log(`[BACKEND] Live Streaming Control Panel & Restreamer Running`);
    console.log(`[BACKEND] Port: ${PORT} | Mode: ${NODE_ENV}`);
    console.log(`[BACKEND] Server IP: ${SERVER_IP} | Edge Domain: ${EDGE_DOMAIN}`);
    console.log(`[BACKEND] R2 Custom Domain: ${R2_CUSTOM_DOMAIN}`);
    console.log(`[BACKEND] Restream profile: ${RESTREAM_PROFILE}${RESTREAM_PROFILE === '480p' ? ` (libx264 ${RESTREAM_X264_PRESET}, ${RESTREAM_VIDEO_KBPS}k video, 128k AAC)` : ''}`);
    console.log(`[BACKEND] Admin Dashboard: http://localhost:${PORT}/admin`);
    console.log('==============================================================');

    // Resume restreams whose persisted desired state is 'running'
    restreamManager.resumeAll();
});
