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
        try {
            const list = Array.from(this.channels.values());
            fs.writeFileSync(this.filePath, JSON.stringify(list, null, 2), 'utf8');
        } catch (err) {
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
// FFmpeg Process & Restream Manager
// ------------------------------------------------------------------------------
class FFmpegRestreamManager {
    constructor() {
        // Map of channelId -> RestreamJob
        this.jobs = new Map();
    }

    start(channelId, sourceUrl) {
        const channel = channelManager.getById(channelId);
        if (!channel) throw new Error('Channel not found');
        if (!sourceUrl || !sourceUrl.trim()) throw new Error('Source URL is required for pull restreaming');

        // Stop existing restream process if running
        this.stop(channelId);

        // Publish with the channel's secret key; MediaMTX validates it via POST /internal/mediamtx-auth
        const rtmpTarget = `rtmp://${MEDIAMTX_RTMP_HOST}:${MEDIAMTX_RTMP_PORT}/live/${channel.streamKey}` +
            `?user=publish&pass=${channel.publishKey}`;
        console.log(`[RESTREAMER] Starting FFmpeg restream: ${channel.name} (${sourceUrl} -> live/${channel.streamKey})`);

        // FFmpeg command arguments:
        // - High resilience network flags (-reconnect, etc.)
        // - Realtime stream throttling (-re)
        // - Copy video codec (-c:v copy) to save CPU
        // - Normalize audio to AAC (-c:a aac) for FLV RTMP container compatibility
        const args = [
            '-nostdin',
            '-hide_banner',
            '-loglevel', 'info',
            '-protocol_whitelist', FFMPEG_PROTOCOL_WHITELIST,
            '-reconnect', '1',
            '-reconnect_at_eof', '1',
            '-reconnect_streamed', '1',
            '-reconnect_delay_max', '2',
            '-re',
            '-i', sourceUrl.trim(),
            '-c:v', 'copy',
            '-c:a', 'aac',
            '-b:a', '128k',
            '-ar', '44100',
            '-f', 'flv',
            rtmpTarget
        ];

        const job = {
            channelId,
            streamKey: channel.streamKey,
            sourceUrl: sourceUrl.trim(),
            status: 'running',
            pid: null,
            startedAt: new Date().toISOString(),
            metrics: {
                fps: 0,
                bitrate: '0kbits/s',
                speed: '0x',
                frame: 0,
                time: '00:00:00.00',
                lastUpdate: Date.now()
            },
            logs: [],
            process: null
        };

        const proc = spawn('ffmpeg', args, { stdio: ['ignore', 'pipe', 'pipe'] });
        job.process = proc;
        job.pid = proc.pid;

        this.appendLog(job, `[SYSTEM] Spawned FFmpeg process PID ${proc.pid}`);
        this.appendLog(job, `[COMMAND] ffmpeg ${args.join(' ')}`);

        // Process stderr output for status & telemetry
        proc.stderr.on('data', (chunk) => {
            const text = chunk.toString();
            this.handleOutput(job, text);
        });

        proc.stdout.on('data', (chunk) => {
            const text = chunk.toString();
            this.appendLog(job, text.trim());
        });

        proc.on('error', (err) => {
            job.status = 'error';
            this.appendLog(job, `[ERROR] Process error: ${err.message}`);
            console.error(`[RESTREAMER-ERROR] Channel ${channel.streamKey}:`, err.message);
        });

        proc.on('close', (code, signal) => {
            job.status = 'stopped';
            this.appendLog(job, `[SYSTEM] Process exited with code ${code}, signal ${signal}`);
            console.log(`[RESTREAMER] Channel ${channel.streamKey} restream exited (${code})`);
        });

        this.jobs.set(channelId, job);

        // Update channel sourceUrl in storage
        channelManager.update(channelId, { sourceUrl: sourceUrl.trim() });

        return this.getStatus(channelId);
    }

    stop(channelId) {
        const job = this.jobs.get(channelId);
        if (!job) return false;

        if (job.process && !job.process.killed) {
            try {
                this.appendLog(job, '[SYSTEM] Stopping restream process...');
                job.process.kill('SIGINT');
                setTimeout(() => {
                    if (job.process && !job.process.killed) {
                        job.process.kill('SIGKILL');
                    }
                }, 2000);
            } catch (err) {
                console.error('[RESTREAMER-STOP-ERROR]', err.message);
            }
        }

        job.status = 'stopped';
        return true;
    }

    restart(channelId) {
        const job = this.jobs.get(channelId);
        const sourceUrl = job ? job.sourceUrl : (channelManager.getById(channelId)?.sourceUrl || '');
        if (!sourceUrl) {
            throw new Error('No source URL available to restart restream.');
        }
        return this.start(channelId, sourceUrl);
    }

    getStatus(channelId) {
        const job = this.jobs.get(channelId);
        if (!job) {
            return {
                channelId,
                status: 'idle',
                pid: null,
                metrics: { fps: 0, bitrate: '0kbits/s', speed: '0x', time: '00:00:00' },
                sourceUrl: channelManager.getById(channelId)?.sourceUrl || ''
            };
        }

        return {
            channelId: job.channelId,
            status: job.status,
            pid: job.pid,
            startedAt: job.startedAt,
            metrics: job.metrics,
            sourceUrl: job.sourceUrl
        };
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
                if (frameMatch) job.metrics.frame = parseInt(frameMatch[1], 10);
                job.metrics.lastUpdate = Date.now();
                job.status = 'running';
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

    cleanupAll() {
        console.log('[RESTREAMER] Terminating all active FFmpeg restream processes...');
        for (const [id, job] of this.jobs.entries()) {
            if (job.process && !job.process.killed) {
                job.process.kill('SIGTERM');
            }
        }
    }
}

const restreamManager = new FFmpegRestreamManager();

// ------------------------------------------------------------------------------
// Real-Time Cloudflare R2 Watcher & Uploader
// ------------------------------------------------------------------------------
class R2PipelineManager {
    constructor() {
        this.watcher = null;
        this.pruneInterval = null;
        this.stats = {
            uploadedSegments: 0,
            uploadedPlaylists: 0,
            deletedSegments: 0,
            lastPruneTime: null
        };
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
        this.watcher.on('error', (err) => console.error('[R2-WATCHER-ERROR]', err));

        // Start pruning loop for R2 bucket
        this.pruneInterval = setInterval(() => this.pruneOldSegments(), 20000);
    }

    async processFile(filePath) {
        const ext = path.extname(filePath).toLowerCase();
        if (ext !== '.ts' && ext !== '.m3u8') return;

        // Extract stream path relative to HLS_DIR
        // e.g. /hls/live/match1/seg_00001.ts -> live/match1/seg_00001.ts
        const relativePath = path.relative(HLS_DIR, filePath).replace(/\\/g, '/');
        const parts = relativePath.split('/');

        // Expect structure: live/{streamKey}/{filename} or {streamKey}/{filename}
        let streamKey = '';
        let fileName = '';

        if (parts.length >= 3 && parts[0] === 'live') {
            streamKey = parts[1];
            fileName = parts.slice(2).join('/');
        } else if (parts.length >= 2) {
            streamKey = parts[0];
            fileName = parts.slice(1).join('/');
        } else {
            return;
        }

        // Map stream key to randomized R2 folder slug
        const channel = channelManager.getByStreamKey(streamKey);
        const folderSlug = channel ? channel.r2_slug : streamKey;
        const r2Prefix = `hd/${folderSlug}`;

        if (ext === '.ts') {
            await this.handleSegment(filePath, r2Prefix, fileName);
        } else if (ext === '.m3u8') {
            await this.handlePlaylist(filePath, r2Prefix, fileName);
        }
    }

    async handleSegment(filePath, r2Prefix, fileName) {
        try {
            if (!fs.existsSync(filePath)) return;
            const fileBuffer = fs.readFileSync(filePath);
            if (fileBuffer.length === 0) return;

            // Camouflage segment extension: seg_001.ts -> seg_001.js
            const camouflagedName = fileName.replace(/\.ts$/i, '.js');
            const r2Key = `${r2Prefix}/${camouflagedName}`;

            await this.uploadObject(
                r2Key, 
                fileBuffer, 
                'application/javascript', 
                'public, max-age=3600, immutable'
            );
            this.stats.uploadedSegments++;
        } catch (err) {
            console.error(`[R2-SEGMENT-ERROR] Failed to process ${filePath}:`, err.message);
        }
    }

    async handlePlaylist(filePath, r2Prefix, fileName) {
        try {
            if (!fs.existsSync(filePath)) return;
            const content = fs.readFileSync(filePath, 'utf8');
            if (!content || !content.includes('#EXTM3U')) return;

            // Rewrite manifest internal segment links: .ts -> .js
            const rewritten = content.replace(/([a-zA-Z0-9_\-]+)\.ts/g, '$1.js');
            const buffer = Buffer.from(rewritten, 'utf8');

            // 1. Upload as index.html (Direct browser and player friendly)
            await this.uploadObject(
                `${r2Prefix}/index.html`,
                buffer,
                'text/html; charset=utf-8',
                'no-store, no-cache, must-revalidate, max-age=0'
            );

            // 2. Upload as index.css (Camouflaged stylesheet delivery)
            await this.uploadObject(
                `${r2Prefix}/index.css`,
                buffer,
                'text/css; charset=utf-8',
                'no-store, no-cache, must-revalidate, max-age=0'
            );

            this.stats.uploadedPlaylists++;
        } catch (err) {
            console.error(`[R2-PLAYLIST-ERROR] Failed to rewrite playlist ${filePath}:`, err.message);
        }
    }

    async uploadObject(r2Key, body, contentType, cacheControl) {
        if (!s3Client) {
            // DRY-RUN mode
            return;
        }

        try {
            const command = new PutObjectCommand({
                Bucket: R2_BUCKET_NAME,
                Key: r2Key,
                Body: body,
                ContentType: contentType,
                CacheControl: cacheControl
            });
            await s3Client.send(command);
        } catch (err) {
            console.error(`[R2-UPLOAD-FAIL] Failed to upload ${r2Key}:`, err.message);
        }
    }

    async pruneOldSegments() {
        if (!s3Client) return;

        try {
            const listCommand = new ListObjectsV2Command({
                Bucket: R2_BUCKET_NAME,
                Prefix: 'hd/'
            });

            const listResponse = await s3Client.send(listCommand);
            if (!listResponse.Contents || listResponse.Contents.length === 0) return;

            const now = Date.now();
            const maxAgeMs = MAX_SEGMENT_AGE_SECONDS * 1000;
            const toDelete = [];

            for (const item of listResponse.Contents) {
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

            if (toDelete.length > 0) {
                // Batch delete in chunks of 500
                const batch = toDelete.slice(0, 500);
                const deleteCommand = new DeleteObjectsCommand({
                    Bucket: R2_BUCKET_NAME,
                    Delete: { Objects: batch }
                });

                await s3Client.send(deleteCommand);
                this.stats.deletedSegments += batch.length;
                this.stats.lastPruneTime = new Date().toISOString();
                console.log(`[R2-PRUNE] Cleaned ${batch.length} expired segment(s) from R2 bucket.`);
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
// Express App & Routing Setup
// ------------------------------------------------------------------------------
const app = express();

// Nginx is the single trusted hop in front of the backend; req.ip = the client address nginx saw.
app.set('trust proxy', 1);

// Security Middlewares
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
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
    maxAge: 86400
});
app.use(['/api/stream', '/api/token'], viewerCors);

// Reject cross-origin browser requests to admin endpoints.
function sameOriginOnly(req, res, next) {
    const origin = req.headers.origin;
    if (!origin) return next();
    try {
        if (new URL(origin).host.toLowerCase() === String(req.headers.host || '').toLowerCase()) return next();
    } catch { /* fall through */ }
    return res.status(403).json({ success: false, error: 'Forbidden: cross-origin admin request' });
}
app.use(['/api/admin', '/api/channels', '/api/stats', '/api/config'], sameOriginOnly);

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
app.delete('/api/channels/:id', verifyAdminAuth, (req, res) => {
    const { id } = req.params;
    restreamManager.stop(id);
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
        const status = restreamManager.start(id, validUrl);
        res.json({ success: true, status });
    } catch (err) {
        res.status(err.status || 500).json({ success: false, error: err.message });
    }
});

// Pull Restreaming: Stop
app.post('/api/channels/:id/restream/stop', verifyAdminAuth, (req, res) => {
    const { id } = req.params;
    const stopped = restreamManager.stop(id);
    res.json({ success: true, status: restreamManager.getStatus(id) });
});

// Pull Restreaming: Restart
app.post('/api/channels/:id/restream/restart', verifyAdminAuth, async (req, res) => {
    const { id } = req.params;
    try {
        const job = restreamManager.jobs.get(id);
        const sourceUrl = job ? job.sourceUrl : (channelManager.getById(id)?.sourceUrl || '');
        if (sourceUrl) await validateSourceUrl(sourceUrl);
        const status = restreamManager.restart(id);
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

    res.json({ token: signViewerToken(decoded.channel), expiresIn: TOKEN_EXPIRATION_SECONDS });
});

// Internal Nginx auth_request endpoint. 200 = allow, 401 = missing/invalid/expired, 403 = channel mismatch
function handleEdgeAuth(req, res) {
    if (!ENABLE_AUTH_ON_PLAYLISTS) {
        return res.status(200).send('OK');
    }

    const originalUri = req.headers['x-original-uri'] || '';
    const token = bearerToken(req) || tokenFromOriginalUri(originalUri);
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
process.on('SIGTERM', () => {
    console.log('[SYSTEM] SIGTERM received. Gracefully shutting down...');
    r2Pipeline.stop();
    restreamManager.cleanupAll();
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('[SYSTEM] SIGINT received. Gracefully shutting down...');
    r2Pipeline.stop();
    restreamManager.cleanupAll();
    process.exit(0);
});

// ------------------------------------------------------------------------------
// Start Express HTTP Server
// ------------------------------------------------------------------------------
app.listen(PORT, '0.0.0.0', () => {
    console.log('==============================================================');
    console.log(`[BACKEND] Live Streaming Control Panel & Restreamer Running`);
    console.log(`[BACKEND] Port: ${PORT} | Mode: ${NODE_ENV}`);
    console.log(`[BACKEND] Server IP: ${SERVER_IP} | Edge Domain: ${EDGE_DOMAIN}`);
    console.log(`[BACKEND] R2 Custom Domain: ${R2_CUSTOM_DOMAIN}`);
    console.log(`[BACKEND] Admin Dashboard: http://localhost:${PORT}/admin`);
    console.log('==============================================================');
});
