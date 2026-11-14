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
const PORT = parseInt(process.env.PORT || '3000', 10);
const NODE_ENV = process.env.NODE_ENV || 'production';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123456';
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_default_jwt_secret_must_be_overridden_in_production_32chars';
const SERVER_IP = process.env.SERVER_IP || '127.0.0.1';
const EDGE_DOMAIN = process.env.EDGE_DOMAIN || 'localhost';
const R2_CUSTOM_DOMAIN = process.env.R2_CUSTOM_DOMAIN || 'r2-custom-domain.shop';
const MEDIAMTX_RTMP_HOST = process.env.MEDIAMTX_RTMP_HOST || 'mediamtx';
const MEDIAMTX_RTMP_PORT = parseInt(process.env.MEDIAMTX_RTMP_PORT || '1935', 10);
const HLS_DIR = path.resolve(process.env.HLS_DIR || '/hls');
const DATA_FILE = path.resolve(process.env.DATA_FILE || path.join(__dirname, 'data', 'channels.json'));
const MAX_SEGMENT_AGE_SECONDS = parseInt(process.env.MAX_SEGMENT_AGE_SECONDS || '120', 10);
const ENABLE_AUTH_ON_PLAYLISTS = process.env.ENABLE_AUTH_ON_PLAYLISTS === 'true';
const TOKEN_EXPIRATION_SECONDS = parseInt(process.env.TOKEN_EXPIRATION_SECONDS || '60', 10);

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
            } else {
                // Initialize default demo channel
                const defaultChannel = {
                    id: 'ch_match1',
                    name: 'Match 1 Primary Feed',
                    streamKey: 'match1',
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

        const rtmpTarget = `rtmp://${MEDIAMTX_RTMP_HOST}:${MEDIAMTX_RTMP_PORT}/live/${channel.streamKey}`;
        console.log(`[RESTREAMER] Starting FFmpeg restream: ${channel.name} (${sourceUrl} -> ${rtmpTarget})`);

        // FFmpeg command arguments:
        // - High resilience network flags (-reconnect, etc.)
        // - Realtime stream throttling (-re)
        // - Copy video codec (-c:v copy) to save CPU
        // - Normalize audio to AAC (-c:a aac) for FLV RTMP container compatibility
        const args = [
            '-nostdin',
            '-hide_banner',
            '-loglevel', 'info',
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
        job.logs.push(`[${timestamp}] ${message}`);
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

// Security Middlewares
app.use(helmet({ 
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false 
}));
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type', 'Range', 'Origin', 'Referer']
}));
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
        JWT_SECRET,
        { expiresIn: '7d' }
    );
}

function verifyAdminAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, error: 'Unauthorized: Missing or malformed token' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
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
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, error: 'Username and password are required' });
    }

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        const token = generateAdminToken(username);
        return res.json({
            success: true,
            token,
            user: { username, role: 'admin' }
        });
    }

    return res.status(401).json({ success: false, error: 'Invalid admin credentials' });
});

// Verify Current Admin Token
app.get('/api/admin/verify', verifyAdminAuth, (req, res) => {
    res.json({ success: true, user: req.admin });
});

// List All Channels with Dynamic Restream Status
app.get('/api/channels', verifyAdminAuth, (req, res) => {
    const channels = channelManager.getAll();
    const enriched = channels.map(channel => {
        const restreamStatus = restreamManager.getStatus(channel.id);
        return {
            ...channel,
            restream: restreamStatus,
            links: {
                obsRtmpUrl: `rtmp://${SERVER_IP}:${MEDIAMTX_RTMP_PORT}/live`,
                obsStreamKey: channel.streamKey,
                edgeCamouflagedUrl: `https://${EDGE_DOMAIN}/live/${channel.streamKey}/index.css`,
                r2DirectHtmlUrl: `https://${R2_CUSTOM_DOMAIN}/hd/${channel.r2_slug}/index.html`,
                r2DirectCssUrl: `https://${R2_CUSTOM_DOMAIN}/hd/${channel.r2_slug}/index.css`,
                iframeEmbedUrl: `https://${EDGE_DOMAIN}/player/?channel=${channel.streamKey}`,
                iframeR2EmbedUrl: `https://${EDGE_DOMAIN}/player/?r2=${channel.r2_slug}`
            }
        };
    });

    res.json({ success: true, channels: enriched });
});

// Create New Channel
app.post('/api/channels', verifyAdminAuth, (req, res) => {
    try {
        const { name, streamKey, r2_slug, sourceUrl } = req.body;
        if (!name && !streamKey) {
            return res.status(400).json({ success: false, error: 'Channel name or stream key is required' });
        }

        const channel = channelManager.create({ name, streamKey, r2_slug, sourceUrl });
        const restreamStatus = restreamManager.getStatus(channel.id);

        res.status(201).json({
            success: true,
            channel: {
                ...channel,
                restream: restreamStatus,
                links: {
                    obsRtmpUrl: `rtmp://${SERVER_IP}:${MEDIAMTX_RTMP_PORT}/live`,
                    obsStreamKey: channel.streamKey,
                    edgeCamouflagedUrl: `https://${EDGE_DOMAIN}/live/${channel.streamKey}/index.css`,
                    r2DirectHtmlUrl: `https://${R2_CUSTOM_DOMAIN}/hd/${channel.r2_slug}/index.html`,
                    r2DirectCssUrl: `https://${R2_CUSTOM_DOMAIN}/hd/${channel.r2_slug}/index.css`,
                    iframeEmbedUrl: `https://${EDGE_DOMAIN}/player/?channel=${channel.streamKey}`
                }
            }
        });
    } catch (err) {
        res.status(400).json({ success: false, error: err.message });
    }
});

// Update Channel
app.put('/api/channels/:id', verifyAdminAuth, (req, res) => {
    const { id } = req.params;
    const { name, sourceUrl, r2_slug } = req.body;

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
app.post('/api/channels/:id/restream/start', verifyAdminAuth, (req, res) => {
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

        const status = restreamManager.start(id, effectiveUrl);
        res.json({ success: true, status });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// Pull Restreaming: Stop
app.post('/api/channels/:id/restream/stop', verifyAdminAuth, (req, res) => {
    const { id } = req.params;
    const stopped = restreamManager.stop(id);
    res.json({ success: true, status: restreamManager.getStatus(id) });
});

// Pull Restreaming: Restart
app.post('/api/channels/:id/restream/restart', verifyAdminAuth, (req, res) => {
    const { id } = req.params;
    try {
        const status = restreamManager.restart(id);
        res.json({ success: true, status });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
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

// Generate dynamic viewer token for Edge CDN playback
app.get('/api/stream', (req, res) => {
    const { channel } = req.query;
    if (!channel) {
        return res.status(400).json({ error: 'channel query parameter is required' });
    }

    const payload = {
        sub: crypto.randomBytes(8).toString('hex'),
        channel: channel.trim(),
        iat: Math.floor(Date.now() / 1000)
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION_SECONDS });
    const edgeUrl = `https://${EDGE_DOMAIN}/live/${channel}/index.css?token=${token}`;

    res.json({
        channel,
        token,
        expiresIn: TOKEN_EXPIRATION_SECONDS,
        streamUrl: edgeUrl
    });
});

// Token Renewal
app.post('/api/token', (req, res) => {
    const { token } = req.body;
    if (!token) {
        return res.status(400).json({ error: 'Token is required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET, { ignoreExpiration: true });
        const newToken = jwt.sign(
            { sub: decoded.sub, channel: decoded.channel },
            JWT_SECRET,
            { expiresIn: TOKEN_EXPIRATION_SECONDS }
        );
        res.json({ token: newToken, expiresIn: TOKEN_EXPIRATION_SECONDS });
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// Internal Nginx Auth Subrequest Endpoint
app.get('/auth', (req, res) => {
    // If strict authentication on playlists is disabled, always allow
    if (!ENABLE_AUTH_ON_PLAYLISTS) {
        return res.status(200).send('OK');
    }

    // Check token from query ?token= or Authorization header
    const token = req.query.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
    if (!token) {
        return res.status(401).send('Unauthorized: Token missing');
    }

    try {
        jwt.verify(token, JWT_SECRET);
        return res.status(200).send('OK');
    } catch (err) {
        return res.status(403).send('Forbidden: Token invalid or expired');
    }
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
