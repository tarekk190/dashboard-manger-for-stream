/**
 * Cloudflare R2 Zero-Egress Uploader & Stream Garbage Collector
 * 
 * Watches /hls directory for generated playlists and segments:
 * 1. Renames .m3u8 -> .css and camouflages internal file references before uploading.
 * 2. Renames .ts -> .js and uploads with immutable caching headers.
 * 3. Periodically purges segments older than 2 minutes to prevent local and bucket bloat.
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const chokidar = require('chokidar');

// Environment Configuration
const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID || '';
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID || '';
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY || '';
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME || 'live-streams';
const R2_ENDPOINT = process.env.R2_ENDPOINT || (R2_ACCOUNT_ID ? `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com` : '');
const HLS_DIR = path.resolve(process.env.HLS_DIR || '/hls');
const MAX_SEGMENT_AGE_SECONDS = parseInt(process.env.MAX_SEGMENT_AGE_SECONDS || '120', 10);
const PURGE_INTERVAL_MS = 30000;

console.log('====================================================');
console.log('[R2-UPLOADER] Starting Zero-Egress Cloudflare R2 Pipeline');
console.log(`[R2-UPLOADER] Watching Directory: ${HLS_DIR}`);
console.log(`[R2-UPLOADER] Bucket: ${R2_BUCKET_NAME}`);
console.log(`[R2-UPLOADER] Max Segment Age: ${MAX_SEGMENT_AGE_SECONDS}s`);
console.log('====================================================');

// Initialize S3 / R2 Client
let s3Client = null;
if (R2_ENDPOINT && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY) {
    s3Client = new S3Client({
        region: 'auto',
        endpoint: R2_ENDPOINT,
        credentials: {
            accessKeyId: R2_ACCESS_KEY_ID,
            secretAccessKey: R2_SECRET_ACCESS_KEY
        }
    });
    console.log('[R2-UPLOADER] S3 Client connected to Cloudflare R2');
} else {
    console.warn('[R2-UPLOADER] WARNING: Cloudflare R2 credentials not fully set. Running in DRY-RUN / local purge mode');
}

/**
 * Upload a buffer or stream to Cloudflare R2 with specific content type and caching
 */
async function uploadToR2(r2Key, fileBuffer, contentType, cacheControl) {
    if (!s3Client) {
        console.log(`[DRY-RUN] Would upload -> ${r2Key} (${contentType}, ${cacheControl}) [${fileBuffer.length} bytes]`);
        return;
    }

    try {
        const command = new PutObjectCommand({
            Bucket: R2_BUCKET_NAME,
            Key: r2Key,
            Body: fileBuffer,
            ContentType: contentType,
            CacheControl: cacheControl
        });

        await s3Client.send(command);
        console.log(`[R2-UPLOAD] Success: ${r2Key} [${contentType}]`);
    } catch (err) {
        console.error(`[R2-UPLOAD-ERROR] Failed to upload ${r2Key}:`, err.message);
    }
}

/**
 * Delete an object from Cloudflare R2
 */
async function deleteFromR2(r2Key) {
    if (!s3Client) return;

    try {
        const command = new DeleteObjectCommand({
            Bucket: R2_BUCKET_NAME,
            Key: r2Key
        });
        await s3Client.send(command);
        console.log(`[R2-PURGE] Deleted from R2: ${r2Key}`);
    } catch (err) {
        console.error(`[R2-PURGE-ERROR] Failed to delete ${r2Key}:`, err.message);
    }
}

/**
 * Handle new or modified playlist file (.m3u8)
 */
async function handlePlaylist(filePath) {
    try {
        const relativePath = path.relative(HLS_DIR, filePath).replace(/\\/g, '/');
        // Rename key to .css
        const r2Key = relativePath.replace(/\.m3u8$/i, '.css');

        let content = fs.readFileSync(filePath, 'utf8');

        // Camouflage all internal references inside the playlist
        const camouflagedContent = content
            .replace(/\.m3u8/g, '.css')
            .replace(/\.ts/g, '.js')
            .replace(/\.m4s/g, '.js')
            .replace(/\.mp4/g, '.js');

        const buffer = Buffer.from(camouflagedContent, 'utf8');

        await uploadToR2(
            r2Key,
            buffer,
            'text/css',
            'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0'
        );
    } catch (err) {
        console.error(`[HANDLER-ERROR] Error handling playlist ${filePath}:`, err.message);
    }
}

/**
 * Handle newly created media segment (.ts or .m4s)
 */
async function handleSegment(filePath) {
    // Wait 50ms for writer to finish flushing to disk
    await new Promise(res => setTimeout(res, 50));

    try {
        if (!fs.existsSync(filePath)) return;

        const relativePath = path.relative(HLS_DIR, filePath).replace(/\\/g, '/');
        // Rename key to .js
        const r2Key = relativePath.replace(/\.(ts|m4s)$/i, '.js');

        const fileBuffer = fs.readFileSync(filePath);

        // Immutable long-term cache for immutable media segments
        await uploadToR2(
            r2Key,
            fileBuffer,
            'application/javascript',
            'public, max-age=31536000, immutable'
        );
    } catch (err) {
        console.error(`[HANDLER-ERROR] Error handling segment ${filePath}:`, err.message);
    }
}

/**
 * Garbage Collector: purge old segments from disk and R2
 */
function runGarbageCollector() {
    console.log('[GARBAGE-COLLECTOR] Scanning for segments older than', MAX_SEGMENT_AGE_SECONDS, 'seconds...');

    function scanDir(dir) {
        if (!fs.existsSync(dir)) return;

        const entries = fs.readdirSync(dir, { withFileTypes: true });
        const now = Date.now();

        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);

            if (entry.isDirectory()) {
                scanDir(fullPath);
            } else if (entry.isFile()) {
                const ext = path.extname(entry.name).toLowerCase();
                if (ext === '.ts' || ext === '.m4s') {
                    try {
                        const stats = fs.statSync(fullPath);
                        const ageSeconds = (now - stats.mtimeMs) / 1000;

                        if (ageSeconds > MAX_SEGMENT_AGE_SECONDS) {
                            console.log(`[PURGE] Deleting expired segment: ${entry.name} (${ageSeconds.toFixed(0)}s old)`);
                            fs.unlinkSync(fullPath);

                            // Also delete obfuscated segment from R2
                            const relativePath = path.relative(HLS_DIR, fullPath).replace(/\\/g, '/');
                            const r2Key = relativePath.replace(/\.(ts|m4s)$/i, '.js');
                            deleteFromR2(r2Key);
                        }
                    } catch (e) {
                        // File may have been removed already
                    }
                }
            }
        }
    }

    try {
        scanDir(HLS_DIR);
    } catch (err) {
        console.error('[GARBAGE-COLLECTOR-ERROR]', err.message);
    }
}

// Ensure HLS dir exists
if (!fs.existsSync(HLS_DIR)) {
    fs.mkdirSync(HLS_DIR, { recursive: true });
}

// Initialize File Watcher
const watcher = chokidar.watch(HLS_DIR, {
    ignored: /(^|[\/\\])\../, // ignore dotfiles
    persistent: true,
    ignoreInitial: false,
    awaitWriteFinish: {
        stabilityThreshold: 100,
        pollInterval: 50
    }
});

watcher
    .on('add', filePath => {
        const ext = path.extname(filePath).toLowerCase();
        if (ext === '.m3u8') {
            handlePlaylist(filePath);
        } else if (ext === '.ts' || ext === '.m4s') {
            handleSegment(filePath);
        }
    })
    .on('change', filePath => {
        const ext = path.extname(filePath).toLowerCase();
        if (ext === '.m3u8') {
            handlePlaylist(filePath);
        }
    })
    .on('error', error => console.error('[WATCHER-ERROR]', error));

// Run periodic garbage collection
setInterval(runGarbageCollector, PURGE_INTERVAL_MS);
runGarbageCollector();
