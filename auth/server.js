/**
 * Dynamic Streaming Authentication Microservice
 * Architecture: High-Scale Live Sports Platform Auth & Stream Routing
 * 
 * Endpoints:
 * - GET  /api/stream : Generates initial short-lived JWT and camouflaged stream URL
 * - POST /api/token  : Seamlessly auto-renews viewer tokens before expiration
 * - GET  /auth       : Internal Nginx auth_request subrequest handler
 * - GET  /health     : Container health and readiness probe
 */

require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// 1. Strict JWT Secret Validation (Minimum 32 characters, no fallback default)
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.trim().length < 32) {
    console.error('[FATAL] JWT_SECRET is missing or shorter than 32 characters. Refusing to start.');
    process.exit(1);
}

// 2. Strict ALLOWED_ORIGINS Validation (No wildcard in production)
const rawAllowedOrigins = process.env.ALLOWED_ORIGINS;
if (!rawAllowedOrigins || rawAllowedOrigins.trim() === '') {
    console.error('[FATAL] ALLOWED_ORIGINS environment variable is required.');
    process.exit(1);
}

const ALLOWED_ORIGINS = rawAllowedOrigins.split(',').map(s => s.trim()).filter(Boolean);
if (NODE_ENV === 'production' && ALLOWED_ORIGINS.includes('*')) {
    console.error('[FATAL] Wildcard ALLOWED_ORIGINS="*" is forbidden when NODE_ENV=production. Specify explicit allowed origins.');
    process.exit(1);
}

const TOKEN_EXPIRATION_SECONDS = parseInt(process.env.TOKEN_EXPIRATION_SECONDS || '60', 10);
const TOKEN_RENEW_GRACE_SECONDS = parseInt(process.env.TOKEN_RENEW_GRACE_SECONDS || '15', 10);

// Middlewares
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (ALLOWED_ORIGINS.includes('*')) return callback(null, true);
        try {
            const reqOrigin = new URL(origin).origin.toLowerCase();
            const isAllowed = ALLOWED_ORIGINS.some(allowed => {
                try {
                    return new URL(allowed).origin.toLowerCase() === reqOrigin;
                } catch {
                    return allowed === reqOrigin;
                }
            });
            if (isAllowed) return callback(null, true);
        } catch {
            if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        }
        callback(new Error('CORS origin rejected by streaming policy'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'HEAD', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type', 'Origin', 'Referer']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Metrics counters
const metrics = {
    totalStreamRequests: 0,
    totalTokenRefreshes: 0,
    authValidationsPassed: 0,
    authValidationsFailed: 0,
    startedAt: new Date().toISOString()
};

/**
 * Sanitize channel identifier to prevent directory traversal
 */
function sanitizeChannel(channel) {
    if (!channel || typeof channel !== 'string') return 'test';
    let sanitized = channel.trim().replace(/^\/+|\/+$/g, '').replace(/[^a-zA-Z0-9_\-\/]/g, '');
    return sanitized || 'test';
}

/**
 * Generate a cryptographically signed viewer JWT token
 */
function generateViewerToken(channel, clientIp = 'unknown') {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        jti: crypto.randomUUID(),
        sub: crypto.createHash('sha256').update(clientIp + channel + Date.now()).digest('hex').substring(0, 16),
        channel: channel,
        role: 'viewer',
        iat: now,
        exp: now + TOKEN_EXPIRATION_SECONDS
    };

    return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
}

/**
 * Extract token from Authorization header, query string, or X-Original-URI
 */
function extractToken(req) {
    // 1. Bearer token in Authorization header
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        return authHeader.substring(7).trim();
    }

    // 2. Query param ?token=...
    if (req.query && req.query.token) {
        return req.query.token;
    }

    // 3. Extract from Nginx X-Original-URI header if passed as subrequest
    const originalUri = req.headers['x-original-uri'];
    if (originalUri && originalUri.includes('?')) {
        try {
            const urlObj = new URL(originalUri, 'http://localhost');
            const tokenParam = urlObj.searchParams.get('token');
            if (tokenParam) return tokenParam;
        } catch (e) {
            // Ignore parse errors
        }
    }

    return null;
}

/**
 * Extract target channel name from request URI
 * Example: /live/test/master.css -> test
 */
function extractChannelFromUri(uri) {
    if (!uri) return null;
    const cleanUri = uri.split('?')[0];
    const match = cleanUri.match(/^\/(?:live|hls)\/([^\/]+)/);
    return match ? match[1] : null;
}

// =============================================================================
// 1. GET /api/stream
// Returns camouflaged .css stream URL and initial short-lived JWT token
// =============================================================================
app.get('/api/stream', (req, res) => {
    metrics.totalStreamRequests++;

    const rawChannel = req.query.channel || 'test';
    const channel = sanitizeChannel(rawChannel);
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';

    const token = generateViewerToken(channel, clientIp);
    const refreshIntervalMs = Math.max(10, TOKEN_EXPIRATION_SECONDS - 15) * 1000;

    return res.json({
        status: 'success',
        channel: channel,
        streamUrl: `/live/${channel}/master.css`,
        fallbackUrl: `/live/${channel}/index.css`,
        token: token,
        tokenType: 'Bearer',
        expiresIn: TOKEN_EXPIRATION_SECONDS,
        refreshIntervalMs: refreshIntervalMs,
        meta: {
            obfuscated: true,
            format: 'hls-camouflaged',
            playerHint: 'Attach Authorization: Bearer <token> to .css and .js requests'
        }
    });
});

// =============================================================================
// 2. POST & GET /api/token
// Auto-renews tokens for active viewers without interrupting video playback
// =============================================================================
const handleTokenRefresh = (req, res) => {
    metrics.totalTokenRefreshes++;

    const token = extractToken(req) || (req.body && req.body.token);
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';

    if (!token) {
        return res.status(400).json({
            status: 'error',
            code: 'TOKEN_REQUIRED',
            message: 'A valid active or recently expired token is required for renewal'
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET, {
            algorithms: ['HS256'],
            clockTolerance: TOKEN_RENEW_GRACE_SECONDS
        });

        const newToken = generateViewerToken(decoded.channel, clientIp);
        const refreshIntervalMs = Math.max(10, TOKEN_EXPIRATION_SECONDS - 15) * 1000;

        return res.json({
            status: 'success',
            channel: decoded.channel,
            token: newToken,
            tokenType: 'Bearer',
            expiresIn: TOKEN_EXPIRATION_SECONDS,
            refreshIntervalMs: refreshIntervalMs
        });
    } catch (err) {
        return res.status(401).json({
            status: 'error',
            code: 'TOKEN_INVALID_OR_EXPIRED',
            message: 'Token verification failed: ' + err.message
        });
    }
};

app.post('/api/token', handleTokenRefresh);
app.get('/api/token', handleTokenRefresh);

// =============================================================================
// 3. GET & HEAD /auth
// Internal verification subrequest invoked by Nginx auth_request /auth
// Verifies JWT token validity, expiration, strict channel authorization, and Origin/Referer
// =============================================================================
const handleAuthValidation = (req, res) => {
    const originalUri = req.headers['x-original-uri'] || '';
    const origin = req.headers['origin'];
    const referer = req.headers['referer'];
    const token = extractToken(req);

    // 1. Verify Origin or Referer if present (direct media segment requests may omit Origin)
    if (origin || referer) {
        if (!ALLOWED_ORIGINS.includes('*')) {
            const source = origin || referer;
            let isAllowed = false;
            try {
                const sourceOrigin = new URL(source).origin.toLowerCase();
                isAllowed = ALLOWED_ORIGINS.some(allowed => {
                    try {
                        return new URL(allowed).origin.toLowerCase() === sourceOrigin;
                    } catch {
                        return allowed.toLowerCase() === sourceOrigin;
                    }
                });
            } catch {
                isAllowed = ALLOWED_ORIGINS.some(allowed => source.startsWith(allowed));
            }

            if (!isAllowed) {
                metrics.authValidationsFailed++;
                return res.status(403).set({
                    'X-Auth-Reason': 'Forbidden Origin or Referer',
                    'Content-Type': 'text/plain'
                }).send('Forbidden Origin or Referer');
            }
        }
    }

    // 2. Token presence check
    if (!token) {
        metrics.authValidationsFailed++;
        return res.status(401).set({
            'WWW-Authenticate': 'Bearer error="token_missing"',
            'X-Auth-Reason': 'Token missing',
            'Content-Type': 'text/plain'
        }).send('Unauthorized: Token Missing');
    }

    // 3. Cryptographic JWT signature and expiration verification
    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

        // 4. Channel Access Control: Verify channel binding with strict equality
        const requestedChannel = extractChannelFromUri(originalUri);
        if (requestedChannel && decoded.channel) {
            const normalizedTokenChannel = sanitizeChannel(decoded.channel).toLowerCase();
            const normalizedReqChannel = sanitizeChannel(requestedChannel).toLowerCase();

            if (normalizedTokenChannel !== normalizedReqChannel) {
                metrics.authValidationsFailed++;
                return res.status(403).set({
                    'X-Auth-Reason': 'Channel token mismatch',
                    'Content-Type': 'text/plain'
                }).send('Forbidden: Token not valid for requested channel');
            }
        }

        // Token is valid
        metrics.authValidationsPassed++;
        return res.status(200).set({
            'X-Auth-User': decoded.sub || 'viewer',
            'X-Auth-Channel': decoded.channel || 'all',
            'Content-Type': 'text/plain'
        }).send('OK');

    } catch (err) {
        metrics.authValidationsFailed++;
        const reason = err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token signature';
        return res.status(401).set({
            'WWW-Authenticate': `Bearer error="${err.name}"`,
            'X-Auth-Reason': reason,
            'Content-Type': 'text/plain'
        }).send(`Unauthorized: ${reason}`);
    }
};

app.get('/auth', handleAuthValidation);
app.head('/auth', handleAuthValidation);

// =============================================================================
// Observability & Health Probes
// =============================================================================
app.get('/health', (req, res) => {
    return res.json({
        status: 'healthy',
        uptimeSeconds: Math.floor(process.uptime()),
        timestamp: new Date().toISOString()
    });
});

app.get('/api/stats', (req, res) => {
    return res.json({
        status: 'success',
        metrics: metrics,
        system: {
            memory: process.memoryUsage(),
            nodeVersion: process.version
        }
    });
});

// Start listening
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[AUTH-SERVICE] Streaming Auth Microservice running on port ${PORT}`);
    console.log(`[AUTH-SERVICE] Token TTL: ${TOKEN_EXPIRATION_SECONDS}s | Grace Period: ${TOKEN_RENEW_GRACE_SECONDS}s`);
    console.log(`[AUTH-SERVICE] Allowed Origins: ${ALLOWED_ORIGINS.join(', ')}`);
});
