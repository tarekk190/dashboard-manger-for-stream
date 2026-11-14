# Enterprise Live Streaming Infrastructure & Admin Restreaming Dashboard

A complete, production-ready, Dockerized live video streaming infrastructure and administration control panel. Designed for high-scale sports and live event distribution supporting **two simultaneous delivery modes**:

1. **Direct Nginx + Cloudflare CDN Mode:** RTMP ingestion -> MediaMTX -> Real-time FFmpeg HLS packaging (`2s` segments, sliding window 6) -> Nginx masking `.m3u8` as `.css` and `.ts` as `.js` with `proxy_cache_lock` micro-caching.
2. **Cloudflare R2 Zero-Egress Mode (Storage + CDN):** Background Node.js watcher (`r2-uploader` inside backend) watches `/hls`, rewrites manifest segment links to `.js`, uploads manifests as `index.html` (and `index.css`) and segments as `.js` to Cloudflare R2 under randomized folder slugs (`/hd/{random_slug}/`), and automatically purges segments older than 120 seconds.

---

## 1. System Architecture & Workflow

```mermaid
flowchart TD
    subgraph Ingestion ["1. Broadcast Ingestion Layer"]
        OBS["OBS Studio Broadcaster\n(rtmp://SERVER_IP:1935/live/{key})"] -->|RTMP Port 1935| MTX["MediaMTX Server"]
        RESTREAM["Admin Restreamer\n(FFmpeg Background Pull)"] -->|RTMP Relay| MTX
        MTX -->|runOnReady Hook\n(RTSP 127.0.0.1:8554)| FFMPEG_PKG["FFmpeg Packager\n(-c copy, 2s segments, list 6)"]
        FFMPEG_PKG -->|Outputs HLS| HLS_VOL[("Shared Volume: /hls/live/{key}/\n(index.m3u8 + seg_%05d.ts)")]
    end

    subgraph BackendAdmin ["2. Admin Control Panel & Backend (Node.js :3000)"]
        ADMIN_UI["Web Dashboard (/admin)\n(Tailwind Dark Mode UI)"]
        FFMPEG_MGR["FFmpeg Process Manager\n(Start/Stop/Restart, Telemetry & Logs)"]
        R2_WATCHER["R2 Real-Time Watcher\n(chokidar + @aws-sdk/client-s3)"]
        PRUNER["R2 Auto-Pruner Loop\n(Purge segments > 120s)"]
        
        ADMIN_UI <--> FFMPEG_MGR
        HLS_VOL -.->|Watch FS Events| R2_WATCHER
        R2_WATCHER -->|Manifest Rewrite & Upload| R2_BUCKET
        PRUNER -.->|Clean Expired Segments| R2_BUCKET
    end

    subgraph DeliveryMode1 ["3. Mode 1: Direct Nginx Edge + Cloudflare CDN"]
        NGINX["Nginx Edge Proxy (:80 / :443)\n(TLS 1.2/1.3 + HTTP/2)"]
        HLS_CACHE[("Nginx proxy_cache\n(Segment Cache: 60s, lock on)")]
        
        HLS_VOL --> NGINX
        NGINX <--> HLS_CACHE
        NGINX -->|sub_filter '.ts' '.js'\nCache-Control: no-store| EDGE_MANIFEST["Camouflaged Manifest\n/live/{key}/index.css"]
        NGINX -->|rewrite '.js' '.ts'\nCache-Control: public, max-age=60| EDGE_SEGMENT["Camouflaged Segments\n/live/{key}/seg_*.js"]
    end

    subgraph DeliveryMode2 ["4. Mode 2: Cloudflare R2 Zero-Egress Storage + CDN"]
        R2_BUCKET[("Cloudflare R2 Bucket\n(Zero Egress Fees)")]
        R2_CDN["Cloudflare Global CDN (300+ PoPs)\nhttps://r2-custom-domain.shop"]
        
        R2_BUCKET --> R2_CDN
        R2_CDN --> R2_MANIFEST["Manifest: /hd/{slug}/index.html\n(Cache: Bypass)"]
        R2_CDN --> R2_SEGMENT["Segments: /hd/{slug}/seg_*.js\n(Cache: 1-4 hours)"]
    end

    subgraph Viewers ["5. Playback & Embeds"]
        PLAYER["Embedded Web Player (/player/)\n(hls.js Low Latency MSE Engine)"]
        EDGE_MANIFEST --> PLAYER
        EDGE_SEGMENT --> PLAYER
        R2_MANIFEST --> PLAYER
        R2_SEGMENT --> PLAYER
    end
```

---

## 2. Directory Structure

```text
/opt/stream/ (or repository root)
├── docker-compose.yml              # Multi-container orchestration (MediaMTX, Backend, Nginx)
├── mediamtx.yml                    # Ingestion & automatic FFmpeg HLS packaging config
├── .env.example                    # Environment template
├── .env                            # Active environment configuration
├── backend/
│   ├── Dockerfile                  # Alpine + Node.js 20 + FFmpeg
│   ├── package.json                # Express, AWS S3 SDK, Chokidar, JWT, Helmet
│   ├── server.js                   # Unified backend: Auth, Restream Manager, R2 Watcher & Pruner
│   ├── .env.example                # Backend-specific environment variables
│   ├── data/
│   │   └── channels.json           # File-backed channel and restream store
│   └── public/
│       └── admin.html              # Full dark-mode Restreaming Dashboard (Tailwind UI)
├── nginx/
│   ├── Dockerfile                  # Production Nginx image
│   ├── nginx.conf                  # Main Nginx edge configuration (TLS, proxy_cache, sub_filter)
│   └── snippets/
│       ├── allowed-origins.conf    # CORS origins list
│       └── stream-locations.conf   # Camouflage routing rules (.css -> .m3u8, .js -> .ts)
├── player/
│   └── index.html                  # Embedded hls.js player supporting both Nginx and R2 URLs
└── certs/
    ├── fullchain.pem               # SSL Certificate (Let's Encrypt / Cloudflare Origin)
    └── privkey.pem                 # SSL Private Key
```

---

## 3. Quick Start & Deployment Guide

### Prerequisites
- A Linux VPS (Ubuntu 22.04 / Debian 12 / Rocky Linux) with Docker and Docker Compose installed.
- Public IP address and domain pointing to your server (e.g. `edge-domain.com`).
- Optional: Cloudflare account for R2 Zero-Egress distribution.

### Step 1: Clone or Copy Project Files
Place the repository files into `/opt/stream`:
```bash
sudo mkdir -p /opt/stream
cd /opt/stream
# Copy project files here
```

### Step 2: Configure Environment Variables
Copy `.env.example` to `.env` and fill in your details:
```bash
cp .env.example .env
nano .env
```

Key environment settings:
```ini
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password_here
JWT_SECRET=generate_with_openssl_rand_hex_32
SERVER_IP=YOUR_VPS_PUBLIC_IP
EDGE_DOMAIN=edge-domain.com
R2_CUSTOM_DOMAIN=r2-custom-domain.shop

# Cloudflare R2 Credentials (Optional - leave blank for local DRY-RUN mode)
R2_ACCOUNT_ID=your_cloudflare_account_id
R2_ACCESS_KEY_ID=your_r2_access_key_id
R2_SECRET_ACCESS_KEY=your_r2_secret_access_key
R2_BUCKET_NAME=live-streams
```

### Step 3: SSL Certificates Setup
Ensure valid TLS certificates exist in `./certs/`:
- **Option A (Self-Signed for testing):**
  ```bash
  mkdir -p certs
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout certs/privkey.pem \
    -out certs/fullchain.pem \
    -subj "/CN=localhost"
  ```
- **Option B (Let's Encrypt via Certbot or Cloudflare Origin CA):**
  Place your certificate in `./certs/fullchain.pem` and private key in `./certs/privkey.pem`.

### Step 4: Build and Launch the Stack
```bash
docker compose up -d --build
```

Verify container status:
```bash
docker compose ps
docker compose logs -f
```

---

## 4. Admin Restreaming Dashboard Usage

Open your browser and navigate to:
```text
https://edge-domain.com/admin
(or http://SERVER_IP/admin)
```

1. **Sign In:** Use your `ADMIN_USERNAME` and `ADMIN_PASSWORD`.
2. **Channel Management:**
   - Click **"New Channel"** to generate a channel (e.g., `match1`).
   - The system automatically generates:
     - **OBS RTMP URL:** `rtmp://SERVER_IP:1935/live`
     - **Stream Key:** `match1`
     - **Randomized R2 Folder Slug:** e.g. `ugrabzavmtzj`
3. **Pull Restreaming (No OBS Needed):**
   - Paste an external stream link (`.m3u8`, `.ts`, `.mp4`) into the source URL field.
   - Click **"Start Restream"**.
   - The backend spawns a resilient background FFmpeg process that pulls the source and relays it to local MediaMTX.
   - Watch live telemetry (FPS, Bitrate, Speed, Uptime) and inspect real-time terminal logs with one click.
4. **Ready-to-Use Output Links (One-Click Copy):**
   - **Nginx Camouflaged Edge:** `https://edge-domain.com/live/{stream_key}/index.css`
   - **Cloudflare R2 Direct CDN:** `https://r2-custom-domain.shop/hd/{random_slug}/index.html` (or `.css`)
   - **Embedded Player Iframe:** Ready `<iframe>` tag pointing to `/player/?channel={stream_key}` or `/player/?r2={random_slug}`.

---

## 5. Step-by-Step Cloudflare R2 & CDN Configuration

Cloudflare R2 provides S3-compatible object storage with **Zero Egress Fees**, making it the ultimate origin storage for massive live streaming audiences when paired with Cloudflare CDN.

### Step 1: Create the Cloudflare R2 Bucket
1. Log into your **Cloudflare Dashboard** -> Navigate to **R2**.
2. Click **Create bucket**.
3. Bucket Name: `live-streams` (or match `R2_BUCKET_NAME` in `.env`).
4. Location: Select **Automatic** (or closest to your VPS).
5. Click **Create Bucket**.

### Step 2: Generate S3 API Credentials
1. In Cloudflare Dashboard -> **R2** -> Click **Manage R2 API Tokens** on the right sidebar.
2. Click **Create API token**.
3. Permissions: Select **Object Read & Write**.
4. Specify bucket: Choose `live-streams` (or Apply to all buckets).
5. TTL: Set to **Forever** or your preferred duration.
6. Click **Create API Token**.
7. Copy the values into your `.env`:
   - **Access Key ID** -> `R2_ACCESS_KEY_ID`
   - **Secret Access Key** -> `R2_SECRET_ACCESS_KEY`
   - **Jurisdiction Endpoint / Account ID** -> `R2_ACCOUNT_ID`

### Step 3: Configure CORS on the R2 Bucket
To allow web video players to load playlists and segments from your R2 bucket without browser CORS blocking:
1. Open your bucket `live-streams` -> Go to **Settings** tab.
2. Scroll to **CORS Policy** -> Click **Add CORS policy**.
3. Paste the following JSON:
```json
[
  {
    "AllowedOrigins": [
      "*"
    ],
    "AllowedMethods": [
      "GET",
      "HEAD"
    ],
    "AllowedHeaders": [
      "*"
    ],
    "ExposeHeaders": [
      "Content-Length",
      "Content-Range",
      "ETag"
    ],
    "MaxAgeSeconds": 86400
  }
]
```
4. Click **Save**.

### Step 4: Connect a Custom Domain to the R2 Bucket
Connecting a custom domain enables Cloudflare's CDN caching and gives clean URLs without exposing S3 endpoints:
1. In the R2 bucket **Settings** tab -> Scroll down to **Custom Domains**.
2. Click **Connect Domain**.
3. Enter your dedicated streaming domain or subdomain:
   - e.g. `r2-custom-domain.shop` or `stream.yourdomain.com`.
4. Cloudflare will automatically configure the DNS CNAME record and provision an SSL/TLS certificate.
5. Set `R2_CUSTOM_DOMAIN=r2-custom-domain.shop` in your `.env`.

### Step 5: Configure Cloudflare CDN Cache Rules
Because live streaming playlists change every 2 seconds while media segments are immutable, strict caching rules must be applied in Cloudflare:

1. In Cloudflare Dashboard -> Select your custom domain (e.g., `r2-custom-domain.shop`).
2. Navigate to **Caching** -> **Cache Rules** -> Click **Create rule**.

#### Cache Rule A: Playlists (Never Cache Manifests)
- **Rule Name:** `Live HLS Manifests - Bypass Cache`
- **When incoming requests match:**
  - Field: `URI Path`
  - Operator: `matches regex`
  - Value: `^/hd/.+/(index\.html|index\.css|master\.css|\.m3u8)$`
  *(Or simple wildcard: `URI Path` contains `/index.html` OR `URI Path` contains `/index.css`)*
- **Cache eligibility:** **Bypass cache**
- Click **Deploy**.

#### Cache Rule B: Video Segments (Edge Cache Everything)
- **Rule Name:** `Live HLS Segments - Cache Everything`
- **When incoming requests match:**
  - Field: `URI Path`
  - Operator: `ends with`
  - Value: `.js` (and `.ts`)
- **Cache eligibility:** **Eligible for cache**
- **Edge Cache TTL:** **Ignore cache-control header and use TTL** -> **2 hours** (or 4 hours)
- **Browser Cache TTL:** **Respect existing headers** (or 60 seconds)
- Click **Deploy**.

---

## 6. How Obfuscation & Camouflage Work

| Asset Type | Real File on Server | Delivered URL | Masqueraded MIME Type | Caching Behavior |
| :--- | :--- | :--- | :--- | :--- |
| **HLS Playlist (Edge)** | `/hls/live/match1/index.m3u8` | `/live/match1/index.css` | `text/css; charset=utf-8` | `Cache-Control: no-store` (No edge/browser caching) |
| **Media Segment (Edge)** | `/hls/live/match1/seg_00001.ts` | `/live/match1/seg_00001.js` | `application/javascript` | `Cache-Control: public, max-age=60` (`proxy_cache` active) |
| **HLS Playlist (R2)** | Uploaded rewritten manifest | `/hd/ugrabzavmtzj/index.html` | `text/html; charset=utf-8` | `Cache-Control: no-store` (Cloudflare Cache Bypassed) |
| **Media Segment (R2)** | Uploaded MPEG-TS segment | `/hd/ugrabzavmtzj/seg_00001.js` | `application/javascript` | Edge cached globally (Cloudflare 2h TTL, purged > 120s) |

---

## 7. Verification & Testing

### Test Ingestion with FFmpeg (CLI Test Stream)
Push a test colorbars live video with audio to MediaMTX:
```bash
ffmpeg -re -f lavfi -i testsrc=size=1920x1080:rate=30 \
  -f lavfi -i sine=frequency=1000:sample_rate=44100 \
  -c:v libx264 -preset veryfast -b:v 3000k -maxrate 3000k -bufsize 6000k -pix_fmt yuv420p -g 60 \
  -c:a aac -b:a 128k \
  -f flv rtmp://127.0.0.1:1935/live/match1
```

### Inspect Camouflaged Manifest Delivery
```bash
curl -I https://edge-domain.com/live/match1/index.css
```
Expected response:
```http
HTTP/2 200
content-type: text/css; charset=utf-8
cache-control: no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0
access-control-allow-origin: *
```

### Inspect Camouflaged Segment Delivery & Caching
```bash
curl -I https://edge-domain.com/live/match1/seg_00001.js
```
Expected response:
```http
HTTP/2 200
content-type: application/javascript
cache-control: public, max-age=60, immutable
x-cache-status: HIT
access-control-allow-origin: *
```

### Inspect Cloudflare R2 Delivery
```bash
curl -I https://r2-custom-domain.shop/hd/ugrabzavmtzj/index.html
```

---

## 8. Embedded Web Player Integration

Use the built-in standalone player or embed via iframe:

```html
<!-- Edge Camouflaged Mode -->
<iframe 
    src="https://edge-domain.com/player/?channel=match1" 
    width="100%" 
    height="100%" 
    frameborder="0" 
    allowfullscreen 
    allow="autoplay; encrypted-media">
</iframe>

<!-- Cloudflare R2 Direct CDN Mode -->
<iframe 
    src="https://edge-domain.com/player/?r2=ugrabzavmtzj" 
    width="100%" 
    height="100%" 
    frameborder="0" 
    allowfullscreen 
    allow="autoplay; encrypted-media">
</iframe>
```

---

## 9. Maintenance & Troubleshooting

- **Check Restreamer logs in real time:**
  Open the Admin Dashboard -> Click **Logs** on any channel card.
- **Inspect MediaMTX ingestion:**
  `docker compose logs -f mediamtx`
- **Inspect Nginx cache metrics:**
  `docker compose logs -f nginx`
- **Clear Nginx edge cache:**
  `docker compose exec nginx rm -rf /var/cache/nginx/hls/*`
- **R2 Storage Cost:**
  The automated 120-second segment pruner runs every 20 seconds, maintaining zero egress fees and minimal R2 object count.
