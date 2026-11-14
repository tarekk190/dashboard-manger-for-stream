# Enterprise Live Streaming Infrastructure & Admin Restreaming Dashboard

A Dockerized live video streaming stack with an admin control panel. It supports **two delivery modes**:

1. **Nginx Edge Mode (token-protected):** RTMP ingest -> MediaMTX -> FFmpeg HLS packaging (`2s` segments, sliding window 6) -> Nginx serves `.m3u8` as `.css` and `.ts` as `.js`, with `proxy_cache_lock` segment micro-caching. Every playlist and segment request is checked against a short-lived viewer token.
2. **Cloudflare R2 Zero-Egress Mode (public):** the backend's R2 watcher watches `/hls`, rewrites segment links to `.js`, uploads segments first and then manifests (`index.html` / `index.css`) to R2 under randomized folder slugs (`/hd/{random_slug}/`), and purges segments older than `MAX_SEGMENT_AGE_SECONDS`. R2 delivery is not token-protected.

---

## 1. System Architecture & Workflow

```mermaid
flowchart TD
    subgraph Ingestion ["1. Broadcast Ingestion Layer"]
        OBS["OBS Studio Broadcaster\n(rtmp://SERVER_IP:1935/live,\nkey: {streamKey}?user=publish&pass={publishKey})"] -->|RTMP Port 1935| MTX["MediaMTX Server"]
        RESTREAM["Admin Restreamer\n(FFmpeg Background Pull, supervised)"] -->|RTMP Relay + publishKey| MTX
        MTX -.->|authMethod: http\nPOST /internal/mediamtx-auth| AUTHHOOK["Backend publish/read check"]
        MTX -->|runOnReady Hook\n(RTSP 127.0.0.1:8554)| FFMPEG_PKG["FFmpeg Packager\n(-c copy, 2s segments, list 6,\nepoch segment numbers)"]
        FFMPEG_PKG -->|Outputs HLS| HLS_VOL[("Shared Volume: /hls/live/{streamKey}/\n(index.m3u8 + seg_{epoch}.ts)")]
    end

    subgraph BackendAdmin ["2. Admin Control Panel & Backend (Node.js :3000, user 'node')"]
        ADMIN_UI["Web Dashboard (/admin)"]
        FFMPEG_MGR["FFmpeg Process Manager\n(Start/Stop/Restart, auto-restart, resume on boot)"]
        R2_WATCHER["R2 Real-Time Watcher\n(chokidar + @aws-sdk/client-s3)"]
        PRUNER["R2 Auto-Pruner Loop"]
        VIEWER_AUTH["Viewer tokens\n/api/stream, /api/token, /auth"]

        ADMIN_UI <--> FFMPEG_MGR
        HLS_VOL -.->|Watch FS Events| R2_WATCHER
        R2_WATCHER -->|Segments first, then manifest| R2_BUCKET
        PRUNER -.->|Clean Expired Segments| R2_BUCKET
    end

    subgraph DeliveryMode1 ["3. Mode 1: Nginx Edge (HTTPS only)"]
        NGINX["Nginx Edge Proxy (:443, :80 -> 301)\n(TLS 1.2/1.3 + HTTP/2)"]
        HLS_CACHE[("Nginx proxy_cache\n(Segment Cache: 60s, lock on)")]

        HLS_VOL --> NGINX
        NGINX <--> HLS_CACHE
        NGINX -.->|auth_request /auth| VIEWER_AUTH
        NGINX -->|sub_filter '.ts' '.js'\nCache-Control: no-store| EDGE_MANIFEST["Camouflaged Manifest\n/live/{streamKey}/index.css"]
        NGINX -->|rewrite '.js' '.ts'\nCache-Control: public, max-age=60| EDGE_SEGMENT["Camouflaged Segments\n/live/{streamKey}/seg_*.js"]
    end

    subgraph DeliveryMode2 ["4. Mode 2: Cloudflare R2 Zero-Egress Storage + CDN"]
        R2_BUCKET[("Cloudflare R2 Bucket\n(Zero Egress Fees)")]
        R2_CDN["Cloudflare Global CDN\nhttps://R2_CUSTOM_DOMAIN"]

        R2_BUCKET --> R2_CDN
        R2_CDN --> R2_MANIFEST["Manifest: /hd/{slug}/index.html\n(Cache: Bypass)"]
        R2_CDN --> R2_SEGMENT["Segments: /hd/{slug}/seg_*.js\n(Cache: 1-4 hours)"]
    end

    subgraph Viewers ["5. Playback & Embeds"]
        PLAYER["Embedded Web Player (/player/)\n(hls.js, fetches + renews viewer token)"]
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
├── docker-compose.yml              # MediaMTX, Backend, Nginx (stock nginx:alpine image)
├── mediamtx.yml                    # Ingest, HTTP auth hook & automatic FFmpeg HLS packaging
├── .env.example                    # Environment template (placeholders only)
├── .env                            # Your configuration (git-ignored, never baked into images)
├── backend/
│   ├── Dockerfile                  # Alpine + Node.js 20 + FFmpeg, runs as user 'node'
│   ├── .dockerignore               # Keeps .env, certs and data out of the image
│   ├── package.json                # Express, AWS S3 SDK, Chokidar, JWT, Helmet, CORS
│   ├── server.js                   # Admin API, restream supervisor, R2 pipeline, viewer auth, MediaMTX auth hook
│   ├── .env.example                # Only for running server.js outside docker compose
│   └── public/
│       └── admin.html              # Restreaming Dashboard (Tailwind UI)
├── nginx/
│   ├── nginx.conf                  # TLS, proxy_cache, CORS map, HTTP->HTTPS redirect
│   └── snippets/
│       ├── allowed-origins.conf    # CORS origins for playlists/segments (map $http_origin)
│       └── stream-locations.conf   # HTTPS locations: camouflage routing + auth_request
├── player/
│   └── index.html                  # The embedded hls.js player (Nginx edge + R2 modes)
├── certbot/
│   └── www/                        # ACME webroot served on port 80
└── certs/
    ├── fullchain.pem               # TLS certificate (git-ignored)
    └── privkey.pem                 # TLS private key (git-ignored)
```

Channel data lives in the `backend_data` docker volume (`/app/data/channels.json`).

---

## 3. Quick Start & Deployment Guide

### Prerequisites
- A Linux VPS with Docker and Docker Compose v2.
- A public IP and a domain (`EDGE_DOMAIN`) pointing to it.
- Optional: Cloudflare account for R2 delivery.

### Step 1: Copy Project Files
```bash
sudo mkdir -p /opt/stream && cd /opt/stream
# Copy project files here
```

### Step 2: Configure Environment Variables
```bash
cp .env.example .env
nano .env
```

Required (compose refuses to start without them, the backend refuses weak values):

| Variable | Rule | How to generate |
| :--- | :--- | :--- |
| `ADMIN_USERNAME` | non-empty | choose one |
| `ADMIN_PASSWORD` | ≥ 12 chars, not a known placeholder | `openssl rand -base64 24` |
| `ADMIN_JWT_SECRET` | ≥ 32 chars, signs admin sessions (12h) | `openssl rand -hex 48` |
| `VIEWER_JWT_SECRET` | ≥ 32 chars, different from the admin secret, signs viewer tokens | `openssl rand -hex 48` |
| `SERVER_IP` | public IP shown as the OBS RTMP server | |
| `EDGE_DOMAIN` | public HTTPS domain of the edge | |

Optional:

| Variable | Default | Meaning |
| :--- | :--- | :--- |
| `ENABLE_AUTH_ON_PLAYLISTS` | `true` | Require a viewer token on every edge playlist **and** segment. `false` makes `/auth` allow everything (debug only). |
| `TOKEN_EXPIRATION_SECONDS` | `60` | Viewer token lifetime |
| `TOKEN_RENEW_GRACE_SECONDS` | `15` | How long after expiry `POST /api/token` still renews a token |
| `ALLOWED_ORIGINS` | empty | Comma-separated origins allowed to call `/api/stream` and `/api/token` cross-origin. `*` is refused when `NODE_ENV=production`. |
| `RESTREAM_MAX_RETRIES` | `10` | Consecutive auto-restarts before a restream is marked `failed` (`0` = unlimited) |
| `R2_*`, `R2_CUSTOM_DOMAIN` | empty | Cloudflare R2. Empty credentials = DRY-RUN (no uploads). |
| `MAX_SEGMENT_AGE_SECONDS` | `120` | R2 segment retention. Keep it well above the 12s playlist window. |

Playlist/segment CORS for third-party sites is configured in `nginx/snippets/allowed-origins.conf` (the bundled player is same-origin and needs no entry).

### Step 3: TLS Certificates
Nginx serves only HTTPS; port 80 answers ACME challenges and redirects everything else.

- **Option A: self-signed (testing only):**
  ```bash
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout certs/privkey.pem -out certs/fullchain.pem -subj "/CN=$EDGE_DOMAIN"
  ```
- **Option B: Let's Encrypt via the webroot** (the stack must be running so port 80 serves `./certbot/www`; start it once with a self-signed cert from Option A):
  ```bash
  docker run --rm \
    -v "$PWD/certbot/www:/var/www/certbot" \
    -v "$PWD/certbot/conf:/etc/letsencrypt" \
    certbot/certbot certonly --webroot -w /var/www/certbot -d "$EDGE_DOMAIN" --agree-tos -m you@example.com
  cp -L "certbot/conf/live/$EDGE_DOMAIN/fullchain.pem" certs/fullchain.pem
  cp -L "certbot/conf/live/$EDGE_DOMAIN/privkey.pem"   certs/privkey.pem
  docker compose exec nginx nginx -s reload
  ```
  Renew with the same command plus `renew` instead of `certonly ...`, then copy and reload again.
- **Option C:** a Cloudflare Origin CA certificate placed at the same two paths.

HSTS is sent as a plain `max-age` (no `includeSubDomains` / `preload`).

### Step 4: Build and Launch
```bash
docker compose config --quiet   # fails clearly if a required variable is missing
docker compose up -d --build
docker compose exec nginx nginx -t
docker compose ps
```

### Upgrading an existing deployment
- Set `ADMIN_JWT_SECRET` and `VIEWER_JWT_SECRET` (the old `JWT_SECRET` is no longer read). Existing admin sessions and viewer tokens become invalid.
- On first start every existing channel gets a random `publishKey`. **OBS / encoder settings must be updated** with the new stream key from the dashboard.
- The backend now runs as uid 1000. If `backend_data` was created by an older root container, fix ownership once:
  `docker compose run --rm -u root backend chown -R node:node /app/data`

---

## 4. Admin Restreaming Dashboard Usage

Open `https://EDGE_DOMAIN/admin` (plain HTTP redirects to HTTPS).

1. **Sign In** with `ADMIN_USERNAME` / `ADMIN_PASSWORD`. Five failed attempts per IP within 15 minutes lock that IP out for the rest of the window (HTTP 429).
2. **Channels:** each channel has
   - a **public stream key** (`streamKey`, e.g. `match1`): the URL path `/live/match1/...` and the `?channel=` value. Not secret.
   - a **secret publish key** (`publishKey`, 32 hex chars): only shown in the dashboard and required to push RTMP.
   - a randomized **R2 folder slug** (`r2_slug`).
3. **OBS settings:**
   - Server: `rtmp://SERVER_IP:1935/live`
   - Stream Key: `match1?user=publish&pass=<publishKey>` (use **Copy Key** on the channel card)

   Publishing without the right key is rejected by MediaMTX. Reading streams over RTMP/RTSP from outside is rejected too; only the packager inside the MediaMTX container may read.
4. **Pull Restreaming:** paste an `http(s)`, `rtmp(s)`, `rtsp` or `srt` source URL and click **Start Restream**.
   - Other schemes (`file:`, `concat:`, `pipe:`, `data:` …) and hosts that resolve to loopback, link-local or private ranges, or to the docker service names, are rejected with HTTP 400. FFmpeg also runs with `-protocol_whitelist`.
   - FFmpeg is supervised: an unexpected exit triggers a restart after 2s, 4s, 8s … (max 60s, `RESTREAM_MAX_RETRIES`). **Stop** is final. Running jobs resume automatically after a backend restart.
5. **Output links:**
   - **Nginx edge:** `https://EDGE_DOMAIN/live/{streamKey}/index.css` (needs a viewer token, see section 7)
   - **Cloudflare R2:** `https://R2_CUSTOM_DOMAIN/hd/{r2_slug}/index.html` (or `.css`)
   - **Player iframe:** `/player/?channel={streamKey}` or `/player/?r2={r2_slug}`

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

| Asset Type | Real File on Server | Delivered URL | MIME Type | Caching Behavior |
| :--- | :--- | :--- | :--- | :--- |
| **HLS Playlist (Edge)** | `/hls/live/match1/index.m3u8` | `/live/match1/index.css` | `text/css; charset=utf-8` | `Cache-Control: no-store` |
| **Media Segment (Edge)** | `/hls/live/match1/seg_1794671902.ts` | `/live/match1/seg_1794671902.js` | `application/javascript` | `public, max-age=60` (`proxy_cache`) |
| **HLS Playlist (R2)** | Uploaded rewritten manifest | `/hd/ugrabzavmtzj/index.html` | `text/html; charset=utf-8` | `no-store` (Cloudflare cache bypassed) |
| **Media Segment (R2)** | Uploaded MPEG-TS segment | `/hd/ugrabzavmtzj/seg_1794671902.js` | `application/javascript` | `public, max-age=3600, immutable` |

- Raw `.m3u8` / `.ts` URLs (and anything else under `/live/` or `/hls/`) return **404**.
- Segment numbers start at the Unix time when the packager starts (`-hls_start_number_source epoch`), so a restarted packager never reuses a segment name. That is what makes the 60s edge cache and the immutable R2 cache safe.
- The MIME types are set by the internal origin (`127.0.0.1:8088` in `nginx.conf`). The edge locations must not `proxy_hide_header Content-Type`: that would disable `sub_filter`.

---

## 7. Viewer Tokens (Nginx edge mode)

1. `GET /api/stream?channel=match1` → `{ channel, token, expiresIn, streamUrl }`. `channel` must match `[a-z0-9_-]` and exist (404 otherwise). `streamUrl` already carries `?token=`.
2. Send the token on every playlist **and** segment request, either as `Authorization: Bearer <token>` (hls.js `xhrSetup`) or as `?token=`.
3. Renew before expiry with `POST /api/token {"token": "<current>"}`. Tokens expired by more than `TOKEN_RENEW_GRACE_SECONDS` return 401 and the client must call `/api/stream` again.
4. Nginx `auth_request /auth` answers **401** for a missing, invalid or expired token and **403** when the token's channel differs from the channel in the URL. Results are micro-cached (200: 5s, 401/403: 1s) under a key of *channel + query token + Authorization header* from the original request.

The bundled player (`/player/?channel=...`) does all of this automatically. Native Safari HLS (no hls.js) can only pass the token in the playlist URL, so its segment requests fail with 401; use hls.js there.

---

## 8. Verification & Testing

Replace `edge-domain.com` with your `EDGE_DOMAIN`. Add `-k` for self-signed certificates.

```bash
# Config and syntax
docker compose config --quiet                 # must fail clearly if a required var is missing
docker compose up -d --build
docker compose exec nginx nginx -t

# HTTPS only
curl -sI http://edge-domain.com/admin                         # 301 -> https://edge-domain.com/admin

# Raw HLS is never reachable, camouflaged HLS needs a token
curl -s -o /dev/null -w '%{http_code}\n' https://edge-domain.com/live/match1/index.m3u8   # 404
curl -s -o /dev/null -w '%{http_code}\n' https://edge-domain.com/live/match1/index.css    # 401

# Valid token: playlist 200 with exactly one Content-Type
TOKEN=$(curl -s 'https://edge-domain.com/api/stream?channel=match1' | jq -r .token)
curl -s -D - -o /tmp/pl.css -H "Authorization: Bearer $TOKEN" https://edge-domain.com/live/match1/index.css | grep -ci '^content-type'   # 1

# Same segment twice: the second response is a cache HIT
SEG=$(grep -m1 '\.js$' /tmp/pl.css)
for i in 1 2; do curl -s -D - -o /dev/null -H "Authorization: Bearer $TOKEN" "https://edge-domain.com/live/match1/$SEG" | grep -i x-cache-status; done

# Token for match1 used on another channel -> 403
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" https://edge-domain.com/live/match2/index.css

# Expired token (older than the grace window) -> 401
curl -s -X POST https://edge-domain.com/api/token -H 'Content-Type: application/json' -d '{"token":"<old token>"}' -w ' %{http_code}\n'

# RTMP publish: rejected without the publish key, accepted with it
ffmpeg -re -f lavfi -i testsrc=size=1280x720:rate=30 -f lavfi -i sine=frequency=1000 \
  -c:v libx264 -preset veryfast -g 60 -pix_fmt yuv420p -c:a aac -f flv \
  rtmp://SERVER_IP:1935/live/match1                                    # "authentication failed"
ffmpeg ... -f flv "rtmp://SERVER_IP:1935/live/match1?user=publish&pass=<publishKey>"   # accepted

# Restream source validation (admin token from POST /api/admin/login)
curl -s -X POST https://edge-domain.com/api/channels/<id>/restream/start \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"sourceUrl":"file:///etc/passwd"}' -w ' %{http_code}\n'          # 400

# Restream supervision
docker compose exec backend pkill -9 ffmpeg     # dashboard shows "restarting", new PID after 2s, 4s, ...
docker compose restart backend                  # running jobs resume ("Resumed restream" in logs)

# Admin login rate limit: the 6th wrong attempt within 15 minutes -> 429
for i in 1 2 3 4 5 6; do curl -s -o /dev/null -w '%{http_code} ' -X POST https://edge-domain.com/api/admin/login \
  -H 'Content-Type: application/json' -d '{"username":"x","password":"wrong-password"}'; done; echo

# No default secrets in the tree
grep -rnE "admin12345[6]|fallback_[d]efault|super_[s]ecret" --exclude-dir=.git .   # [x] keeps this line from matching itself
```

---

## 9. Embedded Web Player Integration

```html
<!-- Nginx edge mode (token fetched and renewed by the player) -->
<iframe src="https://edge-domain.com/player/?channel=match1"
        width="100%" height="100%" frameborder="0" allowfullscreen allow="autoplay; encrypted-media"></iframe>

<!-- Cloudflare R2 mode -->
<iframe src="https://edge-domain.com/player/?r2=ugrabzavmtzj"
        width="100%" height="100%" frameborder="0" allowfullscreen allow="autoplay; encrypted-media"></iframe>
```

---

## 10. Maintenance & Troubleshooting

- **Restreamer logs:** Admin Dashboard -> **Logs** on a channel card (the publish key is masked).
- **Ingest / auth decisions:** `docker compose logs -f mediamtx` and `docker compose logs -f backend | grep MEDIAMTX-AUTH`
- **Nginx:** `docker compose logs -f nginx`
- **Clear the edge cache:** `docker compose exec nginx sh -c 'rm -rf /var/cache/nginx/hls/*'`
- **R2 pruning** runs every 20 seconds and paginates the full `hd/` listing.
