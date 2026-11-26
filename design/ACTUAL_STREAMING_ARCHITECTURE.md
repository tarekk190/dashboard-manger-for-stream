# Actual Streaming Architecture (source-verified)

> Written for an independent reviewer (ChatGPT) who has not seen this repository.
> Written 2026-11-23 from the repository at branch `theme/news-page-cards-branding`,
> HEAD `103f4d9`, **including uncommitted working-tree changes**.
> Read-only investigation: no file other than this one was created or changed, nothing was
> deployed, restarted or requested from production.
>
> Evidence labels used throughout:
> - **[VERIFIED]**: read directly in the source at the cited path and line.
> - **[CLAIMED]**: written in a repository comment, commit message or test fixture header, but
>   not checkable from source alone (usually a statement about what production runs).
> - **[INFERRED]**: follows logically from verified code; no live check.
> - **[UNKNOWN]**: can only be settled by inspecting the live environment.
>
> Line numbers refer to the working-tree files unless a commit is named.

---

## 1. Executive summary

**What the product is.** A small live-sports restreaming system on one VPS (Docker Compose:
MediaMTX, a Node.js backend with FFmpeg, nginx). An operator gives the backend a source URL. The
backend pulls and transcodes it, MediaMTX packages it as HLS, and the backend uploads the HLS
files to Cloudflare R2. Viewers watch through a web player page (`/player/`) that is embedded as
an iframe in other sites.

**The "CSS/JS" mechanism is standard HLS with renamed files.** The repository does **not**
deliver video through a custom CSS/JS rendering or reconstruction scheme. It is ordinary HLS:
an M3U8 playlist plus 2-second MPEG-TS segments (H.264 + AAC). The files get disguised names
and MIME types:

| Real content | Name on R2 (R2 mode) | Name on nginx edge (edge mode) | Content-Type sent |
|---|---|---|---|
| HLS media playlist (`index.m3u8`) | `hd/{slug}/index.html` (optionally also `index.css`) | `/live/{key}/index.css` | `text/html` (R2) / `text/css` (edge) |
| MPEG-TS segment (`seg_NNNNN.ts`) | `hd/{slug}/seg_NNNNN.js` | `/live/{key}/seg_NNNNN.js` | `application/javascript` |

The bytes are not modified. A ".js segment" is a byte-identical MPEG-TS file, and a ".html" or
".css" playlist is M3U8 text with `.ts` rewritten to `.js`. The browser never runs or applies
these files as script or stylesheet. **hls.js 1.5.8** (JavaScript, loaded from jsDelivr) fetches
them with XHR, transmuxes MPEG-TS to fragmented MP4 in JavaScript and appends the result to a
Media Source Extensions `SourceBuffer` behind a normal `<video>` element. Where hls.js is not
supported, the page sets `video.src` to the playlist and the browser's native HLS plays it.
CSS only styles the player UI. [VERIFIED; sections 3 and 4]

**Two playback modes exist in the player, chosen by query parameter:**

- `?r2={slug}` (**R2 mode**). The browser fetches playlists and segments directly from the R2
  custom domain through Cloudflare. The VPS carries no video bytes. It serves only the player
  HTML, one lookup call and a 15-second heartbeat.
- `?channel={key}` (**edge mode**). Playlists and segments are served by nginx on the VPS from
  the local `/hls` volume. Playlists need a short-lived JWT checked by `auth_request`. Video
  bytes flow out of the VPS unless Cloudflare caches the segments.
- `?src={url}` (direct mode). Plays any playlist URL, mainly for testing.

**Which mode production uses is not provable from the repo.** The last embed code in the
repository (baseline theme at `872a75b`) generated URLs carrying `r2=` whenever a slug existed,
and `r2` takes precedence over `channel` in the player. The current repository has removed every
embed from the Blogger theme and Worker, so the current production embeds are outside this
repository. [section 3.5]

**Production is not the repository's HEAD.** Test fixtures and comments claim that production
on 2026-11-23 runs:

- an older player (byte-identical to `player/index.hd-menu.html` at commit `e996297`, i.e. the
  baseline `872a75b` version);
- an older backend without `/api/r2`;
- an nginx framing allowlist that was hand-edited on the server and was never committed until
  the current working tree.

HEAD contains two committed changes that would break production embeds if deployed alone. The
uncommitted working tree undoes both. [section 8]

---

## 2. Verified end-to-end architecture

```
                        ┌──────────────────────────── VPS (docker-compose.yml) ─────────────────────────────┐
 External source        │                                                                                    │
 (HLS m3u8 / HTTP TS /  │  backend container (Node + FFmpeg)          mediamtx container (1.21.3-ffmpeg)    │
  RTMP / RTSP / SRT)    │  ┌──────────────────────────────┐  RTMP/FLV  ┌───────────────────────────────┐   │
 ───────── pull ───────►│  │ FFmpeg #1 "restreamer"        │──────────►│ :1935 path live/{key}          │   │
                        │  │ decode → 480p H.264 1000k     │ ?user=    │ (publish auth → backend        │   │
 OBS (optional push) ──────────────────────────────────────────────────►│  /internal/mediamtx-auth)     │   │
   rtmp://IP:1935/live  │  │ + AAC 96k, keyframe every 2 s │ publish   │ runOnReady: FFmpeg #2          │   │
                        │  │ (optional 720p HD leg via tee │ &pass=    │ "packager" reads RTSP :8554    │   │
                        │  │  → live/{key}-hd)             │           │ -c copy -f hls 2 s × 10        │   │
                        │  └──────────────────────────────┘           └───────────────┬───────────────┘   │
                        │                                                              │ writes             │
                        │                        shared volume hls_data  /hls/live/{key}/index.m3u8        │
                        │                                                /hls/live/{key}/seg_{epoch}.ts    │
                        │  ┌──────────────────────────────┐   chokidar   ▲            │ read-only          │
                        │  │ R2PipelineManager             │◄─────────────┘            ▼                    │
                        │  │ PUT seg → hd/{slug}/seg_N.js  │                ┌──────────────────────────┐   │
                        │  │ PUT pl  → hd/{slug}/index.html│                │ nginx :443 (edge mode)    │   │
                        │  │ prune / ended / HD markers    │                │ /live/{key}/index.css     │   │
                        │  │ Express API :3000             │◄── /api/* ────│ /live/{key}/seg_N.js      │   │
                        │  └──────────────┬───────────────┘  auth_request  │ /player/ (static HTML)    │   │
                        └─────────────────┼─────────────────────────────────┴─────────────┬────────────┘   │
                                          │ S3 API PutObject/List/Delete                   │ HTTPS
                                          ▼                                                ▼
                         Cloudflare R2 bucket (default "live-streams")       Cloudflare proxy (assumed) for
                         served via R2 custom domain + Cloudflare cache      live.smarterwho.site
                                          │                                                │
                                          ▼  R2 mode: playlists + segments                 ▼  player page, /api/*,
                                     ┌────────────────────────────────────────────────────────┐ edge-mode HLS
                                     │ Browser: iframe https://live.smarterwho.site/player/?… │
                                     │ hls.js 1.5.8 (MSE) or native HLS → <video>             │
                                     └────────────────────────────────────────────────────────┘
```

All boxes and arrows inside the VPS are [VERIFIED] in `docker-compose.yml:14-152`,
`mediamtx.yml:19-109`, `backend/server.js` and `nginx/`. Whether `live.smarterwho.site` sits
behind Cloudflare is [INFERRED] from `nginx/nginx.conf:52-74` (Cloudflare real-IP ranges) and
`deploy/vps-firewall.sh` (title: "Cloudflare-only 80/443"). The R2 custom domain's hostname and
its Cloudflare cache rules are [UNKNOWN]: the repo holds only a placeholder
(`r2-custom-domain.shop`, `backend/server.js:90-91`).

---

## 3. Playback and video-delivery mechanism

### 3.1 What the viewer opens

A page on a third-party site (Blogger blogs, according to the framing allowlist) contains an
`<iframe src="https://live.smarterwho.site/player/?…">`. nginx serves the static file
`player/index.html` from `/var/www/player/` (`nginx/snippets/stream-locations.conf:15-24`,
volume `./player:/var/www/player:ro` in `docker-compose.yml:138`) with
`Cache-Control: no-cache, must-revalidate`. The CSP `frame-ancestors` header decides which sites
may frame the player (`stream-locations.conf:22`). [VERIFIED]

The page loads three external resources: Google Fonts CSS and fonts
(`player/index.html:8-10`), and `https://cdn.jsdelivr.net/npm/hls.js@1.5.8/dist/hls.min.js`
(`player/index.html:12`). [VERIFIED]

### 3.2 Mode selection

`player/index.html:538-542` reads `channel`, `r2`, `src` and `token` from the query string.
`resolveStream()` (`player/index.html:824-897`) applies this precedence: **`src` > `r2` >
`channel`** (and `channel` defaults to `match1`). [VERIFIED]

### 3.3 R2 mode (`?r2={slug}`), current working-tree player

1. `GET /api/r2/{slug}` on the page's own origin, i.e. the VPS (`player/index.html:837-839`).
   The backend answers `{ base: "https://{R2_CUSTOM_DOMAIN}/hd/{slug}/", hdSignal: "playlist" }`
   (`backend/server.js:2667-2681`). The endpoint is gated by `requireViewerPage`
   (Origin/Referer/Sec-Fetch checks, `server.js:2563-2581`).
   If the answer is a non-JSON 404 (an older backend without this route), the player falls
   back to `GET /api/config` and builds the base URL from `r2CustomDomain`
   (`player/index.html:844-849`, `1179-1188`).
2. The player builds the SD playlist URL `{base}index.html` and the HD URL
   `{base}hd/index.html` (`player/index.html:861-863`).
3. hls.js loads `{base}index.html`. A custom playlist loader (`PxlRetry.playlistLoaderClass`,
   `player/index.html:495-519`) adds `?_t={unix-seconds}` to every **cross-origin** playlist
   request. It turns an "ended" playlist (`#PXL-STREAM-ENDED`) into a synthetic HTTP 410 error
   and passes every playlist body to `onPlaylistLoaded` so the player can read the HD marker.
4. hls.js reloads the live playlist about once per target duration (≈2 s) and downloads each new
   `seg_N.js` segment from `{base}`. Segment URLs carry no query parameters, headers or
   credentials (`xhrSetup` returns early for cross-origin URLs, `player/index.html:932-946`).
5. Playback runs about 12 s behind the live edge (`liveSyncDuration: 12`,
   `liveMaxLatencyDuration: 18`, `player/index.html:915-916`).

**The VPS carries no video bytes in R2 mode.** Playlists and segments come from the R2 custom
domain. [VERIFIED for the player code; the Cloudflare caching in front of R2 is UNKNOWN]

### 3.4 Edge mode (`?channel={key}`)

1. `GET /api/stream?channel={key}` with credentials (`player/index.html:608-618`). The backend
   returns a JWT that lives 45 s by default and is bound to the User-Agent hash, and also sets
   an `HttpOnly` cookie `stream_auth` with `Path=/live/{key}/` and `SameSite=None; Partitioned`
   (`server.js:2638-2660`, `2590-2599`, `2530-2536`).
2. hls.js loads `/live/{key}/index.css` from the same origin, sending
   `Authorization: Bearer {jwt}` plus the cookie (`player/index.html:895`, `938-945`).
3. nginx (`stream-locations.conf:108-163`):
   - applies the Referer lock (`referer-lock.conf`: only `live.smarterwho.site`);
   - runs `auth_request /auth` against the backend `handleEdgeAuth` (`server.js:2715-2748`),
     with a 20 s cache keyed by channel, token, auth header, cookie, User-Agent and IP
     (`stream-locations.conf:68-102`);
   - rewrites the path to `/live/{key}/index.m3u8` and proxies it to the internal origin
     `127.0.0.1:8088`, which serves `/hls` from disk with `default_type text/css`
     (`nginx.conf:141-168`);
   - rewrites `.ts`→`.js` and `.m3u8`→`.css` in the body with `sub_filter`;
   - sends `Cache-Control: no-store`.
4. Segments `/live/{key}/seg_N.js` (`stream-locations.conf:175-224`) get the Referer lock but
   **no token check**. They are rewritten to `.ts` and served from the local disk through an
   nginx `proxy_cache` (key `$uri`, 60 s) with `Cache-Control: public, max-age=60, immutable`.
5. The token is renewed with `POST /api/token` 15 s before expiry (`player/index.html:602-645`;
   `server.js:2684-2712`).

**In edge mode the VPS is the origin for every playlist request and every segment cache miss.**
[VERIFIED]

### 3.5 Which mode do production embeds use?

- **Evidence for R2 mode [VERIFIED in history, CLAIMED for production].**
  - At baseline `872a75b`, the Blogger theme built the player URL from `{channel, r2_slug}`
    and set **both** `channel` and `r2` when both were present
    (`git show 872a75b:blogger/px-league-theme.xml`, `streamUrl()` around line 4121).
  - The stream-manager dashboard fills the R2 slug automatically when a channel is picked
    (`blogger/stream-manager/index.html:49-55`, `400`: b1→`iesufnzpe8ys`, b2→`l19glp5gmva0`,
    b3→`1ikcxk76du8w`, b4→`iwkksjrvle3u`).
  - Because the player prefers `r2`, those embeds played in R2 mode.
  - A second embed path in the baseline theme took the URL from the post body:
    `<div data-stream-src="https://live.smarterwho.site/player/?channel=b1">` (the comment's
    example is edge mode) or the post's first `<iframe>`.
- **Current repository state [VERIFIED].**
  - Commit `4e0b11e` removed the player from the theme.
  - `b9e26d0` made the Worker strip every `stream` field (`blogger/worker/src/index.js:5-6, 36, 40`).
  - Migration `blogger/stream-manager/migrations/2026-11-21-no-public-stream-columns.sql`
    clears every `channel`/`r2_slug` value.
  - The untracked `blogger-posts-import.xml` contains no player iframe.
  - **No production embed code exists in the repository any more.**
- **Production framing allowlist [CLAIMED].** The working-tree nginx line
  (`stream-locations.conf:20-22`) says it is "the value verified on production (2026-11-23)":
  `'self' https://www.px-league.site https://px-league.site https://powerdoflearn.blogspot.com
  https://tariq-live.blogspot.com http://localhost:* http://127.0.0.1:*`.
  `tariq-live.blogspot.com` appears in no commit (`git log -S tariq-live` is empty), so the
  live nginx was edited on the server.
- **[UNKNOWN]** The iframe URLs actually used on those Blogger sites, whether they use `r2=`,
  `channel=` or both, and which slugs or keys they carry. This needs a look at the live posts.

### 3.6 Native HLS (Safari) path

When `Hls.isSupported()` is false but the browser can play `application/vnd.apple.mpegurl`, the
player sets `video.src = url` (`player/index.html:979-991`). In R2 mode that URL is
`…/index.html` without `_t`, so browser HTTP caching follows the R2/Cloudflare headers. Whether
Apple's native HLS stack accepts a playlist served as `text/html` with a `.html` extension is
[UNKNOWN] (not testable from source).

---

## 4. What CSS and JavaScript actually do

| Layer | Technology | Role in playback |
|---|---|---|
| Player UI | CSS in `player/index.html:13-317` | Layout, controls, spinner, quality menu. **No role in video data.** |
| Player logic | Inline JS (`player/index.html:389-1251`) | Picks the mode; calls `/api/r2`, `/api/stream`, `/api/token`, `/api/ping`; configures hls.js; adds `_t`; reads the `#PXL-*` markers; retries; watches for stalls; switches quality. It does not touch media bytes. |
| Media engine | hls.js 1.5.8 (CDN) | **Directly involved in retrieving and reconstructing video:** XHR download of playlist and segments, MPEG-TS demux, remux to fMP4, MSE `SourceBuffer` append. This is stock hls.js behaviour, with no custom transform. |
| "`.css`" files | M3U8 text (edge mode) | Playlist named `.css`. Never applied as a stylesheet. |
| "`.html`" files | M3U8 text (R2 mode) | Playlist named `.html`. Never rendered as a page. |
| "`.js`" files | MPEG-TS (H.264+AAC) | Video segment named `.js`, served as `application/javascript`. Never executed. |

A search for `WebSocket`, `new MediaSource`, `ManagedMediaSource`, `canvas`, `createObjectURL`,
`decrypt`, `atob(`, `EXT-X-KEY` and `wasm` across the player, backend, nginx and MediaMTX config
found nothing. **No encryption, no byte-level obfuscation, no WebSocket transport, no
canvas rendering and no custom MSE code exists.** [VERIFIED]

Separating the concepts the brief asks to keep apart:

- **Player technology:** hls.js on MSE, or native HLS, rendering into a `<video>` element.
- **Packaging format:** HLS v3 live media playlist with 2 s MPEG-TS segments and a 10-segment
  sliding window (`mediamtx.yml:75-89`). No master playlist and no ABR ladder. "HD" is a
  separate media playlist that the user picks manually.
- **Codecs:** H.264 Main, 480p (default 1000 kbit/s, max 1200 kbit/s) or 720p HD, 25 fps;
  AAC-LC 96 kbit/s, 44.1 kHz stereo (`server.js:861-884`, `909-941`). The `copy` profile
  passes the source codec through.
- **Transport:** plain HTTPS GET (HTTP/2 on nginx; Cloudflare in front of R2).
- **Storage format:** individual R2 objects, one per segment, plus one or two playlist objects
  per rendition, overwritten in place.

---

## 5. Stage-by-stage pipeline trace (one channel, e.g. `b1`)

| # | Stage | Code | Input → Output | Where the bytes live |
|---|---|---|---|---|
| 1 | Admin starts the restream | `POST /api/channels/:id/restream/start` or `/api/channels/start` (`server.js:2389-2410`, `2288-2311`); `validateSourceUrl` (SSRF block, `376-412`) | source URL → job | `channels.json` (`backend_data` volume) |
| 2 | Source probe | `probeSource()` `server.js:604-685`: master playlist → picks one variant; classes `hls-live`/`hls-vod`/`hls-frozen`/`file`/`stream`/`live`; VOD and frozen sources are looped from a rewritten local playlist | URL → probe result | `/tmp/restream-loops/*.m3u8` for looped sources |
| 3 | **FFmpeg #1, restreamer (transcode)** | `buildArgs()` `server.js:786-964`, `spawn('ffmpeg')` `1013` | source → bwdif, scale ≤480, eq, fps 25 → libx264 `veryfast`/`superfast` 1000k + AAC 96k → **FLV over RTMP** to `rtmp://mediamtx:1935/live/{key}?user=publish&pass={publishKey}` (`788-789`). Optional HD leg through the `tee` muxer to `live/{key}-hd` (`905-941`), disabled by default with `MAX_HD_ENCODES=0` (`server.js:465-468`, `docker-compose.yml:96`) | backend container RAM / network |
| 4 | **MediaMTX** ingest | `mediamtx.yml:19-50`; publish authorised by `POST /internal/mediamtx-auth` (`server.js:2756-2780`); native HLS, WebRTC and SRT off (`mediamtx.yml:38-40`) | RTMP in → RTSP relay on `:8554` | MediaMTX RAM |
| 5 | **FFmpeg #2, packager (no re-encode)** | `runOnReady` `mediamtx.yml:75-89`: `-c copy -bsf:v dump_extra -f hls -hls_time 2 -hls_list_size 10 -hls_flags delete_segments+omit_endlist -hls_start_number_source epoch` | RTSP → `index.m3u8` + `seg_{epoch}.ts` | **VPS disk**: volume `hls_data` at `/hls/live/{key}/` |
| 6 | Watcher | `R2PipelineManager.start()` chokidar on `/hls` (`server.js:1429-1464`); `resolveTarget()` maps `live/{key}` → `hd/{r2_slug}`, and `live/{key}-hd` → `hd/{r2_slug}/hd` (`1529-1555`) | file events | – |
| 7 | **Segment upload** | `handleSegment()` `server.js:1583-1604`; `uploadObject()` `1703-1734` (S3 `PutObject`, concurrency 4, 3 retries) | `seg_N.ts` → R2 key `hd/{slug}/seg_N.js`, `Content-Type: application/javascript`, `Cache-Control: public, max-age=3600, immutable` (`1374`) | **R2** |
| 8 | **Playlist upload** | `handlePlaylist()` `1606-1638` (rewrites `.ts`→`.js`, `1629`); `flushPlaylist()` `1647-1683` publishes the newest version whose segments are all uploaded; adds `#PXL-HD-AVAILABLE` while HD is fresh (`1667`) | `index.m3u8` → `hd/{slug}/index.html` (`text/html; charset=utf-8`) and `index.css` only if `R2_PLAYLIST_FILES` contains `css` (`1350-1361`); `Cache-Control: public, max-age=1, s-maxage=1` (`1342-1345`, default `R2_PLAYLIST_MAX_AGE=1`) | **R2**, overwritten every ≈2 s |
| 9 | Lifecycle (working tree only) | `endIdleStreams()` / `endStream()` `1467-1493`; `lib/stream-lifecycle.js` | After 45 s with no playlist the R2 playlist is overwritten with the "ended" body `#EXTM3U … #PXL-STREAM-ENDED #EXT-X-ENDLIST` (`stream-lifecycle.js:21`); an idle HD playlist is deleted after 45 s (`1500-1519`) | R2 |
| 10 | Pruning | `pruneOldSegments()` every 20 s (`1736-1806`): LIST `hd/`, delete `.js` older than `MAX_SEGMENT_AGE_SECONDS` (120) unless protected | – | R2 |
| 11 | Local janitor | `pruneLocalHls()` deletes `/hls` files older than 5 min (`1877-1915`) | – | VPS disk |
| 12 | CDN | R2 custom domain on Cloudflare. README §5 documents the intended cache rules (playlists: respect the 1 s origin TTL; segments: cache everything for 2-4 h). | – | **Cloudflare edge [UNKNOWN live config]** |
| 13 | Browser | R2 mode: GET `…/index.html?_t=…` and `…/seg_N.js`. Edge mode: GET `/live/{key}/index.css` and `/live/{key}/seg_N.js` from nginx | – | browser MSE buffer |

**What R2 holds:** only `.js` segments (MPEG-TS) and `index.html` (plus optional `index.css`)
playlists under `hd/{slug}/` and `hd/{slug}/hd/`. No CSS or JS of the player, no hls.js and no
HTML pages are uploaded to R2. [VERIFIED; `uploadObject` is called only from segment, playlist
and ended-playlist paths]

**Does the VPS carry viewer video?** R2 mode: no. Edge mode: yes (origin for segments and every
playlist request). [VERIFIED]

**Does the browser talk to the VPS during playback?** Yes, in both modes: the player page
loads, the R2 lookup or token runs, and the heartbeat `POST /api/ping/...` goes out every 15 s
for the whole session (`player/index.html:1098-1117`). Edge mode adds token renewal every
≈30 s and every playlist reload. [VERIFIED]

---

## 6. Network request map

Abbreviations: VPS = `live.smarterwho.site` (nginx → backend; Cloudflare-proxied [INFERRED]);
R2CD = R2 custom domain (Cloudflare in front of R2). Frequencies are per viewer.

### 6.1 Current working-tree player (`player/index.html`)

| Phase | Request | Method | Destination | Response | Frequency | Cache behaviour | VPS load? | Source |
|---|---|---|---|---|---|---|---|---|
| Load | `/player/?r2=…` or `?channel=…` | GET | VPS (nginx static) | HTML ≈50 KB | 1 per page view | `no-cache, must-revalidate`; Cloudflare does not cache HTML by default [UNKNOWN rules] | yes | `stream-locations.conf:15-24` |
| Load | `cdn.jsdelivr.net/npm/hls.js@1.5.8/...` | GET | jsDelivr | JS | 1 (browser-cached) | public CDN | no | `index.html:12` |
| Load | `fonts.googleapis.com` / `fonts.gstatic.com` | GET | Google | CSS / fonts | 1 | public CDN | no | `index.html:8-10` |
| Config (R2) | `/api/r2/{slug}` | GET | VPS → Node | JSON `{base, hdSignal}` | 1 per start; retried with backoff 2.5-5 s … 30-60 s on failure | `no-store` | yes | `index.html:837`, `server.js:2667` |
| Config (R2, old backend) | `/api/config` | GET | VPS → Node | JSON incl. `r2CustomDomain` | only if `/api/r2` answers an HTML 404 | `private, no-store` | yes | `index.html:1179-1188`, `server.js:2147-2160` |
| Config (edge) | `/api/stream?channel={key}` | GET | VPS → Node | JSON token + `Set-Cookie stream_auth` | 1 per start | `no-store` | yes | `index.html:608-618`, `server.js:2638` |
| Token refresh (edge) | `/api/token` | POST | VPS → Node | JSON token + cookie | every `expiresIn − 15` s = **every 30 s** (default 45 s) | `no-store` | yes | `index.html:602-645`, `server.js:2684` |
| Playlist (R2) | `{base}index.html?_t={unix seconds}` | GET | R2CD | M3U8 text (`text/html`) | ≈1 per 2 s (hls.js live reload) | Origin header `public, max-age=1, s-maxage=1`; `_t` changes the URL each second | no | `index.html:495-504`, `server.js:1342-1345` |
| Playlist (edge) | `/live/{key}/index.css` (+ Bearer + cookie) | GET | VPS nginx (+ `/auth` subrequest) | M3U8 text (`text/css`) | ≈1 per 2 s | `no-store`; `/auth` result cached 20 s per client | **yes, every reload** | `stream-locations.conf:108-163` |
| Segment (R2) | `{base}seg_{epoch}.js` | GET | R2CD | MPEG-TS ≈250-300 KB [INFERRED from bitrate] | 1 per 2 s | `public, max-age=3600, immutable`; identical URL for all viewers | no | `server.js:1374, 1589-1595` |
| Segment (edge) | `/live/{key}/seg_{epoch}.js` | GET | VPS nginx (proxy_cache) | MPEG-TS | 1 per 2 s | `public, max-age=60, immutable`; nginx cache 60 s | yes on Cloudflare miss | `stream-locations.conf:175-224` |
| HD (new backend) | none: availability is read from the `#PXL-HD-AVAILABLE` line in the SD playlist | – | – | – | 0 | – | no | `index.html:1170-1177`, `server.js:1667` |
| HD (old backend, `hdSignal='probe'`) | `{base}hd/index.html?_t=…` | GET | R2CD | M3U8 or 404 | every 60 s | `fetch(cache:'no-store')`; 404 caching on Cloudflare [UNKNOWN] | no | `index.html:1152-1162, 865-868` |
| HD playback | `{base}hd/index.html?_t=…` + `{base}hd/seg_N.js` | GET | R2CD | as above, 720p | as SD | as SD | no | `index.html:1198-1213` |
| Heartbeat | `/api/ping/{slug or key}?sid={uuid}` | POST (`sendBeacon`, fallback `fetch keepalive`) | VPS → Node | 204 empty | at first `playing`, then **every 15 s while playing** | `no-store`; POST is never cached | **yes** | `index.html:1098-1117`, `server.js:1944-1957` |
| Error recovery (R2) | `{base}index.html?_t=…` probe (`fetch cache:'no-store'`) then `hls.loadSource` | GET | R2CD | M3U8 | backoff 1-2 s, 2-4 s, … capped 15-30 s; reset when a segment loads | as playlist | no | `index.html:1030-1039, 589-594` |
| Error recovery (edge) | `/api/stream` again on 401/403, then playlist reload | GET | VPS | – | on failure | – | yes | `index.html:1041-1061` |
| hls.js internal retries | same playlist/segment URLs | GET | as above | – | playlist: 2 timeout + 2 error retries; fragment: 4 + 6; base delay random 0.5-1.5 s, capped 8 s | – | – | `index.html:474-488, 585` |
| Stall watchdog | triggers the recovery above | – | – | – | if `currentTime` frozen > 20 s (checked every 2 s) | – | – | `index.html:1077-1091` |

### 6.2 Dynamic query parameters

| Parameter | Where | Purpose | Cache-key effect |
|---|---|---|---|
| `_t={floor(Date.now()/1000)}` | cross-origin playlist URLs (R2 mode), HD probe, recovery probe | Defeats the **browser** HTTP cache. The production-fixture comment (`legacy-player.html:731-733`) says it was needed because "the CDN currently sends max-age=14400" on playlists [CLAIMED]. | Cloudflare's default cache key includes the query string, so each second is a new cache key per playlist per PoP. Viewers in the same second at the same PoP share one entry; at most ≈1 origin (R2) fetch per playlist per PoP per second, **if** the playlist is cache-eligible. If Cloudflare is set to ignore the query string, `_t` has no CDN effect. [UNKNOWN live setting] |
| `sid={uuid}` | `/api/ping` | identifies one viewer session for the counter | not cached (POST) |
| `token=` | optional `?token=` on the player URL; `/auth` also accepts `?token=` on playlist URLs (`server.js:2628-2635`) | edge-mode auth | the edge playlist is `no-store` anyway |
| `channel` / `r2` / `src` | player page URL | mode selection | player HTML is `no-cache` |

Segments never carry a query parameter in any mode (`xhrSetup` returns early for cross-origin
requests; the pLoader only wraps playlist loads). [VERIFIED]

### 6.3 Differences in the production player (fixture `backend/test/fixtures/legacy-player.html`, claimed copy of production on 2026-11-23)

- R2 lookup: always `GET /api/config`, and the R2 domain is read from `r2CustomDomain`
  (`legacy-player.html:657-679`). If the field is missing, it silently uses the placeholder
  `r2-custom-domain.shop` (line 661).
- HD: **always** probes `{base}hd/index.html?_t=…` every 60 s (`421`, `676-678`, `917-925`).
  This is an extra R2/CDN request per viewer per minute, and a 404 when HD is off.
- Retries: fixed 3 s (`769-790`, `834-855`), no jitter or backoff. A stall over 20 s reloads.
- No ended-playlist handling (the backend does not write one in that generation).
- Same `_t` pLoader (`734-741`), same 15 s heartbeat (`866-882`), same `liveSyncDuration: 12`.

---

## 7. R2 / CDN object and caching architecture

### 7.1 Object layout [VERIFIED: `server.js:1529-1560`, `1350-1374`, `stream-lifecycle.js:44-48`]

```
{bucket}/hd/{r2_slug}/index.html        SD playlist   text/html; charset=utf-8   public, max-age=1, s-maxage=1   overwritten ≈ every 2 s
{bucket}/hd/{r2_slug}/index.css         (only if R2_PLAYLIST_FILES includes css; default html only)
{bucket}/hd/{r2_slug}/seg_{epoch}.js    SD segment    application/javascript     public, max-age=3600, immutable  write-once, deleted after ≥120 s
{bucket}/hd/{r2_slug}/hd/index.html     HD playlist   (exists only while HD runs; deleted 45 s after it stops)
{bucket}/hd/{r2_slug}/hd/seg_{epoch}.js HD segment
```

- **Immutable:** segments. Names come from `-hls_start_number_source epoch`, so a restart never
  reuses a name (`mediamtx.yml:70-74`). [VERIFIED]
- **Mutable:** playlists, overwritten in place every ≈2 s, and the ended body after 45 s idle
  (working tree only).
- **Player CSS/JS are not in R2.** The player HTML (with inline CSS/JS) comes from nginx on the
  VPS, and hls.js comes from jsDelivr. Video data and player code are cached in completely
  separate places. [VERIFIED]
- **Are playlists actually used by production viewers?** Yes. Every HLS client must reload the
  live playlist to find new segments. In R2 mode that is `hd/{slug}/index.html`. [VERIFIED for
  code; production mode UNKNOWN, see 3.5]
- **R2 is the origin for the actual video bytes** in R2 mode. Every segment byte a viewer
  receives in R2 mode was written to R2 by `handleSegment`. [VERIFIED]

### 7.2 CDN behaviour (code vs live)

- The origin headers above are set by the uploader. **Whether Cloudflare honours them is not
  determinable from source.** README §5 (`README.md:309-341`) describes the intended rules:
  - Rule A: playlists eligible for cache with Edge TTL "use cache-control header" (1 s). Without
    it, `.html` is not cached by default and every reload is an R2 read.
  - Rule B: `.js` segments "cache everything" with a 2-4 h edge TTL.
- The fixture comment "CDN currently sends max-age=14400" (4 h) suggests the live zone overrides
  Browser TTL to 4 h on at least the playlist responses. If the edge TTL is also 4 h, the edge
  copy of a playlist goes stale and only `_t` keeps viewers moving (new cache key each second).
  [CLAIMED / UNKNOWN]
- CORS on R2: README prescribes `AllowedOrigins: ["*"]` (`README.md:271-298`). The player relies
  on non-credentialed cross-origin XHR to R2CD (`xhrSetup` comment, `player/index.html:936-937`).
  [UNKNOWN live]
- **Access control in R2 mode: none.** The Referer lock and tokens apply only to nginx edge
  mode. README admits that R2 mode "is not covered by this lock" (`README.md:385`). Anyone who
  knows a slug can fetch playlists and segments from R2CD. [VERIFIED + documented]

### 7.3 Edge-mode caching (VPS)

- Playlists: `no-store` at nginx, and every request triggers `auth_request`
  (`stream-locations.conf:127, 149`).
- Segments: nginx `proxy_cache` 60 s with `proxy_cache_lock`, and `Cache-Control: public,
  max-age=60, immutable` (`175-224`). Cloudflare caches `.js` by default extension, which would
  make segments edge-cacheable. Cached responses then bypass the nginx Referer lock (documented
  in `referer-lock.conf:258-259`). [INFERRED]

---

## 8. Production vs repository vs working tree

### 8.1 What each environment runs

| Component | Baseline `872a75b` (main) | HEAD `103f4d9` (committed) | Working tree (uncommitted) | Production on 2026-11-23 |
|---|---|---|---|---|
| `/player/` page | `index.html` (no HD menu, `liveSyncDuration: 5`) and `index.hd-menu.html` (HD menu, `liveSyncDuration: 12`, `_t` pLoader) differ | `/api/r2` lookup, otherwise as baseline | Both files identical; adds PxlRetry backoff, ended/HD markers, `/api/config` fallback | **[CLAIMED]** = `e996297:player/index.hd-menu.html`. Verified: the fixture is byte-identical (after CRLF normalisation) to that blob, so production serves the *hd-menu* variant as `index.html`. The fixture's provenance is a comment (`player-backend-compat.test.js:3-4`). |
| Backend `/api/config` | public, includes `r2CustomDomain`, `max-age=300` | **`r2CustomDomain` for admins only** (`d791ef7`) | public again, only when it is a real hostname (`server.js:95-99, 2147-2160`) | **[CLAIMED]** includes `r2CustomDomain`, no `/api/r2` (`player-backend-compat.test.js:6-7`) |
| `/api/r2/:slug` | absent | present | present + `hdSignal` | **[CLAIMED]** absent |
| Viewer tokens | 60 s, unbound | 45 s, UA-bound, page gate | same | [UNKNOWN] |
| Ended-playlist / lifecycle / reconcile | absent | absent | present (`lib/stream-lifecycle.js`, `server.js:1376-1519, 1808-1860`) | absent [INFERRED from the "old backend" claim] |
| `/api/health` version | absent | absent | `BUILD_SHA` (`server.js:62, 2129-2138`) | absent [CLAIMED by `deploy/check-drift.sh:49` logic; not run] |
| nginx `frame-ancestors` | `'self' powerdoflearn` | **`'self'` + `X-Frame-Options SAMEORIGIN`** (`780fcef`) | production allowlist incl. `tariq-live`, px-league, localhost | **[CLAIMED]** = working-tree value |
| `/auth` cache | 60 s, key without UA/IP | 20 s, key with UA/IP | same as HEAD | [UNKNOWN] |
| Blogger theme player | present (reads `match_info.stream`) | removed | removed | [UNKNOWN] which theme is live |

No "staging" environment is defined anywhere in the repository (no file mentions it outside
`node_modules`). "Staging uploader fixes" can only refer to the **uncommitted working-tree
changes** to `backend/server.js` and `backend/lib/stream-lifecycle.js`. Where they have run, if
anywhere, is [UNKNOWN].

### 8.2 Git state [VERIFIED]

- `872a75b` is an ancestor of `main`. `main` = `origin/main` = `844e326`.
- The current branch is 2 commits ahead of `main` (`26d90e7`, `103f4d9`, theme/legal only) and
  in sync with its remote.

---

## 9. Changes since `872a75b` and regression audit

### 9.1 Committed changes touching playback, routing or headers

| Commit | Files | Change | Effect on production playback if deployed |
|---|---|---|---|
| `c499275`, `a131feb` | `backend/public/admin.html` | admin UI source-URL edit mode | none for viewers |
| `3f8bae5`, `51d8c34` | `stream-locations.conf` | adds px-league.site and localhost to `frame-ancestors`. `51d8c34` says it "matches the snippet deployed … 2026-11-19" | widens framing |
| `d791ef7` | `server.js`, `stream-locations.conf`, compose, `.env.example`, players | token 60→45 s with UA binding; `requireViewerPage` gate on `/api/stream`, `/api/token`, `/api/r2`; new `/api/r2/:slug`; **`/api/config` hides `r2CustomDomain` from anonymous callers**; `/auth` cache 60→20 s keyed by UA+IP; player uses `/api/r2` | **Regression risk:** the production player builds R2 URLs from `/api/config.r2CustomDomain`. Deploying this backend without the matching player makes production R2 embeds fall back to `https://r2-custom-domain.shop/...` and fail [INFERRED from `legacy-player.html:661-667`]. Edge mode: about 3× more `/auth` calls reach Node (20 s vs 60 s cache, per-client keys). Third-party embeds call `/api/stream` with a Referer from the iframe's own page (`/player/`), which passes the gate [INFERRED]. |
| `780fcef` | `stream-locations.conf` | `frame-ancestors 'self'` + `X-Frame-Options: SAMEORIGIN` | **Regression risk:** blocks every Blogger embed. The working tree reverts it. |
| `ea2184d` | `deploy/vps-firewall.sh` | firewall script | ops only, not evaluated |
| `1776f92`, `b9e26d0`, `4e0b11e` | Worker, theme | Worker moved to `data.px-league.site`; streams stripped; player removed from theme | Removes the px-league.site embed path entirely |

### 9.2 Uncommitted working-tree changes

| File | Change | Playback effect |
|---|---|---|
| `player/index.html`, `player/index.hd-menu.html` | Now identical. Adds the `pxl-retry` module (jittered exponential backoff), hls.js load policies with a random base delay, ended-playlist → 410 handling, HD marker reading (no 60 s HD probe against the new backend), `/api/r2` with `/api/config` fallback | Fewer synchronised retries; one fewer request per viewer per minute; works against both backend generations [VERIFIED by reading; tests present but **not run** here] |
| `backend/server.js` + new `backend/lib/stream-lifecycle.js` | ended playlist after 45 s idle; HD marker in the SD playlist; per-prefix locks; stale-playlist reconciliation and prune protection; `/api/config` again publishes `r2CustomDomain`; `/api/r2` returns `hdSignal`; `BUILD_SHA` | Changes what R2 contains when a stream stops: the playlist becomes an ended body instead of a frozen live list. Old production players do not recognise `#PXL-STREAM-ENDED`; they see `#EXT-X-ENDLIST` with no segments, which hls.js treats as an ended VOD. They rely on their 20 s stall watchdog and fixed 3 s reloads [INFERRED; not tested here] |
| `nginx/snippets/stream-locations.conf` | restores the production framing allowlist (incl. `tariq-live.blogspot.com`); removes `X-Frame-Options` | matches the claimed production state |
| `docker-compose.yml` | `STREAM_ENDED_IDLE_SECONDS`, `BUILD_SHA` env | – |
| `backend/package.json`, `.dockerignore` | `node --test`, devDependency hls.js 1.5.8; `test/` excluded from the image | none at runtime |
| `deploy/check-drift.sh` (new) | read-only curl comparison of production vs repo | not run in this investigation |
| `backend/test/**` (new) | unit, e2e (fake S3), player/hls.js tests | **not run** (instructed not to run tests) |
| `latestoflearn.xml` deleted; `blogger-posts-import.xml` added | Blogger content | none |

### 9.3 Behaviours that changed or could break (summary)

1. HEAD backend + production player → R2 mode breaks (placeholder domain). Mitigated only by the
   working-tree backend change. [INFERRED]
2. HEAD nginx → all cross-site embeds blocked. Mitigated by the working tree. [VERIFIED by config]
3. The production nginx was hand-edited (an origin that is in no commit). Repo and server
   drifted. [CLAIMED + verified absence in git history]
4. Production player ≠ any committed `player/index.html`; it equals an `index.hd-menu.html`
   blob. Deploying `player/` from HEAD would change production player behaviour. [VERIFIED
   blob match; production provenance CLAIMED]
5. The working-tree ended-playlist logic changes the stream-stop behaviour seen by old players.
   [INFERRED]

Nothing in the repository proves which of these states (if any) is deployed beyond the fixture
and comment claims.

---

## 10. Capacity analysis for 50,000 concurrent viewers

This section only derives demand from the code. It gives **no readiness verdict**; the deciding
numbers are live Cloudflare settings and live measurements.

Assumptions (stated, not verified): single 480p rendition at ≈1.1-1.2 Mbit/s incl. TS overhead
(1000k video + 96k audio, `server.js:440, 883`); 2 s segments; hls.js reloads the playlist
every ≈2 s.

### 10.1 Per-component demand

| Component | Driver in code | Demand at 50k viewers (R2 mode) | Depends on viewers? |
|---|---|---|---|
| **VPS ingest / transcode** | FFmpeg #1 per channel (`server.js:786-964`); FFmpeg #2 copy per channel | README measures ≈1.17 cores per 480p channel from an HEVC 1080p50 source; 4 channels ≈4.7 cores on a 4-vCPU box (`README.md:234-244`) [CLAIMED measurement] | **No** (per channel) |
| **Upload to R2** | 1 segment PUT + 1 playlist PUT (html only) per channel per 2 s; LIST every 20 s; batched deletes (`server.js:1334-1390`) | ≈1.2 Mbit/s and ≈1 Class A op/s per channel (4 channels ≈4.8 Mbit/s, ≈4 PUT/s). Concurrency 4 per process (`1334`) | **No** |
| **Cloudflare edge egress** | segments to every viewer | ≈50k × 1.15 Mbit/s ≈ **55-60 Gbit/s** aggregate; ≈25k segment req/s | yes |
| **Playlist requests at edge** | hls.js reload + `_t` | ≈25k req/s | yes |
| **R2 origin reads (playlists)** | cache-key-per-second via `_t`; origin TTL 1 s | best case ≈1 read per playlist per active PoP per second; **worst case (playlist not cache-eligible) ≈25k Class B reads/s** (as README states) | yes, bounded only by CDN config [UNKNOWN] |
| **R2 origin reads (segments)** | immutable, identical URLs | best case ≈1 read per segment per PoP (tiered cache further reduces it); worst case 25k/s | config-dependent [UNKNOWN] |
| **HD probe (production player only)** | `hd/index.html?_t=` every 60 s | ≈830 req/s of mostly 404s when HD is off; 404 caching [UNKNOWN] | yes |
| **VPS: heartbeat** | `POST /api/ping/...` every 15 s (`player/index.html:1117`) | ≈**3,300 req/s** through Cloudflare → nginx → single Node process; uncacheable POSTs. Per request: regex test + `Map.set`; sweep every 5 s iterates all sessions (`server.js:1967-1973`) | **yes** |
| **VPS: player page** | `/player/` `no-cache` | 1 per view; a kickoff surge (e.g. 50k joins in 2-5 min) ≈170-420 req/s of ≈50 KB HTML from nginx unless Cloudflare caches it [UNKNOWN] | yes |
| **VPS: R2 lookup** | `/api/r2` (new) or `/api/config` (prod) once per start, plus retries | same surge rate as the player page; trivial Node work | yes |
| **VPS: edge mode (if used)** | every playlist reload hits nginx + `auth_request` | ≈25k req/s to nginx; `/auth` cached 20 s per client → ≈2.5k req/s to Node (comment in `stream-locations.conf:93-95` says ≈500/s per 10k); token renewals ≈1.7k req/s; segment bytes from the VPS on every Cloudflare miss | **yes, heavily** |

### 10.2 What determines the ceiling (from code)

1. **Delivery mode.** In R2 mode, video scale is a Cloudflare/R2 question. In edge mode, every
   playlist reload of every viewer reaches the VPS, which makes the VPS the limit.
2. **Cloudflare cache rules on the R2 custom domain** (playlist eligibility, query-string
   handling of `_t`, segment edge TTL, 404 caching, tiered cache). These decide whether R2 sees
   tens or tens of thousands of reads per second. Not in the repo.
3. **The VPS heartbeat** is the only per-viewer load on the VPS in R2 mode that runs for the
   whole session: ≈3.3k uncacheable POST/s into one Node process that also runs the R2
   uploader, the FFmpeg supervisors and the admin API.
4. **CPU for transcoding** limits the number of channels, not viewers. README says 4 HEVC
   1080p50 channels already exceed 4 vCPUs.
5. **Retry storms.** On a playlist/R2 failure, the production player retries at fixed 3 s with
   no jitter (`legacy-player.html:769-790`). The working-tree player uses jittered backoff.
   Which one runs decides how 50k clients behave during an incident.

---

## 11. Unknowns that need live inspection

1. The actual iframe URLs in live posts on `powerdoflearn.blogspot.com`,
   `tariq-live.blogspot.com`, `px-league.site` (`r2=` vs `channel=` vs both; which slugs).
2. Which theme version is live on each Blogger site.
3. The live `/player/` bytes, nginx config, backend build and env (`R2_CUSTOM_DOMAIN`,
   `R2_PLAYLIST_MAX_AGE`, `R2_PLAYLIST_FILES`, `TOKEN_*`, `VIEWER_TOKEN_BIND`, `MAX_HD_ENCODES`,
   `RESTREAM_HD_MODE`, `ALLOWED_ORIGINS`) and `channels.json` (key↔slug, `hdEnabled`). The
   fixture and comment claims should be re-confirmed (`deploy/check-drift.sh` was written for
   this; it was not run here).
4. The R2 custom-domain hostname; its Cloudflare cache rules, Browser/Edge TTL overrides
   (the "14400" claim), cache-key query-string setting, tiered cache, 404 caching; R2 CORS
   policy.
5. Whether `live.smarterwho.site` is orange-clouded, and the Cloudflare rules for `/player/`,
   `/api/*`, `/live/*`; whether any rate limiting or WAF affects `/api/ping`.
6. Whether the working-tree backend has run anywhere (the "staging" environment is not defined
   in the repo).
7. Whether native Safari/iOS HLS accepts `text/html` playlists from R2 (R2 mode on devices where
   hls.js is unsupported).
8. Real segment sizes and bitrates per channel (source-dependent), the VPS NIC/bandwidth plan,
   and the measured CPU at 4 channels.
9. Real heartbeat throughput of the single Node process under ≈3.3k POST/s while uploading.
10. Whether any embed uses `?src=` or `?token=`.

---

## 12. Key source references (index)

| Claim | Location |
|---|---|
| Disguised extensions in R2 | `backend/server.js:1557-1560` (`.ts`→`.js`), `1629` (playlist rewrite), `1350-1353` (`index.html`/`index.css` names and types) |
| Segment headers | `backend/server.js:1374`, `1589-1595` |
| Playlist headers | `backend/server.js:1342-1345`, `1669-1671` |
| R2 key layout | `backend/server.js:1529-1555`; `backend/lib/stream-lifecycle.js:44-48` |
| Ended / HD markers | `backend/lib/stream-lifecycle.js:19-42`; `backend/server.js:1475-1519, 1667` |
| Pruning | `backend/server.js:1736-1806` |
| Restreamer FFmpeg args | `backend/server.js:786-964`, `1013` |
| Packager FFmpeg (HLS) | `mediamtx.yml:75-89` |
| MediaMTX auth hook | `mediamtx.yml:19-21`; `backend/server.js:2756-2780` |
| Edge playlist / segment camouflage | `nginx/snippets/stream-locations.conf:108-224`; `nginx/nginx.conf:141-168` |
| Edge auth | `nginx/snippets/stream-locations.conf:68-102`; `backend/server.js:2715-2748` |
| Viewer API | `backend/server.js:2638-2712`; gate `2563-2581` |
| Heartbeat | `player/index.html:1098-1117`; `backend/server.js:1933-1973` |
| Player mode selection | `player/index.html:538-542, 824-897` |
| hls.js config, `_t`, xhrSetup | `player/index.html:908-947, 495-519` |
| Retry policies | `player/index.html:404-488, 585-594, 1030-1091` |
| Production player (claimed) | `backend/test/fixtures/legacy-player.html:657-679, 734-741, 769-790, 866-882, 917-925`; provenance `backend/test/player-backend-compat.test.js:1-7` |
| Production framing (claimed) | `nginx/snippets/stream-locations.conf:20-22` |
| Baseline embed generator | `git show 872a75b:blogger/px-league-theme.xml` (`streamUrl()`, post `data-stream-src` handler) |
| Stream removal from site | `blogger/worker/src/index.js:5-6, 36, 40`; `blogger/stream-manager/migrations/2026-11-21-no-public-stream-columns.sql` |
| Intended Cloudflare rules (docs, not live) | `README.md:248-341, 371-385` |
| Capacity measurements (docs) | `README.md:234-244`; `backend/server.js:458-468` |
