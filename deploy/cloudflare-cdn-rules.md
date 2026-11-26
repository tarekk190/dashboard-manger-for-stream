# Cloudflare rules for the R2 custom domain (cdn.vsbskl.site)

No Worker runs on this hostname: every playlist and segment is answered from Cloudflare's cache
or R2 directly. The checks below are a **WAF custom rule**, which costs nothing per request, is
available on every plan (Free: 5 custom rules), and runs before the cache, so it also applies
to cached responses.

Access control itself comes from the backend (`STREAM_PATH_SECRET`, see `backend/server.js`,
"Secret R2 paths"): playlists only exist under a rotating secret key, and segment names are
unguessable. This rule adds the browser-side checks on top of that.

## Rule "PXL CDN lock" (Security -> WAF -> Custom rules, zone vsbskl.site), action: Block

```
(http.host eq "cdn.vsbskl.site") and (
  (http.request.method ne "GET" and http.request.method ne "HEAD" and http.request.method ne "OPTIONS")
  or not starts_with(http.request.uri.path, "/hd/")
  or (http.referer ne "" and not starts_with(http.referer, "https://live.smarterwho.site/"))
  or (any(http.request.headers["origin"][*] ne "https://live.smarterwho.site"))
)
```

- **Referer**: the player (`https://live.smarterwho.site/player/`) sends `https://live.smarterwho.site/`
  (nginx sets `Referrer-Policy: strict-origin-when-cross-origin`). A `<video>` or hls.js on any
  other site sends that site's address and is blocked, even with a valid key. Requests without
  a Referer (native iOS HLS, the data Worker's `/api/channel-status`) pass. They still need the
  secret path.
- **Origin**: the same check for CORS requests (hls.js XHR/fetch).
- Local testing of the player from `http://localhost:*` is blocked by design. Add
  `or starts_with(http.referer, "http://localhost:")` to the Referer test while testing.

## Rule "PXL legacy playlists" (add AFTER the cutover), action: Block

After the new player is live and `R2_LEGACY_PLAYLIST=false` is set on the backend, the old
public names must stop answering (their last copy stays in R2 otherwise):

```
(http.host eq "cdn.vsbskl.site") and (
  ends_with(http.request.uri.path, "/index.css")
  or (ends_with(http.request.uri.path, "/index.html") and not http.request.uri.path contains "/w/")
)
```

## Also check

- R2 bucket -> Settings -> **Public Development URL (r2.dev): Disabled**. It would serve the
  bucket without these rules.
- The cache rule for playlists must match the new path too: `hd/{slug}/w/{key}/index.html`
  (`ends_with(http.request.uri.path, "/index.html")` does; a fixed `/hd/*/index.html` wildcard
  also matches, because `*` spans `/`). Expected: `cf-cache-status: HIT` within the same second,
  `max-age=1`.
- Segments (`/hd/{slug}/seg_N-xxxx.js`) keep the "cache everything" rule.

## Viewer sessions: Turnstile widget (zone of the player domain, `live.smarterwho.site`)

The backend hands out playlist keys (`/api/r2/:slug`) and edge tokens (`/api/stream`) only to a
viewer session, and a session only after a passed Turnstile check (`POST /api/session`).

1. Cloudflare dashboard -> **Turnstile** -> **Add widget**.
   - Hostnames: `live.smarterwho.site` (the player page; the blogs only frame it).
   - Widget mode: **Invisible** (or Managed: shows a checkbox only to suspicious visitors).
2. Put the keys in the root `.env`: `TURNSTILE_SITE_KEY=...` and `TURNSTILE_SECRET_KEY=...`,
   then `docker compose up -d backend`.
3. Check: the backend log no longer prints `TURNSTILE_SITE_KEY/TURNSTILE_SECRET_KEY not set`;
   `POST /api/session` without a token answers `403 {"error":"challenge_failed"}`.

Deploy between matches: an open player tab from before this change cannot get a token any more
and keeps retrying until it is reloaded.

## Rate limiting rule (zone of the player domain), action: Block for 10 s

Free plan: one rule. It stops a script that hammers the session/token endpoints before the
request reaches nginx (nginx `viewer_api` still limits each IP at 120/min behind it).

```
(http.host eq "live.smarterwho.site") and (
  starts_with(http.request.uri.path, "/api/session")
  or starts_with(http.request.uri.path, "/api/r2/")
  or http.request.uri.path eq "/api/stream"
  or http.request.uri.path eq "/api/token"
)
```

Characteristics: IP. Period: 10 s. Requests: **30**. A normal viewer makes 1-3 of these
requests per minute; 30 per 10 s per IP leaves room for a few dozen viewers behind one mobile
carrier (CGNAT) address at kickoff.

## Origin segments (`live.smarterwho.site/live/*.js`): keep the query string in the cache key

Origin-path segments now need `?e=..&s=..` (a signature the authenticated playlist adds, shared by
all viewers of a channel for 2-4 minutes). Cloudflare's default cache key includes the query
string, which is what makes this work: a cached segment is only served for the URL with the
signature. **Do not** add a cache rule that ignores the query string for `/live/*`, or Cloudflare
would serve cached segments to anyone who guesses a segment name.

## R2 hostname: tighten the empty-Referer exception (after testing on an iPhone)

The `PXL CDN lock` rule above lets requests without a Referer through, for native iOS HLS. That
also lets curl and VLC through (they still need the rotating secret key, which now requires a
Turnstile session). To keep the exception for Apple's player only, replace the Referer line with:

```
  or (http.referer eq "" and not (
        starts_with(http.user_agent, "AppleCoreMedia/")
        or (http.user_agent contains "iPhone" or http.user_agent contains "iPad" or http.user_agent contains "Macintosh")
     ))
  or (http.referer ne "" and not starts_with(http.referer, "https://live.smarterwho.site/"))
```

A User-Agent can be faked, so this only removes default curl/VLC/ffmpeg clients. Test playback on
a real iPhone (Safari and Chrome) right after enabling it, and remove it again if video stops.
