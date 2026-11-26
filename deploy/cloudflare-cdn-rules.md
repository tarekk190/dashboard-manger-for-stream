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
