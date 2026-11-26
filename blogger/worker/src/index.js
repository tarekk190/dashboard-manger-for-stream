// =============================================================================
// PX League - Cloudflare Worker: API proxy (ysscores matches + standings) with strict CORS,
// per-IP rate limiting, an edge response cache and show/hide filtering from the Master Match
// Controller (Supabase table "match_settings").
// Streams are per origin:
//   - STREAM_ORIGINS (px-league.site, www.px-league.site, tariq-live.blogspot.com): match
//     responses get "stream": { channel, r2_slug } from match_settings, so the blog can embed
//     our player (live.smarterwho.site/player/).
//   - every other allowed origin (e.g. the old powerdoflearn.blogspot.com address): NO stream
//     data; any "stream" field is stripped. The two kinds never share an edge cache entry.
// -----------------------------------------------------------------------------
// >>> YOUR BLOG ORIGIN(S) <<<
// Exact origins: scheme + host only. A trailing slash is tolerated (it is removed below),
// because browsers send the Origin header WITHOUT one.
// The blog moved to the custom domain www.px-league.site (2026-11-19). Blogger 301-redirects
// the apex and the old *.blogspot.com address to it, but both stay listed so a page that was
// still open (or a cached copy) on the old host keeps working.
// Extra origins can be added without a code change via the ALLOWED_ORIGINS var (comma separated).
const ALLOWED_ORIGINS = [
  "https://www.px-league.site",
  "https://px-league.site",
  "https://powerdoflearn.blogspot.com",
].map((o) => o.trim().replace(/\/+$/, ""));
// Origins that receive stream data (each is also an allowed site origin). More can be added
// without a code change via the STREAM_ORIGINS var (comma separated).
const STREAM_ORIGINS = [
  "https://www.px-league.site",
  "https://px-league.site",
  "https://tariq-live.blogspot.com",
].map((o) => o.trim().replace(/\/+$/, ""));
// The dashboard's origin(s) come from the DASHBOARD_ORIGINS variable (comma separated),
// e.g. "https://dashboard.example.com". Only they may ask for ?raw=1.
// The local dashboard (VS Code Live Server on port 5500) is always a dashboard origin too.
// Only a browser page served from this machine's port 5500 sends this Origin, so other sites
// gain nothing from it (an Origin header is forgeable by non-browser clients anyway).
const LOCAL_DASHBOARD_ORIGINS = [
  "http://127.0.0.1:5500",
  "http://localhost:5500",
];
// -----------------------------------------------------------------------------
// Routes (GET only):
//   /api/matches/...            -> https://api-ar.ysscores.com/api/matches/...
//       e.g. /api/matches/matches_date_get/{YYYY-MM-DD}/[]/[]/["8634"]/D/60
//            /api/matches/match_info/{match_id}/D/60
//       matches_date_get: matches with is_visible = false are removed
//       match_info:       passed through (hidden matches stay reachable by id)
//       STREAM_ORIGINS:   a match with a stream gets "stream": { "r2_slug": "..." } (or { "channel" } if no slug)
//                         (list and match_info). A FINISHED match (status 4) never gets one.
//       Other origins:    any "stream" field is removed.
//       ?raw=1 (dashboard origins only): no filtering, no edge cache
//   /api/standings/{id}?include=results
//                               -> https://football-poster-generator.vercel.app/api/standings/{id}?include=results
//   /api/active-streams         -> 410 Gone (themes read match_info.stream instead)
//   /api/channel-status?slugs=a,b  (dashboard origins only) -> { channels: { slug: { live, ageSec } } }
//   /api/health                 -> {"status":"ok"}
//
// Secrets / vars / bindings:
//   wrangler secret put SUPABASE_URL        https://<project>.supabase.co
//   wrangler secret put SUPABASE_ANON_KEY   anon JWT or sb_publishable_... key (RLS: read-only)
//   DASHBOARD_ORIGINS (var)                 https://your-dashboard.vercel.app
//   ALLOWED_ORIGINS (var, optional)         extra blog origins, added to the list above
//   STREAM_ORIGINS (var, optional)          extra stream-enabled origins, added to STREAM_ORIGINS
//   R2_PUBLIC_BASE (var)                    R2 public domain of the HLS files, for /api/channel-status
//   RATE_LIMITER (ratelimit binding)        per-IP limit, see wrangler.toml (absent = no limit)
// Without Supabase settings the proxy works as before (no filtering).
//
// Caching, three layers (all keyed per URL, shared by every visitor of a data centre):
//   1. Edge response cache (Cache API): the FINAL, filtered body is stored for a few seconds
//      (EDGE_FRESH_FILTERED for match endpoints, the route TTL otherwise). Within that time a
//      request is answered from the edge without touching upstream or Supabase. After it, the
//      copy is still served for a short stale-while-revalidate window while ONE background
//      request per isolate refreshes it, so visitors never wait on upstream at expiry.
//   2. Subrequest cache (fetch cf.cacheEverything): upstream responses, errors included
//      (cacheTtlByStatus), so a 403/429/5xx burst reaches upstream once per few seconds.
//   3. Last-good copy (STALE_TTL): when upstream fails, the last good RAW body is served with
//      "X-PXL-Stale: 1" (filtered on the way out, so hidden matches stay hidden).
// Layers 1 and 3 use the Cache API, which only works on a custom domain or route of a Cloudflare
// zone: the site uses https://data.px-league.site (wrangler.toml). The *.workers.dev address is
// kept for old clients only; there the Cache API is a silent no-op (requests still work, they
// just always go upstream).
// Note: every request still INVOKES the Worker (and counts toward the plan's request quota);
// the cache removes the upstream/Supabase work, not the invocation.
//
// CORS: only the origins above get Access-Control-Allow-Origin. Any other Origin (and
// requests without an Origin header) get 403. An Origin header can be forged by non-browser
// clients (curl, servers); the per-IP RATE_LIMITER is what limits those.
// =============================================================================

// Honest identification of this proxy (no browser impersonation)
const UPSTREAM_HEADERS = {
  "Accept": "application/json",
  "Accept-Language": "ar",
  "User-Agent": "PX-League-Proxy/1.0 (+Cloudflare Worker)",
};

const UPSTREAM_TIMEOUT_MS = 10000;
const SETTINGS_TIMEOUT_MS = 4000;     // Supabase must never hold the match list hostage
const STALE_TTL = 900;                // seconds a last-good copy may be served while upstream is failing
const SETTINGS_TTL = 5;               // seconds match_settings are cached (edge + isolate memory)
const FILTERED_MAX_AGE = 10;          // browser cache for filtered match responses (hide/show shows within ~15 s)
const EDGE_FRESH_FILTERED = 5;        // seconds a filtered match response is fresh in the edge cache
const EDGE_SWR_MAX = 30;              // longest stale-while-revalidate window (seconds)
const SETTINGS_STALE_MS = 10 * 60 * 1000;   // last known settings used while Supabase is failing
const MATCH_ID_RE = /^\d{1,12}$/;
const STREAM_KEY_RE = /^[A-Za-z0-9_-]{1,64}$/;
// ysscores match status codes that mean "over" (verified: 4 = finished). A match in one of these
// states never gets a stream attached, whatever match_settings says.
const FINISHED_STATUSES = new Set([4]);

const ROUTES = [
  {
    // ysscores matches API: any path under /api/matches/
    prefix: "/api/matches/",
    upstream: "https://api-ar.ysscores.com/api/matches/",
    // Decoded path may contain the [] / ["8634"] filter segments; nothing else unusual.
    safePath: /^[A-Za-z0-9_\-\/.,\[\]"]+$/,
    forwardQuery: () => false,                              // matches endpoints take no query
    ttl: (rest) => ({ matches_date_get: 30, match_info: 15, matches_event: 20 })[rest.split("/")[0]] ?? 30,
    filtered: true,
  },
  {
    // Standings via the Vercel backend: /api/standings/{numeric id}
    prefix: "/api/standings/",
    upstream: "https://football-poster-generator.vercel.app/api/standings/",
    safePath: /^\d{1,12}$/,                                 // a single numeric season id
    forwardQuery: (key, value) => key === "include" && /^[a-z,]{1,40}$/.test(value),
    ttl: () => 300,                                         // standings change rarely
    filtered: false,
  },
];

// Background edge-cache refreshes in progress (per isolate): one refresh per URL at a time
const refreshing = new Set();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const dashboardOrigins = String(env.DASHBOARD_ORIGINS || "")
      .split(",").map((o) => o.trim().replace(/\/+$/, "")).filter(Boolean)
      .concat(LOCAL_DASHBOARD_ORIGINS);
    const isDashboard = dashboardOrigins.includes(origin);
    const streamOrigins = STREAM_ORIGINS.concat(String(env.STREAM_ORIGINS || "")
      .split(",").map((o) => o.trim().replace(/\/+$/, "")).filter(Boolean));
    const withStreams = streamOrigins.includes(origin);
    const siteOrigins = ALLOWED_ORIGINS.concat(String(env.ALLOWED_ORIGINS || "")
      .split(",").map((o) => o.trim().replace(/\/+$/, "")).filter(Boolean), streamOrigins);
    const originAllowed = siteOrigins.includes(origin) || isDashboard;
    const cors = originAllowed ? corsHeaders(origin) : {};

    // --- Rate limit (per client IP, every method except preflight) ---------
    // Runs before the Origin check so forged-Origin scrapers are throttled as well. Allowed
    // origins get CORS headers on the 429, so the page's script can see it and back off.
    if (request.method !== "OPTIONS" && !(await withinRateLimit(request, env))) {
      return json({ error: "RATE_LIMITED", message: "Too many requests" }, 429, { ...cors, "Retry-After": "60" });
    }

    // --- CORS gate ----------------------------------------------------------
    if (!originAllowed) {
      // No CORS headers: the browser blocks the response for foreign pages.
      return json({ error: "FORBIDDEN_ORIGIN", message: "Origin not allowed" }, 403, {});
    }

    // --- Preflight / methods ------------------------------------------------
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: { ...cors, "Access-Control-Max-Age": "86400" } });
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      return json({ error: "METHOD_NOT_ALLOWED", message: "Only GET is supported" }, 405, { ...cors, "Allow": "GET, HEAD, OPTIONS" });
    }

    // --- Health / legacy streams list --------------------------------------
    if (url.pathname === "/api/health") {
      return json({ status: "ok" }, 200, cors);
    }
    if (url.pathname === "/api/active-streams") {
      return json({ error: "GONE", message: "Streams are not available on this site" }, 410, cors);
    }
    if (url.pathname === "/api/channel-status") {
      if (!isDashboard) return json({ error: "FORBIDDEN_ORIGIN", message: "Dashboard only" }, 403, cors);
      return channelStatus(url, env, cors);
    }

    // --- Route lookup -------------------------------------------------------
    const route = ROUTES.find((r) => url.pathname.startsWith(r.prefix));
    if (!route) {
      return json({ error: "NOT_FOUND", message: "Endpoint does not exist" }, 404, cors);
    }

    const rest = url.pathname.slice(route.prefix.length);  // still percent-encoded
    let decoded;
    try { decoded = decodeURIComponent(rest); } catch { decoded = ""; }
    if (!decoded || !route.safePath.test(decoded) || decoded.includes("..") || decoded.startsWith("/") || decoded.includes("//")) {
      return json({ error: "INVALID_PATH", message: "Unsupported path" }, 400, cors);
    }

    // Only whitelisted query parameters are forwarded
    const query = new URLSearchParams();
    for (const [key, value] of url.searchParams) {
      if (route.forwardQuery(key, value)) query.append(key, value);
    }
    const qs = query.toString();
    const ttl = route.ttl(rest);
    const upstreamUrl = route.upstream + rest + (qs ? "?" + qs : "");

    // Edge filtering applies to the two match endpoints, unless the dashboard asks for raw data
    const kind = decoded.split("/")[0];
    const raw = isDashboard && url.searchParams.get("raw") === "1";
    const filterKind = route.filtered && !raw && (kind === "matches_date_get" || kind === "match_info") ? kind : "";
    const pathId = kind === "match_info" ? decoded.split("/")[1] : "";
    const edgeFresh = filterKind ? EDGE_FRESH_FILTERED : ttl;
    const edgeSwr = Math.min(EDGE_SWR_MAX, Math.max(10, edgeFresh * 2));

    // Cache keys on this Worker's own host (never requested by clients). The query string is
    // the whitelisted one, so ?raw=1 and junk parameters never split or poison the cache.
    // Bodies with stream data live under their own edge key, so a stream-less origin can never
    // be served a cached body that carries streams (and vice versa). The stale copy is the raw
    // upstream body (no streams in it) and stays shared.
    const streams = Boolean(filterKind && withStreams);
    const keyPath = url.pathname + (qs ? "?" + qs : "");
    const staleKey = new Request(url.origin + "/__pxl_stale" + keyPath);
    const edgeKey = new Request(url.origin + (streams ? "/__pxl_edge_s" : "/__pxl_edge") + keyPath);

    // Builds the response from upstream (no CORS headers; they are added per request below).
    const build = () => buildResponse({ upstreamUrl, ttl, filterKind, pathId, raw, streams, staleKey, env, ctx });

    // --- Edge response cache (filtered bodies; skipped for ?raw=1) ----------
    if (!raw) {
      const hit = await edgeGet(edgeKey);
      if (hit) {
        const age = (Date.now() - hit.storedAt) / 1000;
        if (age > edgeFresh && !refreshing.has(edgeKey.url)) {
          // Stale-while-revalidate: answer now, refresh once in the background
          refreshing.add(edgeKey.url);
          ctx.waitUntil(build()
            .then((res) => edgePut(edgeKey, res, edgeFresh, edgeSwr))
            .catch(() => {})
            .finally(() => refreshing.delete(edgeKey.url)));
        }
        return respond(request, hit.response, cors, { "X-PXL-Edge": age > edgeFresh ? "STALE" : "HIT" });
      }
    }

    const res = await build();
    if (!raw) ctx.waitUntil(edgePut(edgeKey, res.clone(), edgeFresh, edgeSwr).catch(() => {}));
    return respond(request, res, cors, raw ? {} : { "X-PXL-Edge": "MISS" });
  },
};

// =============================================================================
// Rate limiting (Workers Rate Limiting binding "RATE_LIMITER", configured in wrangler.toml)
// Key = client IP. The binding counts per Cloudflare location and is eventually consistent,
// so it is a brake on abusive clients, not an exact quota. Mobile carriers put many users
// behind one IP (CGNAT): keep the limit well above one viewer's polling rate (a live match
// page makes up to 3 requests every 10 s = 18/min).
// A missing binding (local dev) or a binding error never blocks traffic.
// =============================================================================
async function withinRateLimit(request, env) {
  if (!env.RATE_LIMITER || typeof env.RATE_LIMITER.limit !== "function") return true;
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  // Our own servers (RATE_LIMIT_EXEMPT_IPS, e.g. the stream VPS that builds the cached match
  // feed for every viewer). CF-Connecting-IP is set by Cloudflare and cannot be forged.
  if (String(env.RATE_LIMIT_EXEMPT_IPS || "").split(",").map((s) => s.trim()).includes(ip)) return true;
  try {
    const { success } = await env.RATE_LIMITER.limit({ key: ip });
    return success !== false;
  } catch {
    return true;
  }
}

// =============================================================================
// Edge response cache helpers (Cache API; no-ops on *.workers.dev)
// Stored copies carry X-PXL-Stored-At so the age can be computed, and a Cache-Control
// max-age of fresh + swr seconds, after which Cloudflare evicts them.
// =============================================================================
async function edgeGet(key) {
  try {
    const hit = await caches.default.match(key);
    if (!hit) return null;
    const storedAt = Number(hit.headers.get("X-PXL-Stored-At"));
    if (!Number.isFinite(storedAt)) return null;
    return { response: hit, storedAt };
  } catch {
    return null;
  }
}

async function edgePut(key, res, fresh, swr) {
  // Only good, cacheable bodies: no errors, no outage copies, no unfiltered ("no-store") bodies
  if (res.status !== 200 || res.headers.get("X-PXL-Stale") === "1") return;
  if (/no-store/i.test(res.headers.get("Cache-Control") || "")) return;
  const headers = new Headers(res.headers);
  headers.delete("Vary");   // the key is per URL only; respond() re-adds Vary: Origin with the CORS headers
  headers.set("X-PXL-Browser-Cache", headers.get("Cache-Control") || "no-store");
  headers.set("Cache-Control", `public, max-age=${fresh + swr}`);
  headers.set("X-PXL-Stored-At", String(Date.now()));
  await caches.default.put(key, new Response(await res.arrayBuffer(), { status: 200, headers }));
}

// Final response for one visitor: the (cached or fresh) body + this request's CORS headers.
// Internal cache bookkeeping headers never reach the browser.
function respond(request, res, cors, extra) {
  const headers = new Headers(res.headers);
  const browserCache = headers.get("X-PXL-Browser-Cache");
  if (browserCache) headers.set("Cache-Control", browserCache);
  headers.delete("X-PXL-Browser-Cache");
  headers.delete("X-PXL-Stored-At");
  for (const [k, v] of Object.entries({ ...cors, ...extra })) headers.set(k, v);
  return new Response(request.method === "HEAD" ? null : res.body, { status: res.status, headers });
}

// =============================================================================
// Upstream fetch + filtering. Returns a Response WITHOUT CORS headers.
// =============================================================================
async function buildResponse({ upstreamUrl, ttl, filterKind, pathId, raw, streams, staleKey, env, ctx }) {
  // Final response: filter (if needed) and add our own headers. Used for fresh AND stale bodies.
  const finish = async (body, contentType, extra) => {
    let out = body, settingsState = "";
    if (filterKind) {
      const r = await applyMatchSettings(filterKind, body, pathId, streams, env);
      out = r.body;
      settingsState = r.state;
    }
    return new Response(out, {
      status: 200,
      headers: {
        "Content-Type": contentType,
        // Filtered bodies depend on Supabase: keep them short-lived, and never cache a body
        // that could not be filtered (settings off/unavailable), so it is not stuck in browsers.
        "Cache-Control": !filterKind ? `public, max-age=${Math.min(ttl, 60)}`
          : (settingsState === "ok" || settingsState === "no-stream-access"
            ? `public, max-age=${Math.min(ttl, FILTERED_MAX_AGE)}` : "no-store"),
        "X-Content-Type-Options": "nosniff",
        "Vary": "Origin",
        ...(settingsState ? { "X-PXL-Settings": settingsState } : {}),
        ...(raw ? { "X-PXL-Raw": "1" } : {}),
        ...extra,
      },
    });
  };

  const staleOr = async (fallback) => {
    try {
      const hit = await caches.default.match(staleKey);
      if (hit) {
        return finish(await hit.arrayBuffer(), hit.headers.get("Content-Type") || "application/json; charset=utf-8",
          { "Cache-Control": "no-store", "X-PXL-Stale": "1" });
      }
    } catch { /* cache unavailable: fall through */ }
    return fallback();
  };

  let upstream;
  try {
    upstream = await fetch(upstreamUrl, {
      method: "GET",
      headers: UPSTREAM_HEADERS,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      // Errors are cached briefly as well, so a 403/429/5xx burst reaches upstream once per
      // data centre per few seconds instead of once per visitor poll.
      cf: {
        cacheEverything: true,
        cacheTtlByStatus: { "200-299": ttl, "404": 60, "403": 15, "429": 15, "500-599": 5 },
      },
    });
  } catch (err) {
    const timedOut = err && err.name === "TimeoutError";
    return staleOr(() => json({ error: timedOut ? "UPSTREAM_TIMEOUT" : "UPSTREAM_UNREACHABLE", message: "Upstream request failed" }, 504, {}));
  }

  if (!upstream.ok) {
    // 404 from upstream (e.g. unknown standings id) stays 404; other failures become 502
    if (upstream.status === 404) {
      return json({ error: "NOT_FOUND", message: "Upstream returned 404" }, 404, {});
    }
    return staleOr(() => json({ error: "UPSTREAM_ERROR", message: `Upstream returned ${upstream.status}` }, 502, {}));
  }

  const contentType = upstream.headers.get("Content-Type") || "application/json; charset=utf-8";
  const body = await upstream.arrayBuffer();
  // Refresh the last-good copy (raw) only when the edge actually went upstream
  if (upstream.headers.get("CF-Cache-Status") !== "HIT") {
    ctx.waitUntil(
      caches.default.put(staleKey, new Response(body.slice(0), {
        headers: { "Content-Type": contentType, "Cache-Control": `public, max-age=${STALE_TTL}` },
      })).catch(() => {})
    );
  }

  // Pass the JSON body through (filtered for the match endpoints); only our own headers
  // go back to the browser (no upstream cookies or server headers).
  return finish(body, contentType, {});
}

// =============================================================================
// Match settings (Supabase "match_settings": match_id, is_visible, channel, r2_slug).
// channel / r2_slug are read only for stream-enabled origins (anon needs the column grant from
// blogger/stream-manager/migrations/2026-11-25-stream-columns-for-stream-origins.sql).
// =============================================================================
const settingsMemo = new Map();   // query URL -> { at, map }   (per isolate, best effort)
const STREAM_DENIED_RETRY_MS = 60 * 1000;
let streamColumnsDeniedAt = -Infinity;   // last time anon was refused channel / r2_slug (per isolate)

function supabaseConfig(env) {
  const base = String(env.SUPABASE_URL || "").replace(/\/+$/, "");
  const key = String(env.SUPABASE_ANON_KEY || "");
  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(base) || !key) return null;
  const headers = { "Accept": "application/json", "apikey": key };
  if (key.startsWith("eyJ")) headers["Authorization"] = `Bearer ${key}`;   // legacy anon JWT
  return { base, headers };
}

// Only the identifier the player actually uses: the player prefers r2 over channel, so a row
// with an R2 slug never publishes its channel key (the edge-mode name of the same stream).
// With STREAM_PATH_SECRET the slug alone opens nothing: the playlist lives under a rotating key.
function cleanStream(row) {
  const channel = STREAM_KEY_RE.test(String(row && row.channel || "")) ? String(row.channel) : "";
  const r2_slug = STREAM_KEY_RE.test(String(row && row.r2_slug || "")) ? String(row.r2_slug) : "";
  if (r2_slug) return { r2_slug };
  return channel ? { channel } : null;
}

// A finished match never carries a stream (match object from ysscores: { status, ... })
function isFinished(match) {
  return FINISHED_STATUSES.has(Number(match && match.status));
}

// Settings for the given match ids -> Map(id -> { visible, stream }) or null if unavailable.
// withStreams = false never asks for channel / r2_slug (stream = null for every row).
async function loadSettings(ids, withStreams, env) {
  const cfg = supabaseConfig(env);
  if (!cfg) return { map: null, state: "off" };
  // Stream columns were refused recently: skip straight to the show/hide query (re-checked
  // every STREAM_DENIED_RETRY_MS, so running the migration takes effect within a minute).
  if (withStreams && Date.now() - streamColumnsDeniedAt < STREAM_DENIED_RETRY_MS) {
    const fallback = await loadSettings(ids, false, env);
    return fallback.state === "ok" ? { map: fallback.map, state: "no-stream-access" } : fallback;
  }
  const list = [...new Set(ids.filter((id) => MATCH_ID_RE.test(id)))].sort().slice(0, 400);
  if (!list.length) return { map: new Map(), state: "ok" };
  const cols = withStreams ? "match_id,is_visible,channel,r2_slug" : "match_id,is_visible";
  const q = `${cfg.base}/rest/v1/match_settings?select=${cols}&match_id=in.(${list.join(",")})`;

  const memo = settingsMemo.get(q);
  if (memo && Date.now() - memo.at < SETTINGS_TTL * 1000) return { map: memo.map, state: "ok" };
  try {
    const res = await fetch(q, {
      headers: cfg.headers,
      signal: AbortSignal.timeout(SETTINGS_TIMEOUT_MS),
      cf: { cacheEverything: true, cacheTtl: SETTINGS_TTL },
    });
    if (!res.ok) {
      // 401/403 for the stream columns = the anon column grant is missing (42501; migration
      // 2026-11-25-stream-columns-for-stream-origins.sql not run). Fall back to the show/hide
      // columns, so hidden matches stay hidden; the page just gets no streams.
      if (withStreams && (res.status === 401 || res.status === 403)) {
        streamColumnsDeniedAt = Date.now();
        const fallback = await loadSettings(ids, false, env);
        return fallback.state === "ok" ? { map: fallback.map, state: "no-stream-access" } : fallback;
      }
      throw new Error(`Supabase ${res.status}`);
    }
    const rows = await res.json();
    const map = new Map();
    for (const r of Array.isArray(rows) ? rows : []) {
      const id = String(r && r.match_id != null ? r.match_id : "");
      if (MATCH_ID_RE.test(id)) map.set(id, { visible: r.is_visible !== false, stream: withStreams ? cleanStream(r) : null });
    }
    if (settingsMemo.size > 200) settingsMemo.clear();
    settingsMemo.set(q, { at: Date.now(), map });
    return { map, state: "ok" };
  } catch {
    // Supabase down: keep using the last known settings for a while, else show everything
    if (memo && Date.now() - memo.at < SETTINGS_STALE_MS) return { map: memo.map, state: "stale" };
    return { map: null, state: "unavailable" };
  }
}

// Filter / annotate a match response. Upstream "stream" fields are always dropped first; with
// withStreams the dashboard's stream is attached (unless the match is finished).
// Any parse problem returns the body untouched.
async function applyMatchSettings(kind, body, pathId, withStreams, env) {
  let doc;
  try { doc = JSON.parse(new TextDecoder().decode(body)); } catch { return { body, state: "unparsed" }; }
  if (!doc || typeof doc !== "object") return { body, state: "unparsed" };

  if (kind === "matches_date_get") {
    if (!Array.isArray(doc.data)) return { body, state: "unparsed" };
    for (const m of doc.data) if (m && typeof m === "object") delete m.stream;
    const { map, state } = await loadSettings(doc.data.map((m) => String(m && m.match_id != null ? m.match_id : "")), withStreams, env);
    // Supabase off/unavailable: everything is shown, no streams (state tells the caller not to cache long)
    if (map) {
      doc.data = doc.data
        .filter((m) => { const s = map.get(String(m && m.match_id)); return !(s && !s.visible); })
        .map((m) => {
          const s = map.get(String(m && m.match_id));
          if (s && s.stream && m && typeof m === "object" && !isFinished(m)) m.stream = s.stream;
          return m;
        });
    }
    return { body: JSON.stringify(doc), state };
  }

  // match_info (hidden matches stay reachable by id)
  if (!doc.data || typeof doc.data !== "object" || Array.isArray(doc.data) || !MATCH_ID_RE.test(pathId)) {
    return { body, state: "unparsed" };
  }
  delete doc.data.stream;
  if (!withStreams) return { body: JSON.stringify(doc), state: "ok" };
  const { map, state } = await loadSettings([pathId], true, env);
  const s = map && map.get(pathId);
  if (s && s.stream && !isFinished(doc.data)) doc.data.stream = s.stream;
  return { body: JSON.stringify(doc), state };
}

// =============================================================================
// GET /api/channel-status?slugs=a,b,c   (dashboard origins only)
// Is each R2 channel broadcasting right now? Reads hd/{slug}/index.html from the R2 public
// domain (R2_PUBLIC_BASE var) server-side, because R2's CORS only allows the player's origin.
//   live   = playlist written within LIVE_MAX_AGE_S seconds and not marked ended
//   ageSec = seconds since the playlist was last written (null if unknown)
// A channel that is not live shows a frozen picture or keeps buffering in the player.
// =============================================================================
const LIVE_MAX_AGE_S = 30;

async function channelStatus(url, env, cors) {
  const base = String(env.R2_PUBLIC_BASE || "").replace(/\/+$/, "");
  if (!/^https:\/\/[a-z0-9.-]+$/i.test(base)) {
    return json({ error: "NOT_CONFIGURED", message: "R2_PUBLIC_BASE missing" }, 503, cors);
  }
  const slugs = [...new Set(String(url.searchParams.get("slugs") || "").split(","))]
    .map((s) => s.trim()).filter((s) => STREAM_KEY_RE.test(s)).slice(0, 20);
  const now = Date.now();
  const entries = await Promise.all(slugs.map(async (slug) => {
    try {
      // Secret R2 paths (backend STREAM_PATH_SECRET, same secret here): the playlist is under
      // the current window key. Without the secret: the old public hd/{slug}/index.html.
      const key = await windowKey(slug, env, now);
      const res = await fetch(`${base}/hd/${slug}/${key ? "w/" + key + "/" : ""}index.html?_t=${Math.floor(now / 1000)}`, {
        signal: AbortSignal.timeout(5000),
        cf: { cacheTtl: 0 },
      });
      if (!res.ok) return [slug, { live: false, ageSec: null, status: res.status }];
      const text = await res.text();
      const modified = Date.parse(res.headers.get("Last-Modified") || "");
      const ageSec = Number.isFinite(modified) ? Math.max(0, Math.round((now - modified) / 1000)) : null;
      const ended = /#PXL-STREAM-ENDED|#EXT-X-ENDLIST/.test(text);
      return [slug, { live: !ended && ageSec !== null && ageSec <= LIVE_MAX_AGE_S, ageSec, ended }];
    } catch {
      return [slug, { live: false, ageSec: null, error: "unreachable" }];
    }
  }));
  return json({ channels: Object.fromEntries(entries) }, 200, cors);
}

// Same derivation as the backend's windowKey() (kind "s"): the first 22 base64url characters of
// HMAC-SHA256(secret, "pxl-win|1|{slug}|s|{floor(unix seconds / R2_WINDOW_SECONDS)}").
// R2_WINDOW_SECONDS must equal the backend's value (default 600).
async function windowKey(slug, env, nowMs) {
  const secret = String(env.STREAM_PATH_SECRET || "");
  if (secret.length < 32) return "";
  const len = Number(env.R2_WINDOW_SECONDS) || 600;
  const w = Math.floor(nowMs / 1000 / len);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`pxl-win|1|${slug}|s|${w}`)));
  let bin = "";
  for (const b of sig) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "").slice(0, 22);
}

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Accept, Content-Type",
    "Access-Control-Expose-Headers": "X-PXL-Stale, X-PXL-Settings, X-PXL-Raw, X-PXL-Edge, Retry-After",
    "Vary": "Origin",
  };
}

function json(body, status, headers) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...headers,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
