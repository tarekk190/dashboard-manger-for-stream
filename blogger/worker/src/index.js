// =============================================================================
// PX League - Cloudflare Worker: API proxy (ysscores matches + standings) with strict CORS
// and edge filtering from the Master Match Controller (Supabase table "match_settings").
// -----------------------------------------------------------------------------
// >>> YOUR BLOG ORIGIN(S) <<<
// Exact origins: scheme + host only. A trailing slash is tolerated (it is removed below),
// because browsers send the Origin header WITHOUT one.
// Add your custom domain as another entry if you use one, e.g. "https://www.pxleague.com".
const ALLOWED_ORIGINS = [
  "https://powerdoflearn.blogspot.com",
].map((o) => o.trim().replace(/\/+$/, ""));
// The dashboard's origin(s) come from the DASHBOARD_ORIGINS variable (comma separated),
// e.g. "https://px-stream-manager.vercel.app". Only they may ask for ?raw=1.
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
//       matches_date_get: matches with is_visible = false are removed, and a match with a
//                         stream gets  "stream": { "channel": "b4", "r2_slug": "..." }
//       match_info:       data.stream is added the same way (hidden matches stay reachable)
//       ?raw=1 (dashboard origins only): no filtering, no injection
//   /api/standings/{id}?include=results
//                               -> https://football-poster-generator.vercel.app/api/standings/{id}?include=results
//   /api/active-streams         -> { streams: [ { match_id, channel, r2_slug } ] }   (legacy)
//   /api/health                 -> {"status":"ok"}
//
// Secrets / vars:
//   wrangler secret put SUPABASE_URL        https://<project>.supabase.co
//   wrangler secret put SUPABASE_ANON_KEY   anon JWT or sb_publishable_... key (RLS: read-only)
//   DASHBOARD_ORIGINS (var)                 https://your-dashboard.vercel.app
// Without Supabase settings the proxy works as before (no filtering).
//
// Responses are cached at Cloudflare's edge, so many visitors share one upstream request.
// Upstream errors are cached briefly too (cacheTtlByStatus), and the last good response of
// each URL is kept for STALE_TTL seconds: when upstream fails (timeout, 403/429, 5xx) the
// Worker serves that copy with "X-PXL-Stale: 1" instead of an error. The stale copy is
// stored RAW and filtered on the way out, so hidden matches stay hidden during an outage.
// (The Cache API needs the Worker on a custom domain/route; on *.workers.dev it is a no-op.)
//
// CORS: only the origins above get Access-Control-Allow-Origin. Any other Origin (and
// requests without an Origin header) get 403. An Origin header can be forged by non-browser
// clients (curl, servers); for hard limits add a Cloudflare rate-limiting rule.
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
const SETTINGS_STALE_MS = 10 * 60 * 1000;   // last known settings used while Supabase is failing
const STREAM_KEY_RE = /^[A-Za-z0-9_-]{1,64}$/;
const MATCH_ID_RE = /^\d{1,12}$/;

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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const dashboardOrigins = String(env.DASHBOARD_ORIGINS || "")
      .split(",").map((o) => o.trim().replace(/\/+$/, "")).filter(Boolean)
      .concat(LOCAL_DASHBOARD_ORIGINS);
    const isDashboard = dashboardOrigins.includes(origin);

    // --- CORS gate ----------------------------------------------------------
    if (!ALLOWED_ORIGINS.includes(origin) && !isDashboard) {
      // No CORS headers: the browser blocks the response for foreign pages.
      return json({ error: "FORBIDDEN_ORIGIN", message: "Origin not allowed" }, 403, {});
    }
    const cors = corsHeaders(origin);

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
      return activeStreams(request, env, cors);
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

    // Final response: filter (if needed) and add our own headers. Used for fresh AND stale bodies.
    const finish = async (body, contentType, extra) => {
      let out = body, settingsState = "";
      if (filterKind) {
        const r = await applyMatchSettings(filterKind, body, pathId, env);
        out = r.body;
        settingsState = r.state;
      }
      return new Response(request.method === "HEAD" ? null : out, {
        status: 200,
        headers: {
          ...cors,
          "Content-Type": contentType,
          // Filtered bodies depend on Supabase: keep them short-lived, and never cache a body
          // that could not be filtered (settings off/unavailable), so it is not stuck in browsers.
          "Cache-Control": !filterKind ? `public, max-age=${Math.min(ttl, 60)}`
            : (settingsState === "ok" ? `public, max-age=${Math.min(ttl, FILTERED_MAX_AGE)}` : "no-store"),
          "X-Content-Type-Options": "nosniff",
          ...(settingsState ? { "X-PXL-Settings": settingsState } : {}),
          ...(raw ? { "X-PXL-Raw": "1" } : {}),
          ...extra,
        },
      });
    };

    // Cache key for the last-good copy (on this Worker's own host, never requested by clients)
    const staleKey = new Request(url.origin + "/__pxl_stale" + url.pathname + (qs ? "?" + qs : ""));
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
      return staleOr(() => json({ error: timedOut ? "UPSTREAM_TIMEOUT" : "UPSTREAM_UNREACHABLE", message: "Upstream request failed" }, 504, cors));
    }

    if (!upstream.ok) {
      // 404 from upstream (e.g. unknown standings id) stays 404; other failures become 502
      if (upstream.status === 404) {
        return json({ error: "NOT_FOUND", message: "Upstream returned 404" }, 404, cors);
      }
      return staleOr(() => json({ error: "UPSTREAM_ERROR", message: `Upstream returned ${upstream.status}` }, 502, cors));
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
  },
};

// =============================================================================
// Match settings (Supabase "match_settings": match_id, is_visible, channel, r2_slug)
// =============================================================================
const settingsMemo = new Map();   // query URL -> { at, map }   (per isolate, best effort)

function supabaseConfig(env) {
  const base = String(env.SUPABASE_URL || "").replace(/\/+$/, "");
  const key = String(env.SUPABASE_ANON_KEY || "");
  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(base) || !key) return null;
  const headers = { "Accept": "application/json", "apikey": key };
  if (key.startsWith("eyJ")) headers["Authorization"] = `Bearer ${key}`;   // legacy anon JWT
  return { base, headers };
}

function cleanStream(row) {
  const channel = STREAM_KEY_RE.test(String(row && row.channel || "")) ? String(row.channel) : "";
  const r2_slug = STREAM_KEY_RE.test(String(row && row.r2_slug || "")) ? String(row.r2_slug) : "";
  return channel || r2_slug ? { channel, r2_slug } : null;
}

// Settings for the given match ids -> Map(id -> { visible, stream }) or null if unavailable.
async function loadSettings(ids, env) {
  const cfg = supabaseConfig(env);
  if (!cfg) return { map: null, state: "off" };
  const list = [...new Set(ids.filter((id) => MATCH_ID_RE.test(id)))].sort().slice(0, 400);
  if (!list.length) return { map: new Map(), state: "ok" };
  const q = `${cfg.base}/rest/v1/match_settings?select=match_id,is_visible,channel,r2_slug&match_id=in.(${list.join(",")})`;

  const memo = settingsMemo.get(q);
  if (memo && Date.now() - memo.at < SETTINGS_TTL * 1000) return { map: memo.map, state: "ok" };
  try {
    const res = await fetch(q, {
      headers: cfg.headers,
      signal: AbortSignal.timeout(SETTINGS_TIMEOUT_MS),
      cf: { cacheEverything: true, cacheTtl: SETTINGS_TTL },
    });
    if (!res.ok) throw new Error(`Supabase ${res.status}`);
    const rows = await res.json();
    const map = new Map();
    for (const r of Array.isArray(rows) ? rows : []) {
      const id = String(r && r.match_id != null ? r.match_id : "");
      if (MATCH_ID_RE.test(id)) map.set(id, { visible: r.is_visible !== false, stream: cleanStream(r) });
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

// Filter / annotate a match response. Any parse problem returns the body untouched.
async function applyMatchSettings(kind, body, pathId, env) {
  let doc;
  try { doc = JSON.parse(new TextDecoder().decode(body)); } catch { return { body, state: "unparsed" }; }
  if (!doc || typeof doc !== "object") return { body, state: "unparsed" };

  if (kind === "matches_date_get") {
    if (!Array.isArray(doc.data)) return { body, state: "unparsed" };
    const { map, state } = await loadSettings(doc.data.map((m) => String(m && m.match_id != null ? m.match_id : "")), env);
    if (!map) return { body, state };
    doc.data = doc.data
      .filter((m) => { const s = map.get(String(m && m.match_id)); return !(s && !s.visible); })
      .map((m) => { const s = map.get(String(m && m.match_id)); if (s && s.stream) m.stream = s.stream; return m; });
    return { body: JSON.stringify(doc), state };
  }

  // match_info
  if (!doc.data || typeof doc.data !== "object" || Array.isArray(doc.data) || !MATCH_ID_RE.test(pathId)) {
    return { body, state: "unparsed" };
  }
  const { map, state } = await loadSettings([pathId], env);
  if (!map) return { body, state };
  const s = map.get(pathId);
  if (s && s.stream) doc.data.stream = s.stream;
  return { body: JSON.stringify(doc), state };
}

// Legacy: GET /api/active-streams -> { streams: [ { match_id, channel, r2_slug } ] }
// (themes from before the edge merge poll this; new themes read match_info.stream)
async function activeStreams(request, env, cors) {
  const cfg = supabaseConfig(env);
  if (!cfg) return json({ error: "NOT_CONFIGURED", message: "SUPABASE_URL / SUPABASE_ANON_KEY missing" }, 503, cors);
  const q = `${cfg.base}/rest/v1/match_settings?select=match_id,channel,r2_slug&or=(channel.not.is.null,r2_slug.not.is.null)&order=updated_at.desc&limit=200`;
  let rows;
  try {
    const res = await fetch(q, { headers: cfg.headers, signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS), cf: { cacheEverything: true, cacheTtl: 20 } });
    if (!res.ok) return json({ error: "UPSTREAM_ERROR", message: `Supabase returned ${res.status}` }, 502, cors);
    rows = await res.json();
  } catch {
    return json({ error: "UPSTREAM_UNREACHABLE", message: "Supabase request failed" }, 504, cors);
  }
  const streams = (Array.isArray(rows) ? rows : [])
    .map((r) => ({ match_id: String(r && r.match_id != null ? r.match_id : ""), ...(cleanStream(r) || {}) }))
    .filter((s) => MATCH_ID_RE.test(s.match_id) && (s.channel || s.r2_slug));
  return new Response(request.method === "HEAD" ? null : JSON.stringify({ streams }), {
    status: 200,
    headers: { ...cors, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "public, max-age=20", "X-Content-Type-Options": "nosniff" },
  });
}

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Accept, Content-Type",
    "Access-Control-Expose-Headers": "X-PXL-Stale, X-PXL-Settings, X-PXL-Raw",
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
