// =============================================================================
// PX League - Cloudflare Worker: API proxy (ysscores matches + standings) with strict CORS
// -----------------------------------------------------------------------------
// >>> YOUR BLOG ORIGIN(S) <<<
// Exact origins: scheme + host only. A trailing slash is tolerated (it is removed below),
// because browsers send the Origin header WITHOUT one.
// Add your custom domain as another entry if you use one, e.g. "https://www.pxleague.com".
const ALLOWED_ORIGINS = [
  "https://powerdoflearn.blogspot.com",
].map((o) => o.trim().replace(/\/+$/, ""));
// -----------------------------------------------------------------------------
// Routes (GET only):
//   /api/matches/...            -> https://api-ar.ysscores.com/api/matches/...
//       e.g. /api/matches/matches_date_get/{YYYY-MM-DD}/[]/[]/["8634"]/D/60
//            /api/matches/match_info/{match_id}/D/60
//   /api/standings/{id}?include=results
//                               -> https://football-poster-generator.vercel.app/api/standings/{id}?include=results
//       {id} is the ysscores season id, e.g. 937599 (Premier League)
//   /api/health                 -> {"status":"ok"}
//
// Responses are cached at Cloudflare's edge, so many visitors share one upstream request.
// Upstream errors are cached briefly too (cacheTtlByStatus), and the last good response of
// each URL is kept for STALE_TTL seconds: when upstream fails (timeout, 403/429, 5xx) the
// Worker serves that copy with "X-PXL-Stale: 1" instead of an error, so an upstream outage
// or rate limit is not amplified by every visitor's poll. (The Cache API needs the Worker on
// a custom domain/route; on *.workers.dev it is a no-op and errors are returned as before.)
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
const STALE_TTL = 900;   // seconds a last-good copy may be served while upstream is failing

const ROUTES = [
  {
    // ysscores matches API: any path under /api/matches/
    prefix: "/api/matches/",
    upstream: "https://api-ar.ysscores.com/api/matches/",
    // Decoded path may contain the [] / ["8634"] filter segments; nothing else unusual.
    safePath: /^[A-Za-z0-9_\-\/.,\[\]"]+$/,
    forwardQuery: () => true,                               // matches endpoints take no query; harmless
    ttl: (rest) => ({ matches_date_get: 30, match_info: 15, matches_event: 20 })[rest.split("/")[0]] ?? 30,
  },
  {
    // Standings via the Vercel backend: /api/standings/{numeric id}
    prefix: "/api/standings/",
    upstream: "https://football-poster-generator.vercel.app/api/standings/",
    safePath: /^\d{1,12}$/,                                 // a single numeric season id
    forwardQuery: (key, value) => key === "include" && /^[a-z,]{1,40}$/.test(value),
    ttl: () => 300,                                         // standings change rarely
  },
];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    // --- CORS gate ----------------------------------------------------------
    if (!ALLOWED_ORIGINS.includes(origin)) {
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

    // --- Health -------------------------------------------------------------
    if (url.pathname === "/api/health") {
      return json({ status: "ok" }, 200, cors);
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
    // Cache key for the last-good copy (on this Worker's own host, never requested by clients)
    const staleKey = new Request(url.origin + "/__pxl_stale" + url.pathname + (qs ? "?" + qs : ""));
    const staleOr = async (fallback) => {
      try {
        const hit = await caches.default.match(staleKey);
        if (hit) {
          return new Response(request.method === "HEAD" ? null : hit.body, {
            status: 200,
            headers: {
              ...cors,
              "Content-Type": hit.headers.get("Content-Type") || "application/json; charset=utf-8",
              "Cache-Control": "no-store",
              "X-PXL-Stale": "1",
              "X-Content-Type-Options": "nosniff",
            },
          });
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
    // Refresh the last-good copy only when the edge actually went upstream (not on every hit)
    if (upstream.headers.get("CF-Cache-Status") !== "HIT") {
      ctx.waitUntil(
        caches.default.put(staleKey, new Response(body.slice(0), {
          headers: { "Content-Type": contentType, "Cache-Control": `public, max-age=${STALE_TTL}` },
        })).catch(() => {})
      );
    }

    // Pass the JSON body through; only our own headers go back to the browser
    // (no upstream cookies or server headers).
    return new Response(request.method === "HEAD" ? null : body, {
      status: 200,
      headers: {
        ...cors,
        "Content-Type": contentType,
        "Cache-Control": `public, max-age=${Math.min(ttl, 60)}`,
        "X-Content-Type-Options": "nosniff",
      },
    });
  },
};

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Accept, Content-Type",
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
