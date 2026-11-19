// worker/src/index.js
// ------------------------------------------------------------
// Cloudflare Worker – public API façade.
// ------------------------------------------------------------
import { adaptMatchesByDate, adaptMatchInfo, adaptLineups, adaptEvents, makeAdapterError } from "./adapter.js";
import { jsonResponse, errorResponse, corsHeaders } from "./utils.js";

const API_BASE = "https://api-ar.ysscores.com/api/matches";

function isValidDate(str) {
  return /^\d{4}-\d{2}-\d{2}$/.test(str);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // -----------------------------------------------------
    // CORS – the PX League site (custom domain) and Blogspot domains
    // -----------------------------------------------------
    const origin = request.headers.get("Origin") || "";
    const allowedOrigin = (origin === "https://www.px-league.site" || origin === "https://px-league.site"
      || origin.endsWith(".blogspot.com")) ? origin : "";
    const cors = allowedOrigin ? corsHeaders(allowedOrigin) : {};

    try {
      // Health check
      if (pathname === "/api/health") {
        return jsonResponse({status: "ok"}, 200, cors);
      }

      // ---------------------------------------------------
      // GET /api/matches?date=YYYY-MM-DD
      // ---------------------------------------------------
      if (pathname === "/api/matches") {
        const date = url.searchParams.get("date");
        if (!date || !isValidDate(date)) {
          return errorResponse("INVALID_PARAMETER", "date must be YYYY-MM-DD", 400, cors);
        }
        const upstream = `${API_BASE}/matches_date_get/${date}/0/D/60`;
        const resp = await fetch(upstream, {
          method: "GET",
          headers: { Accept: "application/json" },
          cf: { cacheTtl: 45, cacheEverything: true }
        });
        if (!resp.ok) {
          return errorResponse("UPSTREAM_ERROR", `YSScores returned ${resp.status}`, resp.status, cors);
        }
        const raw = await resp.json();
        const matches = await adaptMatchesByDate(raw);
        return jsonResponse({matches}, 200, cors);
      }

      // ---------------------------------------------------
      // GET /api/match?id=ID
      // ---------------------------------------------------
      if (pathname === "/api/match") {
        const id = url.searchParams.get("id");
        if (!id) {
          return errorResponse("INVALID_PARAMETER", "Missing id", 400, cors);
        }
        const upstream = `${API_BASE}/match_info/${id}`;
        const resp = await fetch(upstream, {
          method: "GET",
          headers: { Accept: "application/json" },
          cf: { cacheTtl: 15, cacheEverything: true }
        });
        if (!resp.ok) {
          return errorResponse("UPSTREAM_ERROR", `YSScores returned ${resp.status}`, resp.status, cors);
        }
        const raw = await resp.json();
        const match = await adaptMatchInfo(raw);
        return jsonResponse({match}, 200, cors);
      }

      // ---------------------------------------------------
      // GET /api/match/lineups?id=ID
      // ---------------------------------------------------
      if (pathname === "/api/match/lineups") {
        const id = url.searchParams.get("id");
        if (!id) {
          return errorResponse("INVALID_PARAMETER", "Missing id", 400, cors);
        }
        const upstream = `${API_BASE}/matches_lineup/${id}`;
        const resp = await fetch(upstream, {
          method: "GET",
          headers: { Accept: "application/json" },
          cf: { cacheTtl: 300, cacheEverything: true }
        });
        if (!resp.ok) {
          return errorResponse("UPSTREAM_ERROR", `YSScores returned ${resp.status}`, resp.status, cors);
        }
        const raw = await resp.json();
        const lineups = await adaptLineups(raw);
        return jsonResponse({lineups}, 200, cors);
      }

      // ---------------------------------------------------
      // GET /api/match/events?id=ID
      // ---------------------------------------------------
      if (pathname === "/api/match/events") {
        const id = url.searchParams.get("id");
        if (!id) {
          return errorResponse("INVALID_PARAMETER", "Missing id", 400, cors);
        }
        const upstream = `${API_BASE}/matches_event/${id}`;
        const resp = await fetch(upstream, {
          method: "GET",
          headers: { Accept: "application/json" },
          cf: { cacheTtl: 20, cacheEverything: true }
        });
        if (!resp.ok) {
          return errorResponse("UPSTREAM_ERROR", `YSScores returned ${resp.status}`, resp.status, cors);
        }
        const raw = await resp.json();
        const events = await adaptEvents(raw);
        return jsonResponse({events}, 200, cors);
      }

      // Unknown route
      return errorResponse("NOT_FOUND", "Endpoint does not exist", 404, cors);
    } catch (e) {
      if (e.code) {
        return errorResponse(e.code, e.message, 500, cors);
      }
      return errorResponse("CONFIGURATION_ERROR", "Unexpected server error", 500, cors);
    }
  }
};
