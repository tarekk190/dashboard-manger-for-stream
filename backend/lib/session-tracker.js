'use strict';

// ==============================================================================
// Viewer session tracker (Phase 2): what each viewer session does, and limits on it.
//
//   open(sid, info)    a session was issued (POST /api/session). Refused when the network
//                      already opened maxSessionsPerNetwork sessions in networkWindowMs.
//   touch(sid, info)   the session used the viewer API (/api/stream, /api/r2, /api/token).
//                      Refused when it was seen from more than maxNetworks networks, or made
//                      more than maxCallsPerMinute calls in the last 60 s (a script sharing
//                      one session, or minting keys in a loop). A normal player makes 2-4
//                      calls per minute (token renewal every ~30 s, R2 key every 1.5-3 min).
//   list() / summary() data for the admin monitor
//
// In memory, like the revocation list: one backend process serves every viewer. A session
// unknown here (backend restarted) is picked up again on its next call. Every entry needs a
// signed session (a passed Turnstile check), and the size is capped.
// ==============================================================================

function createSessionTracker({
    now = () => Date.now(),
    maxNetworks = 2,
    maxCallsPerMinute = 20,
    maxSessionsPerNetwork = 0,          // 0 = no limit
    networkWindowMs = 10 * 60 * 1000,
    maxEntries = 200000
} = {}) {
    const sessions = new Map();         // sid -> record
    const networkOpens = new Map();     // network -> [timestamps of session opens]

    function record(sid, info) {
        let r = sessions.get(sid);
        if (!r) {
            if (sessions.size >= maxEntries) sweep();
            if (sessions.size >= maxEntries) sessions.delete(sessions.keys().next().value);
            r = {
                sid,
                created: now(),
                exp: Number(info.exp) || now() + 30 * 60 * 1000,
                lastSeen: now(),
                ua: String(info.ua || '').slice(0, 160),
                networks: new Map(),    // network -> calls from it
                calls: [],              // timestamps of the last minute
                totals: { stream: 0, key: 0, token: 0, hlskey: 0 },
                channels: new Set(),
                limited: null           // reason once a limit was hit
            };
            sessions.set(sid, r);
        }
        return r;
    }

    function pruneOpens(network, t) {
        const list = (networkOpens.get(network) || []).filter(x => t - x < networkWindowMs);
        if (list.length) networkOpens.set(network, list);
        else networkOpens.delete(network);
        return list;
    }

    function open(sid, info = {}) {
        const t = now();
        const network = String(info.network || '');
        if (network && maxSessionsPerNetwork > 0) {
            const list = pruneOpens(network, t);
            if (list.length >= maxSessionsPerNetwork) return { ok: false, reason: 'network_session_limit' };
        }
        if (network) networkOpens.set(network, [...(networkOpens.get(network) || []), t]);
        const r = record(sid, info);
        if (network) r.networks.set(network, r.networks.get(network) || 0);
        return { ok: true };
    }

    function touch(sid, info = {}) {
        const t = now();
        const r = record(sid, info);
        if (r.limited) return { ok: false, reason: r.limited };
        r.lastSeen = t;
        const network = String(info.network || '');
        if (network) r.networks.set(network, (r.networks.get(network) || 0) + 1);
        if (info.kind && r.totals[info.kind] !== undefined) r.totals[info.kind] += 1;
        if (info.channel) r.channels.add(String(info.channel).slice(0, 64));
        r.calls = r.calls.filter(x => t - x < 60000);
        r.calls.push(t);
        if (maxNetworks > 0 && r.networks.size > maxNetworks) r.limited = 'too_many_networks';
        else if (maxCallsPerMinute > 0 && r.calls.length > maxCallsPerMinute) r.limited = 'too_many_calls';
        return r.limited ? { ok: false, reason: r.limited } : { ok: true };
    }

    function remove(sid) {
        sessions.delete(sid);
    }

    function clear() {
        sessions.clear();
        networkOpens.clear();
    }

    function sweep() {
        const t = now();
        for (const [sid, r] of sessions) if (r.exp <= t) sessions.delete(sid);
        for (const network of [...networkOpens.keys()]) pruneOpens(network, t);
    }

    function view(r, t) {
        return {
            sid: r.sid,
            created: r.created,
            lastSeen: r.lastSeen,
            expiresAt: r.exp,
            ua: r.ua,
            networks: [...r.networks.keys()],
            callsLastMinute: r.calls.filter(x => t - x < 60000).length,
            totals: { ...r.totals },
            channels: [...r.channels],
            limited: r.limited
        };
    }

    // Active sessions, most recently seen first
    function list({ limit = 200, filter } = {}) {
        const t = now();
        const out = [];
        for (const r of sessions.values()) {
            if (r.exp <= t) continue;
            const v = view(r, t);
            if (!filter || filter(v)) out.push(v);
        }
        out.sort((a, b) => b.lastSeen - a.lastSeen);
        return { total: out.length, sessions: out.slice(0, Math.max(0, limit)) };
    }

    function summary({ activeWithinMs = 5 * 60 * 1000, topNetworks = 10 } = {}) {
        const t = now();
        let active = 0, recent = 0, limited = 0;
        const perNetwork = new Map();
        for (const r of sessions.values()) {
            if (r.exp <= t) continue;
            active++;
            if (t - r.lastSeen < activeWithinMs) recent++;
            if (r.limited) limited++;
            for (const n of r.networks.keys()) perNetwork.set(n, (perNetwork.get(n) || 0) + 1);
        }
        const top = [...perNetwork.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, topNetworks)
            .map(([network, count]) => ({ network, sessions: count }));
        return { active, recent, limited, topNetworks: top };
    }

    return { open, touch, remove, clear, sweep, list, summary, get size() { return sessions.size; } };
}

module.exports = { createSessionTracker };
