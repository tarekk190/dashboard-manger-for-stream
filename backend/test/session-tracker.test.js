'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSessionTracker } = require('../lib/session-tracker');

function clock(start = 1_000_000) {
    let t = start;
    return { now: () => t, advance: (ms) => { t += ms; } };
}

test('normal player traffic stays within the limits', () => {
    const c = clock();
    const tr = createSessionTracker({ now: c.now });
    tr.open('s1', { network: '4:1.2.3.0/24', exp: c.now() + 3600e3, ua: 'UA' });
    // 30 minutes: token renewal every 30 s, key every 2 min
    for (let i = 0; i < 60; i++) {
        assert.equal(tr.touch('s1', { network: '4:1.2.3.0/24', kind: 'token', channel: 'b1' }).ok, true);
        if (i % 4 === 0) assert.equal(tr.touch('s1', { network: '4:1.2.3.0/24', kind: 'key', channel: 'b1' }).ok, true);
        c.advance(30e3);
    }
    const [s] = tr.list().sessions;
    assert.equal(s.totals.token, 60);
    assert.equal(s.totals.key, 15);
    assert.deepEqual(s.channels, ['b1']);
    assert.equal(s.limited, null);
});

test('a session used from too many networks is limited, and stays limited', () => {
    const tr = createSessionTracker({ maxNetworks: 2 });
    tr.open('s1', { network: 'n1' });
    assert.equal(tr.touch('s1', { network: 'n1' }).ok, true);
    assert.equal(tr.touch('s1', { network: 'n2' }).ok, true);
    assert.deepEqual(tr.touch('s1', { network: 'n3' }), { ok: false, reason: 'too_many_networks' });
    assert.equal(tr.touch('s1', { network: 'n1' }).ok, false, 'limit is sticky');
    assert.equal(tr.summary().limited, 1);
});

test('too many calls per minute is limited; the window slides', () => {
    const c = clock();
    const tr = createSessionTracker({ now: c.now, maxCallsPerMinute: 5 });
    for (let i = 0; i < 5; i++) assert.equal(tr.touch('a', { network: 'n' }).ok, true);
    assert.deepEqual(tr.touch('a', { network: 'n' }), { ok: false, reason: 'too_many_calls' });

    for (let i = 0; i < 5; i++) { assert.equal(tr.touch('b', { network: 'n' }).ok, true); c.advance(13e3); }
    assert.equal(tr.touch('b', { network: 'n' }).ok, true, 'old calls left the 60 s window');
});

test('sessions per network: off by default, enforced when set', () => {
    const c = clock();
    const off = createSessionTracker({ now: c.now });
    for (let i = 0; i < 500; i++) assert.equal(off.open(`s${i}`, { network: 'cgnat' }).ok, true);

    const on = createSessionTracker({ now: c.now, maxSessionsPerNetwork: 3, networkWindowMs: 60e3 });
    for (let i = 0; i < 3; i++) assert.equal(on.open(`s${i}`, { network: 'n' }).ok, true);
    assert.deepEqual(on.open('s3', { network: 'n' }), { ok: false, reason: 'network_session_limit' });
    assert.equal(on.open('x', { network: 'other' }).ok, true);
    c.advance(61e3);
    assert.equal(on.open('s4', { network: 'n' }).ok, true, 'window passed');
});

test('expired sessions leave list/summary and are swept', () => {
    const c = clock();
    const tr = createSessionTracker({ now: c.now });
    tr.open('short', { network: 'n1', exp: c.now() + 1000 });
    tr.open('long', { network: 'n2', exp: c.now() + 60e3 });
    c.advance(2000);
    assert.deepEqual(tr.list().sessions.map(s => s.sid), ['long']);
    assert.equal(tr.summary().active, 1);
    tr.sweep();
    assert.equal(tr.size, 1);
});

test('summary ranks networks; unknown sessions are picked up on touch; clear empties', () => {
    const tr = createSessionTracker();
    tr.open('a', { network: 'big' });
    tr.open('b', { network: 'big' });
    tr.open('c', { network: 'small' });
    tr.touch('after-restart', { network: 'big', kind: 'stream', channel: 'b2' });
    assert.deepEqual(tr.summary().topNetworks[0], { network: 'big', sessions: 3 });
    assert.equal(tr.list().total, 4);
    tr.remove('a');
    assert.equal(tr.list().total, 3);
    tr.clear();
    assert.equal(tr.size, 0);
});

test('size cap drops the oldest entry', () => {
    const tr = createSessionTracker({ maxEntries: 2 });
    tr.open('1', {}); tr.open('2', {}); tr.open('3', {});
    assert.equal(tr.size, 2);
    assert.deepEqual(tr.list().sessions.map(s => s.sid).sort(), ['2', '3']);
});
