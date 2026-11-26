'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const vs = require('../lib/viewer-security');

test('ipPrefix: IPv4 /24, mapped IPv4, custom bits', () => {
    assert.equal(vs.ipPrefix('203.0.113.77'), '4:203.0.113.0/24');
    assert.equal(vs.ipPrefix('::ffff:203.0.113.77'), '4:203.0.113.0/24');
    assert.equal(vs.ipPrefix('203.0.113.77', { v4Bits: 16 }), '4:203.0.0.0/16');
    assert.equal(vs.ipPrefix('203.0.113.77', { v4Bits: 32 }), '4:203.0.113.77/32');
    assert.equal(vs.ipPrefix('255.255.255.255'), '4:255.255.255.0/24');
    assert.equal(vs.ipPrefix('203.0.113.1'), vs.ipPrefix('203.0.113.254'));
    assert.notEqual(vs.ipPrefix('203.0.113.1'), vs.ipPrefix('203.0.114.1'));
});

test('ipPrefix: IPv6 /48 and compressed forms', () => {
    assert.equal(vs.ipPrefix('2001:db8:1:2::1'), '6:2001:db8:1:0:0:0:0:0/48');
    assert.equal(vs.ipPrefix('2001:0db8:0001:ffff:ffff:ffff:ffff:ffff'), '6:2001:db8:1:0:0:0:0:0/48');
    assert.equal(vs.ipPrefix('fe80::1%eth0'), '6:fe80:0:0:0:0:0:0:0/48');
    assert.equal(vs.ipPrefix('2001:db8:abcd::', { v6Bits: 40 }), '6:2001:db8:ab00:0:0:0:0:0/40');
    assert.notEqual(vs.ipPrefix('2001:db8:1::1'), vs.ipPrefix('2001:db8:2::1'));
});

test('ipPrefix: garbage gives empty string', () => {
    assert.equal(vs.ipPrefix(''), '');
    assert.equal(vs.ipPrefix(undefined), '');
    assert.equal(vs.ipPrefix('not-an-ip'), '');
    assert.equal(vs.ipPrefix('1.2.3'), '');
});

test('segment signatures: valid within window, shared by all viewers', () => {
    const key = vs.deriveSegmentKey('x'.repeat(48));
    const now = 1_800_000_030;
    const q1 = vs.segmentQuery(key, 'match1', now, 120);
    const q2 = vs.segmentQuery(key, 'match1', now + 50, 120);
    assert.equal(q1, q2, 'same window -> identical URL (cacheable)');
    const p = new URLSearchParams(q1);
    assert.equal(vs.verifySegmentQuery(key, 'match1', p.get('e'), p.get('s'), now, 120), true);
    // still valid in the next window, dead after it
    assert.equal(vs.verifySegmentQuery(key, 'match1', p.get('e'), p.get('s'), now + 150, 120), true);
    assert.equal(vs.verifySegmentQuery(key, 'match1', p.get('e'), p.get('s'), Number(p.get('e')), 120), false);
});

test('segment signatures: refused for other channel, key, tampering, far future', () => {
    const key = vs.deriveSegmentKey('x'.repeat(48));
    const other = vs.deriveSegmentKey('y'.repeat(48));
    const now = 1_800_000_000;
    const p = new URLSearchParams(vs.segmentQuery(key, 'match1', now, 120));
    const e = p.get('e'), s = p.get('s');
    assert.equal(vs.verifySegmentQuery(key, 'match2', e, s, now, 120), false);
    assert.equal(vs.verifySegmentQuery(other, 'match1', e, s, now, 120), false);
    assert.equal(vs.verifySegmentQuery(key, 'match1', String(Number(e) + 120), s, now, 120), false);
    assert.equal(vs.verifySegmentQuery(key, 'match1', e, s.slice(0, -1) + (s.endsWith('A') ? 'B' : 'A'), now, 120), false);
    assert.equal(vs.verifySegmentQuery(key, 'match1', undefined, s, now, 120), false);
    assert.equal(vs.verifySegmentQuery(key, 'match1', e, '', now, 120), false);
    // a correctly signed but too-distant expiry (forged issuer clock) is refused
    const far = String(now + 10_000);
    assert.equal(vs.verifySegmentQuery(key, 'match1', far, vs.segmentSignature(key, 'match1', Number(far)), now, 120), false);
});

test('revocation store: expiry, sweep and size cap', () => {
    let t = 1000;
    const store = vs.createRevocationStore({ max: 2, now: () => t });
    store.revoke('a', 5000);
    assert.equal(store.isRevoked('a'), true);
    assert.equal(store.isRevoked('b'), false);
    t = 6000;
    assert.equal(store.isRevoked('a'), false, 'entry ends when the session would have expired');
    store.revoke('b', 10_000);
    store.revoke('c', 10_000);
    store.revoke('d', 10_000);
    assert.equal(store.size, 2);
    assert.equal(store.isRevoked('b'), false, 'oldest dropped at the cap');
    assert.equal(store.isRevoked('d'), true);
});

test('verifyTurnstile: success, failure, missing token, network error', async () => {
    let sent;
    const ok = await vs.verifyTurnstile({
        secret: 'sec', token: 'tok', remoteip: '1.2.3.4',
        fetchImpl: async (url, init) => {
            sent = { url, body: init.body.toString() };
            return { json: async () => ({ success: true, hostname: 'Live.Example.com', action: 'player' }) };
        }
    });
    assert.deepEqual(ok, { ok: true, hostname: 'live.example.com', action: 'player', codes: [] });
    assert.equal(sent.url, vs.TURNSTILE_VERIFY_URL);
    assert.match(sent.body, /secret=sec/);
    assert.match(sent.body, /remoteip=1\.2\.3\.4/);

    const bad = await vs.verifyTurnstile({
        secret: 'sec', token: 'tok',
        fetchImpl: async () => ({ json: async () => ({ success: false, 'error-codes': ['invalid-input-response'] }) })
    });
    assert.equal(bad.ok, false);
    assert.deepEqual(bad.codes, ['invalid-input-response']);

    const missing = await vs.verifyTurnstile({ secret: 'sec', token: '', fetchImpl: async () => { throw new Error('not called'); } });
    assert.equal(missing.ok, false);

    const down = await vs.verifyTurnstile({ secret: 'sec', token: 'tok', fetchImpl: async () => { throw new Error('ECONNRESET'); } });
    assert.deepEqual(down, { ok: false, codes: ['unreachable'] });
});

test('mayUseNativeHls', () => {
    assert.equal(vs.mayUseNativeHls('Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Version/16.0 Mobile/15E148 Safari/604.1'), true);
    assert.equal(vs.mayUseNativeHls('Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 CriOS/120.0 Mobile/15E148 Safari/604.1'), true);
    assert.equal(vs.mayUseNativeHls('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15'), true);
    assert.equal(vs.mayUseNativeHls('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36'), false);
    assert.equal(vs.mayUseNativeHls('Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36'), false);
    assert.equal(vs.mayUseNativeHls('curl/8.4.0'), false);
});
