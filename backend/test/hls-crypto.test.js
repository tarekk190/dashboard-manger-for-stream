'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { createHlsCrypto, createIndexMap } = require('../lib/hls-crypto');

const SECRET = 'x'.repeat(48);
const T0 = 1_800_000_000_000; // fixed clock (ms)

function make(nowMs = T0, rotateSeconds = 300) {
    return createHlsCrypto({ secret: SECRET, rotateSeconds, now: () => nowMs });
}

test('refuses a short secret', () => {
    assert.throws(() => createHlsCrypto({ secret: 'short' }));
});

test('keys: 16 bytes, deterministic, separate per scope, index and secret', () => {
    const c = make();
    const k = c.deriveKey('r:abc', 10);
    assert.equal(k.length, 16);
    assert.deepEqual(k, make().deriveKey('r:abc', 10));
    assert.notDeepEqual(k, c.deriveKey('r:abc', 11));
    assert.notDeepEqual(k, c.deriveKey('o:abc', 10));
    assert.notDeepEqual(k, createHlsCrypto({ secret: 'y'.repeat(48) }).deriveKey('r:abc', 10));
});

test('IV = segment number, big-endian (the HLS default IV)', () => {
    const c = make();
    assert.equal(c.ivFor('seg_00042').toString('hex'), '0000000000000000000000000000002a');
    assert.equal(c.ivFor('seg_1794671902').toString('hex'), '0000000000000000000000006af8851e');
    assert.equal(c.ivFor('nodigits').length, 16);
});

test('segment encryption is standard AES-128-CBC + PKCS#7 (what hls.js decrypts)', () => {
    const c = make();
    const plain = crypto.randomBytes(188 * 1000 + 7);
    const enc = c.encryptSegment(plain, 'r:abc', 5, 'seg_00042');
    assert.equal(enc.length % 16, 0);
    assert.ok(enc.length > plain.length);
    assert.notDeepEqual(enc.subarray(0, 64), plain.subarray(0, 64));
    // Independent decryption with the key and IV a player would use
    const d = crypto.createDecipheriv('aes-128-cbc', c.deriveKey('r:abc', 5), Buffer.from('0000000000000000000000000000002a', 'hex'));
    assert.deepEqual(Buffer.concat([d.update(enc), d.final()]), plain);
    assert.deepEqual(c.decryptSegment(enc, 'r:abc', 5, 'seg_00042'), plain);
    assert.throws(() => c.decryptSegment(enc, 'r:abc', 6, 'seg_00042'));
});

test('key indices: only near now are released; inline keys cover now-1 .. now+2', () => {
    const c = make();
    const cur = c.currentIndex();
    assert.equal(cur, Math.floor(T0 / 1000 / 300));
    for (const d of [-2, -1, 0, 1, 2]) assert.ok(c.indexAllowed(cur + d), `cur${d}`);
    for (const d of [-3, 3, 1000]) assert.ok(!c.indexAllowed(cur + d), `cur${d}`);
    assert.ok(!c.indexAllowed(NaN));
    assert.ok(!c.indexAllowed(1.5));
    const keys = c.inlineKeys('o:ch');
    assert.deepEqual(Object.keys(keys).map(Number), [cur - 1, cur, cur + 1, cur + 2]);
    assert.equal(Buffer.from(keys[cur], 'base64').toString('hex'), c.deriveKey('o:ch', cur).toString('hex'));
});

test('native tickets: per scope and index, constant-time check', () => {
    const c = make();
    const t = c.nativeTicket('r:abc', 7);
    assert.match(t, /^[A-Za-z0-9_-]{22}$/);
    assert.ok(c.verifyNativeTicket('r:abc', 7, t));
    assert.ok(!c.verifyNativeTicket('r:abc', 8, t));
    assert.ok(!c.verifyNativeTicket('r:abd', 7, t));
    assert.ok(!c.verifyNativeTicket('r:abc', 7, t.slice(1)));
    assert.ok(!c.verifyNativeTicket('r:abc', 7, undefined));
});

const PLAYLIST = [
    '#EXTM3U',
    '#EXT-X-VERSION:3',
    '#EXT-X-TARGETDURATION:2',
    '#EXT-X-MEDIA-SEQUENCE:1794671900',
    '#EXTINF:2.000000,',
    'seg_1794671900.ts',
    '#EXT-X-DISCONTINUITY',
    '#EXTINF:2.000000,',
    'seg_1794671901.ts',
    '#EXTINF:1.960000,',
    'seg_1794671902.ts',
    ''
].join('\n');

test('playlist rewrite: EXT-X-KEY with explicit IV before every segment, new URIs', () => {
    const c = make();
    const out = c.rewritePlaylist(PLAYLIST, {
        segment: (base) => ({ uri: `/hd/s/${base}-h.js`, idx: base.endsWith('02') ? 9 : 8 }),
        keyUri: (idx) => `https://edge.example/api/hls-key/r/s/${idx}`
    });
    const lines = out.split('\n');
    const keys = lines.filter(l => l.startsWith('#EXT-X-KEY:'));
    assert.equal(keys.length, 3);
    assert.equal(keys[0], `#EXT-X-KEY:METHOD=AES-128,URI="https://edge.example/api/hls-key/r/s/8",IV=0x${c.ivFor('seg_1794671900').toString('hex')}`);
    assert.match(keys[2], /\/9",IV=0x0+6af8851e$/);
    // every KEY directly precedes its EXTINF, every EXTINF is followed by its new URI
    for (let i = 0; i < lines.length; i++) {
        if (lines[i].startsWith('#EXTINF')) {
            assert.ok(lines[i - 1].startsWith('#EXT-X-KEY:'));
            assert.match(lines[i + 1], /^\/hd\/s\/seg_\d+-h\.js$/);
        }
    }
    assert.ok(out.includes('#EXT-X-DISCONTINUITY'));
    assert.ok(out.includes('#EXT-X-MEDIA-SEQUENCE:1794671900'));
    assert.ok(!/\.ts\b/.test(out));
    // idempotent on already-keyed input: old KEY tags are replaced, not duplicated
    const twice = c.rewritePlaylist(out.replace(/\/hd\/s\/(seg_\d+)-h\.js/g, '$1.ts'), {
        segment: (base) => ({ uri: `${base}.k1.ts`, idx: 1 }),
        keyUri: (idx) => `/k/${idx}`
    });
    assert.equal(twice.split('\n').filter(l => l.startsWith('#EXT-X-KEY:')).length, 3);
});

test('playlist rewrite leaves master playlists alone', () => {
    const master = '#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1\nlow/index.m3u8\n';
    assert.equal(make().rewritePlaylist(master, { segment: () => ({ uri: 'x', idx: 0 }), keyUri: () => 'k' }), master);
});

test('index map: fixed on first sight, follows the clock for new ids, capped', () => {
    let idx = 100;
    const m = createIndexMap({ indexNow: () => idx, maxEntries: 3 });
    assert.equal(m.get('a'), 100);
    idx = 101;
    assert.equal(m.get('a'), 100);
    assert.equal(m.get('b'), 101);
    assert.equal(m.peek('c'), undefined);
    m.get('c'); m.get('d');
    assert.equal(m.size, 3);
    assert.equal(m.peek('a'), undefined); // oldest dropped
    m.delete('d');
    assert.equal(m.peek('d'), undefined);
});
