// Site Worker /kev.json: caching, stale fallback and cached upstream failures, with mocked fetch and Cache API.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import worker, { kevBody, KEV_MIN } from '../site/worker/index.js';
import { kevJson } from './kev-fixture.mjs';

let store, calls, upstream;
const ctx = () => { const p = []; return { waitUntil: (x) => p.push(x), done: () => Promise.all(p) }; };
beforeEach(() => {
  store = new Map(); calls = 0;
  globalThis.caches = { default: {
    match: async (k) => store.get(k.url)?.clone(),
    put: async (k, r) => { store.set(k.url, r.clone()); },
  } };
  globalThis.fetch = async () => { calls++; return upstream(); };
});
const get = async () => { const c = ctx(); const r = await worker.fetch(new Request('https://x.test/kev.json'), {}, c); await c.done(); return r; };
const good = () => new Response(JSON.stringify(kevJson([{ cveID: 'CVE-2024-1' }, { cveID: 'bad' }], { catalogVersion: '1' })));
const MAIN_KEY = 'https://x.test/kev.json?v=4';

test('serves CVE ids and caches them', async () => {
  upstream = good;
  const r = await get();
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.catalogVersion, '1');
  assert.ok(j.cves.includes('CVE-2024-1') && !j.cves.includes('bad'), 'only well-formed CVE ids');
  assert.ok(j.cves.length > 1000);
  assert.deepEqual(j.latest, []);
  await get();
  assert.equal(calls, 1);
});

test('upstream failure with no last good copy: 502, cached for 5 minutes', async () => {
  upstream = () => new Response('x', { status: 500 });
  const r = await get();
  assert.equal(r.status, 502);
  assert.equal(r.headers.get('cache-control'), 'public, max-age=300');
  const r2 = await get();
  assert.equal(r2.status, 502);
  assert.equal(calls, 1);
});

test('upstream failure serves the last good copy', async () => {
  upstream = good;
  await get();
  store.delete(MAIN_KEY);
  upstream = () => { throw new Error('network'); };
  const r = await get();
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('x-kev-stale'), '1');
  assert.ok((await r.json()).cves.includes('CVE-2024-1'));
  assert.equal(r.headers.get('cache-control'), 'public, max-age=300');
});

test('latest: newest first, public fields only, validated and capped', async () => {
  upstream = () => new Response(JSON.stringify(kevJson([
    { cveID: 'CVE-2024-1', vendorProject: 'Old', product: 'A', dateAdded: '2024-01-01', knownRansomwareCampaignUse: 'Unknown', notes: 'x' },
    { cveID: 'CVE-2026-9', vendorProject: 'Acme<script>', product: 'Router OS', dateAdded: '2026-10-07', knownRansomwareCampaignUse: 'Known' },
    { cveID: 'CVE-2025-5', vendorProject: 'Mid', product: 'B', dateAdded: '2025-06-01' },
    { cveID: 'not-a-cve', vendorProject: 'Bad', product: 'C', dateAdded: '2026-10-08' },
    { cveID: 'CVE-2026-8', vendorProject: 'NoDate', product: 'D', dateAdded: 'yesterday' },
    ...Array.from({ length: 10 }, (_, i) => ({ cveID: `CVE-2020-${i + 10}`, vendorProject: 'V'.repeat(80), product: 'P', dateAdded: '2020-01-01' })),
  ], { catalogVersion: '2' })));
  const { latest } = await (await get()).json();
  assert.equal(latest.length, 8);
  assert.deepEqual(latest[0], { cve: 'CVE-2026-9', vendor: 'Acmescript', product: 'Router OS', added: '2026-10-07', ransomware: true });
  assert.equal(latest[1].cve, 'CVE-2025-5');
  assert.equal(latest[1].ransomware, false);
  assert.ok(latest.every((x) => !('notes' in x) && x.vendor.length <= 40));
  assert.ok(!latest.some((x) => x.cve === 'not-a-cve' || x.cve === 'CVE-2026-8'));
});

// C-M2: an empty or truncated catalog must never be served, cached or kept as "last good", because "no entries" reads as "nothing exploited"
const emptyBodies = {
  'empty object': {},
  'empty list': { catalogVersion: '2026.10.06', vulnerabilities: [] },
  'no catalogVersion': { vulnerabilities: kevJson().vulnerabilities },
  'exactly 1000 entries': kevJson([], { vulnerabilities: kevJson().vulnerabilities.slice(0, 1000) }),
  'entries without CVE ids': { catalogVersion: '1', vulnerabilities: Array.from({ length: 5000 }, () => ({ nope: 1 })) },
  'wrong types': { catalogVersion: 5, vulnerabilities: 'lots' },
};

test('C-M2: kevBody() returns null for an empty or truncated catalog, a body for the real shape', () => {
  for (const [name, j] of Object.entries(emptyBodies)) assert.equal(kevBody(j), null, name);
  assert.equal(kevBody(null), null);
  assert.equal(kevBody(undefined), null);
  const body = JSON.parse(kevBody(kevJson([], { vulnerabilities: kevJson().vulnerabilities.slice(0, 1001) })));
  assert.equal(body.cves.length, 1001);
  assert.equal(KEV_MIN, 1000);
});

test('C-M2 PoC: an empty upstream answer is a 502 cached for 5 minutes, not a 200 with no CVEs', async () => {
  for (const [name, j] of Object.entries(emptyBodies)) {
    store.clear(); calls = 0;
    upstream = () => new Response(JSON.stringify(j));
    const r = await get();
    assert.equal(r.status, 502, name);
    assert.deepEqual(await r.json(), { cves: [] }, name);
    assert.equal(r.headers.get('cache-control'), 'public, max-age=300', name);
    assert.equal((await get()).status, 502, name);
    assert.equal(calls, 1, `${name}: the failure is cached, upstream is not hammered`);
    assert.ok(!store.has('https://x.test/kev.json?stale=4'), `${name}: never kept as the last good copy`);
  }
});

test('C-M2: an empty answer after a good one serves the last good copy (marked stale), and never replaces it', async () => {
  upstream = good;
  await get();
  store.delete(MAIN_KEY);
  upstream = () => new Response('{}');
  const r = await get();
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('x-kev-stale'), '1');
  const j = await r.json();
  assert.ok(j.cves.includes('CVE-2024-1') && j.cves.length > 1000);
  const stale = await store.get('https://x.test/kev.json?stale=4').text();
  assert.ok(JSON.parse(stale).cves.length > 1000, 'the stored last good copy is still the full catalog');
});

test('C-M2: the edge fetch cache cannot pin a bad CISA answer for longer than a cached failure', async () => {
  let init;
  globalThis.fetch = async (u, i) => { calls++; init = i; return good(); };
  await get();
  assert.ok(init.cf.cacheTtl <= 300, `cf.cacheTtl is ${init.cf.cacheTtl}`);
  assert.equal(init.redirect, 'manual', 'Workers reject redirect: error; manual turns a redirect into a failure');
});

test('a redirect from the feed URL is a failure, never followed', async () => {
  upstream = () => new Response(null, { status: 301, headers: { location: 'https://evil.test/kev.json' } });
  const r = await get();
  assert.equal(r.status, 502);
});

test('C-M2: copies cached under the old key (before the empty-catalog check) are never served', async () => {
  store.set('https://x.test/kev.json', new Response('{"catalogVersion":"","cves":[],"latest":[]}', { headers: { 'cache-control': 'public, max-age=21600' } }));
  store.set('https://x.test/kev.json?stale', new Response('{"catalogVersion":"","cves":[],"latest":[]}'));
  upstream = good;
  const j = await (await get()).json();
  assert.ok(j.cves.length > 1000);
  assert.equal(calls, 1);
});
