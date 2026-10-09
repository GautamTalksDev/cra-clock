// Site Worker /kev.json: caching, stale fallback and cached upstream failures, with mocked fetch and Cache API.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../site/worker/index.js';

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
const good = () => new Response(JSON.stringify({ catalogVersion: '1', vulnerabilities: [{ cveID: 'CVE-2024-1' }, { cveID: 'bad' }] }));

test('serves CVE ids and caches them', async () => {
  upstream = good;
  const r = await get();
  assert.equal(r.status, 200);
  assert.deepEqual(await r.json(), { catalogVersion: '1', cves: ['CVE-2024-1'], latest: [] });
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
  store.delete('https://x.test/kev.json');
  upstream = () => { throw new Error('network'); };
  const r = await get();
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('x-kev-stale'), '1');
  assert.deepEqual((await r.json()).cves, ['CVE-2024-1']);
  assert.equal(r.headers.get('cache-control'), 'public, max-age=300');
});

test('latest: newest first, public fields only, validated and capped', async () => {
  upstream = () => new Response(JSON.stringify({ catalogVersion: '2', vulnerabilities: [
    { cveID: 'CVE-2024-1', vendorProject: 'Old', product: 'A', dateAdded: '2024-01-01', knownRansomwareCampaignUse: 'Unknown', notes: 'x' },
    { cveID: 'CVE-2026-9', vendorProject: 'Acme<script>', product: 'Router OS', dateAdded: '2026-10-07', knownRansomwareCampaignUse: 'Known' },
    { cveID: 'CVE-2025-5', vendorProject: 'Mid', product: 'B', dateAdded: '2025-06-01' },
    { cveID: 'not-a-cve', vendorProject: 'Bad', product: 'C', dateAdded: '2026-10-08' },
    { cveID: 'CVE-2026-8', vendorProject: 'NoDate', product: 'D', dateAdded: 'yesterday' },
    ...Array.from({ length: 10 }, (_, i) => ({ cveID: `CVE-2020-${i + 10}`, vendorProject: 'V'.repeat(80), product: 'P', dateAdded: '2020-01-01' })),
  ] }));
  const { latest } = await (await get()).json();
  assert.equal(latest.length, 8);
  assert.deepEqual(latest[0], { cve: 'CVE-2026-9', vendor: 'Acmescript', product: 'Router OS', added: '2026-10-07', ransomware: true });
  assert.equal(latest[1].cve, 'CVE-2025-5');
  assert.equal(latest[1].ransomware, false);
  assert.ok(latest.every((x) => !('notes' in x) && x.vendor.length <= 40));
  assert.ok(!latest.some((x) => x.cve === 'not-a-cve' || x.cve === 'CVE-2026-8'));
});
