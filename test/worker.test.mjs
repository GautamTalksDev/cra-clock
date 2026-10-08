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
  assert.deepEqual(await r.json(), { catalogVersion: '1', cves: ['CVE-2024-1'] });
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
