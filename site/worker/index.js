// Site Worker: static assets + /kev.json, a cached, CORS-safe mirror of the CISA KEV CVE list for the browser scanner
// (cisa.gov does not send CORS headers). Only CVE ids are served; refreshed at most every 6 hours.
// If CISA fails, the last good copy (kept under a stale key) is served; either way the failure is cached for 5 minutes.
const KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const HDR = { 'content-type': 'application/json', 'x-content-type-options': 'nosniff' };
const FAIL_TTL = 300;
const json = (body, maxAge, extra = {}, status = 200) => new Response(body, { status, headers: { ...HDR, 'cache-control': `public, max-age=${maxAge}`, ...extra } });

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/kev.json' && request.method === 'GET') {
      const cache = caches.default;
      const key = new Request(url.origin + '/kev.json');
      const staleKey = new Request(url.origin + '/kev.json?stale');
      const hit = await cache.match(key);
      if (hit) {
        // A cached failure is stored as 200 (the Cache API may skip 5xx) and marked; turn it back into a 502.
        if (hit.headers.get('x-kev-failed')) return json('{"cves":[]}', FAIL_TTL, {}, 502);
        return hit;
      }
      let body = null;
      try {
        const up = await fetch(KEV, { cf: { cacheTtl: 21600 }, redirect: 'error' });
        if (up.ok) {
          const j = await up.json();
          body = JSON.stringify({ catalogVersion: j.catalogVersion, cves: (j.vulnerabilities || []).map((v) => v.cveID).filter((c) => /^CVE-\d{4}-\d+$/.test(c)) });
        }
      } catch { body = null; }
      if (body) {
        const res = json(body, 21600);
        ctx.waitUntil(Promise.all([cache.put(key, res.clone()), cache.put(staleKey, json(body, 2592000))]));
        return res;
      }
      const last = await cache.match(staleKey);
      if (last) {
        const res = json(await last.text(), FAIL_TTL, { 'x-kev-stale': '1' });
        ctx.waitUntil(cache.put(key, res.clone()));
        return res;
      }
      ctx.waitUntil(cache.put(key, json('{"cves":[]}', FAIL_TTL, { 'x-kev-failed': '1' })));
      return json('{"cves":[]}', FAIL_TTL, {}, 502);
    }
    return env.ASSETS.fetch(request);
  },
};
