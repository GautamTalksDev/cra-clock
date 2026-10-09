// Site Worker: static assets + /kev.json, a cached, CORS-safe mirror of the CISA KEV CVE list for the browser scanner
// (cisa.gov does not send CORS headers). Serves the CVE ids plus the 8 newest catalog entries (public fields only) for the
// departures board; refreshed at most every 6 hours.
// If CISA fails, the last good copy (kept under a stale key) is served; either way the failure is cached for 5 minutes.
const KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const HDR = { 'content-type': 'application/json', 'x-content-type-options': 'nosniff' };
const FAIL_TTL = 300;
const LATEST = 8;
// Public catalog fields only, validated and length-capped, so nothing odd from upstream reaches the page.
const clean = (s, n) => (typeof s === 'string' ? s.replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, n) : '');
export function kevBody(j) {
  const vulns = Array.isArray(j?.vulnerabilities) ? j.vulnerabilities : [];
  const latest = vulns
    .filter((v) => /^CVE-\d{4}-\d+$/.test(v?.cveID) && /^\d{4}-\d{2}-\d{2}$/.test(v?.dateAdded))
    .sort((a, b) => (a.dateAdded < b.dateAdded ? 1 : a.dateAdded > b.dateAdded ? -1 : 0))
    .slice(0, LATEST)
    .map((v) => ({ cve: v.cveID, vendor: clean(v.vendorProject, 40), product: clean(v.product, 48), added: v.dateAdded, ransomware: v.knownRansomwareCampaignUse === 'Known' }));
  return JSON.stringify({ catalogVersion: clean(j?.catalogVersion, 32), cves: vulns.map((v) => v?.cveID).filter((c) => /^CVE-\d{4}-\d+$/.test(c)), latest });
}
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
          body = kevBody(await up.json());
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
