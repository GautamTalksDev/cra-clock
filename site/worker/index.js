// Site Worker: static assets + /kev.json, a cached, CORS-safe mirror of the CISA KEV CVE list for the browser scanner
// (cisa.gov does not send CORS headers). Serves the CVE ids plus the 8 newest catalog entries (public fields only) for the
// departures board; refreshed at most every 6 hours.
// If CISA fails, the last good copy (kept under a stale key) is served; either way the failure is cached for 5 minutes.
// An empty or truncated catalog (a maintenance page, "{}") counts as a failure: it is never served as good, never cached
// as good and never kept as the last good copy, because "no entries" would read as "nothing is exploited".
const KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const HDR = { 'content-type': 'application/json', 'x-content-type-options': 'nosniff' };
const FAIL_TTL = 300;
const LATEST = 8;
export const KEV_MIN = 1000; // the real catalog has about 1,400 entries and only grows
// Cache keys carry a version so copies cached before the empty-catalog check cannot be served after a deploy.
const KEY = '/kev.json?v=2', STALE_KEY = '/kev.json?stale=2';
// Public catalog fields only, validated and length-capped, so nothing odd from upstream reaches the page.
const clean = (s, n) => (typeof s === 'string' ? s.replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, n) : '');
/** the public mirror body for a KEV catalog document, or null if the document is not a plausible full catalog */
export function kevBody(j) {
  const vulns = Array.isArray(j?.vulnerabilities) ? j.vulnerabilities : [];
  const catalogVersion = clean(j?.catalogVersion, 32);
  if (!catalogVersion || vulns.filter((v) => /^CVE-\d{4}-\d+$/.test(v?.cveID)).length <= KEV_MIN) return null;
  const latest = vulns
    .filter((v) => /^CVE-\d{4}-\d+$/.test(v?.cveID) && /^\d{4}-\d{2}-\d{2}$/.test(v?.dateAdded))
    .sort((a, b) => (a.dateAdded < b.dateAdded ? 1 : a.dateAdded > b.dateAdded ? -1 : 0))
    .slice(0, LATEST)
    .map((v) => ({ cve: v.cveID, vendor: clean(v.vendorProject, 40), product: clean(v.product, 48), added: v.dateAdded, ransomware: v.knownRansomwareCampaignUse === 'Known' }));
  return JSON.stringify({ catalogVersion, cves: vulns.map((v) => v?.cveID).filter((c) => /^CVE-\d{4}-\d+$/.test(c)), latest });
}
const json = (body, maxAge, extra = {}, status = 200) => new Response(body, { status, headers: { ...HDR, 'cache-control': `public, max-age=${maxAge}`, ...extra } });

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/kev.json' && request.method === 'GET') {
      const cache = caches.default;
      const key = new Request(url.origin + KEY);
      const staleKey = new Request(url.origin + STALE_KEY);
      const hit = await cache.match(key);
      if (hit) {
        // A cached failure is stored as 200 (the Cache API may skip 5xx) and marked; turn it back into a 502.
        if (hit.headers.get('x-kev-failed')) return json('{"cves":[]}', FAIL_TTL, {}, 502);
        return hit;
      }
      let body = null;
      try {
        // The edge may keep CISA's answer for no longer than a cached failure: our own cache below holds the good copy for
        // six hours, and a bad answer (an empty maintenance page) must not stick at the edge for that long.
        const up = await fetch(KEV, { cf: { cacheTtl: FAIL_TTL }, redirect: 'error' });
        if (up.ok) {
          body = kevBody(await up.json()); // null for an empty or truncated catalog
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
