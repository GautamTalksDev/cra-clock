// Site Worker: static assets + /kev.json, a cached, CORS-safe mirror of the CISA KEV CVE list for the browser scanner
// (cisa.gov does not send CORS headers). Only CVE ids are served; refreshed at most every 6 hours.
const KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/kev.json' && request.method === 'GET') {
      const cache = caches.default, key = new Request(url.origin + '/kev.json');
      let res = await cache.match(key);
      if (!res) {
        const up = await fetch(KEV, { cf: { cacheTtl: 21600 }, redirect: 'error' });
        if (!up.ok) return new Response('{"cves":[]}', { status: 502, headers: { 'content-type': 'application/json' } });
        const j = await up.json();
        res = new Response(JSON.stringify({ catalogVersion: j.catalogVersion, cves: (j.vulnerabilities || []).map((v) => v.cveID).filter((c) => /^CVE-\d{4}-\d+$/.test(c)) }), {
          headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=21600', 'x-content-type-options': 'nosniff' },
        });
        ctx.waitUntil(cache.put(key, res.clone()));
      }
      return res;
    }
    return env.ASSETS.fetch(request);
  },
};
