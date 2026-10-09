// Preloaded with `node --import` by the subprocess tests, so the real entry point (src/main.mjs) runs against a fake
// network and retries are instant. CRA_TEST_SCENARIO picks the behaviour.
const scenario = process.env.CRA_TEST_SCENARIO || '';
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...args) => realSetTimeout(fn, 0, ...args);

const filler = Array.from({ length: 1200 }, (_, i) => ({ cveID: `CVE-2000-${1000 + i}` }));

globalThis.fetch = async (url, init = {}) => {
  url = String(url);
  if (url.endsWith('/querybatch')) {
    // upstream error text that tries to start workflow commands on its own lines
    if (scenario === 'osv-throws') throw new Error('upstream said:\n::add-mask::hunter2\n::warning::pwned\r\n::error::fake');
    const q = JSON.parse(init.body).queries;
    return Response.json({ results: q.map(() => ({ vulns: [{ id: 'GHSA-35jh-r3h4-6jhm' }] })) });
  }
  if (url.includes('/vulns/')) return Response.json({ id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], summary: 'Command injection in lodash' });
  if (url.includes('known_exploited')) {
    if (scenario === 'kev-empty') return Response.json({});
    return Response.json({ catalogVersion: '2026.10.06', vulnerabilities: filler });
  }
  if (url.includes('api.first.org')) return Response.json({ data: [{ cve: 'CVE-2021-23337', epss: '0.02', percentile: '0.8' }] });
  throw new Error('unexpected ' + url);
};
