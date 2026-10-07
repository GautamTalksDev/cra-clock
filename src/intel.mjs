// Vulnerability intelligence: OSV.dev (which versions are affected), CISA KEV (which CVEs are exploited in the wild),
// FIRST EPSS (how likely exploitation is in the next 30 days). All free, no keys.
const OSV = 'https://api.osv.dev/v1';
const KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS = 'https://api.first.org/data/v1/epss';

async function getJson(fetcher, url, init, tries = 3) {
  for (let i = 0; ; i++) {
    try {
      const r = await fetcher(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(60_000) });
      if (r.ok) return r.json();
      if (r.status < 500 && r.status !== 429) throw new Error(`${url} -> HTTP ${r.status}`);
    } catch (e) {
      if (i >= tries - 1) throw e;
    }
    await new Promise((res) => setTimeout(res, 2000 * (i + 1)));
  }
}

/** OSV querybatch (1000 per call) -> Map(purl -> [vuln ids]) */
export async function osvBatch(components, fetcher = fetch) {
  const out = new Map();
  for (let i = 0; i < components.length; i += 1000) {
    const chunk = components.slice(i, i + 1000);
    const j = await getJson(fetcher, OSV + '/querybatch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ queries: chunk.map((c) => ({ package: { purl: c.purl } })) }) });
    (j.results || []).forEach((r, k) => { if (r.vulns && r.vulns.length) out.set(chunk[k].purl, r.vulns.map((v) => v.id)); });
  }
  return out;
}

/** OSV details for ids -> Map(id -> {id, summary, aliases, cves, severity, fixed, published, modified, refs}) */
export async function osvDetails(ids, fetcher = fetch, concurrency = 8) {
  const out = new Map();
  const queue = [...new Set(ids)];
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
    for (let id; (id = queue.shift()); ) {
      try {
        const v = await getJson(fetcher, `${OSV}/vulns/${encodeURIComponent(id)}`);
        const cves = [v.id, ...(v.aliases || [])].filter((x) => /^CVE-\d{4}-\d{4,}$/.test(x));
        const fixed = [];
        for (const a of v.affected || []) for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) fixed.push(e.fixed);
        out.set(id, { id, summary: String(v.summary || v.details || '').slice(0, 300), aliases: v.aliases || [], cves: [...new Set(cves)], severity: (v.database_specific && v.database_specific.severity) || null, fixed: [...new Set(fixed)].slice(0, 5), published: v.published || null, refs: (v.references || []).map((r) => r.url).filter((u) => /^https:\/\//.test(u)).slice(0, 5) });
      } catch {
        out.set(id, { id, summary: '', aliases: [], cves: /^CVE-/.test(id) ? [id] : [], severity: null, fixed: [], published: null, refs: [] });
      }
    }
  }));
  return out;
}

/** CISA KEV -> Map(CVE -> {dateAdded, dueDate, ransomware, vendor, product, name, action}) */
export async function kev(fetcher = fetch) {
  const j = await getJson(fetcher, KEV, { headers: { accept: 'application/json' } });
  const m = new Map();
  for (const v of j.vulnerabilities || []) m.set(v.cveID, { dateAdded: v.dateAdded, dueDate: v.dueDate, ransomware: v.knownRansomwareCampaignUse === 'Known', vendor: v.vendorProject, product: v.product, name: v.vulnerabilityName, action: v.requiredAction });
  return { catalogVersion: j.catalogVersion, released: j.dateReleased, map: m };
}

/** EPSS for CVEs -> Map(CVE -> {epss, percentile}) */
export async function epss(cves, fetcher = fetch) {
  const m = new Map();
  const list = [...new Set(cves)];
  for (let i = 0; i < list.length; i += 100) {
    try {
      const j = await getJson(fetcher, `${EPSS}?cve=${list.slice(i, i + 100).join(',')}`);
      for (const d of j.data || []) m.set(d.cve, { epss: Number(d.epss), percentile: Number(d.percentile) });
    } catch { /* EPSS is advisory; carry on without it */ }
  }
  return m;
}
