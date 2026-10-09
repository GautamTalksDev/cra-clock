// Vulnerability intelligence: OSV.dev (which versions are affected), CISA KEV (which CVEs are exploited in the wild),
// FIRST EPSS (how likely exploitation is in the next 30 days). All free, no keys.
// Everything that comes back is untrusted: fields that are printed later are validated here (severity, versions, dates,
// links) and the output layer escapes them again.
import { str, severity, isoDate, version, httpsUrl } from './safe.mjs';

const OSV = 'https://api.osv.dev/v1';
const KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS = 'https://api.first.org/data/v1/epss';
const CVE = /^CVE-\d{4}-\d{4,}$/;

/** The KEV catalog has about 1,400 entries and only grows. A response with fewer than this is an outage, not a clean bill of health. */
export const KEV_MIN_ENTRIES = 1000;

/**
 * GET or POST for JSON with bounded retries: at most `tries` attempts, and it always ends by returning or throwing.
 * 5xx, 429, network errors, unparsable bodies and bodies that fail `validate` are retried; other 4xx are final.
 */
async function getJson(fetcher, url, init, { tries = 3, delayMs = 2000, validate } = {}) {
  let last;
  for (let i = 0; i < tries; i++) {
    let final = false;
    try {
      const r = await fetcher(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(60_000) });
      if (r.ok) {
        const j = await r.json();
        if (validate) validate(j); // a 200 that is not the expected document counts as a failure and is retried
        return j;
      }
      last = new Error(`${url} -> HTTP ${r.status}`);
      final = r.status < 500 && r.status !== 429;
    } catch (e) {
      last = e;
    }
    if (final) break;
    if (i < tries - 1 && delayMs) await new Promise((res) => setTimeout(res, delayMs * (i + 1)));
  }
  throw last;
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

const list = (x) => (Array.isArray(x) ? x : []);

/** OSV details for ids -> Map(id -> {id, summary, aliases, cves, severity, fixed, published, modified, refs}) */
export async function osvDetails(ids, fetcher = fetch, concurrency = 8) {
  const out = new Map();
  const queue = [...new Set(ids)];
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
    for (let id; (id = queue.shift()); ) {
      try {
        const v = await getJson(fetcher, `${OSV}/vulns/${encodeURIComponent(id)}`);
        const aliases = list(v.aliases).filter((x) => typeof x === 'string').slice(0, 50);
        const cves = [v.id, ...aliases].filter((x) => typeof x === 'string' && CVE.test(x));
        const fixed = [];
        for (const a of list(v.affected)) for (const r of list(a && a.ranges)) for (const e of list(r && r.events)) { const x = version(e && e.fixed); if (x) fixed.push(x); }
        out.set(id, {
          id, summary: str(v.summary, 300) || str(v.details, 300), aliases: aliases.map((x) => str(x, 60)), cves: [...new Set(cves)],
          severity: severity(v.database_specific && v.database_specific.severity), fixed: [...new Set(fixed)].slice(0, 5),
          published: str(v.published, 40) || null, refs: list(v.references).map((r) => httpsUrl(r && r.url)).filter(Boolean).slice(0, 5),
        });
      } catch {
        // never treat a failed lookup as "nothing to see": assess() marks it intel-incomplete
        out.set(id, { id, summary: '', aliases: [], cves: CVE.test(id) ? [id] : [], severity: null, fixed: [], published: null, refs: [], incomplete: true });
      }
    }
  }));
  return out;
}

/** Throws unless j looks like the real KEV catalog. An empty object, an empty list or a maintenance page is not "nothing is exploited". */
function checkKev(j) {
  const n = j && Array.isArray(j.vulnerabilities) ? j.vulnerabilities.filter((v) => v && CVE.test(v.cveID)).length : 0;
  if (!j || typeof j.catalogVersion !== 'string' || !j.catalogVersion.trim()) throw new Error('the CISA KEV response has no catalogVersion');
  if (n <= KEV_MIN_ENTRIES) throw new Error(`the CISA KEV response lists only ${n} vulnerabilities (the catalog has over ${KEV_MIN_ENTRIES})`);
}

/**
 * CISA KEV -> Map(CVE -> {dateAdded, dueDate, ransomware, vendor, product, name, action}).
 * Throws when the catalog cannot be fetched or is empty: callers must treat that as "exploitation status unknown".
 */
export async function kev(fetcher = fetch, { delayMs } = {}) {
  const j = await getJson(fetcher, KEV, { headers: { accept: 'application/json' } }, { delayMs, validate: checkKev });
  const m = new Map();
  for (const v of j.vulnerabilities) {
    if (!v || !CVE.test(v.cveID)) continue;
    m.set(v.cveID, {
      dateAdded: isoDate(v.dateAdded), dueDate: isoDate(v.dueDate), ransomware: v.knownRansomwareCampaignUse === 'Known',
      vendor: str(v.vendorProject, 100), product: str(v.product, 100), name: str(v.vulnerabilityName, 200), action: str(v.requiredAction, 300),
    });
  }
  return { catalogVersion: str(j.catalogVersion, 32), released: str(j.dateReleased, 40), map: m };
}

/** EPSS for CVEs -> Map(CVE -> {epss, percentile}); m.failed is the Set of CVEs whose EPSS lookup failed */
export async function epss(cves, fetcher = fetch) {
  const m = new Map();
  m.failed = new Set();
  const ids = [...new Set(cves)];
  for (let i = 0; i < ids.length; i += 100) {
    const chunk = ids.slice(i, i + 100);
    try {
      const j = await getJson(fetcher, `${EPSS}?cve=${chunk.join(',')}`);
      for (const d of j.data || []) m.set(d.cve, { epss: Number(d.epss), percentile: Number(d.percentile) });
    } catch {
      for (const c of chunk) m.failed.add(c); // assess() marks these intel-incomplete instead of "known"
    }
  }
  return m;
}
