// Turns components + intelligence into findings, and findings into the CRA Article 14 clock.
// Tiers:  exploited = a CVE of the vulnerability is in CISA KEV (reliable evidence of exploitation in the wild)
//         likely    = EPSS >= threshold (high chance of exploitation in the next 30 days)
//         intel-incomplete = OSV details, EPSS or the KEV catalog could not be fetched: needs manual review, never silently "known"
//         known     = any other OSV advisory for that exact version
export const HOUR = 3600_000;

/**
 * A stable identifier for a vulnerability: its first CVE id in sorted order, else the advisory id. It does not depend on
 * the order OSV lists advisory ids or aliases in, so the persisted clock cannot reset when that order changes.
 */
export const vulnKey = (v) => [...((v && v.cves) || [])].sort()[0] || (v && v.id);

/**
 * kevUnknown: the CISA KEV catalog could not be read (or came back empty). No advisory can then be called exploited or
 * "known": each one is marked intel-incomplete (missing "CISA KEV") unless EPSS alone already flags it as likely.
 */
export function assess(components, osvMap, details, kevMap, epssMap, { epssThreshold = 0.1, kevUnknown = false } = {}) {
  const findings = [];
  const epssFailed = epssMap && epssMap.failed;
  for (const c of components) {
    for (const id of osvMap.get(c.purl) || []) {
      const d = details.get(id) || { id, cves: [], aliases: [], fixed: [], refs: [] };
      const kevHits = kevUnknown ? [] : d.cves.filter((x) => kevMap.has(x));
      const ep = d.cves.map((x) => epssMap.get(x)).filter(Boolean).sort((a, b) => b.epss - a.epss)[0] || null;
      const missing = [];
      if (d.incomplete) missing.push('OSV details');
      if (epssFailed && d.cves.some((x) => epssFailed.has(x))) missing.push('EPSS');
      if (kevUnknown) missing.push('CISA KEV');
      const tier = kevHits.length ? 'exploited' : ep && ep.epss >= epssThreshold ? 'likely' : missing.length ? 'intel-incomplete' : 'known';
      findings.push({
        fingerprint: `${c.purl}|${vulnKey(d)}`, tier, component: c, vuln: d, kev: kevHits.map((x) => ({ cve: x, ...kevMap.get(x) })), epss: ep,
        ...(missing.length ? { missing } : {}),
      });
    }
  }
  const order = { exploited: 0, likely: 1, 'intel-incomplete': 2, known: 3 };
  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  // ties are broken by purl and advisory id, so the result does not depend on the order OSV answered in
  findings.sort((a, b) => order[a.tier] - order[b.tier] || (b.epss?.epss || 0) - (a.epss?.epss || 0) || cmp(a.component.purl, b.component.purl) || cmp(a.vuln.id, b.vuln.id));
  // OSV publishes one CVE under several ids (GHSA, PYSEC, GO, RUSTSEC): keep one finding per component and CVE,
  // the most severe tier first (the sort above), and remember the other ids as aliases.
  const seen = new Map();
  for (const f of findings) {
    const prev = seen.get(f.fingerprint);
    if (!prev) seen.set(f.fingerprint, { ...f, otherIds: [] });
    else if (!prev.otherIds.includes(f.vuln.id) && prev.vuln.id !== f.vuln.id) prev.otherIds.push(f.vuln.id);
  }
  // Earlier builds keyed the stored clock "purl|<first advisory id>", and any id of the group may have been that first
  // id, so every "purl|id" of the group is also a fingerprint the clock may already be stored under.
  return [...seen.values()].map((f) => ({
    ...f,
    legacyFingerprints: [f.vuln.id, ...f.otherIds].map((id) => `${f.component.purl}|${id}`).filter((fp) => fp !== f.fingerprint),
  }));
}

/** the Article 14 clock from the moment of awareness */
export function clock(awareAt, now = Date.now()) {
  const t = Date.parse(awareAt);
  const stages = [
    { key: 'early_warning', label: 'Early warning to ENISA', due: t + 24 * HOUR },
    { key: 'notification', label: 'Vulnerability notification', due: t + 72 * HOUR },
  ];
  return {
    awareAt: new Date(t).toISOString(),
    stages: stages.map((s) => ({ ...s, dueIso: new Date(s.due).toISOString(), remainingMs: s.due - now, overdue: now > s.due })),
    final: 'Final report: within 14 days after a corrective or mitigating measure is available.',
  };
}

const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const EARLIEST = Date.parse('2024-01-01T00:00:00Z'); // the CRA was published in November 2024: no clock can start before this
const SKEW_MS = 5 * 60_000; // runners' clocks differ by seconds; a few minutes ahead is tolerated, more is not

/** a stored awareness time normalized to ISO, or null if it is not an ISO UTC timestamp, is in the future or is implausibly old */
export function validAware(v, now = Date.now()) {
  if (typeof v !== 'string' || !ISO_UTC.test(v)) return null;
  const t = Date.parse(v);
  if (!Number.isFinite(t) || t > now + SKEW_MS || t < EARLIEST) return null;
  return new Date(t).toISOString();
}

export function fmtRemaining(ms) {
  const neg = ms < 0, a = Math.abs(ms);
  const h = Math.floor(a / HOUR), m = Math.floor((a % HOUR) / 60000);
  return `${neg ? 'OVERDUE by ' : ''}${h}h ${String(m).padStart(2, '0')}m`;
}
