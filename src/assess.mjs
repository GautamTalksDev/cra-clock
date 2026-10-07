// Turns components + intelligence into findings, and findings into the CRA Article 14 clock.
// Tiers:  exploited = a CVE of the vulnerability is in CISA KEV (reliable evidence of exploitation in the wild)
//         likely    = EPSS >= threshold (high chance of exploitation in the next 30 days)
//         known     = any other OSV advisory for that exact version
export const HOUR = 3600_000;

export function assess(components, osvMap, details, kevMap, epssMap, { epssThreshold = 0.1 } = {}) {
  const findings = [];
  for (const c of components) {
    for (const id of osvMap.get(c.purl) || []) {
      const d = details.get(id) || { id, cves: [], aliases: [], fixed: [], refs: [] };
      const kevHits = d.cves.filter((x) => kevMap.has(x));
      const ep = d.cves.map((x) => epssMap.get(x)).filter(Boolean).sort((a, b) => b.epss - a.epss)[0] || null;
      const tier = kevHits.length ? 'exploited' : ep && ep.epss >= epssThreshold ? 'likely' : 'known';
      findings.push({
        fingerprint: `${c.purl}|${id}`, tier, component: c, vuln: d, kev: kevHits.map((x) => ({ cve: x, ...kevMap.get(x) })), epss: ep,
      });
    }
  }
  const order = { exploited: 0, likely: 1, known: 2 };
  findings.sort((a, b) => order[a.tier] - order[b.tier] || (b.epss?.epss || 0) - (a.epss?.epss || 0));
  // OSV publishes one CVE under several ids (GHSA, PYSEC, GO, RUSTSEC): keep one finding per component and CVE,
  // the most severe tier first (the sort above), and remember the other ids as aliases.
  const seen = new Map();
  for (const f of findings) {
    const key = f.component.purl + '|' + (f.vuln.cves[0] || f.vuln.id);
    const prev = seen.get(key);
    if (!prev) seen.set(key, { ...f, otherIds: [] });
    else if (!prev.otherIds.includes(f.vuln.id) && prev.vuln.id !== f.vuln.id) prev.otherIds.push(f.vuln.id);
  }
  return [...seen.values()];
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

export function fmtRemaining(ms) {
  const neg = ms < 0, a = Math.abs(ms);
  const h = Math.floor(a / HOUR), m = Math.floor((a % HOUR) / 60000);
  return `${neg ? 'OVERDUE by ' : ''}${h}h ${String(m).padStart(2, '0')}m`;
}
