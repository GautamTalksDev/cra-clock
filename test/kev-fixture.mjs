// Fake CISA KEV documents for the tests. The real catalog has about 1,400 entries and the code refuses anything under
// 1,000 (an empty or truncated answer is an outage, not "nothing is exploited"), so test catalogs are padded with
// filler CVE ids that no test uses.
export const KEV_FILLER = 1200;

export function padKev(entries = [], total = KEV_FILLER) {
  const filler = Array.from({ length: Math.max(0, total - entries.length) }, (_, i) => ({ cveID: `CVE-2000-${1000 + i}` }));
  return [...entries, ...filler];
}

/** a plausible full KEV catalog containing the given entries */
export const kevJson = (entries = [], over = {}) => ({ catalogVersion: '2026.10.06', vulnerabilities: padKev(entries), ...over });
