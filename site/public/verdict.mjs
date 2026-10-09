// Decisions the in-browser scanner makes about the KEV mirror, kept apart from the DOM so they can be tested.
// Rule: an unreadable or empty KEV mirror is "unknown", and unknown never reads as "nothing is exploited".
export const KEV_MIN = 1000; // the real catalog has about 1,400 entries and only grows

/** the Set of KEV CVE ids in a /kev.json answer, or null when the answer is missing or too small to be the real catalog */
export function kevSet(j) {
  const cves = j && Array.isArray(j.cves) ? j.cves.filter((c) => typeof c === 'string' && /^CVE-\d{4}-\d+$/.test(c)) : [];
  return cves.length > KEV_MIN ? new Set(cves) : null;
}

/** the headline of a scan result */
export function headline({ exploited, advisories, kevKnown }) {
  if (exploited) return `${exploited} actively exploited. Your clock would be running.`;
  if (!advisories) return 'No known vulnerabilities.';
  return kevKnown ? 'Nothing actively exploited right now.' : 'Could not confirm exploitation status.';
}
