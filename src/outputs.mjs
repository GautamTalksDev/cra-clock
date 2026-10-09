// CycloneDX 1.6 SBOM and VEX, and the markdown the Action writes (issue bodies, job summary, ENISA drafts).
// Everything that came from an advisory or a lockfile is untrusted text: md() neutralizes markdown, HTML and @mentions,
// plain() and fenced() keep it inside the draft code blocks, and fields with a known shape are validated again here.
import { clock, fmtRemaining, vulnKey } from './assess.mjs';
import { md, plain, codeSpan, fenced, severity, isoDate, version as validVersion, httpsUrl, encodeId } from './safe.mjs';

export { md, plain, codeSpan };

const uuid = () => crypto.randomUUID();
const MAX_FILES = 20; // "Found in" lists at most this many lockfiles
const MAX_BODY = 60_000; // GitHub rejects issue bodies over 65,536 characters

export function sbom(components, { name, version, tool }) {
  return {
    bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: 'urn:uuid:' + uuid(), version: 1,
    metadata: { timestamp: new Date().toISOString(), tools: { components: [{ type: 'application', name: 'cra-clock', version: tool }] }, component: { type: 'application', name, version: version || 'unversioned', 'bom-ref': 'root' } },
    components: components.map((c) => ({ type: 'library', 'bom-ref': c.purl, name: c.name, version: c.version, purl: c.purl, properties: [{ name: 'cra-clock:files', value: c.files.join(',') }, ...(c.direct ? [{ name: 'cra-clock:direct', value: 'true' }] : [])] })),
  };
}

export function vex(findings, { tool }) {
  const seen = new Map();
  for (const f of findings) {
    const key = vulnKey(f.vuln);
    const isCve = /^CVE-/.test(key);
    const e = seen.get(key) || { id: key, source: { name: isCve ? 'NVD' : 'OSV', url: isCve ? `https://nvd.nist.gov/vuln/detail/${key}` : `https://osv.dev/vulnerability/${encodeId(f.vuln.id)}` }, affects: [], analysis: { state: 'in_triage', detail: '' }, properties: [] };
    e.affects.push({ ref: f.component.purl });
    if (f.tier === 'exploited') e.properties.push({ name: 'cra-clock:actively-exploited', value: 'true (CISA KEV)' });
    if (f.epss) e.properties.push({ name: 'cra-clock:epss', value: String(f.epss.epss) });
    if (f.tier === 'intel-incomplete') e.properties.push({ name: 'cra-clock:intel-incomplete', value: 'true (manual review needed)' });
    e.analysis.detail = f.tier === 'exploited' ? 'Listed in CISA KEV. CRA Article 14 reporting clock started.'
      : f.tier === 'intel-incomplete' ? `Vulnerability intelligence could not be fetched completely${f.missing && f.missing.length ? ` (${f.missing.join(', ')})` : ''}. Review manually.`
      : 'Awaiting triage.';
    seen.set(key, e);
  }
  return { bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: 'urn:uuid:' + uuid(), version: 1, metadata: { timestamp: new Date().toISOString(), tools: { components: [{ type: 'application', name: 'cra-clock', version: tool }] } }, vulnerabilities: [...seen.values()] };
}

/** issue body for one actively exploited finding; the hidden state line keeps the detection time across runs */
export function issueBody(f, { awareAt, product, runUrl, now = Date.now() }) {
  const c = clock(awareAt, now);
  const cve = vulnKey(f.vuln);
  const k = f.kev[0] || {};
  const kevDate = isoDate(k.dateAdded);
  const sev = severity(f.vuln.severity);
  const fixed = (f.vuln.fixed || []).map(validVersion).filter(Boolean).slice(0, 5);
  const epssNum = f.epss && Number.isFinite(f.epss.epss) ? f.epss : null;
  const files = f.component.files || [];
  const shown = files.slice(0, MAX_FILES);
  const refs = [...(f.vuln.refs || []).map((u) => httpsUrl(u)).filter(Boolean).slice(0, 5), `https://osv.dev/vulnerability/${encodeId(String(f.vuln.id).slice(0, 100))}`];
  const state = JSON.stringify({ fp: f.fingerprint, aware: c.awareAt });
  const body = [
    `<!-- cra-clock:${Buffer.from(state).toString('base64')} -->`,
    `## Actively exploited vulnerability in a shipped component`,
    ``,
    `| | |`, `|---|---|`,
    `| Component | ${codeSpan(f.component.name, 120)} ${md(f.component.version, 60)} |`,
    `| Vulnerability | ${md(cve, 40)} (${md(f.vuln.id, 60)}) |`,
    `| Evidence of exploitation | CISA Known Exploited Vulnerabilities, added ${kevDate || 'date n/a'}${k.ransomware ? ', **known ransomware use**' : ''} |`,
    `| EPSS | ${epssNum ? (epssNum.epss * 100).toFixed(1) + '% (percentile ' + (epssNum.percentile * 100).toFixed(0) + ')' : 'n/a'} |`,
    `| Fixed in | ${fixed.length ? fixed.map((x) => md(x, 64)).join(', ') : 'no fixed version published yet'} |`,
    `| Found in | ${shown.map((x) => codeSpan(x, 120)).join(', ') || 'n/a'}${files.length > shown.length ? `, and ${files.length - shown.length} more` : ''} |`,
    ``,
    `### CRA Article 14 clock (counted from CRA Clock's detection at ${c.awareAt})`,
    ``,
    ...c.stages.map((s) => `- **${s.label}**: due ${s.dueIso} (${fmtRemaining(s.remainingMs)})`),
    `- **Final report**: ${c.final.replace('Final report: ', '')}`,
    ``,
    `> Applies if ${md(product, 80)} is a product with digital elements made available on the EU market. This countdown starts when CRA Clock first detected the KEV listing. Your legal 24 hours run from when you became aware; if that was earlier, your deadlines are earlier.`,
    ``,
    `<details><summary>Draft: 24 hour early warning (for the CRA single reporting platform)</summary>`,
    ``,
    ...fenced([
      `Product: ${plain(product, 80)}`,
      `Actively exploited vulnerability: yes`,
      `Vulnerability: ${plain(cve, 40)}`,
      `Affected component: ${plain(f.component.name, 120)} ${plain(f.component.version, 60)}`,
      `Evidence: listed in CISA KEV (${kevDate || 'date n/a'})`,
      `Member States where the product is available: [fill in]`,
      `Detected by CRA Clock: ${c.awareAt}`,
      `Your 24 hours run from when you became aware; edit if earlier.`,
    ]),
    `</details>`,
    ``,
    `<details><summary>Draft: 72 hour notification</summary>`,
    ``,
    ...fenced([
      `General information: ${plain(f.vuln.summary || k.name, 300)}`,
      `Initial severity assessment: ${sev || '[fill in]'}; EPSS ${epssNum ? epssNum.epss : 'n/a'}`,
      `Corrective or mitigating measures: ${fixed.length ? 'upgrade ' + plain(f.component.name, 120) + ' to ' + fixed.map((x) => plain(x, 64)).join(' or ') : '[fill in]'}${k.action ? '. CISA: ' + plain(k.action, 200) : ''}`,
      `Measures users can take: [fill in]`,
      `Sensitivity of the information: [fill in]`,
    ]),
    `</details>`,
    ``,
    `### References`,
    ...refs.map((u) => `- <${u}>`),
    ``,
    `---`,
    `Drafts are a starting point for your submission, not legal advice. Opened by CRA Clock${runUrl && httpsUrl(runUrl) ? ` ([run](${runUrl}))` : ''}. Close this issue once the final report is submitted.`,
  ].join('\n');
  // unreachable with the caps above; the last line of defence against a 422 from GitHub
  return body.length > MAX_BODY ? body.slice(0, MAX_BODY) : body;
}

export function readState(body) {
  const m = String(body || '').match(/<!-- cra-clock:([A-Za-z0-9+/=]+) -->/);
  if (!m) return null;
  try {
    const s = JSON.parse(Buffer.from(m[1], 'base64').toString('utf8'));
    return s && typeof s === 'object' && typeof s.fp === 'string' ? s : null; // s.aware is validated by the caller (validAware)
  } catch { return null; }
}

export function summary(findings, components, { files, kevMeta = {}, kevUnknown = false, notes = [] }) {
  const ex = findings.filter((f) => f.tier === 'exploited'), li = findings.filter((f) => f.tier === 'likely');
  const inc = findings.filter((f) => f.tier === 'intel-incomplete');
  const lines = [
    `## CRA Clock`,
    ``,
    kevUnknown ? `### Could not confirm exploitation status`
      : ex.length ? `### ${ex.length} actively exploited ${ex.length === 1 ? 'vulnerability' : 'vulnerabilities'}: the CRA Article 14 clock is running` : `### No actively exploited vulnerabilities`,
    ``,
    ...(kevUnknown ? [`The CISA Known Exploited Vulnerabilities catalog could not be read, or it came back empty. CRA Clock cannot tell whether any advisory is actively exploited, so this is **not** a clean result and the Article 14 clock could not be evaluated. Re-run the job, or check each advisory against the CISA KEV catalog by hand.`, ``] : []),
    kevUnknown
      ? `Scanned ${components.length} components from ${files.length} lockfile${files.length === 1 ? '' : 's'} against OSV and EPSS. The CISA KEV catalog could not be read.`
      : `Scanned ${components.length} components from ${files.length} lockfile${files.length === 1 ? '' : 's'} against OSV, CISA KEV (catalog ${md(kevMeta.catalogVersion, 20)}) and EPSS.`,
    ``,
    `| Tier | Count |`, `|---|---|`, `| Actively exploited (KEV) | ${kevUnknown ? 'unknown' : ex.length} |`, `| Likely exploited soon (EPSS) | ${li.length} |`, `| Needs manual review (intel incomplete) | ${inc.length} |`, `| Other known advisories | ${findings.length - ex.length - li.length - inc.length} |`,
    ``,
  ];
  if (ex.length || li.length) {
    lines.push(`| | Component | Vulnerability | EPSS | Fixed in |`, `|---|---|---|---|---|`);
    for (const f of [...ex, ...li].slice(0, 50)) lines.push(`| ${f.tier === 'exploited' ? 'EXPLOITED' : 'likely'} | ${codeSpan(f.component.name, 80)} ${md(f.component.version, 40)} | ${md(vulnKey(f.vuln), 40)} | ${f.epss && Number.isFinite(f.epss.epss) ? (f.epss.epss * 100).toFixed(1) + '%' : ''} | ${md((f.vuln.fixed || []).map(validVersion).filter(Boolean).slice(0, 5).join(', '), 80)} |`);
    if (ex.length + li.length > 50) lines.push(``, `${ex.length + li.length - 50} more not shown.`);
    lines.push(``);
  }
  if (inc.length) {
    lines.push(`### Needs manual review: vulnerability intelligence incomplete`, ``,
      `OSV advisory details, EPSS scores or the CISA KEV catalog could not be fetched for these, so CRA Clock cannot tell whether they are exploited. They are not counted as safe. Check each advisory against the CISA KEV catalog by hand, or re-run the job.`, ``,
      `| Component | Advisory | Missing |`, `|---|---|---|`);
    for (const f of inc.slice(0, 100)) lines.push(`| ${codeSpan(f.component.name, 80)} ${md(f.component.version, 40)} | ${md(vulnKey(f.vuln), 60)} | ${md((f.missing || []).join(', '), 40)} |`);
    if (inc.length > 100) lines.push(``, `${inc.length - 100} more not shown.`);
    lines.push(``);
  }
  for (const n of notes) lines.push(`> **Note:** ${md(n, 500)}`, ``);
  return lines.join('\n');
}
