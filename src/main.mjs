// CRA Clock GitHub Action entry point. Zero dependencies (Node 24 runtime).
import { readFileSync, writeFileSync, appendFileSync, readdirSync, lstatSync, mkdirSync } from 'node:fs';
import { join, relative, basename } from 'node:path';
import { isLockfileName, parseFile, dedupe } from './lockfiles.mjs';
import { osvBatch, osvDetails, kev, epss } from './intel.mjs';
import { assess, validAware, vulnKey } from './assess.mjs';
import { sbom, vex, issueBody, readState, summary, plain } from './outputs.mjs';

export const VERSION = '1.0.0';
const SKIP = new Set(['node_modules', '.git', 'vendor', 'dist', 'build', 'target', '.venv', 'venv', '__pycache__', '.next', '.terraform']);
export const FAIL_ON = ['exploited', 'likely', 'never'];

/** walk the repo for lockfiles. lstat, not stat: symlinked files and directories are skipped, never followed */
export function findLockfiles(root, max = 400) {
  const out = [];
  const walk = (dir, depth) => {
    if (depth > 8 || out.length >= max) return;
    let names; try { names = readdirSync(dir); } catch { return; }
    for (const n of names) {
      if (SKIP.has(n)) continue;
      const p = join(dir, n);
      let st; try { st = lstatSync(p); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) walk(p, depth + 1);
      else if (st.isFile() && isLockfileName(n) && st.size < 50 * 1024 * 1024) out.push(p);
    }
  };
  walk(root, 0);
  return out;
}

const input = (name, def = '') => (process.env['INPUT_' + name.toUpperCase().replace(/ /g, '_')] || def).trim();
function setOutput(k, v) { if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${k}=${String(v).replace(/[\r\n]/g, ' ')}\n`); }

/**
 * One workflow-command line. Upstream text (a V8 JSON error quotes the response body, newlines included) must never be
 * able to start a second command such as ::add-mask:: or ::warning::, so line breaks, control characters and "::" go.
 */
export function annotation(level, message, max = 300) {
  const text = String(message ?? '').slice(0, max).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, ' ').replace(/:{2,}/g, (m) => m.split('').join(' '));
  return `::${level}::${text}`;
}

/** validated inputs; throws with a clear message on anything invalid */
export function readInputs() {
  const rawT = input('epss-threshold', '0.1');
  const t = Number(rawT);
  if (rawT === '' || !Number.isFinite(t) || t < 0 || t > 1) throw new Error(`epss-threshold must be a number from 0 to 1 (got "${rawT.slice(0, 40)}")`);
  const failOn = input('fail-on', 'exploited').toLowerCase();
  if (!FAIL_ON.includes(failOn)) throw new Error(`fail-on must be one of ${FAIL_ON.join(', ')} (got "${failOn.slice(0, 40)}")`);
  const bool = (name, def) => {
    const v = input(name, def).toLowerCase();
    if (v !== 'true' && v !== 'false') throw new Error(`${name} must be true or false (got "${v.slice(0, 40)}")`);
    return v === 'true';
  };
  return { epssThreshold: t, failOn, openIssues: bool('open-issues', 'true'), allowIncompleteIntel: bool('allow-incomplete-intel', 'false') };
}

async function gh(fetcher, token, method, path, body) {
  const r = await fetcher('https://api.github.com' + path, { method, redirect: 'error', headers: { authorization: 'Bearer ' + token, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'cra-clock', ...(body ? { 'content-type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
  if (!r.ok) { const e = new Error(`GitHub ${method} ${path.split('?')[0]} -> ${r.status}`); e.status = r.status; throw e; }
  return r.status === 204 ? null : r.json();
}

export const issueTitle = (f) => `CRA Art. 14: actively exploited ${plain(vulnKey(f.vuln), 60)} in ${plain(f.component.name, 120)} ${plain(f.component.version, 60)}`.replace(/\s+/g, ' ').trim().slice(0, 240);

const isBot = (i) => !!(i && i.user && i.user.type === 'Bot');

/** the account a personal access token acts as; null for the workflow's own token, which cannot call /user */
async function tokenLogin(fetcher, token) {
  try { const u = await gh(fetcher, token, 'GET', '/user'); return u && typeof u.login === 'string' ? u.login : null; } catch { return null; }
}

/**
 * One issue per (component, vulnerability); the first detection time is kept in the issue so the clock never resets.
 * Only issues opened by a bot (the workflow token) or by the token's own account are believed: anyone who can label or
 * edit an issue could otherwise plant a fake clock, or a closed issue that silences an alert.
 */
export async function syncIssues(token, repo, findings, opts, fetcher = fetch) {
  const ex = findings.filter((f) => f.tier === 'exploited');
  if (!ex.length) return [];
  const now = opts.now ?? Date.now();
  const existing = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await gh(fetcher, token, 'GET', `/repos/${repo}/issues?labels=cra-clock&state=all&per_page=100&page=${page}`);
    existing.push(...batch.filter((i) => !i.pull_request));
    if (batch.length < 100) break;
  }
  const self = existing.some((i) => !isBot(i)) ? await tokenLogin(fetcher, token) : null;
  const byFp = new Map();
  for (const i of existing) {
    if (!isBot(i) && !(self && i.user && i.user.login === self)) continue;
    const s = readState(i.body); if (!s) continue;
    // a stored time that is not ISO UTC or lies in the future is not believed; GitHub's own created_at is the fallback
    const aware = validAware(s.aware, now) || validAware(i.created_at, now);
    if (!aware) continue;
    if (!byFp.has(s.fp)) byFp.set(s.fp, []);
    byFp.get(s.fp).push({ issue: i, aware });
  }
  const out = [];
  for (const f of ex) {
    // the current fingerprint, or one stored by an earlier build; when several issues match, the earliest clock wins
    const matches = [f.fingerprint, ...(f.legacyFingerprints || [])].flatMap((fp) => byFp.get(fp) || [])
      .sort((a, b) => Date.parse(a.aware) - Date.parse(b.aware) || a.issue.number - b.issue.number);
    const prev = matches[0];
    const awareAt = prev ? prev.aware : new Date(now).toISOString();
    const title = issueTitle(f);
    const body = issueBody(f, { awareAt, product: opts.product, runUrl: opts.runUrl, now });
    if (prev && prev.issue.state === 'closed') { out.push({ number: prev.issue.number, closed: true }); continue; } // resolved by the team
    if (prev) { await gh(fetcher, token, 'PATCH', `/repos/${repo}/issues/${prev.issue.number}`, { title, body }); out.push({ number: prev.issue.number, updated: true, awareAt }); }
    else { const i = await gh(fetcher, token, 'POST', `/repos/${repo}/issues`, { title, body, labels: ['cra-clock', 'security'] }); out.push({ number: i.number, created: true, awareAt }); }
  }
  return out;
}

export const FORK_NOTE = 'CRA Clock could not open or update issues (GitHub returned 403). This is expected on pull requests from forks, where the workflow token is read-only. Findings are in this summary only. Set open-issues: false for pull_request events, and let the push or schedule run open the issues.';
export const KEV_NOTE = 'Could not confirm exploitation status: the CISA KEV catalog could not be read, or it came back empty. This is not a clean result. Re-run the job, or check each advisory against the CISA KEV catalog by hand.';

export async function run({ root = process.env.GITHUB_WORKSPACE || process.cwd(), fetcher = fetch, log = console.log, retryDelayMs } = {}) {
  const opts = readInputs();
  const outDir = join(root, input('output-dir', 'cra-clock'));
  const files = findLockfiles(root);
  const comps = dedupe(files.flatMap((f) => parseFile(basename(f), readFileSync(f, 'utf8'), relative(root, f).replace(/\\/g, '/'))));
  log(`cra-clock ${VERSION}: ${comps.length} components in ${files.length} lockfiles`);
  const osv = await osvBatch(comps, fetcher);
  const ids = [...new Set([...osv.values()].flat())];
  const details = await osvDetails(ids, fetcher);
  // An unreadable or empty KEV catalog is "unknown", never "nothing is exploited": the report says so and the job exits 2.
  let kv, kevUnknown = false;
  try { kv = await kev(fetcher, { delayMs: retryDelayMs }); } catch { kv = { catalogVersion: '', map: new Map() }; kevUnknown = true; }
  const ep = await epss([...details.values()].flatMap((d) => d.cves), fetcher);
  const findings = assess(comps, osv, details, kv.map, ep, { epssThreshold: opts.epssThreshold, kevUnknown });
  const product = input('product-name', (process.env.GITHUB_REPOSITORY || 'this product').split('/').pop());
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'sbom.cdx.json'), JSON.stringify(sbom(comps, { name: product, version: input('product-version', process.env.GITHUB_REF_NAME || ''), tool: VERSION }), null, 2));
  writeFileSync(join(outDir, 'vex.cdx.json'), JSON.stringify(vex(findings, { tool: VERSION }), null, 2));
  const exploited = findings.filter((f) => f.tier === 'exploited');
  const incomplete = findings.filter((f) => f.tier === 'intel-incomplete');
  let issues = [];
  const notes = [];
  const token = input('github-token');
  if (token && opts.openIssues && process.env.GITHUB_REPOSITORY) {
    const runUrl = process.env.GITHUB_SERVER_URL && process.env.GITHUB_RUN_ID ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}` : '';
    try {
      issues = await syncIssues(token, process.env.GITHUB_REPOSITORY, findings, { product, runUrl }, fetcher);
    } catch (e) {
      if (e.status !== 403) throw e;
      notes.push(FORK_NOTE);
      log(annotation('warning', FORK_NOTE, 1000));
    }
  }
  // with the KEV catalog unknown every advisory is incomplete; the summary already says so, and allow-incomplete-intel would not help
  if (!kevUnknown && incomplete.length) notes.push(`${incomplete.length} advisor${incomplete.length === 1 ? 'y' : 'ies'} could not be fully checked and need${incomplete.length === 1 ? 's' : ''} manual review.${opts.allowIncompleteIntel ? ' allow-incomplete-intel is true, so this does not fail the job.' : ' The job fails until this is resolved or allow-incomplete-intel: true is set.'}`);
  const sum = summary(findings, comps, { files, kevMeta: { catalogVersion: kv.catalogVersion }, kevUnknown, notes });
  writeFileSync(join(outDir, 'report.md'), sum);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, sum + '\n');
  setOutput('components', comps.length); setOutput('exploited', kevUnknown ? 'unknown' : exploited.length); setOutput('likely', findings.filter((f) => f.tier === 'likely').length);
  setOutput('intel-incomplete', incomplete.length); setOutput('kev-status', kevUnknown ? 'unknown' : 'ok');
  setOutput('sbom', join(outDir, 'sbom.cdx.json')); setOutput('vex', join(outDir, 'vex.cdx.json'));
  log(kevUnknown ? 'could not confirm exploitation status: the CISA KEV catalog could not be read' : exploited.length ? `${exploited.length} actively exploited: CRA Article 14 clock running` : 'no actively exploited vulnerabilities');
  const reasons = [];
  if (kevUnknown) reasons.push(KEV_NOTE);
  if (opts.failOn !== 'never' && exploited.length) reasons.push('Actively exploited vulnerability in a shipped component. See the CRA Clock issue or job summary.');
  if (opts.failOn === 'likely' && findings.some((f) => f.tier === 'likely')) reasons.push('Vulnerability above the EPSS threshold in a shipped component.');
  if (incomplete.length && !kevUnknown && !opts.allowIncompleteIntel) reasons.push(`Vulnerability intelligence incomplete for ${incomplete.length} advisor${incomplete.length === 1 ? 'y' : 'ies'}: manual review needed (see the job summary). Set allow-incomplete-intel: true to not fail on this.`);
  return { components: comps, findings, issues, notes, fail: reasons.length > 0, outage: kevUnknown, kevUnknown, reasons };
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split(/[\\/]/).pop())) {
  run().then((r) => { if (r.fail) { for (const m of r.reasons) console.log(annotation('error', m, 500)); process.exit(r.outage ? 2 : 1); } })
    .catch((e) => { console.log(annotation('error', `cra-clock failed: ${e && e.message}`)); process.exit(2); });
}
