// CRA Clock GitHub Action entry point. Zero dependencies (Node 24 runtime).
import { readFileSync, writeFileSync, appendFileSync, readdirSync, statSync, mkdirSync } from 'node:fs';
import { join, relative, basename } from 'node:path';
import { PARSERS, parseFile, dedupe } from './lockfiles.mjs';
import { osvBatch, osvDetails, kev, epss } from './intel.mjs';
import { assess } from './assess.mjs';
import { sbom, vex, issueBody, readState, summary } from './outputs.mjs';

export const VERSION = '1.0.0';
const SKIP = new Set(['node_modules', '.git', 'vendor', 'dist', 'build', 'target', '.venv', 'venv', '__pycache__', '.next', '.terraform']);

export function findLockfiles(root, max = 400) {
  const out = [];
  const walk = (dir, depth) => {
    if (depth > 8 || out.length >= max) return;
    let names; try { names = readdirSync(dir); } catch { return; }
    for (const n of names) {
      if (SKIP.has(n)) continue;
      const p = join(dir, n);
      let st; try { st = statSync(p); } catch { continue; }
      if (st.isSymbolicLink?.()) continue;
      if (st.isDirectory()) walk(p, depth + 1);
      else if (PARSERS[n] && st.size < 50 * 1024 * 1024) out.push(p);
    }
  };
  walk(root, 0);
  return out;
}

const input = (name, def = '') => (process.env['INPUT_' + name.toUpperCase().replace(/ /g, '_')] ?? def).trim();
function setOutput(k, v) { if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${k}=${String(v).replace(/\n/g, ' ')}\n`); }

async function gh(token, method, path, body) {
  const r = await fetch('https://api.github.com' + path, { method, redirect: 'error', headers: { authorization: 'Bearer ' + token, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'cra-clock', ...(body ? { 'content-type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
  if (!r.ok) throw new Error(`GitHub ${method} ${path.split('?')[0]} -> ${r.status}`);
  return r.status === 204 ? null : r.json();
}

/** one issue per (component, vulnerability); the first detection time is kept in the issue so the clock never resets */
async function syncIssues(token, repo, findings, opts) {
  const ex = findings.filter((f) => f.tier === 'exploited');
  if (!ex.length) return [];
  const existing = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await gh(token, 'GET', `/repos/${repo}/issues?labels=cra-clock&state=all&per_page=100&page=${page}`);
    existing.push(...batch.filter((i) => !i.pull_request));
    if (batch.length < 100) break;
  }
  const byFp = new Map();
  for (const i of existing) { const s = readState(i.body); if (s && s.fp) byFp.set(s.fp, { issue: i, state: s }); }
  const out = [];
  for (const f of ex) {
    const prev = byFp.get(f.fingerprint);
    const awareAt = prev ? prev.state.aware : new Date().toISOString();
    const title = `CRA Art. 14: actively exploited ${f.vuln.cves[0] || f.vuln.id} in ${f.component.name} ${f.component.version}`.slice(0, 240);
    const body = issueBody(f, { awareAt, product: opts.product, runUrl: opts.runUrl });
    if (prev && prev.issue.state === 'closed') { out.push({ number: prev.issue.number, closed: true }); continue; } // resolved by the team
    if (prev) { await gh(token, 'PATCH', `/repos/${repo}/issues/${prev.issue.number}`, { title, body }); out.push({ number: prev.issue.number, updated: true, awareAt }); }
    else { const i = await gh(token, 'POST', `/repos/${repo}/issues`, { title, body, labels: ['cra-clock', 'security'] }); out.push({ number: i.number, created: true, awareAt }); }
  }
  return out;
}

export async function run({ root = process.env.GITHUB_WORKSPACE || process.cwd(), fetcher = fetch, log = console.log } = {}) {
  const outDir = join(root, input('output-dir', 'cra-clock'));
  const files = findLockfiles(root);
  const comps = dedupe(files.flatMap((f) => parseFile(basename(f), readFileSync(f, 'utf8'), relative(root, f).replace(/\\/g, '/'))));
  log(`cra-clock ${VERSION}: ${comps.length} components in ${files.length} lockfiles`);
  const osv = await osvBatch(comps, fetcher);
  const ids = [...new Set([...osv.values()].flat())];
  const details = await osvDetails(ids, fetcher);
  const kv = await kev(fetcher);
  const ep = await epss([...details.values()].flatMap((d) => d.cves), fetcher);
  const findings = assess(comps, osv, details, kv.map, ep, { epssThreshold: Number(input('epss-threshold', '0.1')) || 0.1 });
  const product = input('product-name', (process.env.GITHUB_REPOSITORY || 'this product').split('/').pop());
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'sbom.cdx.json'), JSON.stringify(sbom(comps, { name: product, version: input('product-version', process.env.GITHUB_REF_NAME || ''), tool: VERSION }), null, 2));
  writeFileSync(join(outDir, 'vex.cdx.json'), JSON.stringify(vex(findings, { tool: VERSION }), null, 2));
  const sum = summary(findings, comps, { files, kevMeta: { catalogVersion: kv.catalogVersion } });
  writeFileSync(join(outDir, 'report.md'), sum);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, sum + '\n');
  const exploited = findings.filter((f) => f.tier === 'exploited');
  let issues = [];
  const token = input('github-token');
  if (token && input('open-issues', 'true') === 'true' && process.env.GITHUB_REPOSITORY) {
    const runUrl = process.env.GITHUB_SERVER_URL && process.env.GITHUB_RUN_ID ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}` : '';
    issues = await syncIssues(token, process.env.GITHUB_REPOSITORY, findings, { product, runUrl });
  }
  setOutput('components', comps.length); setOutput('exploited', exploited.length); setOutput('likely', findings.filter((f) => f.tier === 'likely').length);
  setOutput('sbom', join(outDir, 'sbom.cdx.json')); setOutput('vex', join(outDir, 'vex.cdx.json'));
  log(exploited.length ? `${exploited.length} actively exploited: CRA Article 14 clock running` : 'no actively exploited vulnerabilities');
  const failOn = input('fail-on', 'exploited');
  const fail = (failOn === 'exploited' && exploited.length > 0) || (failOn === 'likely' && findings.some((f) => f.tier !== 'known'));
  return { components: comps, findings, issues, fail };
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split(/[\\/]/).pop())) {
  run().then((r) => { if (r.fail) { console.log('::error::Actively exploited vulnerability in a shipped component. See the CRA Clock issue.'); process.exit(1); } })
    .catch((e) => { console.log(`::error::cra-clock failed: ${String(e.message).slice(0, 300)}`); process.exit(2); });
}
