// Pre-launch audit coverage: symlinks, incomplete intel, input validation, fork PRs, issue sync, titles, sniffing.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as L from '../src/lockfiles.mjs';
import { osvDetails, epss } from '../src/intel.mjs';
import { assess } from '../src/assess.mjs';
import { summary, plain, vex } from '../src/outputs.mjs';
import { run, findLockfiles, readInputs, syncIssues, issueTitle, FORK_NOTE } from '../src/main.mjs';

const ENV = ['INPUT_OUTPUT-DIR', 'INPUT_GITHUB-TOKEN', 'INPUT_FAIL-ON', 'INPUT_EPSS-THRESHOLD', 'INPUT_OPEN-ISSUES', 'INPUT_ALLOW-INCOMPLETE-INTEL', 'GITHUB_REPOSITORY', 'GITHUB_STEP_SUMMARY', 'GITHUB_OUTPUT', 'GITHUB_SERVER_URL', 'GITHUB_RUN_ID'];
beforeEach(() => { for (const k of ENV) delete process.env[k]; process.env['INPUT_OUTPUT-DIR'] = 'out'; });

const LOG4J = 'GHSA-jfh8-c2jp-5v3q', LODASH = 'GHSA-35jh-r3h4-6jhm';
/** fake OSV/KEV/EPSS/GitHub. failDetails / failEpss simulate outages; gh(method, path, body) answers GitHub calls */
function fake({ failDetails = [], failEpss = false, gh = null } = {}) {
  const calls = [];
  const fetcher = async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body });
    if (url.startsWith('https://api.github.com')) return gh(init.method || 'GET', url.slice('https://api.github.com'.length), init.body && JSON.parse(init.body));
    if (url.endsWith('/querybatch')) {
      const q = JSON.parse(init.body).queries;
      return Response.json({ results: q.map((x) => ({ vulns: x.package.purl.includes('log4j') ? [{ id: LOG4J }] : x.package.purl.includes('lodash@4.17.20') ? [{ id: LODASH }] : [] })) });
    }
    for (const id of failDetails) if (url.includes('/vulns/' + id)) return new Response('nope', { status: 404 });
    if (url.includes('/vulns/' + LOG4J)) return Response.json({ id: LOG4J, aliases: ['CVE-2021-44228'], summary: 'Log4Shell', affected: [{ ranges: [{ events: [{ fixed: '2.15.0' }] }] }] });
    if (url.includes('/vulns/' + LODASH)) return Response.json({ id: LODASH, aliases: ['CVE-2021-23337'], summary: 'Command injection in lodash' });
    if (url.includes('known_exploited')) return Response.json({ catalogVersion: '2026.10.06', vulnerabilities: [{ cveID: 'CVE-2021-44228', dateAdded: '2021-12-10', knownRansomwareCampaignUse: 'Known', requiredAction: 'Apply updates' }] });
    if (url.includes('api.first.org')) {
      if (failEpss) return new Response('bad', { status: 400 });
      return Response.json({ data: [{ cve: 'CVE-2021-44228', epss: '0.97', percentile: '0.999' }, { cve: 'CVE-2021-23337', epss: '0.02', percentile: '0.8' }] });
    }
    throw new Error('unexpected ' + url);
  };
  return { fetcher, calls };
}

function repo() {
  const root = mkdtempSync(join(tmpdir(), 'cra-l-'));
  mkdirSync(join(root, 'svc'));
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/lodash': { version: '4.17.20' } } }));
  writeFileSync(join(root, 'svc', 'requirements.txt'), 'log4j-python-shim==1.0\n');
  return root;
}

test('symlinked lockfiles and symlinked directories are skipped, never followed', () => {
  const root = mkdtempSync(join(tmpdir(), 'cra-sym-'));
  const outside = mkdtempSync(join(tmpdir(), 'cra-outside-'));
  mkdirSync(join(outside, 'deep'));
  writeFileSync(join(outside, 'package-lock.json'), '{}');
  writeFileSync(join(outside, 'deep', 'yarn.lock'), '');
  writeFileSync(join(root, 'go.mod'), 'module x\n');
  symlinkSync(join(outside, 'package-lock.json'), join(root, 'package-lock.json'));
  symlinkSync(join(outside, 'deep'), join(root, 'linked-dir'), 'dir');
  symlinkSync(root, join(root, 'loop'), 'dir');
  assert.deepEqual(findLockfiles(root).map((p) => p.slice(root.length + 1)), ['go.mod']);
});

test('OSV detail failure: never silently "known"; intel-incomplete, listed for review, job fails', async () => {
  const d = await osvDetails([LODASH], fake({ failDetails: [LODASH] }).fetcher);
  assert.equal(d.get(LODASH).incomplete, true);
  const root = repo();
  const r = await run({ root, fetcher: fake({ failDetails: [LODASH] }).fetcher, log: () => {} });
  const lod = r.findings.find((f) => f.vuln.id === LODASH);
  assert.equal(lod.tier, 'intel-incomplete');
  assert.deepEqual(lod.missing, ['OSV details']);
  assert.equal(r.fail, true);
  assert.ok(r.reasons.some((m) => /intelligence incomplete/.test(m)));
  const rep = readFileSync(join(root, 'out', 'report.md'), 'utf8');
  assert.match(rep, /Needs manual review: vulnerability intelligence incomplete/);
  assert.match(rep, /GHSA-35jh-r3h4-6jhm/);
  assert.equal(JSON.parse(readFileSync(join(root, 'out', 'vex.cdx.json'), 'utf8')).vulnerabilities.find((v) => v.id === LODASH).analysis.detail.includes('Review manually'), true);
});

test('EPSS failure marks non-KEV advisories intel-incomplete; KEV hits stay exploited', async () => {
  const m = await epss(['CVE-2021-23337'], fake({ failEpss: true }).fetcher);
  assert.ok(m.failed.has('CVE-2021-23337'));
  process.env['INPUT_FAIL-ON'] = 'never';
  const r = await run({ root: repo(), fetcher: fake({ failEpss: true }).fetcher, log: () => {} });
  assert.deepEqual(r.findings.map((f) => [f.vuln.id, f.tier]), [[LOG4J, 'exploited'], [LODASH, 'intel-incomplete']]);
  assert.equal(r.fail, true, 'incomplete intel fails even with fail-on: never');
});

test('allow-incomplete-intel: true reports but does not fail', async () => {
  process.env['INPUT_ALLOW-INCOMPLETE-INTEL'] = 'true'; process.env['INPUT_FAIL-ON'] = 'never';
  const r = await run({ root: repo(), fetcher: fake({ failDetails: [LODASH] }).fetcher, log: () => {} });
  assert.equal(r.fail, false);
  assert.ok(r.notes.some((n) => /does not fail the job/.test(n)));
});

test('assess without failures is unchanged: no intel-incomplete', () => {
  const c = [{ purl: 'p', name: 'n', version: '1', files: ['f'] }];
  const e = new Map(); e.failed = new Set();
  const f = assess(c, new Map([['p', ['V']]]), new Map([['V', { id: 'V', cves: ['CVE-1'], fixed: [], refs: [] }]]), new Map(), e);
  assert.equal(f[0].tier, 'known');
  assert.match(summary(f, c, { files: ['f'], kevMeta: {} }), /Needs manual review \(intel incomplete\) \| 0/);
  assert.equal(vex(f, { tool: 't' }).vulnerabilities[0].analysis.detail, 'Awaiting triage.');
});

test('inputs: epss-threshold accepts 0, rejects invalid; fail-on and booleans are validated', () => {
  assert.equal(readInputs().epssThreshold, 0.1);
  process.env['INPUT_EPSS-THRESHOLD'] = '0'; assert.equal(readInputs().epssThreshold, 0);
  process.env['INPUT_EPSS-THRESHOLD'] = '1'; assert.equal(readInputs().epssThreshold, 1);
  for (const bad of ['abc', '-0.1', '1.5', 'NaN', '0.1x']) { process.env['INPUT_EPSS-THRESHOLD'] = bad; assert.throws(() => readInputs(), /epss-threshold must be a number from 0 to 1/); }
  delete process.env['INPUT_EPSS-THRESHOLD'];
  for (const ok of ['exploited', 'likely', 'never', 'LIKELY']) { process.env['INPUT_FAIL-ON'] = ok; assert.equal(readInputs().failOn, ok.toLowerCase()); }
  for (const bad of ['always', 'exploit', 'none']) { process.env['INPUT_FAIL-ON'] = bad; assert.throws(() => readInputs(), /fail-on must be one of exploited, likely, never/); }
  delete process.env['INPUT_FAIL-ON'];
  process.env['INPUT_OPEN-ISSUES'] = 'yes'; assert.throws(() => readInputs(), /open-issues must be true or false/);
});

test('invalid inputs stop the run before any network call', async () => {
  process.env['INPUT_FAIL-ON'] = 'sometimes';
  const f = fake();
  await assert.rejects(run({ root: repo(), fetcher: f.fetcher, log: () => {} }), /fail-on/);
  assert.equal(f.calls.length, 0);
});

test('fail-on variants: exploited, likely, never', async () => {
  const go = async (failOn, thr) => {
    process.env['INPUT_FAIL-ON'] = failOn; if (thr) process.env['INPUT_EPSS-THRESHOLD'] = thr; else delete process.env['INPUT_EPSS-THRESHOLD'];
    return run({ root: repo(), fetcher: fake().fetcher, log: () => {} });
  };
  assert.equal((await go('exploited')).fail, true);
  assert.equal((await go('never')).fail, false);
  const likely = await go('likely', '0.01');
  assert.equal(likely.fail, true); assert.equal(likely.reasons.length, 2);
  assert.equal(likely.findings.find((f) => f.vuln.id === LODASH).tier, 'likely');
  const zero = await go('never', '0');
  assert.equal(zero.findings.find((f) => f.vuln.id === LODASH).tier, 'likely', 'threshold 0 is honoured, not replaced by the default');
});

test('fail-on likely with no exploited and nothing above threshold passes', async () => {
  process.env['INPUT_FAIL-ON'] = 'likely';
  const root = mkdtempSync(join(tmpdir(), 'cra-l-'));
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/lodash': { version: '4.17.20' } } }));
  const r = await run({ root, fetcher: fake().fetcher, log: () => {} });
  assert.equal(r.fail, false);
});

const exploitedFinding = (over = {}) => ({ fingerprint: 'pkg:npm/x@1|GHSA-1', tier: 'exploited', component: { name: 'x', version: '1', files: ['package-lock.json'] }, vuln: { id: 'GHSA-1', cves: ['CVE-2021-44228'], fixed: [], refs: [] }, kev: [{ cve: 'CVE-2021-44228' }], epss: null, ...over });

test('issue sync: creates new issues, patches open ones keeping the clock, leaves closed ones alone', async () => {
  const { readState, issueBody } = await import('../src/outputs.mjs');
  const old = '2026-10-01T00:00:00.000Z';
  const existing = [
    { number: 7, state: 'open', body: issueBody(exploitedFinding({ fingerprint: 'fp-open' }), { awareAt: old, product: 'p' }) },
    { number: 8, state: 'closed', body: issueBody(exploitedFinding({ fingerprint: 'fp-closed' }), { awareAt: old, product: 'p' }) },
    { number: 9, state: 'open', pull_request: {}, body: '' },
  ];
  const writes = [];
  const f = fake({ gh: (method, path, body) => {
    if (method === 'GET') return Response.json(existing);
    writes.push({ method, path, body });
    return method === 'POST' ? Response.json({ number: 42 }, { status: 201 }) : Response.json({ number: 7 });
  } });
  const out = await syncIssues('t', 'o/r', [exploitedFinding({ fingerprint: 'fp-open' }), exploitedFinding({ fingerprint: 'fp-closed' }), exploitedFinding({ fingerprint: 'fp-new' }), exploitedFinding({ tier: 'known', fingerprint: 'k' })], { product: 'p' }, f.fetcher);
  assert.deepEqual(out.map((o) => [o.number, !!o.updated, !!o.closed, !!o.created]), [[7, true, false, false], [8, false, true, false], [42, false, false, true]]);
  assert.equal(writes.length, 2);
  assert.equal(writes[0].method, 'PATCH'); assert.equal(writes[0].path, '/repos/o/r/issues/7');
  assert.equal(readState(writes[0].body.body).aware, old, 'the clock never resets on re-runs');
  assert.equal(writes[1].method, 'POST'); assert.deepEqual(writes[1].body.labels, ['cra-clock', 'security']);
  assert.equal(f.calls.filter((c) => c.url.includes('/issues?')).length, 1);
});

test('fork PRs: a 403 on issue creation degrades to summary-only with a clear note', async () => {
  Object.assign(process.env, { 'INPUT_GITHUB-TOKEN': 't', GITHUB_REPOSITORY: 'o/r', 'INPUT_FAIL-ON': 'never' });
  const root = repo();
  const r = await run({ root, fetcher: fake({ gh: (m) => (m === 'GET' ? Response.json([]) : new Response('{"message":"Resource not accessible by integration"}', { status: 403 })) }).fetcher, log: () => {} });
  assert.deepEqual(r.issues, []);
  assert.deepEqual(r.notes, [FORK_NOTE]);
  assert.match(readFileSync(join(root, 'out', 'report.md'), 'utf8'), /open-issues: false for pull\\_request events/);
  // other GitHub errors still fail loudly
  await assert.rejects(run({ root, fetcher: fake({ gh: () => new Response('', { status: 500 }) }).fetcher, log: () => {} }), /GitHub GET .* 500/);
});

test('issue titles: control characters and newlines from advisory data are stripped', () => {
  const t = issueTitle(exploitedFinding({ component: { name: 'evil\npkg\r\u0007\u2028x', version: '1\t2', files: [] }, vuln: { id: 'GHSA-1', cves: [], fixed: [], refs: [] } }));
  assert.ok(!/[\u0000-\u001f\u007f\u2028\u2029]/.test(t));
  assert.equal(t, 'CRA Art. 14: actively exploited GHSA-1 in evil pkg x 1 2');
  assert.equal(plain('a`b\u0000c'), "a'b c");
});

test('parsers: gradle.lockfile and npm-shrinkwrap.json', () => {
  const g = L.parseFile('gradle.lockfile', '# This is a Gradle generated file for dependency locking.\n# Manual edits can break the build and are not advised.\norg.springframework:spring-beans:5.3.17=runtimeClasspath\ncom.fasterxml.jackson.core:jackson-databind:2.9.10=compileClasspath,runtimeClasspath\nnot a dependency line\nempty=annotationProcessor\n', 'app/gradle.lockfile');
  assert.deepEqual(g.map((c) => c.purl), ['pkg:maven/org.springframework/spring-beans@5.3.17', 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10']);
  assert.equal(g[0].file, 'app/gradle.lockfile'); assert.equal(g[0].ecosystem, 'Maven');
  const s = L.parseFile('npm-shrinkwrap.json', JSON.stringify({ lockfileVersion: 2, packages: { '': { dependencies: { minimist: '^1' } }, 'node_modules/minimist': { version: '1.2.5' }, 'node_modules/linked': { link: true } }, dependencies: { minimist: { version: '1.2.5' } } }));
  assert.deepEqual(s.map((c) => [c.purl, c.direct, c.file]), [['pkg:npm/minimist@1.2.5', true, 'npm-shrinkwrap.json']]);
  const root = mkdtempSync(join(tmpdir(), 'cra-sw-'));
  writeFileSync(join(root, 'npm-shrinkwrap.json'), '{}'); writeFileSync(join(root, 'gradle.lockfile'), '');
  assert.equal(findLockfiles(root).length, 2);
});

test('sniff: renamed lockfiles are recognised by content', () => {
  assert.equal(L.sniff(JSON.stringify({ lockfileVersion: 3, packages: {} })), 'package-lock.json');
  assert.equal(L.sniff(JSON.stringify({ _meta: {}, default: {} })), 'Pipfile.lock');
  assert.equal(L.sniff(JSON.stringify({ 'content-hash': 'x', packages: [] })), 'composer.lock');
  assert.equal(L.sniff('# yarn lockfile v1\n\nlodash@^4:\n  version "4.17.21"\n'), 'yarn.lock');
  assert.equal(L.sniff("lockfileVersion: '9.0'\npackages:\n"), 'pnpm-lock.yaml');
  assert.equal(L.sniff('module x\n\ngo 1.22\n'), 'go.mod');
  assert.equal(L.sniff('[[package]]\nname = "openssl"\nversion = "0.1"\nsource = "registry+x"\n'), 'Cargo.lock');
  assert.equal(L.sniff('[[package]]\nname = "idna"\nversion = "3.1"\npython-versions = ">=3"\n'), 'poetry.lock');
  assert.equal(L.sniff('GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (6.1.0)\n'), 'Gemfile.lock');
  assert.equal(L.sniff('org.a:b:1.0=runtimeClasspath\n'), 'gradle.lockfile');
  assert.equal(L.sniff('Django==3.2.0\n'), 'requirements.txt');
  assert.equal(L.sniff('{"name":"x","dependencies":{"a":"^1"}}'), null, 'package.json is not a lockfile');
  assert.equal(L.sniff('hello world'), null);
});
