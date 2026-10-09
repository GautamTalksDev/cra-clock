// Regression tests for the 9 Oct 2026 launch audit of CRA Clock (C-M1 to C-M3, C-L1 to C-L5) and the detection-time label.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as L from '../src/lockfiles.mjs';
import { osvDetails, kev, KEV_MIN_ENTRIES } from '../src/intel.mjs';
import { assess, validAware, vulnKey } from '../src/assess.mjs';
import { issueBody, readState, summary, md, plain, codeSpan, vex } from '../src/outputs.mjs';
import { fenced, severity, isoDate, version, httpsUrl } from '../src/safe.mjs';
import { run, findLockfiles, syncIssues, annotation } from '../src/main.mjs';
import { kevSet, headline } from '../site/public/verdict.mjs';
import { kevJson, padKev } from './kev-fixture.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const MAIN = join(HERE, '..', 'src', 'main.mjs');
const STUB = pathToFileURL(join(HERE, 'stub-fetch.mjs')).href;

const ENV = ['INPUT_OUTPUT-DIR', 'INPUT_GITHUB-TOKEN', 'INPUT_FAIL-ON', 'INPUT_EPSS-THRESHOLD', 'INPUT_OPEN-ISSUES', 'INPUT_ALLOW-INCOMPLETE-INTEL', 'GITHUB_REPOSITORY', 'GITHUB_STEP_SUMMARY', 'GITHUB_OUTPUT', 'GITHUB_SERVER_URL', 'GITHUB_RUN_ID'];
beforeEach(() => { for (const k of ENV) delete process.env[k]; process.env['INPUT_OUTPUT-DIR'] = 'out'; });

/** a CommonMark-style reader for fenced code blocks: what is code, and what would GitHub render as Markdown */
function fences(body) {
  const blocks = [], outside = [];
  let open = null;
  for (const line of body.split('\n')) {
    if (!open) {
      const m = /^ {0,3}(`{3,})([^`]*)$/.exec(line);
      if (m) { open = { len: m[1].length, info: m[2].trim(), lines: [] }; blocks.push(open); } else outside.push(line);
    } else {
      const m = /^ {0,3}(`{3,})[ \t]*$/.exec(line);
      if (m && m[1].length >= open.len) open = null; else open.lines.push(line);
    }
  }
  return { blocks, outside, unterminated: !!open };
}

// starts and ends with a line break so the backtick lines stand alone: this payload really does close a fence on the old code
const EVIL = '\n```\n## ZZINJECT\n@octocat [click](https://evil.example) <img src=x onerror=alert(1)>\n```text\n';
const AWARE = '2026-10-07T00:00:00.000Z';
const finding = (over = {}) => ({
  fingerprint: 'pkg:npm/x@1|CVE-2021-44228', tier: 'exploited', component: { name: 'x', version: '1', files: ['package-lock.json'] },
  vuln: { id: 'GHSA-1', cves: ['CVE-2021-44228'], summary: 'Log4Shell', severity: 'CRITICAL', fixed: ['2.15.0'], refs: ['https://ok.example/a'] },
  kev: [{ cve: 'CVE-2021-44228', dateAdded: '2021-12-10', ransomware: false, action: 'Apply updates', name: 'Log4j RCE' }], epss: { epss: 0.97, percentile: 0.99 }, ...over,
});

// ---------------------------------------------------------------- C-M1: advisory data cannot break out of the draft fences

test('C-M1 PoC: hostile severity, fixed version and KEV date cannot leave the draft code fences', () => {
  const f = finding({
    vuln: { id: 'GHSA-1', cves: ['CVE-2021-44228'], summary: 'ok', severity: EVIL, fixed: [`1.0${EVIL}`, EVIL], refs: ['https://ok.example/a'] },
    kev: [{ cve: 'CVE-2021-44228', dateAdded: `2021-12-10${EVIL}`, ransomware: false }],
  });
  const body = issueBody(f, { awareAt: AWARE, product: 'p' });
  const { blocks, outside, unterminated } = fences(body);
  assert.equal(blocks.length, 2); assert.equal(unterminated, false);
  assert.deepEqual(blocks.map((b) => b.info), ['text', 'text']);
  assert.deepEqual(outside.filter((l) => /^#{1,6} /.test(l)).length, 3, 'only the template headings are headings');
  assert.ok(!outside.some((l) => /ZZINJECT/.test(l)), 'nothing from the advisory reaches Markdown');
  assert.match(blocks[1].lines.join('\n'), /Initial severity assessment: \[fill in\]/);
  assert.match(blocks[0].lines.join('\n'), /Evidence: listed in CISA KEV \(date n\/a\)/);
  assert.match(blocks[1].lines.join('\n'), /Corrective or mitigating measures: \[fill in\]/);
});

test('C-M1: every untrusted field, hostile at once, stays inside the fences or is neutralized outside them', () => {
  const f = finding({
    component: { name: `evil${EVIL}`, version: `1${EVIL}`, files: [`a${EVIL}.json`, `b\u2028c.json`] },
    vuln: { id: `GHSA${EVIL}`, cves: ['CVE-2021-44228'], summary: `${EVIL}\u2028${EVIL}`, severity: 'HIGH', fixed: ['2.15.0'], refs: ['https://ok.example/a', `https://evil.example/${EVIL}`, 'https://x.example/a`b'] },
    kev: [{ cve: 'CVE-2021-44228', dateAdded: '2021-12-10', ransomware: true, action: `${EVIL}\n${EVIL}`, name: EVIL }],
  });
  const body = issueBody(f, { awareAt: AWARE, product: `Acme ${EVIL}`, runUrl: 'https://github.com/o/r/actions/runs/1' });
  const { blocks, outside, unterminated } = fences(body);
  assert.equal(blocks.length, 2); assert.equal(unterminated, false);
  assert.equal(body.split('\n').filter((l) => /^`{3,}/.test(l)).length, 4, 'exactly two fences open and close');
  assert.ok(!/[\r\u2028\u2029]/.test(body), 'no line separators other than \\n');
  // the reference list and the footer are generated from validated URLs; everything else is untrusted text
  const refs = outside.filter((l) => l.startsWith('- <https://'));
  assert.equal(refs.length, 2, 'the two hostile references were dropped');
  assert.equal(refs[0], '- <https://ok.example/a>');
  assert.match(refs[1], /^- <https:\/\/osv\.dev\/vulnerability\/[A-Za-z0-9._~%-]+>$/, 'the OSV link is fully percent-encoded');
  assert.ok(outside.some((l) => l.includes('[run](https://github.com/o/r/actions/runs/1)')));
  // text inside a code span is literal on GitHub (no mentions, links or HTML), so it may keep its characters
  const md_ = outside.filter((l) => !l.startsWith('- <https://') && !l.startsWith('Drafts are a starting point')).join('\n').replace(/`[^`\n]*`/g, '``');
  assert.equal(md_.match(/^#{1,6} /gm).length, 3, 'no injected headings');
  assert.ok(!/@(?!\u200b)[A-Za-z]/.test(md_), 'no live @mentions');
  assert.ok(!/\]\(/.test(md_), 'no injected links');
  assert.ok(!/<img/i.test(md_), 'no HTML');
  assert.ok(!/https?:\/\//i.test(md_), 'no live autolinks: every scheme has a zero-width space before ://');
});

test('C-M1: the fence is longer than any backtick run in the content, whatever plain() does', () => {
  const lines = fenced(['a ```` b', 'x ``` y', '`'.repeat(9)]);
  assert.equal(lines[0], '`'.repeat(10) + 'text');
  assert.equal(lines[2], '`'.repeat(10));
  const parsed = fences(['before', ...lines, 'after ## still outside'].join('\n'));
  assert.equal(parsed.blocks.length, 1); assert.equal(parsed.blocks[0].lines.length, 3);
  assert.deepEqual(parsed.outside, ['before', 'after ## still outside']);
  assert.equal(fenced(['no backticks'])[0], '```text');
});

test('C-M1: the same data through the real pipeline (OSV, KEV, EPSS parsing) cannot break out either', async () => {
  const HOSTILE = 'GHSA-aaaa-bbbb-cccc';
  const fetcher = async (url) => {
    if (url.includes('/vulns/')) return Response.json({
      id: HOSTILE, aliases: ['CVE-2021-44228', EVIL], summary: EVIL, details: EVIL, database_specific: { severity: EVIL },
      affected: [{ ranges: [{ events: [{ fixed: `1.0${EVIL}` }, { fixed: '2.15.0' }, { fixed: { toString: 'x' } }, { fixed: 7 }] }] }],
      references: [{ url: 'https://ok.example/a' }, { url: 'javascript:alert(1)' }, { url: `https://evil.example/${EVIL}` }, { url: 42 }],
    });
    return Response.json(kevJson([{ cveID: 'CVE-2021-44228', dateAdded: `2021-12-10${EVIL}`, vendorProject: EVIL, product: EVIL, vulnerabilityName: EVIL, requiredAction: EVIL, knownRansomwareCampaignUse: 'Known' }]));
  };
  const d = (await osvDetails([HOSTILE], fetcher)).get(HOSTILE);
  assert.equal(d.severity, null); assert.deepEqual(d.fixed, ['2.15.0']); assert.deepEqual(d.refs, ['https://ok.example/a']);
  assert.deepEqual(d.cves, ['CVE-2021-44228']); assert.ok(!/[\n\r]/.test(d.summary));
  const k = await kev(fetcher, { delayMs: 0 });
  const entry = k.map.get('CVE-2021-44228');
  assert.equal(entry.dateAdded, null); assert.ok(!/[\n\r]/.test(entry.action + entry.name + entry.vendor));
  const [fnd] = assess([{ purl: 'p', name: 'x', version: '1', files: ['f'] }], new Map([['p', [HOSTILE]]]), new Map([[HOSTILE, d]]), k.map, new Map());
  assert.equal(fnd.tier, 'exploited');
  const { blocks, outside, unterminated } = fences(issueBody(fnd, { awareAt: AWARE, product: 'p' }));
  assert.equal(blocks.length, 2); assert.equal(unterminated, false);
  assert.ok(!outside.some((l) => /ZZINJECT/.test(l)));
});

test('C-M1: validators accept real values and reject anything that could carry markup', () => {
  for (const s of ['LOW', 'moderate', 'High', ' CRITICAL ']) assert.ok(severity(s));
  for (const s of [EVIL, 'HIGH\nINJECT', '', null, 7, {}]) assert.equal(severity(s), null);
  for (const v of ['2.17.1', 'v0.17.0', '1.0.0-rc.1+build.5', '1!2.0.post1', '1:2.3-4~deb11u1', '0.0.0-20210101000000-abcdef123456', 'a'.repeat(40), '4.17.21']) assert.equal(version(v), v);
  for (const v of ['1.0 2.0', '1.0`', '1.0\n', '<1', '[1]', '', 'x'.repeat(65), null, 5, ['1']]) assert.equal(version(v), null);
  assert.equal(isoDate('2021-12-10'), '2021-12-10');
  for (const v of ['2021-12-10\n', '2021-12-10 ```', '12/10/2021', '2021-13-40', null, 20211210]) assert.equal(isoDate(v), null);
  assert.equal(httpsUrl('https://ok.example/a?b=c#d'), 'https://ok.example/a?b=c#d');
  for (const u of ['http://x.example', 'javascript:alert(1)', 'https://x.example/a b', 'https://x.example/`', 'https://x.example/)', 'https://x.example/<', 'https://x.example/\\', 'https://' + 'a'.repeat(400), null]) assert.equal(httpsUrl(u), null);
});

test('C-M1: md() also neutralizes www. autolinks, other schemes, math, GH-123 references and bidi controls', () => {
  const s = md('see www.evil.example and ftp://evil.example and $\\alpha$ and GH-12 and \u202eevil and a@b.example');
  assert.ok(!/www\.evil/.test(s) && !/ftp:\/\//.test(s) && !/GH-12/.test(s) && !/\u202e/.test(s));
  assert.ok(!/(^|[^\\])\$/.test(s), 'dollar signs are escaped');
  assert.ok(!/@[a-z]/.test(s));
  assert.equal(plain('a\u202eb\u200bc`d\ne'), "abc'd e");
});

// ---------------------------------------------------------------- C-L5: backslashes inside code spans

test('C-L5: names and paths in code spans show no backslashes; a pipe cannot split a table cell', () => {
  assert.equal(codeSpan('typing_extensions'), '`typing_extensions`');
  assert.equal(codeSpan('my_app/package-lock.json'), '`my_app/package-lock.json`');
  assert.equal(codeSpan('a`b|c'), "`a'b\\|c`");
  assert.equal(codeSpan(''), '`n/a`');
  const f = finding({ component: { name: 'typing_extensions', version: '4.0.0', files: ['my_app/package-lock.json', 'a_b/yarn.lock'] } });
  const body = issueBody(f, { awareAt: AWARE, product: 'p' });
  assert.match(body, /\| Component \| `typing_extensions` 4\.0\.0 \|/);
  assert.match(body, /\| Found in \| `my_app\/package-lock\.json`, `a_b\/yarn\.lock` \|/);
  const rep = summary([f], [f.component], { files: ['f'], kevMeta: { catalogVersion: '1' } });
  assert.match(rep, /\| EXPLOITED \| `typing_extensions` 4\.0\.0 \|/);
  const inc = summary([{ ...f, tier: 'intel-incomplete', missing: ['EPSS'] }], [f.component], { files: ['f'], kevMeta: {} });
  assert.match(inc, /\| `typing_extensions` 4\.0\.0 \| CVE-2021-44228 \| EPSS \|/);
  assert.ok(!/typing\\_extensions|my\\_app/.test(body + rep + inc));
});

// ---------------------------------------------------------------- detection-time label

test('the draft labels the time "Detected by CRA Clock" and says the legal clock runs from awareness', () => {
  const body = issueBody(finding(), { awareAt: AWARE, product: 'p' });
  const draft = fences(body).blocks[0].lines;
  assert.ok(draft.includes(`Detected by CRA Clock: ${AWARE}`));
  assert.ok(draft.includes('Your 24 hours run from when you became aware; edit if earlier.'));
  assert.ok(!/Awareness:/.test(body));
  assert.match(body, /Your legal 24 hours run from when you became aware/);
  assert.match(body, /counted from CRA Clock's detection at 2026-10-07T00:00:00\.000Z/);
  assert.ok(!/[\u2013\u2014]/.test(body), 'no em or en dashes');
});

// ---------------------------------------------------------------- C-M2: an empty or failed KEV response is "unknown"

const hostileKev = {
  empty: () => Response.json({}),
  emptyList: () => Response.json({ catalogVersion: '2026.10.06', vulnerabilities: [] }),
  noVersion: () => Response.json({ vulnerabilities: padKev([]) }),
  tooSmall: () => Response.json(kevJson([], { vulnerabilities: padKev([], KEV_MIN_ENTRIES) })),
  garbage: () => Response.json({ catalogVersion: 'x', vulnerabilities: Array.from({ length: 5000 }, () => ({ nope: 1 })) }),
  notJson: () => new Response('<html>Down for maintenance</html>', { status: 200 }),
  http503: () => new Response('maintenance', { status: 503 }),
  html404: () => new Response('nope', { status: 404 }),
};

test('C-M2: kev() throws for an empty, truncated, malformed or failed response, and accepts the real shape', async () => {
  for (const [name, make] of Object.entries(hostileKev)) await assert.rejects(kev(async () => make(), { delayMs: 0 }), undefined, name);
  await assert.rejects(kev(async () => hostileKev.empty(), { delayMs: 0 }), /catalogVersion/);
  await assert.rejects(kev(async () => hostileKev.emptyList(), { delayMs: 0 }), /only 0 vulnerabilities/);
  const ok = await kev(async () => Response.json(kevJson([], { vulnerabilities: padKev([], KEV_MIN_ENTRIES + 1) })), { delayMs: 0 });
  assert.equal(ok.map.size, KEV_MIN_ENTRIES + 1);
  assert.equal(ok.catalogVersion, '2026.10.06');
});

test('C-M2: an outage ends in an error after bounded retries instead of hanging (persistent 5xx and 429 used to retry forever)', async () => {
  for (const status of [500, 503, 429]) {
    let n = 0;
    await assert.rejects(kev(async () => { n++; return new Response('down', { status }); }, { delayMs: 0 }), new RegExp(`HTTP ${status}`));
    assert.equal(n, 3, `HTTP ${status}: three attempts, then an error`);
  }
  let n = 0;
  await assert.rejects(kev(async () => { n++; return new Response('gone', { status: 404 }); }, { delayMs: 0 }), /HTTP 404/);
  assert.equal(n, 1, 'a 404 is final, not retried');
  n = 0;
  await assert.rejects(kev(async () => { n++; throw new Error('ECONNRESET'); }, { delayMs: 0 }), /ECONNRESET/);
  assert.equal(n, 3);
});

test('C-M2: an empty response is retried, so a transient maintenance page does not fail the job', async () => {
  let n = 0;
  const m = await kev(async () => (++n < 3 ? hostileKev.empty() : Response.json(kevJson())), { delayMs: 0 });
  assert.equal(n, 3); assert.ok(m.map.size > KEV_MIN_ENTRIES);
});

const lockRepo = () => {
  const root = mkdtempSync(join(tmpdir(), 'cra-a-'));
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/lodash': { version: '4.17.20' } } }));
  writeFileSync(join(root, 'requirements.txt'), 'log4j-python-shim==1.0\n');
  return root;
};
const LOG4J = 'GHSA-jfh8-c2jp-5v3q', LODASH = 'GHSA-35jh-r3h4-6jhm';
function world({ order = [LOG4J], kevResponse, gh } = {}) {
  const calls = [];
  const fetcher = async (url, init = {}) => {
    calls.push(url);
    if (url.startsWith('https://api.github.com')) return gh(init.method || 'GET', url.slice('https://api.github.com'.length), init.body && JSON.parse(init.body));
    if (url.endsWith('/querybatch')) return Response.json({ results: JSON.parse(init.body).queries.map((q) => ({ vulns: q.package.purl.includes('log4j') ? order.map((id) => ({ id })) : q.package.purl.includes('lodash') ? [{ id: LODASH }] : [] })) });
    if (url.includes('/vulns/')) {
      const id = decodeURIComponent(url.split('/vulns/')[1]);
      return Response.json(id === LODASH ? { id, aliases: ['CVE-2021-23337'], summary: 'lodash' } : { id, aliases: id === order[0] ? ['CVE-2021-44228', 'CVE-2021-45046'] : ['CVE-2021-45046', 'CVE-2021-44228'], summary: 'Log4Shell', affected: [{ ranges: [{ events: [{ fixed: '2.15.0' }] }] }] });
    }
    if (url.includes('known_exploited')) return kevResponse ? kevResponse() : Response.json(kevJson([{ cveID: 'CVE-2021-44228', dateAdded: '2021-12-10', knownRansomwareCampaignUse: 'Known' }]));
    if (url.includes('api.first.org')) return Response.json({ data: [{ cve: 'CVE-2021-44228', epss: '0.97', percentile: '0.999' }, { cve: 'CVE-2021-23337', epss: '0.02', percentile: '0.8' }] });
    throw new Error('unexpected ' + url);
  };
  return { fetcher, calls };
}

test('C-M2 PoC: an empty KEV response never reports "nothing exploited"; the job exits 2, the report says it could not confirm', async () => {
  for (const [name, make] of Object.entries(hostileKev)) {
    const root = lockRepo();
    const outFile = join(root, 'gh-output');
    process.env.GITHUB_OUTPUT = outFile;
    const r = await run({ root, fetcher: world({ kevResponse: make }).fetcher, log: () => {}, retryDelayMs: 0 });
    delete process.env.GITHUB_OUTPUT;
    assert.equal(r.kevUnknown, true, name);
    assert.equal(r.fail, true, name); assert.equal(r.outage, true, name);
    assert.ok(r.reasons.some((m) => /Could not confirm exploitation status/.test(m)), name);
    assert.ok(r.findings.every((f) => f.tier !== 'known' && f.tier !== 'exploited'), `${name}: nothing is "known" or "exploited" without KEV`);
    assert.ok(r.findings.every((f) => f.missing.includes('CISA KEV')), name);
    const rep = readFileSync(join(root, 'out', 'report.md'), 'utf8');
    assert.match(rep, /### Could not confirm exploitation status/);
    assert.match(rep, /not\*\* a clean result/);
    assert.match(rep, /\| Actively exploited \(KEV\) \| unknown \|/);
    assert.ok(!/No actively exploited/i.test(rep) && !/nothing (is )?(actively )?exploited/i.test(rep), name);
    const out = readFileSync(outFile, 'utf8');
    assert.match(out, /^exploited=unknown$/m); assert.match(out, /^kev-status=unknown$/m);
    const v = JSON.parse(readFileSync(join(root, 'out', 'vex.cdx.json'), 'utf8'));
    assert.ok(v.vulnerabilities.every((x) => !x.properties.some((p) => p.name === 'cra-clock:actively-exploited')));
    assert.ok(v.vulnerabilities.some((x) => /CISA KEV/.test(x.analysis.detail)));
    assert.equal(JSON.parse(readFileSync(join(root, 'out', 'sbom.cdx.json'), 'utf8')).components.length, 2, 'the SBOM is still written');
  }
});

test('C-M2: a healthy KEV catalog still reports normally and says kev-status ok', async () => {
  process.env['INPUT_FAIL-ON'] = 'never';
  const root = lockRepo();
  const outFile = join(root, 'gh-output');
  process.env.GITHUB_OUTPUT = outFile;
  const r = await run({ root, fetcher: world().fetcher, log: () => {}, retryDelayMs: 0 });
  assert.equal(r.kevUnknown, false); assert.equal(r.fail, false);
  assert.match(readFileSync(outFile, 'utf8'), /^kev-status=ok$/m);
  assert.match(readFileSync(outFile, 'utf8'), /^exploited=1$/m);
  assert.match(readFileSync(join(root, 'out', 'report.md'), 'utf8'), /### 1 actively exploited vulnerability/);
});

test('C-M2: the real entry point exits 2 and prints an error, never a clean line, for an empty KEV response', () => {
  const root = lockRepo();
  const r = spawnSync(process.execPath, ['--import', STUB, MAIN], { encoding: 'utf8', env: cleanEnv({ GITHUB_WORKSPACE: root, CRA_TEST_SCENARIO: 'kev-empty' }) });
  assert.equal(r.status, 2, r.stdout + r.stderr);
  assert.match(r.stdout, /^::error::Could not confirm exploitation status/m);
  assert.ok(!/no actively exploited/i.test(r.stdout));
});

function cleanEnv(extra) {
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (k.startsWith('INPUT_') || k.startsWith('GITHUB_')) delete env[k];
  return { ...env, 'INPUT_OUTPUT-DIR': 'out', ...extra };
}

test('C-M2: the browser scanner treats a missing, empty or tiny KEV answer as unknown', () => {
  for (const bad of [null, undefined, {}, { cves: null }, { cves: [] }, { cves: 'CVE-2021-44228' }, { cves: Array.from({ length: 1000 }, (_, i) => `CVE-2000-${1000 + i}`) }, { cves: Array.from({ length: 5000 }, () => 'bogus') }]) assert.equal(kevSet(bad), null);
  const set = kevSet({ cves: Array.from({ length: 1001 }, (_, i) => `CVE-2000-${1000 + i}`).concat(['nope', 7]) });
  assert.equal(set.size, 1001);
  assert.equal(headline({ exploited: 0, advisories: 3, kevKnown: false }), 'Could not confirm exploitation status.');
  assert.equal(headline({ exploited: 0, advisories: 3, kevKnown: true }), 'Nothing actively exploited right now.');
  assert.equal(headline({ exploited: 2, advisories: 3, kevKnown: true }), '2 actively exploited. Your clock would be running.');
  assert.equal(headline({ exploited: 0, advisories: 0, kevKnown: false }), 'No known vulnerabilities.');
  const src = readFileSync(join(HERE, '..', 'site', 'public', 'landing.js'), 'utf8');
  assert.match(src, /headline\(\{ exploited: ex, advisories: rows\.length, kevKnown \}\)/, 'landing.js uses the tested headline');
  assert.ok(!/Nothing actively exploited/.test(src), 'no hard-coded clean headline in landing.js');
  assert.ok(!/\bkev\.cves\b/.test(src.split('// scanner')[1]), 'the scanner no longer trusts kev.cves directly');
});

// ---------------------------------------------------------------- C-M3: the clock cannot reset when OSV reorders ids

const BOT = { login: 'github-actions[bot]', type: 'Bot' };
function github() {
  const issues = [];
  let n = 100;
  const handler = (method, path, body) => {
    if (method === 'GET' && path.startsWith('/repos/o/r/issues?')) return Response.json(issues);
    if (method === 'GET' && path === '/user') return new Response('{"message":"Resource not accessible by integration"}', { status: 403 });
    if (method === 'POST') { const i = { number: ++n, state: 'open', user: BOT, created_at: new Date().toISOString(), ...body }; issues.push(i); return Response.json(i, { status: 201 }); }
    if (method === 'PATCH') { const i = issues.find((x) => path.endsWith('/' + x.number)); Object.assign(i, body); return Response.json(i); }
    throw new Error(`unexpected ${method} ${path}`);
  };
  return { issues, handler };
}
const A = 'GHSA-aaaa-aaaa-aaaa', B = 'PYSEC-2021-9999';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('C-M3 PoC: the same CVE with OSV ids in a different order keeps one issue and the first detection time', async () => {
  Object.assign(process.env, { 'INPUT_GITHUB-TOKEN': 't', GITHUB_REPOSITORY: 'o/r', 'INPUT_FAIL-ON': 'never' });
  const gh = github(), root = lockRepo();
  const r1 = await run({ root, fetcher: world({ order: [A, B], gh: gh.handler }).fetcher, log: () => {}, retryDelayMs: 0 });
  assert.equal(r1.issues.length, 1); assert.equal(r1.issues[0].created, true);
  const first = r1.issues[0].awareAt;
  await sleep(20);
  const r2 = await run({ root, fetcher: world({ order: [B, A], gh: gh.handler }).fetcher, log: () => {}, retryDelayMs: 0 });
  assert.equal(gh.issues.length, 1, 'no second issue is opened');
  assert.deepEqual(r2.issues.map((i) => [i.number, !!i.updated, !!i.created]), [[101, true, false]]);
  assert.equal(r2.issues[0].awareAt, first, 'the clock did not reset');
  assert.equal(readState(gh.issues[0].body).aware, first);
});

test('C-M3: the fingerprint and finding identity do not depend on advisory id order or alias order', () => {
  const comp = [{ purl: 'p', name: 'n', version: '1', files: ['f'] }];
  const det = (id, cves) => [id, { id, cves, aliases: [], fixed: [], refs: [] }];
  const kevMap = new Map([['CVE-2021-44228', {}]]);
  const go = (ids, cveOrder) => assess(comp, new Map([['p', ids]]), new Map([det(A, cveOrder(A)), det(B, cveOrder(B))]), kevMap, new Map());
  const fwd = go([A, B], () => ['CVE-2021-45046', 'CVE-2021-44228']);
  const rev = go([B, A], () => ['CVE-2021-44228', 'CVE-2021-45046']);
  assert.equal(fwd.length, 1); assert.equal(rev.length, 1);
  assert.equal(fwd[0].fingerprint, 'p|CVE-2021-44228');
  assert.equal(fwd[0].fingerprint, rev[0].fingerprint);
  assert.equal(fwd[0].vuln.id, rev[0].vuln.id, 'even the displayed advisory id is deterministic');
  assert.deepEqual([...fwd[0].legacyFingerprints].sort(), [`p|${A}`, `p|${B}`].sort());
  assert.equal(vulnKey({ id: 'X', cves: ['CVE-2022-2', 'CVE-2021-9'] }), 'CVE-2021-9');
  assert.equal(vulnKey({ id: 'X', cves: [] }), 'X');
});

test('C-M3: a clock stored under an older "purl|first advisory id" fingerprint is found and kept, whichever id it used', async () => {
  const old = '2026-10-01T00:00:00.000Z';
  const make = (fp) => ({ number: 7, state: 'open', user: BOT, created_at: old, body: `<!-- cra-clock:${Buffer.from(JSON.stringify({ fp, aware: old })).toString('base64')} -->\nold body` });
  for (const stored of [A, B]) {
    const gh = github(); gh.issues.push(make(`pkg:pypi/log4j-python-shim@1.0|${stored}`));
    const fnd = assess([{ purl: 'pkg:pypi/log4j-python-shim@1.0', name: 'log4j-python-shim', version: '1.0', files: ['requirements.txt'] }], new Map([['pkg:pypi/log4j-python-shim@1.0', [A, B]]]),
      new Map([[A, { id: A, cves: ['CVE-2021-44228'], aliases: [], fixed: [], refs: [] }], [B, { id: B, cves: ['CVE-2021-44228'], aliases: [], fixed: [], refs: [] }]]), new Map([['CVE-2021-44228', { dateAdded: '2021-12-10' }]]), new Map());
    const out = await syncIssues('t', 'o/r', fnd, { product: 'p' }, async (url, init = {}) => gh.handler(init.method || 'GET', url.slice('https://api.github.com'.length), init.body && JSON.parse(init.body)));
    assert.equal(gh.issues.length, 1, `stored under ${stored}`);
    assert.deepEqual(out.map((o) => [o.number, !!o.updated, o.awareAt]), [[7, true, old]]);
    assert.equal(readState(gh.issues[0].body).fp, 'pkg:pypi/log4j-python-shim@1.0|CVE-2021-44228', 'upgraded in place to the stable fingerprint');
    assert.equal(readState(gh.issues[0].body).aware, old);
  }
});

test('C-M3: if an earlier reset already left two issues for one vulnerability, the earliest clock wins', async () => {
  const gh = github();
  const fnd = { ...finding({ fingerprint: 'p|CVE-2021-44228' }), legacyFingerprints: ['p|GHSA-1', 'p|GHSA-2'] };
  const mk = (number, fp, aware, state = 'open') => ({ number, state, user: BOT, created_at: aware, body: `<!-- cra-clock:${Buffer.from(JSON.stringify({ fp, aware })).toString('base64')} -->` });
  gh.issues.push(mk(9, 'p|GHSA-2', '2026-10-05T00:00:00.000Z'), mk(4, 'p|GHSA-1', '2026-10-02T00:00:00.000Z'));
  const out = await syncIssues('t', 'o/r', [fnd], { product: 'p' }, async (url, init = {}) => gh.handler(init.method || 'GET', url.slice('https://api.github.com'.length), init.body && JSON.parse(init.body)));
  assert.deepEqual(out.map((o) => [o.number, o.awareAt]), [[4, '2026-10-02T00:00:00.000Z']]);
});

// ---------------------------------------------------------------- C-L1: workflow-command injection

test('C-L1: annotation() cannot be made to start a second workflow command', () => {
  const evil = 'upstream said:\n::add-mask::hunter2\r\n::warning::pwned\u2028::stop-commands::x\u0085:::error::y';
  const out = annotation('error', `cra-clock failed: ${evil}`);
  assert.ok(out.startsWith('::error::cra-clock failed: upstream said:'));
  assert.ok(!/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(out), 'one line');
  assert.ok(!out.slice('::error::'.length).includes('::'), 'no further "::" anywhere in the message');
  assert.ok(out.length <= '::error::'.length + 300);
  assert.equal(annotation('warning', 'plain text'), '::warning::plain text');
});

test('C-L1 PoC: upstream error text with command lines does not reach the log as commands (real entry point)', () => {
  const root = lockRepo();
  const r = spawnSync(process.execPath, ['--import', STUB, MAIN], { encoding: 'utf8', env: cleanEnv({ GITHUB_WORKSPACE: root, CRA_TEST_SCENARIO: 'osv-throws' }) });
  assert.equal(r.status, 2, r.stdout + r.stderr);
  const lines = r.stdout.split('\n').filter((l) => l.startsWith('::'));
  assert.equal(lines.length, 1, `exactly one workflow command line, got: ${JSON.stringify(lines)}`);
  assert.match(lines[0], /^::error::cra-clock failed: upstream said:/);
  assert.ok(!/^::(add-mask|warning|stop-commands)::/m.test(r.stdout));
});

test('C-L1: invalid input containing newlines is also reported as one safe error line', () => {
  const root = lockRepo();
  const r = spawnSync(process.execPath, [MAIN], { encoding: 'utf8', env: cleanEnv({ GITHUB_WORKSPACE: root, 'INPUT_FAIL-ON': 'x\n::add-mask::hunter2\n::warning::pwned' }) });
  assert.equal(r.status, 2);
  assert.equal(r.stdout.split('\n').filter((l) => l.startsWith('::')).length, 1);
  assert.ok(!/^::(add-mask|warning)::/m.test(r.stdout));
});

// ---------------------------------------------------------------- C-L2: files named like Object.prototype members

test('C-L2 PoC: a file named constructor, toString or __proto__ is not a lockfile', async () => {
  const names = ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__', 'isPrototypeOf', '__defineGetter__'];
  const root = mkdtempSync(join(tmpdir(), 'cra-proto-'));
  for (const n of names) writeFileSync(join(root, n), 'x==1\n');
  writeFileSync(join(root, 'requirements.txt'), 'Django==3.2.0\n');
  assert.deepEqual(findLockfiles(root).map((p) => p.slice(root.length + 1)), ['requirements.txt']);
  for (const n of names) { assert.equal(L.isLockfileName(n), false, n); assert.deepEqual(L.parseFile(n, 'Django==3.2.0\n'), [], n); }
  for (const n of Object.keys(L.PARSERS)) assert.equal(L.isLockfileName(n), true, n);
  const seen = [];
  const r = await run({ root, log: () => {}, retryDelayMs: 0, fetcher: async (url, init = {}) => {
    seen.push(url);
    if (url.endsWith('/querybatch')) { const q = JSON.parse(init.body).queries; assert.ok(q.every((x) => typeof x.package.purl === 'string' && x.package.purl.startsWith('pkg:')), 'only real purls reach OSV'); return Response.json({ results: q.map(() => ({})) }); }
    if (url.includes('known_exploited')) return Response.json(kevJson());
    return Response.json({ data: [] });
  } });
  assert.equal(r.components.length, 1); assert.equal(r.fail, false);
  const landing = readFileSync(join(HERE, '..', 'site', 'public', 'landing.js'), 'utf8');
  assert.ok(!/PARSERS\s*\[/.test(landing), 'the browser scanner does not index PARSERS directly');
  assert.match(landing, /isLockfileName\(name\)/);
});

// ---------------------------------------------------------------- C-L3: issue body size

test('C-L3 PoC: huge upstream fields cannot push the issue body past GitHub\'s 65,536 character limit', () => {
  const big = 'x'.repeat(30_000);
  const f = finding({
    component: { name: big, version: big, files: Array.from({ length: 400 }, (_, i) => `dir${i}/${'p'.repeat(120)}/package-lock.json`) },
    vuln: { id: big, cves: ['CVE-2021-44228'], summary: big + big, severity: big, fixed: Array.from({ length: 50 }, () => big), refs: Array.from({ length: 50 }, () => 'https://ok.example/' + 'a'.repeat(30_000)) },
    kev: [{ cve: 'CVE-2021-44228', dateAdded: big, action: big, name: big }],
  });
  const body = issueBody(f, { awareAt: AWARE, product: big, runUrl: 'https://github.com/o/r/actions/runs/1' });
  assert.ok(body.length < 20_000, `body is ${body.length} characters`);
  assert.match(body, /, and 380 more \|/, 'the file list is capped and says how many are left');
  assert.equal(fences(body).unterminated, false);
});

test('C-L3: the fixed versions and references taken from OSV are capped per field at the source', async () => {
  const fetcher = async () => Response.json({
    id: A, aliases: ['CVE-2021-44228'], summary: 'x'.repeat(5000),
    affected: [{ ranges: [{ events: Array.from({ length: 500 }, (_, i) => ({ fixed: `1.0.${i}` })).concat([{ fixed: 'x'.repeat(5000) }]) }] }],
    references: Array.from({ length: 500 }, (_, i) => ({ url: `https://ok.example/${i}` })).concat([{ url: 'https://ok.example/' + 'a'.repeat(5000) }]),
  });
  const d = (await osvDetails([A], fetcher)).get(A);
  assert.equal(d.fixed.length, 5); assert.equal(d.refs.length, 5); assert.ok(d.summary.length <= 300);
  assert.ok(d.refs.every((u) => u.length <= 300));
});

// ---------------------------------------------------------------- C-L4: issue state is only believed from bots, and only if it is sane

const stateBody = (fp, aware) => `<!-- cra-clock:${Buffer.from(JSON.stringify({ fp, aware })).toString('base64')} -->\nbody`;
const sync = (gh, fnd = [finding()], opts = {}) => syncIssues('t', 'o/r', fnd, { product: 'p', ...opts }, async (url, init = {}) => gh.handler(init.method || 'GET', url.slice('https://api.github.com'.length), init.body && JSON.parse(init.body)));
const FP = 'pkg:npm/x@1|CVE-2021-44228';

test('C-L4 PoC: an issue planted by a non-bot with a fake clock, or closed to silence an alert, is ignored', async () => {
  const mallory = { login: 'mallory', type: 'User' };
  for (const planted of [
    { number: 3, state: 'open', user: mallory, created_at: '2026-01-01T00:00:00Z', body: stateBody(FP, '2026-01-01T00:00:00.000Z') },
    { number: 3, state: 'closed', user: mallory, created_at: '2026-10-01T00:00:00Z', body: stateBody(FP, '2026-10-01T00:00:00.000Z') },
    { number: 3, state: 'open', user: null, created_at: '2026-10-01T00:00:00Z', body: stateBody(FP, '2026-10-01T00:00:00.000Z') },
  ]) {
    const gh = github(); gh.issues.push(planted);
    const before = Date.now();
    const out = await sync(gh);
    assert.deepEqual(out.map((o) => !!o.created), [true]);
    assert.ok(Date.parse(out[0].awareAt) >= before - 1000, 'a fresh clock, not the planted one');
    assert.equal(gh.issues.length, 2);
  }
});

test('C-L4: a bot-authored issue with an invalid or future time falls back to GitHub\'s created_at, never throws', async () => {
  for (const aware of ['not a date', '10/02/2026', '2099-01-01T00:00:00.000Z', '2026-10-02', 12345, null, '', '1999-01-01T00:00:00.000Z']) {
    const gh = github(); gh.issues.push({ number: 5, state: 'open', user: BOT, created_at: '2026-10-02T00:00:00Z', body: stateBody(FP, aware) });
    const out = await sync(gh);
    assert.deepEqual(out.map((o) => [o.number, !!o.updated, o.awareAt]), [[5, true, '2026-10-02T00:00:00.000Z']], String(aware));
  }
  const gh = github(); gh.issues.push({ number: 5, state: 'open', user: BOT, created_at: 'also bad', body: stateBody(FP, 'bad') });
  const out = await sync(gh);
  assert.deepEqual(out.map((o) => !!o.created), [true], 'unusable state: a new issue with a fresh clock');
});

test('C-L4: validAware accepts real ISO times only, up to a few minutes ahead', () => {
  const now = Date.parse('2026-10-09T12:00:00Z');
  assert.equal(validAware('2026-10-07T00:00:00.000Z', now), '2026-10-07T00:00:00.000Z');
  assert.equal(validAware('2026-10-07T00:00:00Z', now), '2026-10-07T00:00:00.000Z');
  assert.equal(validAware('2026-10-09T12:04:00Z', now), '2026-10-09T12:04:00.000Z', 'clock skew between runners is tolerated');
  for (const v of ['2026-10-09T12:06:00Z', '2026-10-10T00:00:00Z', '2026-10-07', '2026-10-07T00:00:00+02:00', 'yesterday', '', null, undefined, 1.7e12, {}, '2023-12-31T23:59:59Z']) assert.equal(validAware(v, now), null, String(v));
});

test('C-L4: an issue opened with a personal access token is still believed when /user names that account', async () => {
  const me = { login: 'gautam', type: 'User' };
  const gh = github(); gh.issues.push({ number: 6, state: 'open', user: me, created_at: '2026-10-03T00:00:00Z', body: stateBody(FP, '2026-10-03T00:00:00.000Z') });
  const base = gh.handler;
  gh.handler = (m, p, b) => (m === 'GET' && p === '/user' ? Response.json({ login: 'gautam' }) : base(m, p, b));
  const out = await sync(gh);
  assert.deepEqual(out.map((o) => [o.number, !!o.updated, o.awareAt]), [[6, true, '2026-10-03T00:00:00.000Z']]);
  assert.equal(gh.issues.length, 1);
});

test('C-L4: the common case (bot issues only) makes no /user call', async () => {
  const gh = github(); gh.issues.push({ number: 6, state: 'open', user: BOT, created_at: '2026-10-03T00:00:00Z', body: stateBody(FP, '2026-10-03T00:00:00.000Z') });
  let userCalls = 0; const base = gh.handler;
  gh.handler = (m, p, b) => { if (p === '/user') userCalls++; return base(m, p, b); };
  await sync(gh);
  assert.equal(userCalls, 0);
});

test('closed-by-the-team still stops updates, for bot-authored issues', async () => {
  const gh = github(); gh.issues.push({ number: 8, state: 'closed', user: BOT, created_at: '2026-10-03T00:00:00Z', body: stateBody(FP, '2026-10-03T00:00:00.000Z') });
  const out = await sync(gh);
  assert.deepEqual(out, [{ number: 8, closed: true }]);
  assert.equal(gh.issues.length, 1);
});

// ---------------------------------------------------------------- tier and report text with the KEV state

test('VEX and summary: with the KEV catalog known nothing changes for clean repos', () => {
  const c = [{ purl: 'p', name: 'n', version: '1', files: ['f'] }];
  const e = new Map(); e.failed = new Set();
  const f = assess(c, new Map([['p', ['V']]]), new Map([['V', { id: 'V', cves: ['CVE-1'], fixed: [], refs: [] }]]), new Map(), e);
  assert.equal(f[0].tier, 'known');
  assert.match(summary(f, c, { files: ['f'], kevMeta: { catalogVersion: '2026.10.06' } }), /### No actively exploited vulnerabilities/);
  assert.equal(vex(f, { tool: 't' }).vulnerabilities[0].analysis.detail, 'Awaiting triage.');
});

test('links: the 1.0 symlink and sniff behaviour is unchanged by the lockfile-name check', () => {
  const root = mkdtempSync(join(tmpdir(), 'cra-s-'));
  const out = mkdtempSync(join(tmpdir(), 'cra-o-'));
  writeFileSync(join(out, 'go.mod'), 'module x\n');
  symlinkSync(join(out, 'go.mod'), join(root, 'go.mod'));
  mkdirSync(join(root, 'svc')); writeFileSync(join(root, 'svc', 'go.mod'), 'module y\n');
  assert.deepEqual(findLockfiles(root).map((p) => p.slice(root.length + 1)), ['svc/go.mod']);
});
