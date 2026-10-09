import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as L from '../src/lockfiles.mjs';
import { assess, clock, fmtRemaining, HOUR } from '../src/assess.mjs';
import { issueBody, readState, md, vex } from '../src/outputs.mjs';
import { run, findLockfiles } from '../src/main.mjs';
import { kevJson } from './kev-fixture.mjs';

test('lockfile parsers: npm v3 and v1, yarn, pnpm, pip, poetry, Pipfile, go, cargo, gem, composer', () => {
  const npm3 = L.npmLock(JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { express: '^4' } }, 'node_modules/express': { version: '4.17.1' }, 'node_modules/@scope/pkg': { version: '1.0.0' }, 'node_modules/express/node_modules/qs': { version: '6.5.2' } } }));
  assert.deepEqual(npm3.map((c) => c.purl), ['pkg:npm/express@4.17.1', 'pkg:npm/%40scope/pkg@1.0.0', 'pkg:npm/qs@6.5.2']);
  assert.equal(npm3[0].direct, true); assert.equal(npm3[2].direct, false);
  assert.equal(L.npmLock(JSON.stringify({ dependencies: { lodash: { version: '4.17.20', dependencies: { x: { version: '1.0.0' } } } } })).length, 2);
  assert.deepEqual(L.yarnLock('"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.1.2"\n\nlodash@^4.17.0:\n  version "4.17.21"\n').map((c) => c.purl), ['pkg:npm/%40babel/core@7.1.2', 'pkg:npm/lodash@4.17.21']);
  assert.deepEqual(L.pnpmLock("lockfileVersion: '9.0'\npackages:\n  '@types/node@20.1.0':\n    resolution: {}\n  lodash@4.17.21:\n    resolution: {}\nsnapshots:\n  lodash@4.17.21: {}\n").map((c) => c.name), ['@types/node', 'lodash']);
  assert.deepEqual(L.requirements('Django==3.2.0  # web\nrequests[socks]==2.25.1\nflask>=2\n-e .\n').map((c) => c.purl), ['pkg:pypi/django@3.2.0', 'pkg:pypi/requests@2.25.1']);
  assert.equal(L.poetryLock('[[package]]\nname = "urllib3"\nversion = "1.26.4"\n\n[[package]]\nname = "idna"\nversion = "3.1"\n').length, 2);
  assert.equal(L.pipfileLock(JSON.stringify({ default: { pyyaml: { version: '==5.3' } }, develop: {} }))[0].purl, 'pkg:pypi/pyyaml@5.3');
  assert.deepEqual(L.goMod('module x\ngo 1.22\nrequire (\n\tgolang.org/x/net v0.17.0 // indirect\n\tgithub.com/a/b v1.2.3\n)\nrequire github.com/c/d v0.1.0\n').map((c) => c.purl), ['pkg:golang/golang.org/x/net@v0.17.0', 'pkg:golang/github.com/a/b@v1.2.3', 'pkg:golang/github.com/c/d@v0.1.0']);
  assert.equal(L.cargoLock('[[package]]\nname = "openssl"\nversion = "0.10.30"\n')[0].purl, 'pkg:cargo/openssl@0.10.30');
  assert.equal(L.gemfileLock('GEM\n  remote: x\n  specs:\n    rails (6.1.0)\n      actionpack (= 6.1.0)\n    nokogiri (1.10.0)\n\nPLATFORMS\n').length, 2);
  assert.equal(L.composerLock(JSON.stringify({ packages: [{ name: 'guzzlehttp/guzzle', version: 'v7.0.0' }] }))[0].purl, 'pkg:composer/guzzlehttp/guzzle@7.0.0');
  assert.equal(L.gradleLock('# lock\norg.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath\nempty=\n')[0].purl, 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1');
  assert.deepEqual(L.parseFile('package-lock.json', '{not json'), [], 'malformed files never stop the scan');
});

test('the Article 14 clock: 24h early warning, 72h notification, overdue math', () => {
  const t0 = '2026-10-07T00:00:00.000Z';
  const c = clock(t0, Date.parse(t0) + 30 * HOUR);
  assert.equal(c.stages[0].dueIso, '2026-10-08T00:00:00.000Z');
  assert.equal(c.stages[1].dueIso, '2026-10-10T00:00:00.000Z');
  assert.equal(c.stages[0].overdue, true); assert.equal(c.stages[1].overdue, false);
  assert.equal(fmtRemaining(-6 * HOUR), 'OVERDUE by 6h 00m');
  assert.equal(fmtRemaining(42 * HOUR + 5 * 60000), '42h 05m');
});

test('advisory text is untrusted: markdown, HTML, links and @mentions are neutralized in issues', () => {
  const evil = 'Pwn <img src=x onerror=alert(1)> [click](https://evil.example) @everyone `code`';
  const s = md(evil);
  assert.ok(!s.includes('<img')); assert.ok(!/\]\(/.test(s)); assert.ok(!s.includes('@everyone')); assert.ok(!s.includes('https://evil'));
  const f = { fingerprint: 'pkg:npm/x@1|GHSA-1', tier: 'exploited', component: { name: 'x', version: '1', files: ['package-lock.json'] }, vuln: { id: 'GHSA-1', cves: ['CVE-2021-44228'], fixed: ['2.17.1'], refs: ['javascript:alert(1)', 'https://ok.example/a'], summary: evil }, kev: [{ cve: 'CVE-2021-44228', dateAdded: '2021-12-10', ransomware: true, action: 'Apply updates' }], epss: { epss: 0.97, percentile: 0.99 } };
  const body = issueBody(f, { awareAt: '2026-10-07T00:00:00Z', product: 'Acme <b>Router</b>' });
  assert.ok(!body.includes('javascript:'), 'only https references');
  assert.ok(!body.split('```')[0].includes('<b>'), 'no raw HTML outside the plain-text draft blocks');
  assert.ok(!body.split('```')[1].includes('```'), 'drafts cannot break out of their code fence');
  assert.deepEqual(readState(body), { fp: 'pkg:npm/x@1|GHSA-1', aware: '2026-10-07T00:00:00.000Z' }, 'the awareness time survives in the issue');
  assert.match(body, /known ransomware use/);
});

function fakeIntel({ kevCves = ['CVE-2021-44228'] } = {}) {
  const calls = [];
  const fetcher = async (url, init = {}) => {
    calls.push(url);
    if (url.endsWith('/querybatch')) {
      const q = JSON.parse(init.body).queries;
      return Response.json({ results: q.map((x) => ({ vulns: x.package.purl.includes('log4j') ? [{ id: 'GHSA-jfh8-c2jp-5v3q' }] : x.package.purl.includes('lodash@4.17.20') ? [{ id: 'GHSA-35jh-r3h4-6jhm' }] : [] })) });
    }
    if (url.includes('/vulns/GHSA-jfh8')) return Response.json({ id: 'GHSA-jfh8-c2jp-5v3q', aliases: ['CVE-2021-44228'], summary: 'Log4Shell', affected: [{ ranges: [{ events: [{ introduced: '2.0' }, { fixed: '2.15.0' }] }] }], references: [{ url: 'https://logging.apache.org/log4j/2.x/security.html' }] });
    if (url.includes('/vulns/GHSA-35jh')) return Response.json({ id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], summary: 'Command injection in lodash' });
    if (url.includes('known_exploited')) return Response.json(kevJson(kevCves.map((c) => ({ cveID: c, dateAdded: '2021-12-10', knownRansomwareCampaignUse: 'Known', vulnerabilityName: 'Log4j RCE', requiredAction: 'Apply updates' }))));
    if (url.includes('api.first.org')) return Response.json({ data: [{ cve: 'CVE-2021-44228', epss: '0.97', percentile: '0.999' }, { cve: 'CVE-2021-23337', epss: '0.02', percentile: '0.8' }] });
    throw new Error('unexpected ' + url);
  };
  return { fetcher, calls };
}

test('end to end: a repo with an actively exploited dependency gets an exploited finding, a failing job, an SBOM and a VEX', async () => {
  const root = mkdtempSync(join(tmpdir(), 'cra-'));
  mkdirSync(join(root, 'svc'), { recursive: true }); mkdirSync(join(root, 'node_modules', 'x'), { recursive: true });
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/lodash': { version: '4.17.20' } } }));
  writeFileSync(join(root, 'svc', 'requirements.txt'), 'log4j-python-shim==1.0\n'); // purl contains log4j for the fake
  writeFileSync(join(root, 'node_modules', 'x', 'package-lock.json'), '{}'); // must be skipped
  assert.equal(findLockfiles(root).length, 2);
  process.env['INPUT_OUTPUT-DIR'] = 'out'; delete process.env['INPUT_GITHUB-TOKEN']; delete process.env.GITHUB_STEP_SUMMARY; delete process.env.GITHUB_OUTPUT;
  const { fetcher } = fakeIntel();
  const r = await run({ root, fetcher, log: () => {} });
  assert.equal(r.components.length, 2);
  assert.deepEqual(r.findings.map((f) => f.tier), ['exploited', 'known']);
  assert.equal(r.fail, true, 'fails the job when something is actively exploited');
  const v = JSON.parse(readFileSync(join(root, 'out', 'vex.cdx.json'), 'utf8'));
  assert.equal(v.vulnerabilities[0].id, 'CVE-2021-44228');
  assert.equal(v.vulnerabilities[0].properties[0].value, 'true (CISA KEV)');
  const s = JSON.parse(readFileSync(join(root, 'out', 'sbom.cdx.json'), 'utf8'));
  assert.equal(s.specVersion, '1.6'); assert.equal(s.components.length, 2);
});

test('assess: EPSS above threshold is "likely" even without KEV', () => {
  const comps = [{ purl: 'p', name: 'n', version: '1', files: ['f'] }];
  const f = assess(comps, new Map([['p', ['V']]]), new Map([['V', { id: 'V', cves: ['CVE-1'], fixed: [], refs: [] }]]), new Map(), new Map([['CVE-1', { epss: 0.4, percentile: 0.9 }]]));
  assert.equal(f[0].tier, 'likely');
  assert.equal(vex(f, { tool: 't' }).vulnerabilities[0].analysis.state, 'in_triage');
});
