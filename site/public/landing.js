// CRA Clock landing: the demo hero clock and the in-browser lockfile scanner (same parsers and tiers as the Action).
// No innerHTML anywhere: every node is built with createElement and textContent (the CSP enforces Trusted Types).
import { PARSERS, parseFile, dedupe, sniff } from '/lockfiles.mjs';
const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...kids) => { const n = document.createElement(tag); Object.assign(n, props); for (const k of kids) if (k != null) n.append(k); return n; };
const link = (href, text, cls) => el('a', { href, textContent: text, target: '_blank', rel: 'noopener noreferrer', ...(cls ? { className: cls } : {}) });
const pad = (n) => String(n).padStart(2, '0');
const fmt = (ms) => { const s = Math.max(0, Math.floor(ms / 1000)); return `${pad(Math.floor(s / 3600))}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`; };

const MAX_COMPONENTS = 1000, MAX_ADVISORIES = 150, EPSS_LIKELY = 0.1;
const ACTION_URL = 'https://github.com/GautamTalksDev/cra-clock';
const MARKET_URL = 'https://github.com/marketplace/actions/cra-clock';

// hero: a demo 24h countdown from page load, with dim separators
const t0 = Date.now(), DAY = 24 * 3600_000;
function tick() {
  const [h, m, s] = fmt(DAY - (Date.now() - t0)).split(':');
  $('clock').replaceChildren(h, el('span', { className: 'colon', textContent: ':' }), m, el('span', { className: 'colon', textContent: ':' }), s);
}
tick(); setInterval(tick, 1000);

// scanner
const drop = $('drop'), file = $('file');
['dragenter', 'dragover'].forEach((e) => drop.addEventListener(e, (ev) => { ev.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach((e) => drop.addEventListener(e, () => drop.classList.remove('over')));
drop.addEventListener('drop', (ev) => { ev.preventDefault(); const f = ev.dataTransfer.files[0]; if (f) scanFile(f); });
file.addEventListener('change', () => file.files[0] && scanFile(file.files[0]));
$('demo').onclick = (ev) => {
  ev.preventDefault(); ev.stopPropagation();
  scan('gradle.lockfile', [
    '# A Java service that still ships Log4Shell, disclosed in December 2021, nearly five years on.',
    'org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath',
    'org.apache.logging.log4j:log4j-api:2.14.1=compileClasspath,runtimeClasspath',
    'org.springframework:spring-beans:5.3.17=runtimeClasspath',
    'com.fasterxml.jackson.core:jackson-databind:2.9.10=runtimeClasspath',
    'org.apache.commons:commons-text:1.9=runtimeClasspath',
    'empty=',
  ].join('\n'), 'demo project');
};

async function scanFile(f) {
  if (f.size > 20 * 1024 * 1024) return message('That file is too big for the browser scanner. The Action has no such limit.');
  const name = f.name.split(/[\\/]/).pop();
  const text = await f.text();
  const kind = PARSERS[name] ? name : sniff(text);
  if (!kind) return message(`${name} does not look like one of the 12 lockfile formats CRA Clock reads.`);
  scan(kind, text, kind === name ? name : `${name} (read as ${kind})`);
}

async function getJson(url, init) { const r = await fetch(url, { ...init, redirect: 'error' }); if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }

async function scan(kind, text, label) {
  const comps = dedupe(parseFile(kind, text));
  if (!comps.length) return message(`No pinned components found in ${label}.`);
  message(`Scanning ${comps.length} components from ${label}...`);
  try {
    const checked = comps.slice(0, MAX_COMPONENTS);
    const res = await getJson('https://api.osv.dev/v1/querybatch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ queries: checked.map((c) => ({ package: { purl: c.purl } })) }) });
    const hits = [];
    (res.results || []).forEach((r, i) => (r.vulns || []).forEach((v) => hits.push({ c: checked[i], id: v.id })));
    const shown = hits.slice(0, MAX_ADVISORIES);
    const details = await Promise.all(shown.map((h) => getJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(h.id)}`).catch(() => ({ id: h.id, failed: true }))));
    const kev = await getJson('/kev.json').catch(() => ({ cves: null }));
    const kset = new Set(kev.cves || []);
    const rows = details.map((d, i) => {
      const cves = [d.id, ...(d.aliases || [])].filter((x) => /^CVE-\d{4}-\d+$/.test(x));
      const fixed = []; for (const a of d.affected || []) for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) fixed.push(e.fixed);
      return { c: shown[i].c, id: d.id, cve: cves[0] || d.id, cves, summary: d.summary || '', fixed: [...new Set(fixed)], failed: !!d.failed };
    });
    const allCves = [...new Set(rows.flatMap((r) => r.cves))];
    const ep = new Map(), epFailed = new Set();
    for (let i = 0; i < allCves.length; i += 100) {
      const chunk = allCves.slice(i, i + 100);
      try { const j = await getJson(`https://api.first.org/data/v1/epss?cve=${chunk.join(',')}`); for (const d of j.data || []) ep.set(d.cve, Number(d.epss)); }
      catch { chunk.forEach((c) => epFailed.add(c)); }
    }
    const seen = new Set(), out = [];
    for (const r of rows) {
      const key = r.c.purl + '|' + r.cve; if (seen.has(key)) continue; seen.add(key);
      const e = Math.max(0, ...r.cves.map((x) => ep.get(x) || 0));
      const kevCve = r.cves.find((x) => kset.has(x)), inKev = !!kevCve;
      const incomplete = r.failed || r.cves.some((x) => epFailed.has(x)) || !kev.cves;
      out.push({ ...r, epss: e, inKev, kevCve, tier: inKev ? 'exploited' : e >= EPSS_LIKELY ? 'likely' : incomplete ? 'review' : 'known' });
    }
    const order = { exploited: 0, likely: 1, review: 2, known: 3 };
    out.sort((a, b) => order[a.tier] - order[b.tier] || b.epss - a.epss);
    const notes = [];
    if (comps.length > MAX_COMPONENTS) notes.push(`Only the first ${MAX_COMPONENTS} of ${comps.length} components were checked in the browser.`);
    if (hits.length > MAX_ADVISORIES) notes.push(`Only the first ${MAX_ADVISORIES} of ${hits.length} advisories were looked up in the browser.`);
    if (!kev.cves) notes.push('The KEV mirror could not be reached, so nothing can be confirmed as exploited here.');
    if (notes.length) notes.push('The Action checks everything.');
    show({ label, comps: comps.length, rows: out, notes });
  } catch {
    message('Could not reach OSV.dev from this browser. The Action has no such limit.');
  }
}

function message(title) { render({ title, sub: '', rows: [] }); }

function show({ label, comps, rows, notes }) {
  const n = (t) => rows.filter((r) => r.tier === t).length;
  const ex = n('exploited'), li = n('likely'), rv = n('review'), kn = n('known');
  const title = ex ? `${ex} actively exploited. Your clock would be running.` : rows.length ? 'Nothing actively exploited right now.' : 'No known vulnerabilities.';
  render({ title, sub: `${label}: ${comps} components, ${rows.length} advisories`, rows, stats: { ex, li, rv, kn }, notes, exploited: ex });
}

function render({ title, sub, rows, stats, notes = [], exploited = null }) {
  $('result').hidden = false;
  $('rTitle').textContent = title;
  $('rSub').textContent = sub;
  const rc = $('rClock');
  clearInterval(render.t);
  if (exploited) { const s = Date.now(); rc.className = 'r-clock'; const f = () => (rc.textContent = fmt(DAY - (Date.now() - s))); f(); render.t = setInterval(f, 1000); }
  else { rc.className = 'r-clock calm'; rc.textContent = exploited === 0 ? 'clock not running' : ''; }

  const st = $('rStats');
  st.hidden = !stats;
  if (stats) st.replaceChildren(
    stat(stats.ex, 'Actively exploited', 'exploited'), stat(stats.li, 'Likely soon (EPSS)', 'likely'),
    stat(stats.rv, 'Needs manual review', 'review'), stat(stats.kn, 'Other known advisories', 'known'));

  const note = $('rNote');
  note.hidden = !notes.length;
  note.textContent = notes.join(' ');

  const nx = $('rNext');
  nx.hidden = !stats;
  if (stats) nx.replaceChildren(...nextSteps(stats));

  $('rList').replaceChildren(...rows.slice(0, 200).map((r) => el('div', { className: 'r-row' },
    el('span', { className: 'tag ' + r.tier, textContent: { exploited: 'EXPLOITED', likely: 'LIKELY', review: 'REVIEW', known: 'known' }[r.tier] }),
    el('span', { className: 'm', textContent: `${r.c.name} ${r.c.version}` }),
    el('span', { className: 'd' }, el('span', { textContent: r.cve }), r.fixed.length ? el('span', { className: 'fix', textContent: 'fix: ' + r.fixed.slice(0, 2).join(', ') }) : null),
    el('span', { className: 'links' },
      link(`https://osv.dev/vulnerability/${encodeURIComponent(r.id)}`, 'OSV'),
      r.inKev ? link(`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(r.kevCve)}`, 'KEV', 'kev') : null),
    el('span', { className: 'm epss', textContent: r.epss ? (r.epss * 100).toFixed(1) + '%' : '' }))));
  $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function stat(v, label, cls) { return el('div', { className: 'stat ' + cls }, el('b', { textContent: String(v) }), el('span', { textContent: label })); }

function nextSteps({ ex, li, rv }) {
  const steps = [];
  if (ex) {
    steps.push(el('h3', { textContent: 'What to do next' }));
    steps.push(el('ol', {},
      el('li', { textContent: 'Confirm the exploited component is in a product you make available on the EU market.' }),
      el('li', { textContent: 'Upgrade to a fixed version where one exists, and plan the 24 hour early warning from the moment you became aware.' }),
      el('li', { textContent: 'Add the Action so every push and every six hours is checked, with an issue, deadlines and pre-filled drafts when this happens for real.' })));
    steps.push(el('div', { className: 'r-cta' },
      el('p', {}, el('b', { textContent: 'This is what CRA Clock watches for, around the clock.' }), el('span', { textContent: ' Free and open source. Ninety seconds to install.' })),
      el('div', { className: 'ctas' }, el('a', { className: 'btn-x pri', href: '#install', textContent: 'Add the Action' }), link(MARKET_URL, 'on GitHub Marketplace', 'btn-x'))));
  } else {
    steps.push(el('h3', { textContent: 'What this means' }));
    steps.push(el('p', { textContent: (li ? `${li} advisor${li === 1 ? 'y has' : 'ies have'} a high chance of exploitation soon. Upgrading those first is a good use of today. ` : '') + (rv ? `${rv} could not be fully checked here; review them by hand. ` : '') + 'The KEV catalog changes daily, so a clean result today can change tomorrow. The Action re-checks every six hours and starts the clock the moment it does.' }));
    steps.push(el('div', { className: 'ctas' }, el('a', { className: 'btn-x pri', href: '#install', textContent: 'Add the Action' }), link(ACTION_URL, 'View on GitHub', 'btn-x')));
  }
  return steps;
}
