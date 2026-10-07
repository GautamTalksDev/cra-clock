// CRA Clock landing: the ticking hero clock and the in-browser lockfile scanner (same parsers and tiers as the Action).
import { PARSERS, parseFile, dedupe } from '/lockfiles.mjs';
const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...kids) => { const n = document.createElement(tag); Object.assign(n, props); for (const k of kids) if (k != null) n.append(k); return n; };
const pad = (n) => String(n).padStart(2, '0');
const fmt = (ms) => { const s = Math.max(0, Math.floor(ms / 1000)); return `${pad(Math.floor(s / 3600))}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`; };

// hero clock: a real 24h countdown from page load, with blinking separators
const t0 = Date.now(), DAY = 24 * 3600_000;
function tick() {
  const [h, m, s] = fmt(DAY - (Date.now() - t0)).split(':');
  const c = $('clock'); c.replaceChildren(h, el('span', { className: 'colon', textContent: ':' }), m, el('span', { className: 'colon', textContent: ':' }), s);
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
    '# A Java service that still ships Log4Shell, three years on.',
    'org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath',
    'org.apache.logging.log4j:log4j-api:2.14.1=compileClasspath,runtimeClasspath',
    'org.springframework:spring-beans:5.3.17=runtimeClasspath',
    'com.fasterxml.jackson.core:jackson-databind:2.9.10=runtimeClasspath',
    'org.apache.commons:commons-text:1.9=runtimeClasspath',
    'empty=',
  ].join('\n'));
};

async function scanFile(f) {
  if (f.size > 20 * 1024 * 1024) return show('That file is too big for the browser scanner. Use the Action.', [], null);
  const name = f.name.split(/[\\/]/).pop();
  if (!PARSERS[name]) return show(`${name} is not a lockfile CRA Clock reads.`, [], null);
  scan(name, await f.text());
}

async function getJson(url, init) { const r = await fetch(url, { ...init, redirect: 'error' }); if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }

async function scan(name, text) {
  const comps = dedupe(parseFile(name, text));
  show(`Scanning ${comps.length} components...`, [], null);
  try {
    const res = await getJson('https://api.osv.dev/v1/querybatch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ queries: comps.slice(0, 1000).map((c) => ({ package: { purl: c.purl } })) }) });
    const hits = [];
    (res.results || []).forEach((r, i) => (r.vulns || []).forEach((v) => hits.push({ c: comps[i], id: v.id })));
    const details = await Promise.all(hits.slice(0, 150).map((h) => getJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(h.id)}`).catch(() => ({ id: h.id }))));
    const kev = await getJson('/kev.json').catch(() => ({ cves: [] }));
    const kset = new Set(kev.cves || []);
    const rows = details.map((d, i) => {
      const cves = [d.id, ...(d.aliases || [])].filter((x) => /^CVE-/.test(x));
      const fixed = []; for (const a of d.affected || []) for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) fixed.push(e.fixed);
      return { c: hits[i].c, id: d.id, cve: cves[0] || d.id, cves, summary: d.summary || '', fixed: [...new Set(fixed)] };
    });
    const allCves = [...new Set(rows.flatMap((r) => r.cves))];
    const ep = new Map();
    for (let i = 0; i < allCves.length; i += 100) {
      const j = await getJson(`https://api.first.org/data/v1/epss?cve=${allCves.slice(i, i + 100).join(',')}`).catch(() => ({ data: [] }));
      for (const d of j.data || []) ep.set(d.cve, Number(d.epss));
    }
    const seen = new Set(), out = [];
    for (const r of rows) {
      const key = r.c.purl + '|' + r.cve; if (seen.has(key)) continue; seen.add(key);
      const e = Math.max(0, ...r.cves.map((x) => ep.get(x) || 0));
      out.push({ ...r, epss: e, tier: r.cves.some((x) => kset.has(x)) ? 'exploited' : e >= 0.1 ? 'likely' : 'known' });
    }
    const order = { exploited: 0, likely: 1, known: 2 };
    out.sort((a, b) => order[a.tier] - order[b.tier] || b.epss - a.epss);
    const ex = out.filter((r) => r.tier === 'exploited').length;
    show(ex ? `${ex} actively exploited. Your clock would be running.` : out.length ? 'Nothing actively exploited right now.' : 'No known vulnerabilities.', out, ex, comps.length, kev.cves ? null : 'KEV unavailable here; tiers use EPSS only.');
  } catch (e) {
    show('Could not reach OSV.dev from this browser. The Action has no such limit.', [], null);
  }
}

function show(title, rows, exploited, n, note) {
  $('result').hidden = false;
  $('rTitle').textContent = title;
  $('rSub').textContent = n != null ? `${n} components, ${rows.length} advisories${note ? '. ' + note : ''}` : '';
  const rc = $('rClock');
  clearInterval(show.t);
  if (exploited) { const s = Date.now(); rc.className = 'r-clock'; const f = () => (rc.textContent = fmt(DAY - (Date.now() - s))); f(); show.t = setInterval(f, 1000); }
  else { rc.className = 'r-clock calm'; rc.textContent = exploited === 0 ? 'clock not running' : ''; }
  $('rList').replaceChildren(...rows.slice(0, 200).map((r) => el('div', { className: 'r-row' },
    el('span', { className: 'tag ' + r.tier, textContent: r.tier === 'exploited' ? 'EXPLOITED' : r.tier === 'likely' ? 'LIKELY' : 'known' }),
    el('span', { className: 'm', textContent: `${r.c.name} ${r.c.version}` }),
    el('span', { className: 'd', textContent: `${r.cve}${r.fixed.length ? '  fix: ' + r.fixed.slice(0, 2).join(', ') : ''}` }),
    el('span', { className: 'm', textContent: r.epss ? (r.epss * 100).toFixed(1) + '%' : '' }))));
  $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
