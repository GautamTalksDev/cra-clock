// CRA Clock landing: the station clock, split-flap boards (deadlines + live KEV arrivals) and the in-browser lockfile scanner (same parsers and tiers as the Action).
// No innerHTML anywhere: every node is built with createElement and textContent (the CSP enforces Trusted Types).
import { isLockfileName, parseFile, dedupe, sniff } from '/lockfiles.mjs';
import { kevSet, headline } from '/verdict.mjs';
const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...kids) => { const n = document.createElement(tag); Object.assign(n, props); for (const k of kids) if (k != null) n.append(k); return n; };
const link = (href, text, cls) => el('a', { href, textContent: text, target: '_blank', rel: 'noopener noreferrer', ...(cls ? { className: cls } : {}) });
const pad = (n) => String(n).padStart(2, '0');
const fmt = (ms) => { const s = Math.max(0, Math.floor(ms / 1000)); return `${pad(Math.floor(s / 3600))}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`; };

const MAX_COMPONENTS = 1000, MAX_ADVISORIES = 150, EPSS_LIKELY = 0.1;
const ACTION_URL = 'https://github.com/GautamTalksDev/cra-clock';

const RM = matchMedia('(prefers-reduced-motion: reduce)').matches;

// header glass once scrolled
const topbar = document.querySelector('.top');
const onScroll = () => topbar.classList.toggle('scrolled', scrollY > 24);
addEventListener('scroll', onScroll, { passive: true }); onScroll();

// split-flap helper: one span per character; a changed character flips
const FLAP = ' ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-:.';
function flapInto(node, text, { sep = ':' } = {}) {
  const cur = [...node.querySelectorAll('.f')];
  if (cur.length !== text.length) {
    node.replaceChildren(...[...text].map((ch) => el('span', { className: 'f' + (ch === sep ? ' sep' : ''), textContent: ch })));
    return;
  }
  [...text].forEach((ch, i) => {
    const f = cur[i]; if (f.textContent === ch) return;
    f.textContent = ch;
    if (!RM) { f.classList.remove('flip'); void f.offsetWidth; f.classList.add('flip'); }
  });
}
// flip a word in from random letters (departures board), resolving left to right
function flipWord(node, target, delay = 0) {
  if (RM) { node.textContent = target; return; }
  node.replaceChildren(...[...target].map((ch) => el('span', { className: 'dch', textContent: ch === ' ' ? ' ' : FLAP[(Math.random() * 27) | 0 + 1] })));
  const kids = [...node.children];
  kids.forEach((k, i) => {
    let n = 5 + i * 1.6 | 0;
    const step = () => {
      if (n-- <= 0) { k.textContent = target[i] === ' ' ? ' ' : target[i]; return; }
      k.textContent = target[i] === ' ' ? ' ' : FLAP[1 + ((Math.random() * (FLAP.length - 1)) | 0)];
      setTimeout(step, 42);
    };
    setTimeout(step, delay + i * 18);
  });
}

// hero: a demo 24h countdown from page load, on flaps
const t0 = Date.now(), DAY = 24 * 3600_000;
const clockFlaps = $('clock');
function tick() { flapInto(clockFlaps, fmt(DAY - (Date.now() - t0))); }
tick(); setInterval(tick, 1000);

// the station clock: real local time, sweeping second hand
const hH = $('hHour'), hM = $('hMin'), hS = $('hSec');
function hands() {
  const d = new Date(), ms = d.getMilliseconds(), s = d.getSeconds() + ms / 1000, m = d.getMinutes() + s / 60, h = (d.getHours() % 12) + m / 60;
  hS.style.transform = `rotate(${s * 6}deg)`; hM.style.transform = `rotate(${m * 6}deg)`; hH.style.transform = `rotate(${h * 30}deg)`;
  requestAnimationFrame(hands);
}
if (RM) { const still = () => { const d = new Date(); hS.style.transform = `rotate(${d.getSeconds() * 6}deg)`; hM.style.transform = `rotate(${(d.getMinutes() + d.getSeconds() / 60) * 6}deg)`; hH.style.transform = `rotate(${((d.getHours() % 12) + d.getMinutes() / 60) * 30}deg)`; }; still(); setInterval(still, 1000); }
else requestAnimationFrame(hands);
{ const f = $('face'); f.addEventListener('error', () => f.remove()); if (f.complete && !f.naturalWidth) f.remove(); }

// departures board: flips into place when it scrolls into view
const dep = $('depBoard');
const depIO = new IntersectionObserver((es) => es.forEach((e) => {
  if (!e.isIntersecting) return; depIO.disconnect();
  [...dep.querySelectorAll('[data-flap]')].forEach((n, i) => flipWord(n, n.dataset.flap, i * 120));
}), { threshold: 0.35 });
depIO.observe(dep);

// live board: the newest CISA KEV entries from this site's own mirror (public catalog fields only)
async function kevBoard() {
  const board = $('kevBoard'), msg = $('kevMsg');
  let j;
  try { const r = await fetch('/kev.json', { redirect: 'error' }); if (!r.ok) throw 0; j = await r.json(); } catch { msg.textContent = 'The catalog could not be reached just now. The Action reads it directly from CISA.'; return; }
  const rows = Array.isArray(j.latest) ? j.latest.filter((x) => /^CVE-\d{4}-\d+$/.test(x.cve)) : [];
  if (!rows.length) { msg.textContent = 'No recent entries to show right now.'; return; }
  msg.remove();
  const built = rows.map((x) => {
    const t = el('span', { className: 't', textContent: x.added });
    const d = el('span', { className: 'd' }, link(`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(x.cve)}`, x.cve, 'cvl'));
    const v = el('span', { className: 'x' }, el('b', { textContent: x.vendor || 'Unknown vendor' }), ' ', x.product || '');
    const s = el('span', { className: 's ' + (x.ransomware ? 'ransom' : 'nr'), textContent: x.ransomware ? 'Known use' : 'Not known' });
    return el('div', { className: 'b-row' }, t, d, v, s);
  });
  board.append(...built);
  if (j.catalogVersion) $('kevMeta').textContent = `Source: CISA KEV catalog, version ${j.catalogVersion}. CRA Clock does not add, rank or interpret these entries.`;
  const io = new IntersectionObserver((es) => es.forEach((e) => {
    if (!e.isIntersecting) return; io.disconnect();
    built.forEach((row, i) => { const a = row.querySelector('.cvl'); flipWord(a, a.textContent, i * 90); flipWord(row.querySelector('.t'), row.querySelector('.t').textContent, i * 90); });
  }), { threshold: 0.25 });
  io.observe(board);
}
kevBoard();

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
  if (f.size > 20 * 1024 * 1024) return message('That file is too big for the browser scanner. The Action reads lockfiles up to 50 MB.');
  const name = f.name.split(/[\\/]/).pop();
  const text = await f.text();
  const kind = isLockfileName(name) ? name : sniff(text);
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
    // null when the mirror failed or answered with an empty or truncated catalog: exploitation status is then unknown
    const kset = kevSet(await getJson('/kev.json').catch(() => null));
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
      const kevCve = kset ? r.cves.find((x) => kset.has(x)) : undefined, inKev = !!kevCve;
      const incomplete = r.failed || r.cves.some((x) => epFailed.has(x)) || !kset;
      out.push({ ...r, epss: e, inKev, kevCve, tier: inKev ? 'exploited' : e >= EPSS_LIKELY ? 'likely' : incomplete ? 'review' : 'known' });
    }
    const order = { exploited: 0, likely: 1, review: 2, known: 3 };
    out.sort((a, b) => order[a.tier] - order[b.tier] || b.epss - a.epss);
    const notes = [];
    if (comps.length > MAX_COMPONENTS) notes.push(`Only the first ${MAX_COMPONENTS} of ${comps.length} components were checked in the browser.`);
    if (hits.length > MAX_ADVISORIES) notes.push(`Only the first ${MAX_ADVISORIES} of ${hits.length} advisories were looked up in the browser.`);
    if (!kset) notes.push('The KEV catalog could not be read here, so exploitation status could not be confirmed.');
    if (notes.length) notes.push('The Action checks everything.');
    show({ label, comps: comps.length, rows: out, notes, kevKnown: !!kset });
  } catch {
    message('Could not reach OSV.dev from this browser. The Action has no such limit.');
  }
}

function message(title) { render({ title, sub: '', rows: [] }); }

function show({ label, comps, rows, notes, kevKnown }) {
  const n = (t) => rows.filter((r) => r.tier === t).length;
  const ex = n('exploited'), li = n('likely'), rv = n('review'), kn = n('known');
  const title = headline({ exploited: ex, advisories: rows.length, kevKnown });
  render({ title, sub: `${label}: ${comps} components, ${rows.length} advisories`, rows, stats: { ex, li, rv, kn }, notes, exploited: kevKnown ? ex : null, kevKnown });
}

function render({ title, sub, rows, stats, notes = [], exploited = null, kevKnown = true }) {
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
    stat(kevKnown ? stats.ex : '?', 'Actively exploited', 'exploited'), stat(stats.li, 'Likely soon (EPSS)', 'likely'),
    stat(stats.rv, 'Needs manual review', 'review'), stat(stats.kn, 'Other known advisories', 'known'));

  const note = $('rNote');
  note.hidden = !notes.length;
  note.textContent = notes.join(' ');

  const nx = $('rNext');
  nx.hidden = !stats;
  if (stats) nx.replaceChildren(...nextSteps({ ...stats, kevKnown }));

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

function nextSteps({ ex, li, rv, kevKnown }) {
  const steps = [];
  if (ex) {
    steps.push(el('h3', { textContent: 'What to do next' }));
    steps.push(el('ol', {},
      el('li', { textContent: 'Confirm the exploited component is in a product you make available on the EU market.' }),
      el('li', { textContent: 'Upgrade to a fixed version where one exists, and plan the 24 hour early warning from the moment you became aware.' }),
      el('li', { textContent: 'Add the Action so every push and every six hours is checked, with an issue, deadlines and pre-filled drafts when this happens for real.' })));
    steps.push(el('div', { className: 'r-cta' },
      el('p', {}, el('b', { textContent: 'This is what CRA Clock watches for, around the clock.' }), el('span', { textContent: ' Free and open source. Ninety seconds to install.' })),
      el('div', { className: 'ctas' }, el('a', { className: 'btn-x pri', href: '#install', textContent: 'Add the Action' }), link(ACTION_URL, 'View on GitHub', 'btn-x'))));
  } else {
    steps.push(el('h3', { textContent: 'What this means' }));
    steps.push(el('p', { textContent: (li ? `${li} advisor${li === 1 ? 'y has' : 'ies have'} a high chance of exploitation soon. Upgrading those first is a good use of today. ` : '') + (rv ? `${rv} could not be fully checked here; review them by hand. ` : '') + (kevKnown ? 'The KEV catalog changes daily, so a clean result today can change tomorrow. The Action re-checks every six hours and starts the clock the moment it does.' : 'Nothing here is confirmed clean. Try again in a minute, or add the Action: it reads the CISA catalog directly, and fails the job rather than report clean when it cannot.') }));
    steps.push(el('div', { className: 'ctas' }, el('a', { className: 'btn-x pri', href: '#install', textContent: 'Add the Action' }), link(ACTION_URL, 'View on GitHub', 'btn-x')));
  }
  return steps;
}

// the hall: soft daylight through a glazed station roof, drifting slowly (WebGL, tiny and blurred)
(() => {
  const cv = $('hall'); if (!cv || RM) return;
  const gl = cv.getContext('webgl', { alpha: true, antialias: false, premultipliedAlpha: false }); if (!gl) return;
  const vs = 'attribute vec2 p;void main(){gl_Position=vec4(p,0.,1.);}';
  const fs = `precision mediump float;uniform vec2 r;uniform float t;
  float h(vec2 p){return fract(sin(dot(p,vec2(41.3,289.1)))*43758.5);}
  float n(vec2 p){vec2 i=floor(p),f=fract(p);f=f*f*(3.-2.*f);return mix(mix(h(i),h(i+vec2(1,0)),f.x),mix(h(i+vec2(0,1)),h(i+vec2(1,1)),f.x),f.y);}
  void main(){vec2 uv=gl_FragCoord.xy/r;vec2 p=uv*vec2(r.x/r.y,1.);float T=t*.012;
    vec2 q=p*vec2(1.,1.2)+vec2(T,T*.35);q=mat2(.92,-.38,.38,.92)*q*3.2;
    vec2 g=abs(fract(q)-.5);float pane=smoothstep(.5,.42,max(g.x,g.y));
    float cloud=n(p*1.3+vec2(T*2.,0.))*.6+n(p*3.1-vec2(0.,T*3.))*.4;
    float light=pane*(.55+.45*cloud)*smoothstep(1.2,.1,distance(uv,vec2(.75,.95)));
    vec3 warm=vec3(1.,.97,.9);gl_FragColor=vec4(warm,light*.55);}`;
  const sh = (ty, src) => { const o = gl.createShader(ty); gl.shaderSource(o, src); gl.compileShader(o); return o; };
  const pr = gl.createProgram(); gl.attachShader(pr, sh(gl.VERTEX_SHADER, vs)); gl.attachShader(pr, sh(gl.FRAGMENT_SHADER, fs)); gl.linkProgram(pr);
  if (!gl.getProgramParameter(pr, gl.LINK_STATUS)) return;
  gl.useProgram(pr); gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer()); gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(pr, 'p'); gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
  const uR = gl.getUniformLocation(pr, 'r'), uT = gl.getUniformLocation(pr, 't');
  const S = 0.3;
  const size = () => { cv.width = Math.max(2, innerWidth * S | 0); cv.height = Math.max(2, innerHeight * S | 0); gl.viewport(0, 0, cv.width, cv.height); gl.uniform2f(uR, cv.width, cv.height); };
  addEventListener('resize', size); size();
  const t0 = performance.now();
  (function loop(ts) { if (!document.hidden) { gl.uniform1f(uT, (ts - t0) / 1000); gl.drawArrays(gl.TRIANGLES, 0, 3); } requestAnimationFrame(loop); })(t0);
})();

// reveal on scroll
for (const n of document.querySelectorAll('.sec-head, .board.big, .s-tool, .platforms article, .mock, .window, .install-notes > div, .ticket-card')) n.classList.add('rv');
const rio = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add('in'); rio.unobserve(e.target); } }), { threshold: 0.12, rootMargin: '0px 0px -6% 0px' });
document.querySelectorAll('.rv').forEach((n) => rio.observe(n));
