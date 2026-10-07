// Lockfile parsers -> components [{ ecosystem, name, version, purl, file, direct? }]. Zero dependencies.
// Each parser is defensive: malformed input yields fewer components, never an exception that stops the scan.

const enc = (s) => encodeURIComponent(s).replace(/%40/g, '@').replace(/%2F/g, '/');
const purl = {
  npm: (n, v) => `pkg:npm/${n.startsWith('@') ? '%40' + enc(n.slice(1)) : enc(n)}@${enc(v)}`,
  PyPI: (n, v) => `pkg:pypi/${enc(n.toLowerCase().replace(/[-_.]+/g, '-'))}@${enc(v)}`,
  Go: (n, v) => `pkg:golang/${n.split('/').map(enc).join('/')}@${enc(v)}`,
  'crates.io': (n, v) => `pkg:cargo/${enc(n)}@${enc(v)}`,
  RubyGems: (n, v) => `pkg:gem/${enc(n)}@${enc(v)}`,
  Packagist: (n, v) => `pkg:composer/${n.split('/').map(enc).join('/')}@${enc(v)}`,
  Maven: (n, v) => { const [g, a] = n.split(':'); return `pkg:maven/${enc(g)}/${enc(a)}@${enc(v)}`; },
};
const comp = (ecosystem, name, version, file, direct) => (name && version ? { ecosystem, name, version, purl: purl[ecosystem](name, version), file, ...(direct !== undefined ? { direct } : {}) } : null);

export function npmLock(text, file = 'package-lock.json') {
  const j = JSON.parse(text);
  const out = [];
  if (j.packages) {
    const root = j.packages[''] || {};
    const directs = new Set([...Object.keys(root.dependencies || {}), ...Object.keys(root.devDependencies || {})]);
    for (const [path, p] of Object.entries(j.packages)) {
      if (!path || p.link) continue;
      const name = p.name || path.split('node_modules/').pop();
      out.push(comp('npm', name, p.version, file, path === 'node_modules/' + name && directs.has(name)));
    }
  } else if (j.dependencies) {
    const walk = (deps, top) => { for (const [n, d] of Object.entries(deps || {})) { out.push(comp('npm', n, d.version, file, top)); walk(d.dependencies, false); } };
    walk(j.dependencies, true);
  }
  return out.filter(Boolean);
}

export function yarnLock(text, file = 'yarn.lock') {
  const out = [];
  let names = null;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line) && line.endsWith(':') && !line.startsWith('#') && !line.startsWith('__metadata')) {
      names = line.slice(0, -1).split(',').map((s) => s.trim().replace(/^"|"$/g, '')).map((s) => s.slice(0, s.lastIndexOf('@')) || s);
    } else if (names && /^\s+version:?\s+/.test(line)) {
      const v = line.trim().replace(/^version:?\s+/, '').replace(/^"|"$/g, '');
      out.push(comp('npm', names[0], v, file));
      names = null;
    }
  }
  return out.filter(Boolean);
}

export function pnpmLock(text, file = 'pnpm-lock.yaml') {
  const out = [];
  let inPk = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^(packages|snapshots):\s*$/.test(line)) { inPk = line.startsWith('packages'); continue; }
    if (/^\S/.test(line)) { inPk = false; continue; }
    if (!inPk) continue;
    const m = line.match(/^ {2}'?\/?((?:@[^/@\s]+\/)?[^@\s/][^@\s]*)@([^():'\s]+)/);
    if (m) out.push(comp('npm', m[1], m[2], file));
  }
  return out.filter(Boolean);
}

export function requirements(text, file = 'requirements.txt') {
  const out = [];
  for (let line of text.split(/\r?\n/)) {
    line = line.replace(/#.*/, '').trim();
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+)/);
    if (m) out.push(comp('PyPI', m[1], m[2], file, true));
  }
  return out.filter(Boolean);
}

export function poetryLock(text, file = 'poetry.lock') {
  const out = [];
  let name = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.trim() === '[[package]]') { name = null; continue; }
    const n = line.match(/^name\s*=\s*"([^"]+)"/); if (n) { name = n[1]; continue; }
    const v = line.match(/^version\s*=\s*"([^"]+)"/); if (v && name) { out.push(comp('PyPI', name, v[1], file)); name = null; }
  }
  return out.filter(Boolean);
}

export function pipfileLock(text, file = 'Pipfile.lock') {
  const j = JSON.parse(text), out = [];
  for (const sec of ['default', 'develop']) for (const [n, d] of Object.entries(j[sec] || {})) {
    const v = (d.version || '').replace(/^==/, '');
    out.push(comp('PyPI', n, v, file, sec === 'default'));
  }
  return out.filter(Boolean);
}

export function goMod(text, file = 'go.mod') {
  const out = [];
  let block = false;
  for (let line of text.split(/\r?\n/)) {
    line = line.replace(/\/\/.*/, '').trim();
    if (/^require\s*\($/.test(line)) { block = true; continue; }
    if (block && line === ')') { block = false; continue; }
    const m = (block ? line : line.replace(/^require\s+/, '')).match(/^(\S+)\s+(v\S+)$/);
    if ((block || /^require\s/.test(line)) && m) out.push(comp('Go', m[1], m[2], file));
  }
  return out.filter(Boolean);
}

export function cargoLock(text, file = 'Cargo.lock') {
  const out = [];
  let name = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.trim() === '[[package]]') { name = null; continue; }
    const n = line.match(/^name\s*=\s*"([^"]+)"/); if (n) { name = n[1]; continue; }
    const v = line.match(/^version\s*=\s*"([^"]+)"/); if (v && name) { out.push(comp('crates.io', name, v[1], file)); name = null; }
  }
  return out.filter(Boolean);
}

export function gemfileLock(text, file = 'Gemfile.lock') {
  const out = [];
  let specs = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^ {2}specs:/.test(line)) { specs = true; continue; }
    if (/^\S/.test(line)) specs = false;
    const m = specs && line.match(/^ {4}([A-Za-z0-9_.-]+) \(([^)\s]+)\)$/);
    if (m) out.push(comp('RubyGems', m[1], m[2], file));
  }
  return out.filter(Boolean);
}

/** Gradle dependency locking: "group:artifact:version=configurations" per line */
export function gradleLock(text, file = 'gradle.lockfile') {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9_.+-]+)=/);
    if (m) out.push(comp('Maven', `${m[1]}:${m[2]}`, m[3], file));
  }
  return out.filter(Boolean);
}

export function composerLock(text, file = 'composer.lock') {
  const j = JSON.parse(text), out = [];
  for (const sec of ['packages', 'packages-dev']) for (const p of j[sec] || []) out.push(comp('Packagist', p.name, String(p.version || '').replace(/^v/, ''), file, false));
  return out.filter(Boolean);
}

export const PARSERS = {
  'package-lock.json': npmLock, 'npm-shrinkwrap.json': npmLock, 'yarn.lock': yarnLock, 'pnpm-lock.yaml': pnpmLock,
  'requirements.txt': requirements, 'poetry.lock': poetryLock, 'Pipfile.lock': pipfileLock, 'go.mod': goMod,
  'Cargo.lock': cargoLock, 'Gemfile.lock': gemfileLock, 'composer.lock': composerLock, 'gradle.lockfile': gradleLock,
};

export function parseFile(basename, text, path = basename) {
  const p = PARSERS[basename];
  if (!p) return [];
  try { return p(text, path); } catch { return []; }
}

/** de-duplicate by purl, keeping every file a component appears in */
export function dedupe(components) {
  const m = new Map();
  for (const c of components) {
    const e = m.get(c.purl);
    if (e) { if (!e.files.includes(c.file)) e.files.push(c.file); e.direct = e.direct || c.direct; }
    else m.set(c.purl, { ...c, files: [c.file] });
  }
  return [...m.values()];
}
