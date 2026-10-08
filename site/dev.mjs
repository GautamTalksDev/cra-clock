// Local preview of the site with a live /kev.json (node site/dev.mjs [port])
import http from 'node:http';
import { readFileSync, existsSync, statSync } from 'node:fs';
const port = Number(process.argv[2] || 8792), PUB = new URL('./public/', import.meta.url);
const T = { html: 'text/html; charset=utf-8', js: 'text/javascript', mjs: 'text/javascript', css: 'text/css', svg: 'image/svg+xml', png: 'image/png', woff2: 'font/woff2' };
const H = {}; for (const l of readFileSync(new URL('_headers', PUB), 'utf8').split('\n').slice(1)) { const i = l.indexOf(':'); if (i > 0) H[l.slice(0, i).trim()] = l.slice(i + 1).trim().replace(' upgrade-insecure-requests', ''); }
let kev = null;
http.createServer(async (req, res) => {
  const p = new URL(req.url, 'http://x').pathname;
  if (p === '/kev.json') {
    if (!kev) { const j = await (await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')).json(); kev = JSON.stringify({ catalogVersion: j.catalogVersion, cves: j.vulnerabilities.map((v) => v.cveID) }); }
    res.writeHead(200, { 'content-type': 'application/json' }); return res.end(kev);
  }
  if (p.includes('..')) { res.writeHead(403); return res.end(); }
  let f = new URL('.' + (p.endsWith('/') ? p + 'index.html' : p), PUB);
  if (existsSync(f) && statSync(f).isDirectory()) f = new URL('.' + p + '/index.html', PUB);
  if (!existsSync(f)) { res.writeHead(404, { 'content-type': T.html, ...H }); return res.end(readFileSync(new URL('404.html', PUB))); }
  res.writeHead(200, { 'content-type': T[f.pathname.split('.').pop()] || 'application/octet-stream', ...H }); res.end(readFileSync(f));
}).listen(port, () => console.log('CRA Clock site on http://localhost:' + port));
