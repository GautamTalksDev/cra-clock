# Security

Report vulnerabilities privately to **security@gautamkhosla.com** or through a GitHub private advisory.

## How the Action is built to be safe in your CI

| Risk | Control |
|---|---|
| Supply chain (OWASP A06, A08) | Zero runtime dependencies. No install step, no `node_modules`, nothing fetched at run time except data. Pin the Action by commit SHA in your workflow. |
| Token scope (A01) | Needs only `contents: read` and `issues: write`. Never pushes code, never reads secrets. |
| Data leaving your repo | Only package names and versions (as purls) go to OSV.dev; only CVE ids go to FIRST EPSS; the KEV catalog is downloaded. Source code and lockfile contents are not sent. |
| Untrusted advisory text in issues (A03) | Advisory summaries, names and versions are escaped: HTML entities, markdown control characters, `@` mentions and autolinks are neutralized; draft blocks cannot break out of their code fences; only `https:` references are linked. Tested. |
| Hostile repositories | Lockfile parsing is defensive (malformed files yield nothing, never crash the scan); files over 50 MB, symlinked files and symlinked directories are skipped (the walk uses `lstat` and never follows a link; tested); dependency directories (`node_modules`, `vendor`, ...) are not walked. |
| Network | 60 s timeouts, bounded retries, redirects refused. If OSV details or EPSS cannot be fetched, affected advisories are flagged `intel-incomplete` for manual review and the job fails (unless `allow-incomplete-intel: true`); a failed lookup is never reported as clean. |
| Fork pull requests | The token is read-only there; a 403 on issue creation degrades to the job summary with a note. Use `open-issues: false` for `pull_request`. |
| Inputs | `fail-on`, `epss-threshold` and boolean inputs are validated; invalid values stop the run with an error before any network call. |

## The website

Static, strict CSP with Trusted Types (`connect-src` limited to the site, `api.osv.dev` and `api.first.org`), HSTS
preload, no cookies, no analytics. The lockfile you drop is parsed in the page and never uploaded.
