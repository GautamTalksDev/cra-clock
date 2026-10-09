# Security

Report vulnerabilities privately to **security@gautamkhosla.com** or through a GitHub private advisory.

## How the Action is built to be safe in your CI

| Risk | Control |
|---|---|
| Supply chain (OWASP Top 10 2025: A03, A08) | Zero runtime dependencies. No install step, no `node_modules`, nothing fetched at run time except data. Pin the Action by commit SHA in your workflow. |
| Token scope (A01) | Needs only `contents: read` and `issues: write`. Never pushes code, never reads secrets. |
| Data leaving your repo | Only package names and versions (as purls) go to OSV.dev; only CVE ids go to FIRST EPSS; the KEV catalog is downloaded. Source code and lockfile contents are not sent. |
| Untrusted advisory text in issues (A05) | Advisory summaries, names and versions are escaped: HTML entities, markdown control characters, `@` mentions and autolinks are neutralized. Fields with a known shape are validated before use (severity must be a known level, fixed versions a version pattern, dates `YYYY-MM-DD`, references `https:` links without markup characters). Draft blocks cannot break out of their code fences: their text has no backticks or line breaks and the fence is longer than any backtick run inside it. Issue bodies are size-capped (at most 20 lockfiles, 5 fixed versions and 5 references plus the OSV link listed). Tested. |
| Issue state (A01, A08) | The detection time kept in an issue is believed only for issues opened by a bot or by the token's own account, and only if it is an ISO timestamp that is not in the future; otherwise GitHub's own creation time is used. The stored key is the component and the first CVE id in sorted order, so a different order of OSV ids cannot reset a clock. |
| Workflow commands (A05) | Upstream error text is flattened to one line and `::` is broken up before it is logged, so a response body cannot start `::add-mask::` or `::warning::` commands. |
| Hostile repositories | Lockfile parsing is defensive (malformed files yield nothing, never crash the scan); files over 50 MB, symlinked files and symlinked directories are skipped (the walk uses `lstat` and never follows a link; tested); dependency directories (`node_modules`, `vendor`, ...) are not walked. |
| Network | 60 s timeouts, bounded retries, redirects refused. If OSV details or EPSS cannot be fetched, affected advisories are flagged `intel-incomplete` for manual review and the job fails (unless `allow-incomplete-intel: true`); a failed lookup is never reported as clean. A KEV catalog that cannot be read, or is empty or truncated (fewer than 1,000 entries; the real one has about 1,400), is "exploitation status unknown": the report says so, no advisory is called known or clean, and the job exits 2. The website's `/kev.json` mirror applies the same rule and never serves or caches an empty catalog. |
| Fork pull requests | The token is read-only there; a 403 on issue creation degrades to the job summary with a note. Use `open-issues: false` for `pull_request`. |
| Inputs | `fail-on`, `epss-threshold` and boolean inputs are validated; invalid values stop the run with an error before any network call. |

## The website

Static, strict CSP with Trusted Types (`connect-src` limited to the site, `api.osv.dev` and `api.first.org`), HSTS
preload, no cookies, no analytics. The lockfile you drop is parsed in the page and never uploaded.
