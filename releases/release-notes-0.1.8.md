# iptools 0.1.8

iptools 0.1.8 improves diagnostic safety, runtime storage and MTR polling,
with calculator fixes and fresh-checkout regression coverage.

## Highlights

- Runtime state and logs require safe ownership and permissions. Existing
  unsafe storage is refused instead of silently using another directory.
- Forwarded HTTPS headers require explicit trusted-proxy opt-in. Diagnostic
  output is bounded and slow requests no longer block other tabs in the session.
- MTR launch and polling share scratch storage and timeouts, recover from
  transient polling failures, and enforce three requests per minute per client.
- IPv4 mask handling, IPv6 traceroute and exact IPv6 subnet counts are fixed.
  ULA generation works without GMP; IPv6 calculations report missing GMP cleanly.
- Release archives include the shared MTR runtime helper, with consistent
  permissions and matching 0.1.8 builder, footer and website versions.

## Installation

1. Download `ip-tools-0.1.8.tar.gz` or `ip-tools-0.1.8.zip` from the GitHub release.
2. Back up per-tool settings and any edits to `mtr_runtime.php`.
3. Extract into the web root and reapply those settings.
4. Prepare app-owned runtime directories and protect them from web access as
   described in `README.md`. MTR needs its configured writable scratch directory.
   Shared rate-limit and probe-slot state uses a private system-temp fallback
   only when suite `tmp/` is absent, never when existing storage is unsafe.

Release archives exclude tests, website, build tooling, Git metadata and runtime
`logs/` and `tmp/` data. For source checkouts, remove `tests/` from the document
root or deny HTTP access to it. Apache must honor `.htaccess`, or equivalent
virtual-host rules; other servers need equivalent protection. See `README.md`.

## Upgrading

- Back up and reapply local settings after extracting, including shared MTR
  defaults. Configuration still lives in PHP files; no separate config file
  is introduced. There is no database migration or new PHP requirement.
- Follow README's ownership and permission migration before retaining runtime
  state: stop workers, inspect without following links, use app-owned directories
  (prefer `0700`, or `0750` for an administrative read group) and private `0600`
  state/log files. The private fallback directory must be `0700`. Remove only
  vetted disposable state; retain logs safely. Unsafe or unwritable existing
  storage is refused. Do not recursively chmod unknown paths. Restart and test.
- For Secure cookies behind TLS termination, configure backend HTTPS or define
  `IPTOOLS_TRUST_PROXY` as `true` before the tools load. Enable it only behind
  a trusted proxy that overwrites inbound forwarding headers; otherwise leave
  it off. Client rate limits still use `REMOTE_ADDR`.
- Move local MTR `$tempDir` and `$tracerouteTimeout` overrides to shared
  `IPTOOLS_MTR_TEMP_DIR` and `IPTOOLS_MTR_TIMEOUT` before either endpoint loads,
  or edit their defaults in `mtr_runtime.php`. Defaults are suite `tmp/` and
  60 seconds (minimum 1). Protect alternate scratch storage like `tmp/`.
- Account for MTR's `$burstRequests = 3` per `$burstWindow = 60` seconds,
  alongside its hourly and concurrent limits. Reload in-flight MTR pages after
  upgrading. The `IPTOOLSSESSID` cookie name is unchanged; there is no forced
  sign-in, session reset or blanket token invalidation. Reload expired forms.

## Requirements

- PHP 7.3 or newer; PHP 8.2+ recommended. GMP is needed for IPv6 subnet
  calculations and IPv6 cheat-sheet tables, not ULA generation or IPv4 tools.
- A web server honoring the supplied Apache protections or equivalent rules.
- The command-line utilities used by enabled tools, including `timeout`.
- MTR for `mtr.php`; see README for optional sudo configuration.

## Verification

### Reported baseline (before this patch)

- PHP 8.4.27: 257 checks, 15 PHP syntax checks, five deterministic JavaScript
  polling scenarios and Bash syntax passed. GMP coverage was skipped.
- Baseline archives had matching 18-file payloads but still used 0.1.7 names
  and footer. Those checks did not verify the patched 0.1.8 candidate.

### Final 0.1.8 candidate

- PHP 8.4.27: all 257 checks pass, including footer-versus-builder, runtime
  permissions, proxy cookies and shared MTR settings. All 15 PHP files lint;
  five deterministic JavaScript polling scenarios, Bash syntax and whitespace
  checks pass.
- Both 0.1.8 archives pass integrity, identical 18-file payload and exclusion
  checks, with `0755` directories and `0644` files. Extracted and permission-
  preserving copied trees are readable/traversable by `nobody`; both render
  the v0.1.8 footer under that unprivileged user.
- Apache/Chromium: index, IPv4 calculator, ULA and MTR return HTTP 200;
  browser result: `PASS, 4 page(s) clean`.
- Website returns HTTP 200 and displays 0.1.8 with the GitHub release asset
  URL matching the builder's tag and tarball name. Browser result:
  `FAIL, 1 of 1 page(s) had findings`: four external requests blocked by the
  loopback-only browser and the existing donation iframe attribute warning.

### Not verified

- Other PHP versions and Windows: only PHP 8.4 on Linux is available.
- GMP-enabled IPv6 calculations and tables: GMP is unavailable; GMP-free ULA
  generation is covered.
- Live probe binaries and privileged MTR: no live or privileged probe testing
  was performed; regression fixtures cover command and lifecycle behavior.
- Production ownership migration and proxy behavior: local fixtures are not a
  deployed environment. No deployment or server policy was changed.
- Third-party analytics/donation integrations: external requests are blocked
  by the browser. The website browser check does not pass cleanly as noted above.
- Public 0.1.8 download availability: publication belongs to the pipeline after
  merge; this run only checks the local URL against the builder's asset name.
