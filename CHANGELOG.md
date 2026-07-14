# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Planned

- Optional `iptools_config.php` for per-tool settings, never overwritten by
  releases, so upgrades become a straight file replacement (config currently
  lives at the top of each tool file and must be re-applied after upgrading).

## [0.1.2] - 07-12-2026

### Added

- Output syntax highlighting across the network tools, matching the theme:
  amber for key numbers (ping/RTT times, whois domain and expiry date),
  green for good answers (resolved records, name servers, signedDelegation,
  0% packet loss), red for failures (timeouts, unreachable, NXDOMAIN,
  packet loss, dead hops), and dim for chrome (whois field labels, hop
  numbers, table headers). Implemented server-side in
  `iptools_highlight()` (iptools_common.php); output is escaped before
  spans are injected. Colors only — no bold — so monospace column
  alignment in traceroute/MTR tables is preserved.
- The MTR live view now streams highlighted output (mtr_output.php returns
  an escaped, highlighted HTML fragment).

## [0.1.1] - 07-11-2026

### Added

- `index.php`: landing page with a dashboard of all tools.
- `subnets.php`: IPv4 + IPv6 subnet cheat sheet in the suite theme. Tables
  are generated with GMP, so all values are exact (the old hand-typed IPv6
  counts had float rounding errors). `subnets.html` now redirects here; its
  Matomo tracking scripts were dropped (the suite CSP would block them —
  whitelist your Matomo origin in `iptools_common.php` if you want them back).

### Changed

- Nav reordered: whois, nslookup, ping, trace, mtr, calc4, calc6, ula,
  cheatsheet. The `iptools://` brand now links to the landing page.
- Output panels size to their content: snug around short results, stretching
  to the full viewport for wide output (e.g. whois), with horizontal scroll
  inside the block for extreme lines.

## [0.1.0] - 07-11-2026

### Added

- `iptools_common.php`: shared security + theme layer required by every tool.
- CSRF tokens on every command-executing form.
- SSRF / internal-probe guard: ping, traceroute, and MTR refuse targets that
  are (or resolve to) private/reserved addresses. Configurable via
  `$allowPrivateTargets`.
- Security headers: `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, and hardened session cookies (HttpOnly, SameSite=Lax,
  Secure on HTTPS).
- Green-phosphor terminal theme with a shared nav bar across all tools.
- nslookup.php: TXT record query type.
- subnetcalc.php: usable host count; rejects non-contiguous subnet masks.
- traceroute.php: hop count capped (`$maxHops`) so runs can't hang.

### Fixed

- Content Security Policy was never actually delivered: the full license
  block emitted output before `header()`, and PHP drops multi-line header
  values. CSP is now a single-line, nonce-based policy sent before any
  output, with `unsafe-inline` removed entirely.
- Rate limiting was session-based and could be bypassed by discarding the
  session cookie. It is now file-based and keyed by client IP.
- Query logs were written into the web root as world-readable `.txt` files.
  They now go to a `logs/` directory with an Apache deny-all `.htaccess`.
- ping.php: broken IPv6 regex replaced with `filter_var` validation; IPv6
  targets now use `ping -6` on Linux.
- subnetcalc.php: `/0` prefix produced an invalid mask (undefined shift).
- mtr.php / mtr_output.php: session id sanitized before use in file paths.
- nslookup.php: failed IPv6 PTR conversion no longer falls through to an
  undefined-variable command build.

### Changed

- Full 22-line MIT license block in every source file replaced with a
  two-line pointer to LICENSE.txt (the canonical license text).
- Duplicated validation, rate limiting, logging, and CSS consolidated into
  `iptools_common.php`.

## [0.0.5] - 01-30-2024

### Added

- Initial public pre-release.

## [0.0.6] - 07-27-2024

### nslookup.php

- Added configurable to set DNS server for queries.

## [0.0.8] - 10-25-2024

### nslookup.php
### ping.php
### subnetcalc-ipv6.php
### subnetcalc.php
### traceroute.php
### whois.php

- UI improvements.

- Added security features:
* Content Security Policy for mitigating risks like Cross-Site Scripting (XSS).
* Rate Limiting options.
* Optional Logging of queries to a logfile for auditing.
