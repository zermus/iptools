# iptools 0.1.7

iptools 0.1.7 improves shared probe admission, form and session handling,
and runtime-state recovery, with calculator and website fixes.

## Highlights

- WHOIS, nslookup, ping and traceroute share an eight-probe cap and each
  allow five requests per minute per client alongside their hourly limits.
- Private runtime files recover safely from malformed rate-limit state;
  shared probe locks are released automatically when a worker exits.
- String-only form inputs, isolated session cookies and proxy-aware Secure
  cookies improve deployment safety. Public embedded IPv4 targets remain usable.
- IPv4 /31 results show both addresses; ULA addresses use consistent notation.
- Website downloads and analytics, release permissions and regression coverage
  are updated for 0.1.7.

## Installation

1. Download `ip-tools-0.1.7.tar.gz` or `ip-tools-0.1.7.zip` from the project release.
2. Back up per-tool settings at the top of your installed PHP files.
3. Extract the archive into the web root and reapply those settings.
4. A writable suite `tmp/` is recommended for shared runtime state; MTR still
   requires it. The new rate-limit and probe-slot helpers fall back to the
   system temporary directory if suite `tmp/` is absent or not writable.

Release archives exclude tests, website, build tooling, Git metadata and runtime
`logs/` and `tmp/` data. For source checkouts, remove `tests/` from the document
root or deny HTTP access to it. Apache must honor `.htaccess`, or equivalent
virtual-host rules; other servers need equivalent protection. See `README.md`.

## Upgrading

- Use a writable shared `tmp/` when possible; the new helpers' fallback means
  creating it is recommended, not mandatory. MTR's requirements are unchanged.
- Reload open forms and in-flight MTR pages once: the cookie name changes to
  `IPTOOLSSESSID`. Behind TLS termination, configure `SetEnv HTTPS on` or forward
  `X-Forwarded-Proto: https` for Secure cookies.
- Replace old sudoers examples with README's anchored numeric-address argument
  regex (sudo 1.9.10+). With older sudo, leave sudo mode off and use
  `cap_net_raw+ep` on `mtr-packet` instead.
- Reapply local edits after extracting. WHOIS, nslookup, ping and traceroute
  add/reset `$maxConcurrent = 8`, `$burstRequests = 5`, `$burstWindow = 60`;
  keep the shared cap equal across those tools. Existing hourly settings remain.
  There are no database migrations or new PHP requirements.

## Requirements

- PHP 7.3 or newer, with GMP for IPv6 tools.
- A web server honoring the supplied Apache protections or equivalent rules.
- The command-line utilities used by enabled tools, including `timeout`.
- MTR for `mtr.php`; see README for optional sudo configuration.

## Verification

- PHP 8.4: expanded CLI/HTTP regression suite and all PHP syntax checks pass.
- Apache/Chromium form, result, footer and private-target checks pass.
- Analytics queue and download events checked with intercepted external fixtures;
  no production analytics events were sent. The existing donation iframe emits
  an allowpaymentrequest warning; direct website checks block external resources.
- Both archives built and checked for integrity, contents, modes and footer.

### Not verified

- Other PHP versions, including 8.3 and 7.3–8.1: only PHP 8.4 is installed.
- GMP-dependent ULA generation and IPv6 calculations: GMP is unavailable.
- Privileged sudo/MTR execution and deployed proxy behavior: no privileged or
  deployment environment was changed. The documented sudoers syntax is checked
  locally, but not installed as policy.
- Live WHOIS/DNS/ping/traceroute/MTR results: probe binaries are not installed;
  missing-command cleanup and admission behavior were tested.
- Windows checkout behavior: no Windows environment is available.
- Live third-party analytics/donation services: deliberately intercepted or blocked.
