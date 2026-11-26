# IPTOOLS

```
 _       _              _
(_)_ __ | |_ ___   ___ | |___
| | '_ \| __/ _ \ / _ \| / __|
| | |_) | || (_) | (_) | \__ \
|_| .__/ \__\___/ \___/|_|___/
  |_|          network recon, self-hosted
```

A suite of self-hosted PHP network diagnostic tools with a green-phosphor
terminal theme. Input validation, shell-argument escaping, CSRF protection,
IP-based rate limiting, and SSRF guards are built in. These tools are loosely
based on older PHP scripts that have become deprecated over the years and are
completely rewritten from scratch for modern PHP.

📦 **[Download the latest release](https://github.com/zermus/iptools/releases)** —
grab the tarball from the Releases page and extract it into a web root. There is
no build step.

Licensed under the MIT License — see LICENSE.txt. Each source file carries a
short pointer to that file instead of the full license text.

## Components

| File                  | Tool                                                    |
|-----------------------|---------------------------------------------------------|
| `index.php`           | Landing page — dashboard of all tools                   |
| `whois.php`           | Domain / IP WHOIS lookup                                |
| `nslookup.php`        | DNS lookups (A, AAAA, MX, NS, TXT, PTR) with a configurable DNS server |
| `ping.php`            | ICMP ping (IPv4 + IPv6)                                 |
| `traceroute.php`      | Traceroute, capped hop count                            |
| `mtr.php` + `mtr_output.php` | MTR (My Traceroute) in report mode with Ajax polling |
| `subnetcalc.php`      | IPv4 subnet calculator (CIDR or dotted mask)            |
| `subnetcalc-ipv6.php` | IPv6 subnet calculator                                  |
| `ula_generator.php`   | RFC 4193 IPv6 Unique Local Address generator            |
| `subnets.php`         | IPv4 + IPv6 subnet cheat sheet (`subnets.html` redirects here) |
| `iptools_common.php`  | Shared security + theme layer (required by every tool)  |

## Installation

1. Copy **all** the PHP files — including `iptools_common.php` — into the same
   directory under your web server's document root. The tools will not run
   without the common file.
2. For the MTR tool, follow the extra steps below.
3. A `logs/` directory is created automatically on first logged query
   (with an Apache `.htaccess` deny-all inside; the MTR tool drops the same
   into `tmp/`). On Nginx, block both yourself:

   ```
   location ^~ /path/to/iptools/logs/ { deny all; }
   location ^~ /path/to/iptools/tmp/  { deny all; }
   ```

## Source checkouts and tests

Release archives exclude `tests/`. When deploying a source checkout, remove that
directory from the document root or deny all HTTP access to it. The supplied
root and `tests/.htaccess` rules protect Apache deployments only when overrides
are enabled. With `AllowOverride None`, put an equivalent `Require all denied`
rule in the virtual host's `<Directory "/absolute/path/to/iptools/tests">`
section. For Nginx, add these locations before PHP handling (adjust the prefix
for your installation):

```
location = /path/to/iptools/tests { deny all; }
location ^~ /path/to/iptools/tests/ { deny all; }
```

Other servers must enforce the same directory-wide denial; PHP guards do not
protect static fixtures. Verify that both the directory and files beneath it
return 403 or 404 without executing PHP, including in subdirectory installs.

Run the suite locally with `php tests/run.php`. It requires process execution
and loopback sockets, starts temporary PHP HTTP servers, and cleans them up.
The runner is CLI-only; `poller_router.php` is an intentional local HTTP fixture
for the CLI-launched PHP development server, not a deployable endpoint.

## Upgrading

**From 0.1.x:** configuration lives at the top of each tool file
(`$dnsServer`, `$allowPrivateTargets`, `$maxRequests`, `$mtrPath`, …), so
extracting a new release over your install will overwrite any values you
changed. Note your tweaks first, extract, then re-apply them. Your `logs/`
and `tmp/` directories are not touched by the release archive.

**From the pre-0.1.0 standalone scripts:** treat it as a fresh install —
the tools now require `iptools_common.php` alongside them. Also delete any
old `*_logs.txt` files from the web root; those were world-readable, which
is one of the things 0.1.0 fixed (logging now goes to the protected
`logs/` directory).

*Planned for 0.2.0:* an optional `iptools_config.php` (never overwritten by
releases) so upgrades become a straight file replacement.

For 0.1.8, back up and reapply local settings, including any shared defaults in
`mtr_runtime.php`. Keep the `IPTOOLSSESSID` cookie introduced in 0.1.7; no forced
session reset is added. A writable suite `tmp/` is recommended for shared
rate-limit and probe-slot state. These helpers use a private system-temporary
directory only when suite `tmp/` is absent; unsafe or unwritable existing state
is refused, not bypassed. Follow the ownership and permission migration under
[MTR notes](#notes) before reusing retained `tmp/` and `logs/` data. MTR still
requires its configured writable scratch directory. No database migration or
new PHP requirement is needed.

Migrate local MTR `$tempDir` and `$tracerouteTimeout` overrides to the shared
`IPTOOLS_MTR_TEMP_DIR` and `IPTOOLS_MTR_TIMEOUT` settings before either endpoint
loads, or edit their defaults in `mtr_runtime.php` (see MTR notes below).
MTR now permits three requests per client per 60 seconds (`$burstRequests = 3`,
`$burstWindow = 60`), in addition to its hourly and concurrent-run limits.
Reload in-flight MTR pages after upgrading so launch and polling agree.

WHOIS, nslookup, ping and traceroute now share `$maxConcurrent = 8` probe slots
and each has `$burstRequests = 5` per `$burstWindow = 60` seconds, in addition
to the hourly limit. Keep the shared cap equal across all four tools and reapply
local settings after extracting. Review the updated sudoers guidance below.

Behind a TLS-terminating proxy, configure backend HTTPS (for example,
`SetEnv HTTPS on` in the Apache backend vhost), or explicitly define
`IPTOOLS_TRUST_PROXY` as `true` in a server-side bootstrap before the tools load.
Enable proxy trust only behind a trusted proxy that overwrites inbound forwarding
headers and sends `X-Forwarded-Proto: https`; the first protocol token is used.
Without opt-in, forwarded protocol headers are ignored. This affects cookie
security only; client limits still use `REMOTE_ADDR`.

## Requirements

- PHP 7.3+; PHP 8.2+ recommended (its `FILTER_FLAG_GLOBAL_RANGE` strengthens
  the SSRF guard). GMP is required for IPv6 subnet calculations and IPv6
  cheat-sheet tables, but not for ULA generation or IPv4 tools
- Optional: the intl extension, to accept internationalized domain names
- coreutils `timeout` (present on virtually every Linux system), used to
  kill hung lookups
- A web server (Apache, or Nginx with PHP-FPM)
- WHOIS: the `whois` binary installed and accessible by the web user
- NSLOOKUP: the `nslookup` binary (commonly in the `bind-utils` / `dnsutils` package)
- PING / TRACEROUTE: the respective system binaries

## Security features

Every tool shares the hardening layer in `iptools_common.php`:

- **Content Security Policy** with a per-request nonce — no `unsafe-inline`
  anywhere — plus `X-Frame-Options`, `X-Content-Type-Options`, and
  `Referrer-Policy` headers.
- **CSRF tokens** on every form that triggers a command.
- **Rate limiting keyed by client IP** and stored server-side in a temp file,
  so it can't be bypassed by discarding the session cookie. IPv6 clients are
  counted per /64, so rotating addresses doesn't reset the limit. Configure
  `$maxRequests` / `$timeFrame` at the top of each tool. Behind a reverse
  proxy every client shares the proxy's address; configure your web server
  to restore the real client IP into `REMOTE_ADDR`.
- **SSRF / internal-probe guard**: ping, traceroute, and MTR resolve the
  target themselves and refuse it unless it resolves and every address is
  public (not RFC 1918, loopback, link-local, CGNAT, multicast, or an IPv6
  form wrapping one of those). The probe binary is then handed the IP, not
  the name, so numeric shorthand (`127.1`), `/etc/hosts` entries, and DNS
  rebinding can't slip past. Set `$allowPrivateTargets = true` in a tool to
  relax this for internal deployments. For hardened deployments, also
  firewall outbound traffic from the web server.
- **Command timeouts** (`$commandTimeout` / `$tracerouteTimeout`) so a hung
  lookup can't tie up PHP workers, and a cap on concurrent MTR runs
  (`$maxConcurrent`).
- **Strict input validation** (hostname/IP whitelisting) before anything
  reaches `escapeshellarg()` and the shell.
- **Query logging** (optional, `$enableLogging`) into `logs/<tool>.log`,
  outside casual web reach — never into the web root as loose `.txt` files.
- **Hardened session cookies** (`HttpOnly`, `SameSite=Lax`, `Secure` on HTTPS).

## MTR tool setup

The MTR tool executes `mtr` in report mode and streams the output to the
browser through Ajax polling (every 5 seconds).

### Requirements

- MTR installed on the system
  - RHEL/CentOS/Fedora: `sudo dnf install mtr`
  - Debian/Ubuntu: `sudo apt-get install mtr`
- Distro packages ship `mtr-packet` with the raw-socket privilege it needs
  (setuid or `cap_net_raw`), so MTR normally runs fine as the web server
  user with no sudo at all. That is the default (`$mtrUseSudo = false`).

### Steps

1. **Create the temp directory** next to the PHP files and make it writable
   by the web server:

   ```
   mkdir /path/to/iptools/tmp
   sudo chown apache:apache /path/to/iptools/tmp     # RHEL/CentOS/Fedora
   # or
   sudo chown www-data:www-data /path/to/iptools/tmp # Debian/Ubuntu
   sudo chmod 700 /path/to/iptools/tmp
   ```

2. **Check the MTR path** with `which mtr` (typically `/usr/sbin/mtr`) and
   set `$mtrPath` in `mtr.php` if it differs.

3. **Test** with `$showDiagnostics = true` set in `mtr.php`: browse to it,
   enter a target, and submit. Setup problems (missing tmp dir, MTR not
   runnable) are reported in detail at the top of the page. Set
   `$showDiagnostics` back to `false` when done — it reveals server paths
   and the web server user to visitors.

4. **Only if MTR won't run unprivileged**, set `$mtrUseSudo = true` and
   grant sudo for exactly the command the tool runs (`sudo visudo`, sudo 1.9.10+):

   ```
   apache ALL=(root) NOPASSWD: /usr/sbin/mtr ^-rw -c 10 [0-9A-Fa-f\:.]+$     # RHEL/CentOS/Fedora
   # or
   www-data ALL=(root) NOPASSWD: /usr/sbin/mtr ^-rw -c 10 [0-9A-Fa-f\:.]+$   # Debian/Ubuntu
   ```

   Upgrading from 0.1.x with a bare `NOPASSWD: /usr/sbin/mtr` line? Narrow
   it as above (also replace older wildcard argument rules), or remove it if MTR works without sudo.
   The colon is escaped for sudoers, not for the regular expression.
   With older sudo, do not enable sudo mode; use
   `setcap cap_net_raw+ep /usr/sbin/mtr-packet` (adjust the binary path) instead.

### Notes

- Prefer distro-supported `cap_net_raw` on `mtr-packet` rather than root-owned `sudo mtr`:
  unprivileged `timeout` cannot reliably signal privileged processes, and
  sudo `env_reset` strips `COLUMNS` and `TERM`. The numeric-only sudoers
  rule requires `$allowPrivateTargets = false`.
- POSIX runtime state requires native ownership and permission support.
  Before upgrading, secure existing state and log files to `0600`; the
  private fallback directory must be `0700`. Invalid files are refused.
- Keep `tmp/` and `logs/` app-owned, non-symlink directories, not writable
  by other users (prefer `0700`, or `0750` for an administrative read group).
  Stop web workers before migration. Inspect ownership and file types without
  following links; remove symlinks rather than changing their targets. Owned,
  disposable slot/rate/MTR state can be removed while workers are stopped and
  recreated automatically. Keep the `tmp/` directory itself for MTR. For logs
  you need to retain, move only vetted, owned regular files into an app-owned
  directory and set them to `0600`; do not recursively chmod unknown paths.
  Restart and verify queries and polling after migration. No untrusted pathname
  is chmodded automatically. Windows skips POSIX UID/mode checks: configure
  NTFS ACLs so only the application identity and administrators can modify
  runtime directories/files. Linux mounts must implement POSIX modes/ownership.
- Where Apache overrides are disabled, apply equivalent server-level rules:
  deny `logs`, `tmp`, `tests`, `.git` at any install prefix and deny
  `iptools_common.php`, `mtr_runtime.php`, `build-release.sh` (including PATH_INFO).
  On Nginx, place deny locations before the PHP handler, for example:
  `location ~* /(?:logs|tmp|tests|\.git)(?:/|$) { deny all; }` and
  `location ~ /(?:iptools_common\.php|mtr_runtime\.php|build-release\.sh)(?:/|$) { deny all; }`.
- Forwarded protocol headers require explicit `IPTOOLS_TRUST_PROXY = true`
  in a server-side bootstrap; enable only behind a trusted proxy that
  overwrites incoming forwarding headers. The first protocol token is used.
- WHOIS clients follow registry referrals over TCP. Restrict outbound access
  with a firewall; hostname validation does not constrain referrals.
- Combined stdout/stderr capture is capped at 512 KiB, including a truncation
  notice. Poll log reads are also capped at 512 KiB, not a disk quota. Bounded runtime still requires a
  working `timeout` binary, or external worker limits on other platforms.

- On SELinux (RHEL) or AppArmor (Ubuntu) systems you may need policy
  adjustments if you hit permission issues.
- Set shared MTR scratch storage and run timeout in trusted server-side PHP
  configuration before either endpoint loads: `IPTOOLS_MTR_TEMP_DIR` (default
  `__DIR__ . '/tmp'`) and `IPTOOLS_MTR_TIMEOUT` (default 60 seconds, minimum 1).
  Both launch and polling use these settings from `mtr_runtime.php`. Alternatively,
  edit the defaults in that helper. Migrate any local `$tempDir` or
  `$tracerouteTimeout` override from `mtr.php` to these shared settings; reload
  in-flight pages after migration. Protect alternate scratch directories with the
  same ownership, permissions and web-access restrictions as `tmp/`.
- Other config knobs (output expiry, MTR path) live at the top of `mtr.php`.
- `env TERM=xterm` forces non-interactive report mode and avoids terminal
  errors.

## Customization

Each tool keeps its configuration variables at the top of the file. The
shared theme lives in `iptools_common.php` (`iptools_page_open()`); tweak the
CSS variables in `:root` to re-skin the whole suite at once.

## License

Released under the [MIT License](LICENSE.txt).

- Official website: https://cgee.net/iptools/
- Feedback: cgee [at] cgee [dot] net
