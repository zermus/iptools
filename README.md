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

## Requirements

- PHP 7.3+ with the GMP extension (used by the IPv6 tools); PHP 8.2+
  recommended (its `FILTER_FLAG_GLOBAL_RANGE` strengthens the SSRF guard)
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
   sudo chmod 755 /path/to/iptools/tmp
   ```

2. **Check the MTR path** with `which mtr` (typically `/usr/sbin/mtr`) and
   set `$mtrPath` in `mtr.php` if it differs.

3. **Test** with `$showDiagnostics = true` set in `mtr.php`: browse to it,
   enter a target, and submit. Setup problems (missing tmp dir, MTR not
   runnable) are reported in detail at the top of the page. Set
   `$showDiagnostics` back to `false` when done — it reveals server paths
   and the web server user to visitors.

4. **Only if MTR won't run unprivileged**, set `$mtrUseSudo = true` and
   grant sudo for exactly the command the tool runs (`sudo visudo`):

   ```
   apache ALL=(root) NOPASSWD: /usr/sbin/mtr -rw -c 10 *     # RHEL/CentOS/Fedora
   # or
   www-data ALL=(root) NOPASSWD: /usr/sbin/mtr -rw -c 10 *   # Debian/Ubuntu
   ```

   Upgrading from 0.1.x with a bare `NOPASSWD: /usr/sbin/mtr` line? Narrow
   it as above, or remove it if MTR works without sudo.

### Notes

- On SELinux (RHEL) or AppArmor (Ubuntu) systems you may need policy
  adjustments if you hit permission issues.
- Config knobs (temp directory, expiry, MTR path, poll timeout) live at the
  top of `mtr.php`.
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
