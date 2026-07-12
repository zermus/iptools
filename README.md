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

📦 **[Download the latest release](https://cgee.net/iptools/ip-tools-0.1.1.tar.gz)** —
or grab it from the [GitHub repo](https://github.com/zermus/iptools). Just extract
into a web root; there is no build step.

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
   (with an Apache `.htaccess` deny-all inside). On Nginx, block it yourself:

   ```
   location ^~ /path/to/iptools/logs/ { deny all; }
   ```

## Requirements

- PHP 7.3+ with the GMP extension (used by the IPv6 tools)
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
  so it can't be bypassed by discarding the session cookie. Configure
  `$maxRequests` / `$timeFrame` at the top of each tool.
- **SSRF / internal-probe guard**: ping, traceroute, and MTR refuse targets
  that are — or resolve to — private/reserved addresses (RFC 1918, loopback,
  link-local, etc.). Set `$allowPrivateTargets = true` in a tool to relax this
  for internal deployments. Note the guard resolves DNS separately from the
  probe binary (a small rebinding window); for hardened deployments also
  firewall outbound traffic from the web server.
- **Strict input validation** (hostname/IP whitelisting) before anything
  reaches `escapeshellarg()` and the shell.
- **Query logging** (optional, `$enableLogging`) into `logs/<tool>.log`,
  outside casual web reach — never into the web root as loose `.txt` files.
- **Hardened session cookies** (`HttpOnly`, `SameSite=Lax`, `Secure` on HTTPS).

## MTR tool setup

The MTR tool executes `mtr` in report mode via `sudo` and streams the output
to the browser through Ajax polling (every 5 seconds).

### Requirements

- MTR installed on the system
  - RHEL/CentOS/Fedora: `sudo dnf install mtr`
  - Debian/Ubuntu: `sudo apt-get install mtr`
- Sudo configured so the web server user can run MTR without a password.

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

2. **Configure sudoers.** Find the MTR path with `which mtr` (typically
   `/usr/sbin/mtr`), then run `sudo visudo` and add:

   ```
   apache ALL=(root) NOPASSWD: /usr/sbin/mtr     # RHEL/CentOS/Fedora
   # or
   www-data ALL=(root) NOPASSWD: /usr/sbin/mtr   # Debian/Ubuntu
   ```

3. **Test** by browsing to `mtr.php`, entering a target, and submitting.
   Environment problems (missing tmp dir, sudo not configured) are reported
   in an error box at the top of the page.

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
