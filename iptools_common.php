<?php
/*
 * IPTOOLS :: common security + theme layer
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 *
 * Shared by every tool in the suite:
 *   - Security headers + per-request CSP nonce (single-line header, actually delivered)
 *   - CSRF token generation / validation
 *   - File-based rate limiting keyed by client IP (survives cookie-less clients)
 *   - Input validation for hostnames / IPs
 *   - Private/reserved target guard (SSRF & internal-network-probe protection)
 *   - Query logging into a web-inaccessible logs/ directory
 *   - The terminal theme (page chrome, nav, output blocks)
 */

/**
 * Start the hardened session, emit security headers, and return
 * [$nonce, $csrfToken]. Must be called before any output.
 */
function iptools_boot(): array {
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Lax',
        'secure'   => !empty($_SERVER['HTTPS']),
    ]);
    session_start();

    $nonce = base64_encode(random_bytes(16));

    // NOTE: header() drops any value containing a newline, so the CSP must stay one line.
    header("Content-Security-Policy: default-src 'self'; script-src 'nonce-{$nonce}'; style-src 'nonce-{$nonce}'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');

    if (empty($_SESSION['iptools_csrf'])) {
        $_SESSION['iptools_csrf'] = bin2hex(random_bytes(32));
    }

    return [$nonce, $_SESSION['iptools_csrf']];
}

/**
 * Validate the CSRF token on a POST submission.
 */
function iptools_csrf_ok(): bool {
    return isset($_POST['csrf'])
        && is_string($_POST['csrf'])
        && hash_equals($_SESSION['iptools_csrf'] ?? '', $_POST['csrf']);
}

/**
 * File-based rate limiter keyed by client IP. Unlike a session-based
 * limiter, this cannot be bypassed by discarding the session cookie.
 * Returns true when the limit is exceeded (the request is NOT recorded).
 */
function iptools_rate_limited(string $tool, int $maxRequests, int $timeFrame): bool {
    $ip   = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $key  = hash('sha256', $ip); // don't store raw IPs in the shared temp file
    $file = sys_get_temp_dir() . '/iptools_ratelimit_' . preg_replace('/[^a-z0-9_-]/i', '', $tool) . '.json';

    $fh = @fopen($file, 'c+');
    if ($fh === false) {
        return false; // fail open: a broken temp dir shouldn't take the tool down
    }
    flock($fh, LOCK_EX);
    $raw  = stream_get_contents($fh);
    $data = $raw ? (json_decode($raw, true) ?: []) : [];
    $now  = time();

    // Prune stale entries across all clients so the file can't grow unbounded
    foreach ($data as $k => $timestamps) {
        $data[$k] = array_values(array_filter($timestamps, function ($t) use ($now, $timeFrame) {
            return $t > $now - $timeFrame;
        }));
        if (empty($data[$k])) {
            unset($data[$k]);
        }
    }

    $hits    = $data[$key] ?? [];
    $limited = count($hits) >= $maxRequests;
    if (!$limited) {
        $hits[]     = $now;
        $data[$key] = $hits;
    }

    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($data));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);

    return $limited;
}

/**
 * Sanitize and validate user input as a hostname or IP address.
 * Returns the cleaned value, or false if invalid.
 */
function iptools_validate_host(string $input) {
    $input = preg_replace('/\s+/', '', trim($input));
    if ($input === '' || strlen($input) > 253) {
        return false;
    }
    if (filter_var($input, FILTER_VALIDATE_IP) !== false) {
        return $input;
    }
    if (filter_var($input, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false) {
        return $input;
    }
    return false;
}

/**
 * True when the IP is publicly routable (not RFC1918 / loopback /
 * link-local / other reserved space).
 */
function iptools_is_public_ip(string $ip): bool {
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
}

/**
 * SSRF / internal-probe guard for the active network tools (ping,
 * traceroute, mtr). When $allowPrivate is false, refuse any target that
 * is — or resolves to — a private or reserved address, so a public
 * deployment can't be used to map the internal network.
 *
 * Caveat: resolution here and resolution by the probe binary are two
 * separate lookups (DNS rebinding window). For a hardened deployment,
 * also firewall outbound traffic from the web server.
 */
function iptools_target_allowed(string $target, bool $allowPrivate): bool {
    if ($allowPrivate) {
        return true;
    }
    if (filter_var($target, FILTER_VALIDATE_IP) !== false) {
        return iptools_is_public_ip($target);
    }
    $ips = [];
    foreach ((dns_get_record($target, DNS_A + DNS_AAAA) ?: []) as $rec) {
        if (!empty($rec['ip']))   { $ips[] = $rec['ip']; }
        if (!empty($rec['ipv6'])) { $ips[] = $rec['ipv6']; }
    }
    if (empty($ips)) {
        return true; // unresolvable — let the underlying tool report the failure
    }
    foreach ($ips as $ip) {
        if (!iptools_is_public_ip($ip)) {
            return false;
        }
    }
    return true;
}

/**
 * Append a query log entry to logs/<tool>.log. The logs/ directory is
 * created outside of casual reach: an .htaccess deny-all is dropped in
 * (Apache); on Nginx, block the directory in your server config.
 */
function iptools_log(string $tool, string $message): void {
    $dir = __DIR__ . '/logs';
    if (!is_dir($dir)) {
        @mkdir($dir, 0750, true);
        @file_put_contents($dir . '/.htaccess', "Require all denied\n");
        @file_put_contents($dir . '/index.html', '');
    }
    $tool  = preg_replace('/[^a-z0-9_-]/i', '', $tool);
    $entry = date('Y-m-d H:i:s') . ' - ' . ($_SERVER['REMOTE_ADDR'] ?? '-') . ' - ' . $message . "\n";
    @file_put_contents($dir . '/' . $tool . '.log', $entry, FILE_APPEND | LOCK_EX);
}

/**
 * Open the themed page: doctype, head (with nonce'd CSS), nav, container.
 */
function iptools_page_open(string $title, string $nonce, string $active = ''): void {
    $tools = [
        'nslookup.php'        => 'nslookup',
        'ping.php'            => 'ping',
        'traceroute.php'      => 'trace',
        'mtr.php'             => 'mtr',
        'whois.php'           => 'whois',
        'subnetcalc.php'      => 'calc4',
        'subnetcalc-ipv6.php' => 'calc6',
        'ula_generator.php'   => 'ula',
    ];
    $titleEsc = htmlspecialchars($title);
    echo "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n";
    echo "<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    echo "<title>iptools :: {$titleEsc}</title>\n";
    echo "<style nonce=\"{$nonce}\">\n";
    ?>
:root {
    --bg: #050905;
    --panel: #0a120b;
    --panel-deep: #030603;
    --ink: #b9f0c5;
    --grn: #00ff66;
    --dim: #3fa860;
    --brd: #1d5c2e;
    --err: #ff5555;
    --amber: #ffb000;
}
* { box-sizing: border-box; }
body {
    background: var(--bg);
    background-image: radial-gradient(ellipse at 50% -20%, #0c1a0e 0%, var(--bg) 60%);
    color: var(--ink);
    font-family: "Cascadia Code", "Fira Code", Consolas, "Courier New", monospace;
    margin: 0;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 24px 12px 70px;
}
/* CRT scanlines */
body::before {
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    background: repeating-linear-gradient(0deg, rgba(0, 0, 0, 0.15) 0 1px, transparent 1px 3px);
    z-index: 99;
}
nav {
    width: 92%;
    max-width: 860px;
    border: 1px solid var(--brd);
    background: var(--panel);
    padding: 8px 14px;
    margin-bottom: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 4px 14px;
    align-items: center;
    box-shadow: 0 0 22px rgba(0, 255, 102, 0.07);
}
nav .brand {
    color: var(--grn);
    text-shadow: 0 0 8px rgba(0, 255, 102, 0.6);
    margin-right: 8px;
    user-select: none;
}
nav a {
    color: var(--dim);
    text-decoration: none;
}
nav a:hover { color: var(--grn); text-shadow: 0 0 8px rgba(0, 255, 102, 0.6); }
nav a.active { color: var(--grn); }
nav a.active::before { content: "["; }
nav a.active::after { content: "]"; }
.container {
    width: 92%;
    max-width: 860px;
    padding: 22px 26px;
    border: 1px solid var(--brd);
    background: var(--panel);
    box-shadow: 0 0 22px rgba(0, 255, 102, 0.07);
}
h1 {
    margin: 0 0 4px;
    font-size: 1.35em;
    color: var(--grn);
    text-shadow: 0 0 10px rgba(0, 255, 102, 0.55);
    text-transform: lowercase;
    letter-spacing: 1px;
}
h1::before { content: "> "; color: var(--dim); }
.cursor { animation: blink 1.1s steps(1) infinite; }
@keyframes blink { 50% { opacity: 0; } }
.tagline { color: var(--dim); margin: 0 0 18px; font-size: 0.85em; }
form { text-align: left; }
label { display: block; margin-bottom: 5px; color: var(--dim); }
label::before { content: ":: "; }
input[type="text"], select {
    width: 100%;
    padding: 9px 12px;
    background: var(--panel-deep);
    border: 1px solid var(--brd);
    color: var(--grn);
    caret-color: var(--grn);
    font-family: inherit;
    font-size: 0.95em;
    margin-bottom: 12px;
}
input[type="text"]::placeholder { color: #2c6b3f; }
input[type="text"]:focus, select:focus {
    outline: none;
    border-color: var(--grn);
    box-shadow: 0 0 10px rgba(0, 255, 102, 0.25);
}
input[type="checkbox"] { accent-color: var(--grn); }
.submit-container { text-align: center; margin-top: 6px; }
input[type="submit"] {
    padding: 8px 26px;
    background: transparent;
    border: 1px solid var(--grn);
    color: var(--grn);
    font-family: inherit;
    text-transform: lowercase;
    cursor: pointer;
    transition: background 0.15s ease, color 0.15s ease;
}
input[type="submit"]:hover {
    background: var(--grn);
    color: #030603;
    box-shadow: 0 0 16px rgba(0, 255, 102, 0.5);
}
.output-item { margin-top: 22px; text-align: left; }
.output-item .out-label { color: var(--dim); font-size: 0.85em; }
.output-item .out-label::before { content: "── "; }
.output-item .out-label::after { content: " ─────"; }
pre {
    white-space: pre-wrap;
    text-align: left;
    background: var(--panel-deep);
    border: 1px solid var(--brd);
    border-left: 3px solid var(--grn);
    color: var(--ink);
    padding: 12px;
    overflow: auto;
    max-height: 480px;
    margin-top: 8px;
    font-family: inherit;
    font-size: 0.9em;
}
ul.results { list-style: none; padding: 0; margin: 18px auto 0; max-width: 640px; text-align: left; }
ul.results li { margin-bottom: 6px; padding-left: 18px; }
ul.results li::before { content: "▸ "; color: var(--grn); margin-left: -18px; }
ul.results li strong { color: var(--grn); font-weight: normal; }
table { margin: 12px auto 0; border-collapse: collapse; }
table th, table td { border: 1px solid var(--brd); padding: 6px 16px; }
table th { background: var(--panel-deep); color: var(--grn); font-weight: normal; }
p.error-message { color: var(--err); text-shadow: 0 0 8px rgba(255, 85, 85, 0.4); margin-top: 18px; }
p.error-message::before { content: "[!] "; }
h3, h4 { color: var(--grn); font-weight: normal; }
.readonly-field {
    width: auto;
    min-width: 320px;
    max-width: 100%;
    display: inline-block;
    text-align: center;
    cursor: pointer;
}
.pre-wrapper { position: relative; margin-top: 8px; min-height: 200px; }
.pre-wrapper pre { min-height: 200px; white-space: pre; margin-top: 0; }
.spinner {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    border: 3px solid rgba(0, 255, 102, 0.2);
    border-top: 3px solid var(--grn);
    border-radius: 50%;
    width: 28px;
    height: 28px;
    animation: spin 1s linear infinite;
    z-index: 2;
}
@keyframes spin { 100% { transform: translate(-50%, -50%) rotate(360deg); } }
.error-box {
    border: 1px solid var(--err);
    background: rgba(255, 85, 85, 0.06);
    color: var(--err);
    padding: 10px 14px;
    margin-bottom: 18px;
    text-align: left;
    font-size: 0.9em;
}
.error-box code { color: var(--amber); }
footer {
    position: fixed;
    bottom: 0;
    left: 0;
    width: 100%;
    text-align: center;
    padding: 8px 0;
    background: var(--panel-deep);
    border-top: 1px solid var(--brd);
    color: var(--dim);
    font-size: 0.8em;
    z-index: 10;
}
@media screen and (max-width: 600px) {
    .container { width: 100%; padding: 16px; }
    nav { width: 100%; }
    pre { font-size: 0.8em; }
    input[type="submit"] { width: 100%; }
    .readonly-field { min-width: 0; width: 100%; }
}
    <?php
    echo "</style>\n</head>\n<body>\n<nav><span class=\"brand\">iptools://</span>";
    foreach ($tools as $file => $label) {
        $cls = ($file === $active) ? ' class="active"' : '';
        echo "<a href=\"{$file}\"{$cls}>{$label}</a>";
    }
    echo "</nav>\n<div class=\"container\">\n";
    echo "<h1>{$titleEsc}<span class=\"cursor\">_</span></h1>\n";
}

/**
 * Close the themed page.
 */
function iptools_page_close(): void {
    echo "</div>\n<footer>iptools v0.1.0 — MIT licensed — [ all systems nominal ]</footer>\n</body>\n</html>\n";
}
