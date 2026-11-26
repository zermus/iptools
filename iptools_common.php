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
 * Start the hardened session shared by full pages and companion endpoints.
 */
function iptools_start_session(): bool {
    if (session_status() === PHP_SESSION_ACTIVE) {
        return true;
    }

    session_name('IPTOOLSSESSID');
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    $https = isset($_SERVER['HTTPS'])
        && $_SERVER['HTTPS'] !== ''
        && strtolower((string)$_SERVER['HTTPS']) !== 'off';
    if (defined('IPTOOLS_TRUST_PROXY') && IPTOOLS_TRUST_PROXY === true) {
        $proto = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')[0]);
        $https = $https || strcasecmp($proto, 'https') === 0;
    }
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Lax',
        'secure'   => $https,
    ]);

    return session_start();
}

/**
 * Start the hardened session, emit security headers, and return
 * [$nonce, $csrfToken]. Must be called before any output.
 */
function iptools_boot(): array {
    iptools_start_session();

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

function iptools_e($value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function iptools_post_string(string $key): string {
    return isset($_POST[$key]) && is_string($_POST[$key]) ? $_POST[$key] : '';
}

function iptools_csrf_ok(): bool {
    $token = iptools_post_string('csrf');
    return $token !== '' && hash_equals($_SESSION['iptools_csrf'] ?? '', $token);
}

function iptools_private_dir(string $dir, bool $strict = false): bool {
    clearstatcache(true, $dir);
    $stat = @lstat($dir);
    if (!$stat || ($stat['mode'] & 0170000) !== 0040000 || !is_writable($dir)) {
        return false;
    }
    // Reject symlinks in ancestors too, before opening any child pathname.
    $parent = $dir;
    while (true) {
        if (is_link($parent)) {
            return false;
        }
        $next = dirname($parent);
        if ($next === $parent) {
            break;
        }
        $parent = $next;
    }
    return PHP_OS_FAMILY === 'Windows'
        || (($stat['mode'] & 0022) === 0
            && (!$strict || ($stat['mode'] & 0777) === 0700)
            && (!function_exists('posix_geteuid') || $stat['uid'] === posix_geteuid()));
}

function iptools_state_dir(): string {
    $preferred = __DIR__ . '/tmp';
    if (file_exists($preferred) || is_link($preferred)) {
        if (!iptools_private_dir($preferred)) {
            throw new RuntimeException('IPTools state directory is unsafe or unavailable.');
        }
        return $preferred;
    }
    $uid = function_exists('posix_geteuid') ? posix_geteuid() : get_current_user();
    $dir = sys_get_temp_dir() . '/iptools_'
        . substr(hash('sha256', __DIR__ . ':' . $uid), 0, 16);
    if (!file_exists($dir) && !is_link($dir)) {
        $mask = umask(0077);
        try {
            @mkdir($dir, 0700);
        } finally {
            umask($mask);
        }
    }
    if (!iptools_private_dir($dir, true)) {
        throw new RuntimeException('Private IPTools state directory unavailable.');
    }
    return $dir;
}

function iptools_state_open(string $file, string $context, bool $private = true) {
    clearstatcache(true, $file);
    $existing = @lstat($file);
    if (!iptools_private_dir(dirname($file)) || is_link($file)
        || ($existing && ($existing['mode'] & 0170000) !== 0100000)) {
        error_log($context . ': cannot open unsafe state path');
        return false;
    }
    $mask = umask(0077);
    try {
        $fh = @fopen($file, 'c+');
    } finally {
        umask($mask);
    }
    if ($fh === false) {
        $reason = error_get_last();
        error_log($context . ': cannot open state file: ' . ($reason['message'] ?? 'unknown error'));
        return false;
    }
    clearstatcache(true, $file);
    $stat = fstat($fh);
    $path = @lstat($file);
    if (!$stat || !$path || is_link($file) || ($stat['mode'] & 0170000) !== 0100000
        || (PHP_OS_FAMILY !== 'Windows'
            && ($stat['ino'] !== $path['ino'] || $stat['dev'] !== $path['dev']))
        || (PHP_OS_FAMILY !== 'Windows' && (($private ? ($stat['mode'] & 0777) !== 0600 : ($stat['mode'] & 0022) !== 0)
            || (function_exists('posix_geteuid') && $stat['uid'] !== posix_geteuid())))) {
        error_log($context . ': cannot secure state file permissions');
        fclose($fh);
        return false;
    }
    return $fh;
}

function iptools_probe_acquire(int $maxConcurrent) {
    try {
        $dir = iptools_state_dir();
    } catch (RuntimeException $error) {
        error_log('Probe admission refused: invalid state directory');
        return false;
    }
    for ($i = 0; $i < $maxConcurrent; $i++) {
        $fh = iptools_state_open($dir . '/.probe_slot_' . $i, 'Probe admission refused');
        if ($fh === false) {
            return false;
        }
        $wouldBlock = 0;
        if (@flock($fh, LOCK_EX | LOCK_NB, $wouldBlock)) {
            return $fh;
        }
        fclose($fh);
        if (!$wouldBlock) {
            error_log('Probe admission refused: cannot lock slot state');
            return false;
        }
    }
    return false;
}

function iptools_probe_release($slot): void {
    if (is_resource($slot)) {
        flock($slot, LOCK_UN);
        fclose($slot);
    }
}

/**
 * File-based rate limiter keyed by client IP. Unlike a session-based
 * limiter, this cannot be bypassed by discarding the session cookie.
 * Returns true when the limit is exceeded (the request is NOT recorded).
 */
function iptools_rate_limited(string $tool, int $maxRequests, int $timeFrame, bool $failClosed = false): bool {
    $ip  = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $bin = @inet_pton($ip);
    if ($bin !== false && strlen($bin) === 16) {
        if (iptools_ip_in_cidr($bin, '::ffff:0:0/96')) {
            // IPv4 client seen through a dual-stack socket
            $ip = inet_ntop(substr($bin, 12, 4));
        } else {
            // An IPv6 client usually controls its whole /64; count it as one
            // client so rotating addresses can't dodge the limit
            $ip = bin2hex(substr($bin, 0, 8)) . '/64';
        }
    }
    $key  = hash('sha256', $ip); // don't store raw IPs in the shared temp file
    try {
        $dir = iptools_state_dir();
    } catch (RuntimeException $error) {
        error_log('Rate limiting unavailable: invalid state directory');
        return $failClosed;
    }
    $file = $dir . '/iptools_ratelimit_' . preg_replace('/[^a-z0-9_-]/i', '', $tool) . '.json';

    $fh = iptools_state_open($file, 'Rate limiting is off');
    if ($fh === false) {
        return $failClosed;
    }
    try {
        if (!@flock($fh, LOCK_EX)) {
            error_log('Rate limiting is off: cannot lock state file');
            return $failClosed;
        }
        $raw = stream_get_contents($fh);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        $data = is_array($data) ? $data : [];
        $now = time();
        foreach ($data as $k => $timestamps) {
            if (!is_array($timestamps) || count(array_filter($timestamps, 'is_int')) !== count($timestamps)) {
                unset($data[$k]);
                continue;
            }
            $data[$k] = array_values(array_filter($timestamps, function ($t) use ($now, $timeFrame) {
                return $t > $now - $timeFrame;
            }));
            if (!$data[$k]) {
                unset($data[$k]);
            }
        }
        $hits = $data[$key] ?? [];
        $limited = count($hits) >= $maxRequests;
        if (!$limited) {
            $hits[] = $now;
            $data[$key] = $hits;
        }
        $encoded = json_encode($data);
        if (!ftruncate($fh, 0) || !rewind($fh) || fwrite($fh, $encoded) !== strlen($encoded) || !fflush($fh)) {
            error_log('Rate limiting is off: cannot write state file');
            return $failClosed;
        }
        return $limited;
    } finally {
        flock($fh, LOCK_UN);
        fclose($fh);
    }
}

/**
 * Sanitize and validate user input as a hostname or IP address.
 * Internationalized names are converted to punycode when the intl
 * extension is available. $allowUnderscore permits DNS-only names such as
 * _dmarc.example.com (valid in DNS, not as a hostname).
 * Returns the cleaned value, or false if invalid.
 */
function iptools_validate_host(string $input, bool $allowUnderscore = false) {
    $input = trim($input);
    if ($input === '' || preg_match('/\s/', $input)) {
        return false;
    }
    if (filter_var($input, FILTER_VALIDATE_IP) !== false) {
        return $input;
    }
    if (preg_match('/[^\x00-\x7F]/', $input)) {
        if (!function_exists('idn_to_ascii')) {
            return false;
        }
        $input = idn_to_ascii($input, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
        if ($input === false) {
            return false;
        }
    }
    if (strlen($input) > 253) {
        return false;
    }
    // Labels never start or end with a hyphen, so nothing can reach a
    // command line looking like an option
    $label = $allowUnderscore
        ? '[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?'
        : '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';
    if (!preg_match('/^' . $label . '(?:\.' . $label . ')*\.?$/', $input)) {
        return false;
    }
    return $input;
}

/**
 * True when the packed address ($bin, from inet_pton) is inside $cidr.
 */
function iptools_ip_in_cidr(string $bin, string $cidr): bool {
    [$net, $bits] = explode('/', $cidr);
    $netBin = inet_pton($net);
    if ($netBin === false || strlen($netBin) !== strlen($bin)) {
        return false;
    }
    $bits  = (int)$bits;
    $bytes = intdiv($bits, 8);
    $rem   = $bits % 8;
    if ($bytes > 0 && strncmp($bin, $netBin, $bytes) !== 0) {
        return false;
    }
    if ($rem === 0) {
        return true;
    }
    $mask = (0xFF << (8 - $rem)) & 0xFF;
    return (ord($bin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask);
}

/**
 * True when the IP is publicly routable (not RFC1918 / loopback /
 * link-local / CGNAT / other special-purpose space). IPv6 forms that
 * embed an IPv4 address are judged by the embedded address.
 */
function iptools_is_public_ip(string $ip): bool {
    $bin = inet_pton($ip);
    if ($bin === false) {
        return false;
    }

    // IPv4-mapped, NAT64 well-known prefix, 6to4: check the IPv4 inside
    if (strlen($bin) === 16) {
        foreach (['::ffff:0:0/96' => 12, '64:ff9b::/96' => 12, '2002::/16' => 2] as $cidr => $offset) {
            if (iptools_ip_in_cidr($bin, $cidr)) {
                return iptools_is_public_ip(inet_ntop(substr($bin, $offset, 4)));
            }
        }
    }

    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }
    if (defined('FILTER_FLAG_GLOBAL_RANGE')
        && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) === false) {
        return false; // PHP 8.2+: the full IANA special-purpose registry
    }

    // Ranges older PHP versions don't treat as private/reserved
    $blocked = [
        '::/96',
        '::ffff:0:0:0/96',
        '192.0.2.0/24',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '100::/64',
        '2001:2::/48',
        '2001:10::/28',
        '2001:20::/28',
        'fec0::/10',
        '3fff::/20',
        '5f00::/16',
        '100.64.0.0/10',  // carrier-grade NAT
        '192.0.0.0/24',   // IETF protocol assignments
        '198.18.0.0/15',  // benchmarking
        '224.0.0.0/4',    // multicast
        '64:ff9b:1::/48', // local-use NAT64
        '2001::/32',      // Teredo (embedded IPv4 is obfuscated)
        '2001:db8::/32',  // documentation
        'fc00::/7',       // unique local
        'fe80::/10',      // link-local
        'ff00::/8',       // multicast
    ];
    foreach ($blocked as $cidr) {
        if (iptools_ip_in_cidr($bin, $cidr)) {
            return false;
        }
    }
    return true;
}

/**
 * SSRF / internal-probe guard for the active network tools (ping,
 * traceroute, mtr). Returns what the probe binary should be pointed at,
 * or false when the target is refused.
 *
 * With $allowPrivate the target passes through untouched (internal
 * deployments may rely on /etc/hosts or search domains). Otherwise the
 * name is resolved here and refused unless it resolves, and every address
 * is public. The probe then gets the IP itself, never the name, so the
 * binary can't resolve it differently: numeric shorthand like "127.1" or
 * "2130706433", /etc/hosts entries, and DNS rebinding all fail closed.
 */
function iptools_resolve_target(string $target, bool $allowPrivate) {
    if ($allowPrivate) {
        return $target;
    }
    if (filter_var($target, FILTER_VALIDATE_IP) !== false) {
        return iptools_is_public_ip($target) ? $target : false;
    }
    $v4 = [];
    $v6 = [];
    foreach ((@dns_get_record($target, DNS_A + DNS_AAAA) ?: []) as $rec) {
        if (!empty($rec['ip']))   { $v4[] = $rec['ip']; }
        if (!empty($rec['ipv6'])) { $v6[] = $rec['ipv6']; }
    }
    $ips = array_merge($v4, $v6); // prefer IPv4, as the probe binaries do
    if (empty($ips)) {
        return false;
    }
    foreach ($ips as $ip) {
        if (!iptools_is_public_ip($ip)) {
            return false;
        }
    }
    return $ips[0];
}

function iptools_capture(string $command, int $maxBytes = 524288): string {
    $maxBytes = max(0, $maxBytes);
    if (!function_exists('proc_open')) {
        return '';
    }
    $process = @proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'],
        2 => ['redirect', 1]], $pipes);
    if (!is_resource($process)) {
        return '';
    }
    fclose($pipes[0]);
    $output = '';
    $truncated = false;
    try {
        while (!feof($pipes[1])) {
            $chunk = fread($pipes[1], 8192);
            if ($chunk === false) {
                break;
            }
            $remaining = $maxBytes - strlen($output);
            $truncated = $truncated || strlen($chunk) > $remaining;
            $output .= substr($chunk, 0, $remaining);
        }
    } finally {
        fclose($pipes[1]);
        proc_close($process);
    }
    if ($truncated) {
        $notice = "\n[output truncated]\n";
        return substr($output, 0, max(0, $maxBytes - strlen($notice)))
            . substr($notice, 0, $maxBytes);
    }
    return $output;
}

/**
 * Shell prefix that kills a command after $seconds, so a hung whois
 * server or black-holed traceroute can't pin a PHP worker. Empty when
 * coreutils timeout isn't available (e.g. Windows).
 */
function iptools_timeout_prefix(int $seconds): string {
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        return '';
    }
    foreach (['/usr/bin/timeout', '/bin/timeout'] as $bin) {
        if (@is_executable($bin)) {
            return escapeshellarg($bin) . ' -k 5 ' . (int)$seconds . ' ';
        }
    }
    return '';
}

/**
 * Append a query log entry to logs/<tool>.log. The logs/ directory is
 * created outside of casual reach: an .htaccess deny-all is dropped in
 * (Apache); on Nginx, block the directory in your server config.
 */
function iptools_log(string $tool, string $message): void {
    $dir = __DIR__ . '/logs';
    if (!file_exists($dir) && !is_link($dir)) {
        @mkdir($dir, 0750);
    }
    if (!iptools_private_dir($dir)) {
        error_log('Query logging is off: unsafe log directory');
        return;
    }
    foreach (['.htaccess' => "Require all denied\n", 'index.html' => ''] as $name => $contents) {
        $guard = iptools_state_open($dir . '/' . $name, 'Query log guard', false);
        if ($guard === false) {
            return;
        }
        if (flock($guard, LOCK_EX)) {
            if (fstat($guard)['size'] === 0) {
                fwrite($guard, $contents);
            }
            flock($guard, LOCK_UN);
        }
        fclose($guard);
    }
    $tool  = preg_replace('/[^a-z0-9_-]/i', '', $tool);
    $entry = date('Y-m-d H:i:s') . ' - ' . ($_SERVER['REMOTE_ADDR'] ?? '-') . ' - ' . $message . "\n";
    $fh = iptools_state_open($dir . '/' . $tool . '.log', 'Query logging is off');
    if ($fh !== false) {
        if (flock($fh, LOCK_EX)) {
            fseek($fh, 0, SEEK_END);
            fwrite($fh, $entry);
            flock($fh, LOCK_UN);
        }
        fclose($fh);
    }
}

/**
 * Escape and colorize tool output for display inside a <pre>.
 *
 * Rules are per tool. "line" rules match against the RAW line and wrap the
 * whole (escaped) line in one span — first match wins. "token" rules run in
 * order against the ESCAPED line (so patterns see &lt; etc.); each carries a
 * guard so later patterns never match inside an already-injected span.
 * Rule format: [pattern-body, pcre-flags, css-class]. Bodies may use \K to
 * highlight only the tail of a match. Unknown tools fall back to plain
 * escaping. Colors only — no bold — so column alignment survives.
 */
function iptools_highlight(string $raw, string $tool): string {
    static $rulesets = null;
    if ($rulesets === null) {
        $rulesets = [
            'ping' => [
                'line' => [
                    ['Destination Host Unreachable|Request timed out|Unknown host|Name or service not known|failure in name resolution|100% packet loss', 'i', 'hl-r'],
                ],
                'token' => [
                    ['\b\d+(?:\.\d+)?/\d+(?:\.\d+)?/\d+(?:\.\d+)?/\d+(?:\.\d+)?', '', 'hl-a'],
                    ['(?:&lt;)?\b\d+(?:\.\d+)? ?ms\b', '', 'hl-a'],
                    ['\b0(?:\.0)?% (?:packet )?loss', '', 'hl-g'],
                    ['\b\d+(?:\.\d+)?% (?:packet )?loss', '', 'hl-r'],
                ],
            ],
            'traceroute' => [
                'line' => [
                    ['^\s*\d+\s+(?:\*\s*)+$', '', 'hl-r'],
                    ['Request timed out|Unable to resolve target', 'i', 'hl-r'],
                ],
                'token' => [
                    ['(?:&lt;)?\b\d+(?:\.\d+)? ms\b', '', 'hl-a'],
                    ['(?<=\s)\*(?=\s|$)', '', 'hl-r'],
                    ['\b\d{1,3}(?:\.\d{1,3}){3}\b', '', 'hl-g'],
                    ['\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]+', '', 'hl-g'],
                    ['^ *\d+(?=\s)', '', 'hl-d'],
                ],
            ],
            'mtr' => [
                'line' => [
                    ['^(?:Start:|HOST:)', '', 'hl-d'],
                ],
                'token' => [
                    ['\?\?\?', '', 'hl-r'],
                    ['\b0\.0%', '', 'hl-g'],
                    ['\b\d+(?:\.\d+)?%', '', 'hl-r'],
                    ['^\s*\d+\.\|--', '', 'hl-d'],
                ],
            ],
            'nslookup' => [
                'line' => [
                    ["can't find|NXDOMAIN|SERVFAIL|REFUSED|No answer|connection timed out|no servers could be reached", 'i', 'hl-r'],
                    ['^Server:\s', '', 'hl-d'],
                    ['^Address:\s+\S+#\d+\s*$', '', 'hl-d'],
                ],
                'token' => [
                    ['\bAddress(?:es)?: *\K[0-9a-fA-F:.]+$', '', 'hl-g'],
                    ['\b(?:name|nameserver|mail exchanger|internet address|text) = \K.*$', '', 'hl-g'],
                ],
            ],
            'whois' => [
                'line' => [
                    ['^\s*(?:No match for|NOT FOUND|No entries found|Domain not found|The queried object does not exist|No Data Found)', 'i', 'hl-r'],
                ],
                'token' => [
                    ['^\s*Domain Name: *\K.*$', 'i', 'hl-a'],
                    ['^\s*Registr(?:y Expiry|ar Registration Expiration) Date: *\K.*$', 'i', 'hl-a'],
                    ['^\s*Name Server: *\K\S.*$', 'i', 'hl-g'],
                    ['\bsignedDelegation\b', '', 'hl-g'],
                    ['\bunsigned\b', 'i', 'hl-a'],
                    ['^ *[A-Za-z][A-Za-z0-9 ._/()-]{0,40}:(?=\s|$)', '', 'hl-d'],
                ],
            ],
        ];
    }

    if (!isset($rulesets[$tool])) {
        return iptools_e($raw);
    }

    $rules = $rulesets[$tool];
    $out   = [];
    foreach (preg_split('/\r\n|\r|\n/', $raw) as $line) {
        $esc     = iptools_e($line);
        $wrapped = false;
        foreach ($rules['line'] as $r) {
            if (preg_match('~(?:' . $r[0] . ')~' . $r[1], $line)) {
                $out[]   = '<span class="' . $r[2] . '">' . $esc . '</span>';
                $wrapped = true;
                break;
            }
        }
        if (!$wrapped) {
            foreach ($rules['token'] as $r) {
                $highlighted = preg_replace(
                    '~(?:' . $r[0] . ')(?![^<]*</span>)~' . $r[1],
                    '<span class="' . $r[2] . '">$0</span>',
                    $esc
                );
                // null = PCRE hit its backtrack limit (huge remote-supplied
                // line); keep the line uncolored rather than blanking it
                if ($highlighted !== null) {
                    $esc = $highlighted;
                }
            }
            $out[] = $esc;
        }
    }
    return implode("\n", $out);
}

/**
 * Open the themed page: doctype, head (with nonce'd CSS), nav, container.
 */
function iptools_page_open(string $title, string $nonce, string $active = ''): void {
    $tools = [
        'whois.php'           => 'whois',
        'nslookup.php'        => 'nslookup',
        'ping.php'            => 'ping',
        'traceroute.php'      => 'trace',
        'mtr.php'             => 'mtr',
        'subnetcalc.php'      => 'calc4',
        'subnetcalc-ipv6.php' => 'calc6',
        'ula_generator.php'   => 'ula',
        'subnets.php'         => 'cheatsheet',
    ];
    $titleEsc = iptools_e($title);
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
    width: 98%;
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
/* The panel hugs its content: snug around the form and small results,
   growing up to the full viewport when output (e.g. whois) demands it */
.container {
    width: fit-content;
    min-width: min(700px, 98%);
    max-width: 98%;
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
/* Forms stay a readable width while output blocks use the full container */
form { text-align: left; max-width: 640px; margin: 0 auto; }
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
    /* Sized to the widest output line so the panel stretches with the
       content; once the panel hits the viewport edge, long lines wrap
       instead of scrolling off-screen */
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    width: max-content;
    min-width: 100%;
    max-width: 100%;
    text-align: left;
    background: var(--panel-deep);
    border: 1px solid var(--brd);
    border-left: 3px solid var(--grn);
    color: var(--ink);
    padding: 12px;
    overflow: auto;
    max-height: 75vh;
    margin-top: 8px;
    font-family: inherit;
    font-size: 0.9em;
}
/* Output highlighting (iptools_highlight): amber = key numbers,
   green = good answers, red = failures, dim = labels/chrome */
pre .hl-a { color: var(--amber); }
pre .hl-g { color: var(--grn); }
pre .hl-r { color: var(--err); }
pre .hl-d { color: var(--dim); }
ul.results { list-style: none; padding: 0; margin: 18px auto 0; max-width: 640px; text-align: left; }
ul.results li { margin-bottom: 6px; padding-left: 18px; }
ul.results li::before { content: "▸ "; color: var(--grn); margin-left: -18px; }
ul.results li strong { color: var(--grn); font-weight: normal; }
table { margin: 12px auto 0; border-collapse: collapse; }
table th, table td { border: 1px solid var(--brd); padding: 6px 16px; }
table th { background: var(--panel-deep); color: var(--grn); font-weight: normal; }
/* Cheat sheet: rows flagged as notable allocations */
tr.hilite th, tr.hilite td {
    background: rgba(255, 176, 0, 0.08);
    color: var(--amber);
    border-color: rgba(255, 176, 0, 0.35);
}
/* Cheat sheet: side-by-side subnet guide panels */
.cheat-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 18px;
    justify-content: center;
    align-items: flex-start;
    margin-top: 12px;
}
.cheat-grid .cheat-panel { text-align: center; }
.cheat-grid .cheat-panel > strong { color: var(--grn); font-weight: normal; }
/* Landing page tool grid */
.tool-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
    gap: 14px;
    margin-top: 20px;
    width: min(880px, 94vw);
}
a.tool-card {
    display: block;
    border: 1px solid var(--brd);
    background: var(--panel-deep);
    padding: 14px 16px;
    text-decoration: none;
    text-align: left;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
}
a.tool-card:hover {
    border-color: var(--grn);
    box-shadow: 0 0 14px rgba(0, 255, 102, 0.25);
}
a.tool-card .tool-name { color: var(--grn); display: block; }
a.tool-card .tool-name::before { content: "./"; color: var(--dim); }
a.tool-card .tool-desc { color: var(--dim); font-size: 0.82em; display: block; margin-top: 6px; }
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
.pre-wrapper { position: relative; margin-top: 8px; min-height: 200px; min-width: min(600px, 100%); }
/* MTR report output stays unwrapped (columns must line up); scrolls instead */
.pre-wrapper pre { min-height: 200px; margin-top: 0; white-space: pre; overflow-wrap: normal; }
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
    .container { width: 100%; min-width: 0; padding: 16px; }
    nav { width: 100%; }
    /* Wrap output on small screens instead of forcing a wide panel */
    pre { font-size: 0.8em; white-space: pre-wrap; width: auto; }
    input[type="submit"] { width: 100%; }
    .readonly-field { min-width: 0; width: 100%; }
}
    <?php
    echo "</style>\n</head>\n<body>\n<nav><a class=\"brand\" href=\"index.php\">iptools://</a>";
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
    echo "</div>\n<footer>iptools v0.1.7 — MIT licensed — [ all systems nominal ]</footer>\n</body>\n</html>\n";
}
