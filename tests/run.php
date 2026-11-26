<?php
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/mtr_runtime.php';
require dirname(__DIR__) . '/iptools_common.php';

$failures = 0;
$tests = 0;

function check(bool $condition, string $message): void {
    global $failures, $tests;
    $tests++;
    if (!$condition) {
        $failures++;
        fwrite(STDERR, "FAIL: {$message}\n");
    }
}

function test_dir(): string {
    $dir = sys_get_temp_dir() . '/iptools_mtr_test_' . bin2hex(random_bytes(8));
    mkdir($dir, 0700);
    return $dir;
}

function remove_dir(string $dir): void {
    foreach (array_merge(glob($dir . '/*') ?: [], glob($dir . '/.*') ?: []) as $file) {
        if (basename($file) !== '.' && basename($file) !== '..') {
            is_dir($file) ? rmdir($file) : unlink($file);
        }
    }
    rmdir($dir);
}

// The HTTP test server below runs with mkdir() disabled and its own sys_temp_dir. So the suite's runtime
// directories must exist before it starts: logs/ for query logging, and tmp/ so this process and the server
// share one state directory (probe slots, rate limits). A fresh checkout has neither. Create them for this
// run if missing, and remove them again afterwards.
$createdRuntimeDirs = [];
foreach (['tmp', 'logs'] as $name) {
    $dir = dirname(__DIR__) . '/' . $name;
    if (!is_dir($dir)) {
        mkdir($dir, 0700);
        $createdRuntimeDirs[] = $dir;
    }
}
register_shutdown_function(function () use ($createdRuntimeDirs) {
    foreach ($createdRuntimeDirs as $dir) {
        if (is_dir($dir)) {
            remove_dir($dir);
        }
    }
});

$buildScript = file_get_contents(dirname(__DIR__) . '/build-release.sh');
$hasBuildVersion = preg_match('/^VERSION="([0-9]+\.[0-9]+\.[0-9]+)"\r?$/m', $buildScript, $buildVersion) === 1;
check($hasBuildVersion, 'release builder declares a version');
ob_start();
iptools_page_close();
$footer = ob_get_clean();
check($hasBuildVersion && strpos($footer, '<footer>iptools v' . $buildVersion[1] . ' —') !== false,
    'rendered footer matches the release build version');

$httpState = [];
foreach (['whois', 'nslookup', 'ping', 'traceroute', 'subnetcalc'] as $tool) {
    foreach ([$tool, $tool . '-burst'] as $key) {
        $file = iptools_state_dir() . '/iptools_ratelimit_' . $key . '.json';
        $httpState[$file] = is_file($file) ? file_get_contents($file) : null;
        if (is_file($file)) { unlink($file); }
    }
}
$httpTemp = test_dir();
$port = random_int(20000, 45000);
$command = 'exec ' . escapeshellarg(PHP_BINARY)
    . ' -d disable_functions=mkdir,exec,proc_open'
    . ' -d ' . escapeshellarg('sys_temp_dir=' . $httpTemp)
    . ' -d ' . escapeshellarg('session.save_path=' . $httpTemp)
    . ' -S 127.0.0.1:' . $port . ' -t ' . escapeshellarg(dirname(__DIR__));
$process = proc_open($command, [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
if (is_resource($process)) {
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    try {
        foreach (['/tests/run.php', '/tests/run.php/extra', '/tests/poller_router.php', '/tests/poller_router.php/extra'] as $path) {
            foreach (['GET', 'POST'] as $method) {
                $context = stream_context_create(['http' => [
                    'method' => $method, 'ignore_errors' => true, 'timeout' => 2,
                ]]);
                $body = false;
                $headers = [];
                for ($attempt = 0; $attempt < 30; $attempt++) {
                    $http_response_header = [];
                    $body = @file_get_contents('http://127.0.0.1:' . $port . $path, false, $context);
                    $headers = $http_response_header;
                    if ($headers !== []) {
                        break;
                    }
                    usleep(50000);
                }
                check(strpos($headers[0] ?? '', '404') !== false && $body === '',
                    "{$method} {$path} is rejected before side effects");
            }
        }
        check((glob($httpTemp . '/*') ?: []) === [] && (glob($httpTemp . '/.*') ?: []) ===
            [$httpTemp . '/.', $httpTemp . '/..'], 'HTTP requests create no test or session artifacts');
        $toolRequest = function (string $tool, array $post = [], string $cookie = '') use ($port): array {
            $context = stream_context_create(['http' => ['ignore_errors' => true,
                'method' => $post ? 'POST' : 'GET',
                'header' => "Cookie: {$cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\n",
                'content' => http_build_query($post)]]);
            $body = file_get_contents('http://127.0.0.1:' . $port . '/' . $tool . '.php', false, $context);
            preg_match('/Set-Cookie:\s*([^;]+)/i', implode("\n", $http_response_header), $match);
            return [$body, $match[1] ?? $cookie];
        };
        $slots = [];
        for ($i = 0; $i < 8; $i++) { $slots[] = iptools_probe_acquire(8); }
        try {
            foreach (['whois', 'nslookup', 'ping', 'traceroute'] as $tool) {
                $files = [iptools_state_dir() . '/iptools_ratelimit_' . $tool . '.json',
                    iptools_state_dir() . '/iptools_ratelimit_' . $tool . '-burst.json'];
                $saved = [];
                foreach ($files as $file) {
                    $saved[$file] = is_file($file) ? file_get_contents($file) : null;
                    if (is_file($file)) { unlink($file); }
                }
                try {
                    [$page, $cookie] = $toolRequest($tool);
                    preg_match('/name="csrf" value="([a-f0-9]+)"/', $page, $match);
                    $token = $match[1] ?? '';
                    [$body] = $toolRequest($tool, ['csrf' => ['bad'], 'domain' => '8.8.8.8', 'queryType' => 'PTR'], $cookie);
                    check(strpos($body, 'Invalid or expired form token') !== false
                        && !file_exists($files[0]) && !file_exists($files[1]),
                        $tool . ' invalid CSRF consumes neither counter and runs no command');
                    for ($i = 0; $i < 5; $i++) {
                        [$body] = $toolRequest($tool, ['csrf' => $token, 'domain' => '8.8.8.8', 'queryType' => 'PTR'], $cookie);
                        check(strpos($body, 'The server is busy. Please try again in a minute.') !== false
                            && strpos($body, '<pre>') === false, $tool . ' shares cap and runs no command when busy');
                    }
                    [$body] = $toolRequest($tool, ['csrf' => $token, 'domain' => '8.8.8.8', 'queryType' => 'PTR'], $cookie);
                    check(strpos($body, 'Rate limit exceeded') !== false && strpos($body, '<pre>') === false,
                        $tool . ' sixth burst request runs no command');
                    $raw = @file_get_contents($files[0]);
                    $state = $raw === false ? null : json_decode($raw, true);
                    $entries = is_array($state) ? ($state[hash('sha256', '127.0.0.1')] ?? null) : null;
                    check(is_array($entries) && count($entries) === 5,
                        $tool . ' burst rejection does not consume hourly counter (valid JSON required)');
                } finally {
                    foreach ($saved as $file => $contents) {
                        if ($contents === null) { if (is_file($file)) { unlink($file); } }
                        else { file_put_contents($file, $contents); }
                    }
                }
            }
        } finally {
            foreach ($slots as $slot) { iptools_probe_release($slot); }
        }
        foreach (['whois', 'nslookup', 'ping', 'traceroute'] as $tool) {
            [$page, $cookie] = $toolRequest($tool);
            preg_match('/name="csrf" value="([a-f0-9]+)"/', $page, $match);
            [$body] = $toolRequest($tool, ['csrf' => $match[1], 'domain' => ['x'], 'queryType' => 'A'], $cookie);
            check(strpos($body, 'Invalid domain') !== false && strpos($body, '<pre>') === false,
                $tool . ' array target rejected without command');
            $slot = iptools_probe_acquire(1);
            check(is_resource($slot), $tool . ' validation exit releases slot');
            iptools_probe_release($slot);
        }
        [$page, $cookie] = $toolRequest('nslookup');
        preg_match('/name="csrf" value="([a-f0-9]+)"/', $page, $match);
        [$body] = $toolRequest('nslookup', ['csrf' => $match[1], 'domain' => 'example.com', 'queryType' => ['A']], $cookie);
        check(strpos($body, 'Invalid query type.') !== false && strpos($body, '<pre>') === false,
            'array query type rejected before execution');
        [$page, $cookie] = $toolRequest('whois');
        preg_match('/name="csrf" value="([a-f0-9]+)"/', $page, $match);
        [$body] = $toolRequest('whois', ['csrf' => $match[1], 'domain' => '192.0.2.1'], $cookie);
        check(strpos($body, '<pre>') !== false || strpos($body, 'No WHOIS information') !== false,
            'WHOIS command completion renders output or error');
        $slot = iptools_probe_acquire(1);
        check(is_resource($slot), 'command completion/error releases shared slot');
        iptools_probe_release($slot);
        [$page, $cookie] = $toolRequest('subnetcalc');
        preg_match('/name="csrf" value="([a-f0-9]+)"/', $page, $match);
        foreach (['1.2.3.4/0' => '0.0.0.1 - 255.255.255.254', '10.1.2.3/08' => '10.0.0.1 - 10.255.255.254', '1.2.3.4 0.0.0.0' => '0.0.0.1 - 255.255.255.254', '192.0.2.0/31' => '192.0.2.0 - 192.0.2.1', '192.0.2.1/32' => 'N/A'] as $cidr => $expected) {
            [$body] = $toolRequest('subnetcalc', ['csrf' => $match[1], 'cidr' => $cidr], $cookie);
            check(strpos($body, $expected) !== false, 'rendered usable range for ' . $cidr);
        }
        if (!extension_loaded('gmp')) {
            [$body] = $toolRequest('subnets');
            check(strpos($body, 'GMP extension') !== false && strpos($body, '</html>') !== false,
                'cheat sheet reports missing GMP without a partial fatal response');
            [$page, $cookie] = $toolRequest('subnetcalc-ipv6');
            preg_match('/name="csrf" value="([a-f0-9]+)"/', $page, $match);
            [$body] = $toolRequest('subnetcalc-ipv6', ['csrf' => $match[1], 'cidr' => '2606:4700::/64'], $cookie);
            check(strpos($body, 'GMP extension') !== false && strpos($body, '</html>') !== false,
                'IPv6 calculator reports missing GMP cleanly');
        }
        [$page, $cookie] = $toolRequest('ula_generator');
        preg_match('/name="csrf" value="([a-f0-9]+)"/', $page, $match);
        for ($size = 48; $size <= 64; $size++) {
            [$body] = $toolRequest('ula_generator', ['csrf' => $match[1], 'subnet_size' => (string)$size], $cookie);
            preg_match_all("/class='readonly-field copy-on-click' value='([^']+)'/", $body, $values);
            $addresses = $values[1];
            $first = isset($addresses[1]) ? inet_pton(explode('/', $addresses[1])[0]) : false;
            $last = isset($addresses[2]) ? inet_pton(explode('/', $addresses[2])[0]) : false;
            $mask = (1 << (64 - $size)) - 1;
            check($first !== false && $last !== false
                && substr($first, 0, 6) === substr($last, 0, 6)
                && substr($first, 6) === str_repeat("\0", 10)
                && substr($last, 6, 2) === pack('n', $mask)
                && substr($last, 8) === str_repeat("\0", 8),
                'ULA /' . $size . ' has exact first/last /64 without GMP');
        }
        if (extension_loaded('gmp')) {
            [$page, $cookie] = $toolRequest('ula_generator');
            preg_match('/name="csrf" value="([a-f0-9]+)"/', $page, $match);
            [$body] = $toolRequest('ula_generator', ['csrf' => $match[1], 'subnet_size' => '48'], $cookie);
            preg_match_all("/class='readonly-field copy-on-click' value='([^']+)'/", $body, $values);
            check(count($values[1]) === 3, 'ULA renders three escaped address values');
            foreach ($values[1] as $value) {
                [$address] = explode('/', html_entity_decode($value, ENT_QUOTES));
                check(inet_ntop(inet_pton($address)) === $address && strpos($value, "'") === false,
                    'ULA address value is normalized and escaped');
            }
            [$page, $cookie] = $toolRequest('subnetcalc-ipv6');
            preg_match('/name="csrf" value="([a-f0-9]+)"/', $page, $match);
            [$body] = $toolRequest('subnetcalc-ipv6', ['csrf' => $match[1], 'cidr' => '2606:4700::/64'], $cookie);
            check(strpos($body, '2606:4700::') !== false && strpos($body, 'Subnet Prefix Length') !== false,
                'GMP IPv6 calculator renders valid result');
            foreach (['::ffff:192.0.2.1/96', 'ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128', '::/0'] as $cidr) {
                [$body] = $toolRequest('subnetcalc-ipv6', ['csrf' => $match[1], 'cidr' => $cidr,
                    'calculate_subnets' => '1'], $cookie);
                check(strpos($body, 'Received Input') !== false, 'GMP calculation accepts ' . $cidr);
                check(substr($cidr, -4) === '/128' ? strpos($body, '<table>') === false
                    : strpos($body, '<table>') !== false, 'derived table respects host route: ' . $cidr);
                if ($cidr === '::/0') check(strpos($body,
                    '340,282,366,920,938,463,463,374,607,431,768,211,456') !== false,
                    'GMP derived counts retain exact grouped 128-bit precision');
            }
        }
        $errors = stream_get_contents($pipes[2]);
        // Disabled side-effect functions make attempted filesystem or process work fail visibly.
        check(strpos($errors, 'Fatal error') === false && strpos($errors, 'Warning:') === false,
            'HTTP requests never reach filesystem or process-launch code');
    } finally {
        proc_terminate($process);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);
        remove_dir($httpTemp);
    }
} else {
    check(false, 'HTTP guard test server starts');
    remove_dir($httpTemp);
}

foreach ($httpState as $file => $contents) {
    if ($contents === null) { if (is_file($file)) { unlink($file); } }
    else { file_put_contents($file, $contents); }
}

$fallbackPreferred = dirname(__DIR__) . '/tmp';
$fallbackBackup = $fallbackPreferred . '-investigation-backup';
rename($fallbackPreferred, $fallbackBackup);
$fallback = null;
$fallbackCreated = false;
try {
    $uid = function_exists('posix_geteuid') ? posix_geteuid() : get_current_user();
    $expected = sys_get_temp_dir() . '/iptools_'
        . substr(hash('sha256', dirname(__DIR__) . ':' . $uid), 0, 16);
    $fallbackCreated = !file_exists($expected);
    $fallback = iptools_state_dir();
    check($fallback === $expected && !is_link($fallback)
        && (fileperms($fallback) & 0777) === 0700, 'missing tmp uses private per-install fallback');
    check(!function_exists('posix_geteuid') || fileowner($fallback) === posix_geteuid(),
        'fallback belongs to effective user');
    if ($fallbackCreated) {
        rmdir($fallback);
        symlink($fallbackBackup, $fallback);
        $refused = false;
        try { iptools_state_dir(); } catch (RuntimeException $error) { $refused = true; }
        check($refused, 'fallback symlink fails closed');
        unlink($fallback);
    }
} finally {
    if ($fallbackCreated && $fallback !== null && is_dir($fallback) && !is_link($fallback)) {
        rmdir($fallback);
    }
    rename($fallbackBackup, $fallbackPreferred);
}

$logName = 'security-test-' . bin2hex(random_bytes(8));
$logDir = dirname(__DIR__) . '/logs';
$guards = [];
foreach (['.htaccess', 'index.html'] as $name) {
    $guards[$name] = is_file($logDir . '/' . $name) ? file_get_contents($logDir . '/' . $name) : null;
    if (is_file($logDir . '/' . $name)) { unlink($logDir . '/' . $name); }
}
try {
    iptools_log($logName, 'test');
    check(file_get_contents($logDir . '/.htaccess') === "Require all denied\n"
        && is_file($logDir . '/index.html'), 'preexisting log directory receives access guards');
    check((fileperms($logDir . '/' . $logName . '.log') & 0777) === 0600, 'query log is private');
} finally {
    unlink($logDir . '/' . $logName . '.log');
    foreach ($guards as $name => $contents) {
        if ($contents === null) { unlink($logDir . '/' . $name); }
        else { file_put_contents($logDir . '/' . $name, $contents); }
    }
}

$targetDir = test_dir();
$target = $targetDir . '/target';
file_put_contents($target, 'untouched');
chmod($target, 0644);
$logPath = $logDir . '/' . $logName . '.log';
symlink($target, $logPath);
iptools_log($logName, 'must not write');
check(file_get_contents($target) === 'untouched' && (fileperms($target) & 0777) === 0644,
    'query log symlink refused without modifying target');
unlink($logPath);
remove_dir($targetDir);

$command = escapeshellarg(PHP_BINARY) . ' -r '
    . escapeshellarg('fwrite(STDOUT, str_repeat("a", 600000)); fwrite(STDERR, "stderr");');
$output = iptools_capture($command);
check(strlen($output) === 524288 && substr($output, -strlen("[output truncated]\n")) === "[output truncated]\n",
    'capture bounds combined stdout/stderr and reports truncation');
check(strlen(iptools_capture($command, 4)) === 4, 'small capture limit stays bounded');
check(iptools_capture(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg('fwrite(STDERR, "err");')) === 'err',
    'capture includes stderr');
$prefix = iptools_timeout_prefix(1);
check($prefix === '' || strpos($prefix, ' -k 5 1 ') !== false, 'timeout has kill-after grace');
check(iptools_e("'\"<>&\xff") === '&#039;&quot;&lt;&gt;&amp;�', 'escaping handles quotes and invalid UTF-8');

if ($prefix !== '' && function_exists('pcntl_signal')) {
    $start = microtime(true);
    $output = iptools_capture($prefix . escapeshellarg(PHP_BINARY) . ' -r '
        . escapeshellarg('pcntl_async_signals(true); pcntl_signal(SIGTERM, SIG_IGN); echo "ready"; while (true) { usleep(100000); }'));
    $elapsed = microtime(true) - $start;
    check(strpos($output, 'ready') !== false && $elapsed >= 5 && $elapsed < 9,
        'timeout escalates TERM-ignoring local process to KILL after five seconds');
}
$code = 'require ' . var_export(dirname(__DIR__) . '/iptools_common.php', true)
    . '; ini_set("session.use_only_cookies", "0"); iptools_start_session(); echo ini_get("session.use_only_cookies");';
check(iptools_capture(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code)) === '1',
    'session startup enforces cookie-only sessions');

$dir = test_dir();
$target = $dir . '/target';
file_put_contents($target, 'unchanged');
chmod($target, 0644);
symlink($target, $dir . '/link');
check(iptools_state_open($dir . '/link', 'test') === false, 'state open refuses symlink');
check(file_get_contents($target) === 'unchanged' && (fileperms($target) & 0777) === 0644,
    'refused symlink leaves target and permissions unchanged');
check(iptools_state_open($target, 'test') === false, 'state open rejects insecure existing mode');
$fh = iptools_state_open($dir . '/private', 'test');
check(is_resource($fh) && (fstat($fh)['mode'] & 0777) === 0600, 'new state descriptor is private');
if (is_resource($fh)) { fclose($fh); }
mkdir($dir . '/directory', 0700);
check(iptools_state_open($dir . '/directory', 'test') === false, 'state refuses nonregular directory');
if (function_exists('posix_mkfifo')) {
    posix_mkfifo($dir . '/fifo', 0600);
    check(iptools_state_open($dir . '/fifo', 'test') === false, 'state refuses FIFO without blocking');
}
mkdir($dir . '/unsafe', 0777);
chmod($dir . '/unsafe', 0777);
check(iptools_state_open($dir . '/unsafe/state', 'test') === false
    && !file_exists($dir . '/unsafe/state'), 'state refuses non-app-controlled parent');
rmdir($dir . '/unsafe');
if (function_exists('posix_geteuid') && posix_geteuid() !== 0) {
    check(iptools_state_open('/etc/hosts', 'test') === false, 'foreign-owned parent and file refused');
}
$mask = umask(0000);
$fh = iptools_state_open($dir . '/umask', 'test');
check(is_resource($fh) && (fstat($fh)['mode'] & 0777) === 0600 && umask() === 0000,
    'private state creation restores permissive umask');
if (is_resource($fh)) { fclose($fh); }
umask($mask);
chmod($target, 0600);
$fh = iptools_state_open($target, 'test');
check(is_resource($fh), 'owned state works after safe permission migration');
if (is_resource($fh)) { fclose($fh); }
remove_dir($dir);

$dir = test_dir();
$id = str_repeat('d', 32);
$mask = umask(0000);
try {
    check(iptools_mtr_claim($dir, $id, time() + 30), 'direct MTR claim succeeds');
    check(umask() === 0000, 'MTR claim restores permissive umask');
} finally {
    umask($mask);
}
foreach (['log', 'active'] as $ext) {
    check((fileperms($dir . '/mtr_' . $id . '.' . $ext) & 0777) === 0600,
        'MTR scratch ' . $ext . ' is private');
}
file_put_contents($dir . '/mtr_' . $id . '.log', str_repeat('x', 600000));
check(strlen(iptools_mtr_status($dir, $id)['output']) === 524288, 'MTR poll output is capped');
check((fileperms($dir . '/.mtr.lock') & 0777) === 0600, 'MTR lock is private');
iptools_mtr_release($dir, $id, true);
remove_dir($dir);

$dir = test_dir();
$first = iptools_mtr_reserve($dir, 2, 30); // session A
$second = iptools_mtr_reserve($dir, 2, 30); // session A, second tab
$third = iptools_mtr_reserve($dir, 2, 30); // session B
check($first['status'] === 'ok' && $second['status'] === 'ok', 'same-session runs reserve distinct global slots');
check($first['id'] !== $second['id'], 'same-session runs receive unique output identities');
check($third['status'] === 'busy', 'cross-session request observes the global concurrency limit');
file_put_contents($dir . '/mtr_' . $first['id'] . '.log', 'first');
file_put_contents($dir . '/mtr_' . $second['id'] . '.log', 'second');
check(iptools_mtr_status($dir, $first['id'])['output'] === 'first', 'first run reads only its output');
check(iptools_mtr_status($dir, $second['id'])['output'] === 'second', 'second run reads only its output');
iptools_mtr_release($dir, $first['id'], true);
$replacement = iptools_mtr_reserve($dir, 2, 30);
check($replacement['status'] === 'ok', 'completed run releases its concurrency slot');
iptools_mtr_release($dir, $second['id'], true);
iptools_mtr_release($dir, $replacement['id'], true);
remove_dir($dir);

$dir = test_dir();
mkdir($dir . '/.mtr.lock');
check(iptools_mtr_reserve($dir, 1, 30)['status'] === 'error', 'lock acquisition failure fails closed');
rmdir($dir . '/.mtr.lock');
rmdir($dir);


$dir = test_dir();
$id = str_repeat('a', 32);
file_put_contents($dir . '/mtr_' . $id . '.active', (string)(time() + 30));
check(!iptools_mtr_claim($dir, $id, time() + 30), 'reservation file collision fails closed');
check(!is_file($dir . '/mtr_' . $id . '.log'), 'failed reservation removes its partial output file');
check(!iptools_mtr_launch('true', $dir, '../invalid'), 'invalid launch identity is rejected');
unlink($dir . '/mtr_' . $id . '.active');
rmdir($dir);

$cheatSheet = file_get_contents(dirname(__DIR__) . '/subnets.php');
check(preg_match("/96\\s*=>\\s*'Equivalent to the entire IPv4 Internet/", $cheatSheet) === 1,
    'IPv4 Internet equivalence belongs to IPv6 /96 (2^32 addresses)');

$dir = test_dir();
$reserved = iptools_mtr_reserve($dir, 1, 30);
$marker = $dir . '/mtr_' . $reserved['id'] . '.active';
file_put_contents($marker, 'corrupt');
check(iptools_mtr_reserve($dir, 1, 30)['status'] === 'busy', 'fresh corrupt marker retains its slot');
touch($marker, time() - 36);
clearstatcache();
check(iptools_mtr_status($dir, $reserved['id'], 30)['status'] === 'complete',
    'expired corrupt marker completes during polling');
file_put_contents($marker, '');
chmod($marker, 0600);
touch($marker, time() - 36);
$replacement = iptools_mtr_reserve($dir, 1, 30);
check($replacement['status'] === 'ok', 'expired corrupt marker cannot permanently leak a slot');
iptools_mtr_release($dir, $reserved['id'], true);
if (isset($replacement['id'])) { iptools_mtr_release($dir, $replacement['id'], true); }
remove_dir($dir);

$standins = dirname(__DIR__) . '/tmp/tools-' . bin2hex(random_bytes(4));
mkdir($standins, 0700);
try {
    foreach (['traceroute', 'traceroute6'] as $binary) {
        file_put_contents($standins . '/' . $binary, "#!/bin/sh\nprintf '%s\\n' '" . $binary . "' \"$@\"\n");
        chmod($standins . '/' . $binary, 0700);
    }
    foreach ([['8.8.8.8', 'traceroute', false], ['2606:4700::1111', 'traceroute6', false],
        ['2606:4700::1111', 'traceroute', true]] as $case) {
        if ($case[2]) unlink($standins . '/traceroute6');
        $code = 'putenv(' . var_export('PATH=' . $standins, true) . ');'
            . '$_SERVER["REQUEST_METHOD"] = "POST"; $_SERVER["REMOTE_ADDR"] = "trace-test";'
            . 'require ' . var_export(dirname(__DIR__) . '/iptools_common.php', true) . ';'
            . 'iptools_start_session(); $_SESSION["iptools_csrf"] = "valid";'
            . '$_POST = ["csrf" => "valid", "domain" => ' . var_export($case[0], true) . '];'
            . '$source = file_get_contents(' . var_export(dirname(__DIR__) . '/traceroute.php', true) . ');'
            . '$source = preg_replace("/require __DIR__[^;]+;/", "", $source);'
            . 'eval("?>" . $source);';
        $body = shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code));
        check(strpos($body, '<pre>' . $case[1]) !== false
            && (strpos($body, '-6') !== false) === $case[2],
            'traceroute selects literal family and available Unix tool: ' . $case[0] . '/' . $case[1]);
    }
} finally {
    remove_dir($standins);
}

foreach (['ping', 'traceroute', 'whois', 'nslookup'] as $tool) {
    foreach (['valid', 'invalid'] as $token) {
        $code = 'session_name("IPTOOLSSESSID"); session_start(); $_SESSION["iptools_csrf"] = "valid";'
            . ' $_SERVER["REQUEST_METHOD"] = "POST"; $_POST = ["csrf" => ' . var_export($token, true)
            . ', "domain" => "invalid input", "queryType" => "A"]; ob_start(); require '
            . var_export(dirname(__DIR__) . '/' . $tool . '.php', true)
            . '; ob_end_clean(); echo session_status() === PHP_SESSION_NONE ? "closed" : "locked";';
        check(shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code)) === 'closed',
            $tool . ' releases session after ' . $token . ' CSRF without reopening during rendering');
    }
}

$timingDir = dirname(__DIR__) . '/tmp/timing-' . bin2hex(random_bytes(4));
mkdir($timingDir, 0700);
try {
    foreach (['ping', 'traceroute', 'whois', 'nslookup'] as $tool) {
        $marker = $timingDir . '/started';
        file_put_contents($timingDir . '/' . $tool, "#!/bin/sh\n/bin/touch " . escapeshellarg($marker)
            . "\n/bin/sleep 2\nprintf 'local output\\n'\n");
        chmod($timingDir . '/' . $tool, 0700);
        $session = 'timing' . bin2hex(random_bytes(8));
        $setup = 'ini_set("session.save_path", ' . var_export($timingDir, true) . ');'
            . 'session_name("IPTOOLSSESSID"); session_id(' . var_export($session, true) . ');';
        $code = $setup . 'session_start(); $_SESSION["iptools_csrf"] = "valid";'
            . 'putenv(' . var_export('PATH=' . $timingDir, true) . ');'
            . '$_SERVER["REQUEST_METHOD"] = "POST"; $_SERVER["REMOTE_ADDR"] = "timing-' . $tool . '";'
            . '$_POST = ["csrf" => "valid", "domain" => "8.8.8.8", "queryType" => "PTR"]; require '
            . var_export(dirname(__DIR__) . '/' . $tool . '.php', true) . ';';
        $worker = proc_open('exec ' . escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code),
            [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $workerPipes);
        $until = microtime(true) + 3;
        while (!is_file($marker) && microtime(true) < $until) { usleep(10000); clearstatcache(); }
        $start = microtime(true);
        $probe = shell_exec(escapeshellarg(PHP_BINARY) . ' -r '
            . escapeshellarg($setup . 'session_start(); echo "available"; session_write_close();'));
        check(is_file($marker) && $probe === 'available' && microtime(true) - $start < 1,
            $tool . ' blocking command does not block a concurrent same-session request');
        foreach ($workerPipes as $pipe) fclose($pipe);
        proc_close($worker);
        if (is_file($marker)) unlink($marker);
    }
} finally {
    remove_dir($timingDir);
}

$dir = test_dir();
$old = str_repeat('a', 32);
$fresh = iptools_mtr_reserve($dir, 1, 30);
$prefix = $dir . '/mtr_' . $old;
file_put_contents($prefix . '.done', '');
touch($prefix . '.done', time() - 4000);
$activeLog = $dir . '/mtr_' . $fresh['id'] . '.log';
touch($activeLog, time() - 4000);
check(iptools_mtr_cleanup($dir, 3600, 30), 'expiry cleanup obtains shared lock');
check(!file_exists($prefix . '.done'), 'expiry cleanup removes old orphan completion markers');
check(file_exists($activeLog), 'expiry cleanup preserves output of a live reservation');
iptools_mtr_release($dir, $fresh['id'], true);
file_put_contents($prefix . '.log', 'old');
touch($prefix . '.log', time() - 4000);
iptools_mtr_cleanup($dir, 3600, 30);
check(!file_exists($prefix . '.log'), 'expiry cleanup removes expired unreserved output');
$code = 'define("IPTOOLS_MTR_TEMP_DIR", ' . var_export($dir . '/', true) . '); require '
    . var_export(dirname(__DIR__) . '/mtr_runtime.php', true) . '; echo iptools_mtr_temp_dir();';
check(shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code)) === $dir . '/',
    'shared MTR directory honors server-side override and normalizes its separator');
remove_dir($dir);

foreach (['reserve', 'poll', 'cleanup'] as $operation) {
    $dir = test_dir();
    $run = iptools_mtr_reserve($dir, 1, 2);
    $prefix = $dir . '/mtr_' . $run['id'];
    file_put_contents($prefix . '.active', 'corrupt');
    $apply = function () use ($operation, $dir, $run) {
        if ($operation === 'reserve') {
            return iptools_mtr_reserve($dir, 1, 2);
        }
        return $operation === 'poll' ? iptools_mtr_status($dir, $run['id'], 2)
            : iptools_mtr_cleanup($dir, 3600, 2);
    };
    $apply();
    check(is_file($prefix . '.active'), $operation . ' preserves fresh corrupt deadline grace');
    touch($prefix . '.active', time() - 8);
    $result = $apply();
    clearstatcache();
    check(!is_file($prefix . '.active'), $operation . ' expires corrupt deadline after grace');
    touch($prefix . '.log', time() - 4000);
    file_put_contents($prefix . '.done', '');
    iptools_mtr_cleanup($dir, 3600, 2);
    check(is_file($prefix . '.log') && is_file($prefix . '.done'),
        $operation . ' cleanup preserves newly completed output despite old log mtime');
    touch($prefix . '.done', time() - 4000);
    iptools_mtr_cleanup($dir, 3600, 2);
    check(!is_file($prefix . '.log') && !is_file($prefix . '.done'),
        $operation . ' cleanup expires old completed output');
    remove_dir($dir);
}

$code = 'define("IPTOOLS_MTR_TIMEOUT", 7); require '
    . var_export(dirname(__DIR__) . '/mtr_runtime.php', true) . '; echo iptools_mtr_timeout();';
check(shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code)) === '7',
    'shared MTR timeout honors server-side override');

$code = '$_SERVER["REQUEST_METHOD"] = "GET"; ob_start(); require '
    . var_export(dirname(__DIR__) . '/subnetcalc-ipv6.php', true) . '; ob_end_clean();'
    . '$inputs = ["::ffff:192.0.2.1/96", "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128",'
    . ' "::ffff:999.0.2.1/96", "::::/64", "::1/129"];'
    . 'foreach ($inputs as $input) echo sanitizeAndValidateIPv6CIDR($input) === false ? "invalid\n" : "valid\n";'
    . 'echo fmt_big("340282366920938463463374607431768211456");';
check(shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code)) ===
    "valid\nvalid\ninvalid\ninvalid\ninvalid\n340,282,366,920,938,463,463,374,607,431,768,211,456",
    'IPv6 semantic validation accepts embedded 49-character CIDR and groups exact large counts');

$source = file_get_contents(dirname(__DIR__) . '/subnetcalc-ipv6.php');
check(strpos($source, 'maxlength="49"') !== false, 'IPv6 input permits the longest embedded CIDR');

$stage = dirname(__DIR__) . '/tmp/package-test-' . bin2hex(random_bytes(4));
mkdir($stage, 0700);
try {
    $expected = ['index.php', 'iptools_common.php', 'mtr.php', 'mtr_output.php', 'mtr_runtime.php',
        'nslookup.php', 'ping.php', 'subnetcalc-ipv6.php', 'subnetcalc.php', 'subnets.php',
        'traceroute.php', 'ula_generator.php', 'whois.php', 'subnets.html', '.htaccess',
        'README.md', 'CHANGELOG.md', 'LICENSE.txt'];
    foreach (array_merge($expected, ['build-release.sh']) as $file) {
        copy(dirname(__DIR__) . '/' . $file, $stage . '/' . $file);
    }
    file_put_contents($stage . '/stray.php', '<?php echo "not shipped";');
    exec('bash ' . escapeshellarg($stage . '/build-release.sh') . ' 2>&1', $buildOutput, $buildExit);
    check($buildExit === 0, 'isolated local archive build succeeds without publishing');
    foreach (['zip', 'tar.gz'] as $extension) {
        $archive = $stage . '/releases/ip-tools-' . $buildVersion[1] . '.' . $extension;
        $entries = [];
        exec(($extension === 'zip' ? 'unzip -Z1 ' : 'tar -tzf ') . escapeshellarg($archive), $entries, $exit);
        $files = array_values(array_filter(array_map('basename', $entries), function ($file) use ($buildVersion) {
            return $file !== 'ip-tools-' . $buildVersion[1];
        }));
        sort($files);
        $sorted = $expected;
        sort($sorted);
        check($exit === 0 && $files === $sorted, $extension . ' contains exactly the allowlisted files, not stray PHP');
    }
} finally {
    if (is_dir($stage . '/releases')) remove_dir($stage . '/releases');
    remove_dir($stage);
}

$dir = test_dir();
$reserved = iptools_mtr_reserve($dir, 1, 1);
file_put_contents($dir . '/mtr_' . $reserved['id'] . '.active', (string)(time() - 1));
check(iptools_mtr_status($dir, $reserved['id'])['status'] === 'complete', 'expired reservation becomes complete without inspecting output size');
check(!is_file($dir . '/mtr_' . $reserved['id'] . '.active'), 'expired reservation marker is removed under lock');
iptools_mtr_release($dir, $reserved['id'], true);
remove_dir($dir);

$dir = test_dir();
$reserved = iptools_mtr_reserve($dir, 1, 5);
check(iptools_mtr_launch("printf 'done'", $dir, $reserved['id']), 'background command launches');
$deadline = microtime(true) + 3;
do {
    usleep(20000);
    $doneFile = $dir . '/mtr_' . $reserved['id'] . '.done';
    if (is_file($doneFile)) {
        check((fileperms($doneFile) & 0777) === 0600, 'MTR done marker is private');
    }
    $status = iptools_mtr_status($dir, $reserved['id']);
} while ($status['status'] === 'running' && microtime(true) < $deadline);
check($status['status'] === 'complete' && $status['output'] === 'done', 'completion removes marker and preserves output');
iptools_mtr_release($dir, $reserved['id'], true);
remove_dir($dir);

$port = random_int(20000, 45000);
$router = __DIR__ . '/poller_router.php';
$command = 'exec ' . escapeshellarg(PHP_BINARY) . ' -S 127.0.0.1:' . $port . ' ' . escapeshellarg($router);
$process = proc_open($command, [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
if (is_resource($process)) {
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $request = function (string $url, string $cookie = ''): array {
        $headers = $cookie === '' ? '' : "Cookie: {$cookie}\r\n";
        $context = stream_context_create(['http' => [
            'ignore_errors' => true,
            'header' => $headers,
        ]]);
        $body = @file_get_contents($url, false, $context);
        return ['body' => (string)$body, 'headers' => $http_response_header ?? []];
    };
    $runId = str_repeat('0', 32);
    $url = 'http://127.0.0.1:' . $port . '/mtr_output.php?run=' . $runId;
    $response = ['body' => '', 'headers' => []];
    for ($attempt = 0; $attempt < 30; $attempt++) {
        usleep(50000);
        $response = $request($url, 'IPTOOLSSESSID=fixedattackerid');
        if (!empty($response['headers'])) {
            break;
        }
    }
    $cookie = implode("\n", array_filter($response['headers'], function ($header) {
        return stripos($header, 'Set-Cookie:') === 0;
    }));
    preg_match('/Set-Cookie:\s*([^;]+)/i', $cookie, $cookieMatch);
    $sessionCookie = $cookieMatch[1] ?? '';
    check(strpos($sessionCookie, 'IPTOOLSSESSID=') === 0, 'poller-first request creates the isolated session cookie');
    check(stripos($cookie, 'fixedattackerid') === false, 'strict mode rejects an uninitialized supplied session id');
    check(stripos($cookie, '; secure') !== false, 'HTTPS poller cookie is Secure');
    check(stripos($cookie, '; httponly') !== false, 'poller cookie is HttpOnly');
    check(stripos($cookie, 'samesite=Lax') !== false, 'poller cookie uses SameSite=Lax');
    check(strpos($response['headers'][0] ?? '', '404') !== false, 'unowned run is rejected');

    $tmpDir = dirname(__DIR__) . '/tmp';
    if (!is_dir($tmpDir)) {
        mkdir($tmpDir, 0700);
    }
    file_put_contents($tmpDir . '/mtr_' . $runId . '.log', '<private>');
    chmod($tmpDir . '/mtr_' . $runId . '.log', 0600);
    $seed = $request('http://127.0.0.1:' . $port . '/seed.php?run=' . $runId, $sessionCookie);
    check(strpos($seed['headers'][0] ?? '', '200') !== false && $seed['body'] === 'seeded',
        'seed succeeds before session ownership assertions');
    $ownedResponse = $request($url, $sessionCookie);
    mkdir($tmpDir . '/alternate', 0700);
    $alternate = iptools_mtr_reserve($tmpDir . '/alternate', 1, 2);
    file_put_contents($tmpDir . '/alternate/mtr_' . $alternate['id'] . '.log', 'alternate-output');
    $request('http://127.0.0.1:' . $port . '/seed.php?run=' . $alternate['id'], $sessionCookie);
    $alternateResponse = $request('http://127.0.0.1:' . $port . '/mtr_output.php?run='
        . $alternate['id'] . '&scratch=alternate', $sessionCookie);
    check(strpos($alternateResponse['body'], 'alternate-output') !== false
        && in_array('X-IPTools-MTR-Status: running', $alternateResponse['headers']),
        'owned HTTP poll reads alternate shared scratch directory');
    iptools_mtr_release($tmpDir . '/alternate', $alternate['id'], true);
    remove_dir($tmpDir . '/alternate');
    $otherResponse = $request($url);
    check(strpos($ownedResponse['body'], '&lt;private&gt;') !== false, 'owning session receives escaped run output');
    check(strpos($otherResponse['body'], 'private') === false, 'another session cannot read run output');
    check(strpos($otherResponse['headers'][0] ?? '', '404') !== false, 'cross-session run request is rejected');
    unlink($tmpDir . '/mtr_' . $runId . '.log');

    $bad = $request('http://127.0.0.1:' . $port . '/mtr_output.php?run%5B%5D=1');
    check(strpos($bad['headers'][0] ?? '', '404') !== false
        && strpos($bad['body'], 'Warning') === false, 'array run is warning-free 404');
    foreach (["Content-Security-Policy: default-src 'none'; frame-ancestors 'none'",
        'X-Frame-Options: DENY', 'Referrer-Policy: no-referrer'] as $header) {
        check(in_array($header, $bad['headers']), 'poller sends ' . $header);
    }
    $admit = function (array $post = [], string $cookie = '', string $route = 'admission.php') use ($port): array {
        $context = stream_context_create(['http' => ['ignore_errors' => true,
            'method' => $post ? 'POST' : 'GET',
            'header' => "Cookie: {$cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\n",
            'content' => http_build_query($post)]]);
        $body = file_get_contents('http://127.0.0.1:' . $port . '/' . $route, false, $context);
        preg_match('/Set-Cookie:\s*([^;]+)/i', implode("\n", $http_response_header), $match);
        return [$body, $match[1] ?? $cookie];
    };
    [$page, $dnsCookie] = $admit([], '', 'dns.php');
    preg_match('/name="csrf" value="([a-f0-9]+)"/', $page, $dnsToken);
    foreach (['1.2.3.4' => '4.3.2.1.in-addr.arpa.', '2001:4860::1' =>
        implode('.', str_split(strrev(bin2hex(inet_pton('2001:4860::1'))))) . '.ip6.arpa.',
        'singlelabel' => 'singlelabel'] as $target => $query) {
        [$body] = $admit(['csrf' => $dnsToken[1], 'domain' => $target,
            'queryType' => $target === 'singlelabel' ? 'A' : 'PTR'], $dnsCookie, 'dns.php');
        check(strpos($body, '-nosearch') !== false && strpos($body, $query) !== false,
            'DNS invocation uses no-search and absolute PTR when applicable: ' . $target);
    }
    $saved = [];
    foreach (['mtr', 'mtr-burst'] as $key) {
        $file = iptools_state_dir() . '/iptools_ratelimit_' . $key . '.json';
        $saved[$file] = is_file($file) ? file_get_contents($file) : null;
        if (is_file($file)) { unlink($file); }
    }
    $hourly = iptools_state_dir() . '/iptools_ratelimit_mtr.json';
    $burst = iptools_state_dir() . '/iptools_ratelimit_mtr-burst.json';
    $runs = [];
    try {
        [$page, $admitCookie] = $admit();
        preg_match('/name="csrf" value="([a-f0-9]+)"/', $page, $match);
        $token = $match[1] ?? '';
        [$body] = $admit(['csrf' => ['bad'], 'domain' => '8.8.8.8'], $admitCookie);
        check(strpos($body, 'Invalid or expired form token') !== false
            && !file_exists($hourly) && !file_exists($burst), 'MTR invalid CSRF consumes no counters');
        mkdir($burst, 0700);
        [$body] = $admit(['csrf' => $token, 'domain' => '8.8.8.8'], $admitCookie);
        check(strpos($body, 'admission storage unavailable') !== false && !file_exists($hourly),
            'MTR unavailable burst state refuses admission before hourly count or launch');
        rmdir($burst);
        for ($i = 0; $i < 4; $i++) {
            [$body] = $admit(['csrf' => $token, 'domain' => '8.8.8.8'], $admitCookie);
            preg_match('/mtr_output\.php\?run=([a-f0-9]{32})/', $body, $run);
            if (isset($run[1])) { $runs[] = $run[1]; }
            check($i < 3 ? isset($run[1]) : strpos($body, 'Rate limit exceeded') !== false,
                'eligible MTR burst admission ' . ($i + 1));
        }
        $state = json_decode(file_get_contents($hourly), true);
        check(count($state[hash('sha256', '127.0.0.1')] ?? []) === 3 && count($runs) === 3,
            'fourth MTR request neither counts hourly nor reserves or launches');
        foreach ($runs as $run) {
            $deadline = microtime(true) + 3;
            do {
                usleep(20000);
                $result = $request('http://127.0.0.1:' . $port . '/mtr_output.php?run=' . $run, $admitCookie);
            } while (in_array('X-IPTools-MTR-Status: running', $result['headers']) && microtime(true) < $deadline);
            check(in_array('X-IPTools-MTR-Status: complete', $result['headers'])
                && strpos($result['body'], '8.8.8.8') !== false, 'local MTR tool launch and owned completion poll');
        }
    } finally {
        foreach ($runs as $run) { iptools_mtr_release($tmpDir, $run, true); }
        foreach ($saved as $file => $contents) {
            if (is_file($file)) { unlink($file); }
            if ($contents !== null) { file_put_contents($file, $contents); chmod($file, 0600); }
        }
    }

    $offResponse = $request($url . '&https=off');
    $offCookie = implode("\n", array_filter($offResponse['headers'], function ($header) {
        return stripos($header, 'Set-Cookie:') === 0;
    }));
    check(stripos($offCookie, '; secure') === false, 'HTTPS=off does not set a Secure cookie');

    foreach (['/tests/poller_router.php', '/tests/poller_router.php/extra', '/poller_router.php/extra'] as $path) {
        $denied = $request('http://127.0.0.1:' . $port . $path);
        check(strpos($denied['headers'][0] ?? '', '404') !== false && $denied['body'] === '',
            'router mode denies direct fixture path ' . $path);
    }
    $context = stream_context_create(['http' => ['ignore_errors' => true,
        'header' => "X-Forwarded-Proto: hTtPs, http\r\n"]]);
    file_get_contents($url . '&https=off', false, $context);
    check(stripos(implode("\n", $http_response_header), '; secure') !== false,
        'trusted comma-separated forwarded HTTPS marks cookie Secure');

    foreach (['&trust=no' => "https", '&trust=yes' => "http, https"] as $options => $proto) {
        $context = stream_context_create(['http' => ['ignore_errors' => true,
            'header' => "X-Forwarded-Proto: {$proto}\r\n"]]);
        file_get_contents($url . '&https=off' . $options, false, $context);
        check(stripos(implode("\n", $http_response_header), '; secure') === false,
            'untrusted proxy or non-HTTPS first token cannot mark cookie secure ' . $options);
    }

    proc_terminate($process);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);
} else {
    check(false, 'PHP test server starts');
}

foreach (['192.0.2.1', '198.51.100.1', '203.0.113.1', '100::1', '2001:2::1',
    '2001:10::1', '2001:20::1', 'fec0::1', '3fff::1', '5f00::1', '::ffff:0:127.0.0.1', '::10.0.0.1', '::127.0.0.1', '::ffff:10.0.0.1', '2002:0a00:0001::1',
    '64:ff9b::a00:1'] as $ip) {
    check(!iptools_is_public_ip($ip), 'refuse nonpublic IP ' . $ip);
}
foreach (['8.8.8.8', '2606:4700:4700::1111', '::ffff:8.8.8.8',
    '64:ff9b::808:808', '2002:0808:0808::1'] as $ip) {
    check(iptools_is_public_ip($ip), 'allow public IP ' . $ip);
}
$_POST = ['array' => ['x'], 'number' => 1, 'string' => 'example.com', 'csrf' => ['x']];
check(iptools_post_string('array') === '' && iptools_post_string('missing') === ''
    && iptools_post_string('number') === '' && iptools_post_string('string') === 'example.com',
    'POST helper accepts strings only');
check(!iptools_csrf_ok(), 'array CSRF is refused');

$_SERVER['REMOTE_ADDR'] = '192.0.2.123';
$tool = 'test-' . bin2hex(random_bytes(8));
$file = iptools_state_dir() . '/iptools_ratelimit_' . $tool . '.json';
try {
    foreach (['{"x":5}', 'not JSON', '5', 'null', '"scalar"',
        '{"x":[1,"2",true],"y":false}'] as $raw) {
        file_put_contents($file, $raw);
        chmod($file, 0600);
        check(iptools_rate_limited($tool, 1, 60) === false, 'malformed state recovers: ' . $raw);
        check(iptools_rate_limited($tool, 1, 60) === true, 'valid requests count after recovery');
    }
    clearstatcache();
    check((fileperms($file) & 0777) === 0600, 'rate state is private');
    unlink($file);
    for ($i = 0; $i < 5; $i++) {
        check(!iptools_rate_limited($tool, 5, 60), 'burst request admitted ' . ($i + 1));
    }
    check(iptools_rate_limited($tool, 5, 60), 'sixth burst request refused');
    unlink($file);
    check(!iptools_rate_limited($tool, 100, 3600), 'hourly request admitted');
    $key = hash('sha256', $_SERVER['REMOTE_ADDR']);
    file_put_contents($file, json_encode([$key => array_fill(0, 100, time())]));
    check(iptools_rate_limited($tool, 100, 3600), 'hourly limit retained');
    unlink($file);
    mkdir($file, 0700);
    $log = test_dir();
    $oldLog = ini_get('error_log');
    ini_set('error_log', $log . '/errors');
    try {
        check(iptools_rate_limited($tool, 1, 60) === false, 'open failure fails open');
        check(strpos(file_get_contents($log . '/errors'), 'Rate limiting is off: cannot open') !== false,
            'open failure logs why rate limiting is off');
        check(iptools_state_dir() === dirname(__DIR__) . '/tmp', 'writable suite tmp preferred even if file fails');
    } finally {
        ini_set('error_log', $oldLog);
        remove_dir($log);
        rmdir($file);
    }
} finally {
    if (is_file($file)) { unlink($file); }
}

$slotFile = iptools_state_dir() . '/.probe_slot_0';
$backup = is_file($slotFile) ? file_get_contents($slotFile) : null;
if (is_file($slotFile)) { unlink($slotFile); }
mkdir($slotFile, 0700);
$log = test_dir();
$oldLog = ini_get('error_log');
ini_set('error_log', $log . '/errors');
try {
    check(iptools_probe_acquire(2) === false, 'slot state open failure refuses admission instead of skipping slot');
    check(strpos(file_get_contents($log . '/errors'), 'Probe admission refused: cannot open') !== false,
        'slot state failure logs reason');
} finally {
    ini_set('error_log', $oldLog);
    remove_dir($log);
    rmdir($slotFile);
    if ($backup !== null) { file_put_contents($slotFile, $backup); chmod($slotFile, 0600); }
}

$preferred = dirname(__DIR__) . '/tmp';
$mode = fileperms($preferred) & 0777;
try {
    chmod($preferred, 0500);
    clearstatcache();
    if (!is_writable($preferred)) {
        $refused = false;
        try { iptools_state_dir(); } catch (RuntimeException $error) { $refused = true; }
        check($refused && iptools_probe_acquire(1) === false,
            'invalid existing storage refuses admission without fallback');
    }
} finally {
    chmod($preferred, $mode);
    clearstatcache();
}

$one = iptools_probe_acquire(2);
$two = iptools_probe_acquire(2);
try {
    check(is_resource($one) && is_resource($two), 'two shared slots admitted');
    check(iptools_probe_acquire(2) === false, 'third shared slot refused');
    clearstatcache();
    check((fileperms(iptools_state_dir() . '/.probe_slot_0') & 0777) === 0600, 'slot state is private');
    $code = 'require ' . var_export(dirname(__DIR__) . '/iptools_common.php', true)
        . '; exit(iptools_probe_acquire(2) === false ? 0 : 1);';
    exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code), $unused, $exit);
    check($exit === 0, 'independent PHP process observes shared contention');
    iptools_probe_release($one);
    $one = iptools_probe_acquire(2);
    check(is_resource($one), 'released slot can be reacquired');
} finally {
    iptools_probe_release($one);
    iptools_probe_release($two);
}
$code = 'require ' . var_export(dirname(__DIR__) . '/iptools_common.php', true)
    . '; $slot = iptools_probe_acquire(1); echo is_resource($slot) ? "held\n" : "failed\n"; flush(); sleep(30);';
$worker = proc_open('exec ' . escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code),
    [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $workerPipes);
if (is_resource($worker)) {
    check(trim(fgets($workerPipes[1])) === 'held' && iptools_probe_acquire(1) === false,
        'worker holds shared lock');
    proc_terminate($worker, 9);
    foreach ($workerPipes as $pipe) { fclose($pipe); }
    proc_close($worker);
    $slot = iptools_probe_acquire(1);
    check(is_resource($slot), 'kernel releases slot after worker death');
    iptools_probe_release($slot);
} else {
    check(false, 'slot worker starts');
}

if ($failures > 0) {
    fwrite(STDERR, "{$failures} of {$tests} checks failed.\n");
    exit(1);
}
echo "All {$tests} checks passed.\n";
if (!extension_loaded('gmp')) {
    echo "Not verified: GMP-enabled cheat sheet and IPv6 calculator execution (GMP unavailable).\n";
}
