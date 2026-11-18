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
                    check(count(json_decode(file_get_contents($files[0]), true)[hash('sha256', '127.0.0.1')]) === 5,
                        $tool . ' burst rejection does not consume hourly counter');
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
        foreach (['192.0.2.0/31' => '192.0.2.0 - 192.0.2.1', '192.0.2.1/32' => 'N/A'] as $cidr => $expected) {
            [$body] = $toolRequest('subnetcalc', ['csrf' => $match[1], 'cidr' => $cidr], $cookie);
            check(strpos($body, $expected) !== false, 'rendered usable range for ' . $cidr);
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
    $seed = $request('http://127.0.0.1:' . $port . '/seed.php?run=' . $runId, $sessionCookie);
    check(strpos($seed['headers'][0] ?? '', '200') !== false && $seed['body'] === 'seeded',
        'seed succeeds before session ownership assertions');
    $ownedResponse = $request($url, $sessionCookie);
    $otherResponse = $request($url);
    check(strpos($ownedResponse['body'], '&lt;private&gt;') !== false, 'owning session receives escaped run output');
    check(strpos($otherResponse['body'], 'private') === false, 'another session cannot read run output');
    check(strpos($otherResponse['headers'][0] ?? '', '404') !== false, 'cross-session run request is rejected');
    unlink($tmpDir . '/mtr_' . $runId . '.log');

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
        'header' => "X-Forwarded-Proto: hTtPs\r\n"]]);
    file_get_contents($url . '&https=off', false, $context);
    check(stripos(implode("\n", $http_response_header), '; secure') !== false,
        'case-insensitive forwarded HTTPS marks cookie Secure');

    proc_terminate($process);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);
} else {
    check(false, 'PHP test server starts');
}

foreach (['::10.0.0.1', '::127.0.0.1', '::ffff:10.0.0.1', '2002:0a00:0001::1',
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
    check(iptools_state_dir() === sys_get_temp_dir(), 'unwritable suite tmp falls back to system tmp');
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
    echo "Not verified: GMP-dependent ULA and IPv6 calculator execution (GMP unavailable).\n";
}
