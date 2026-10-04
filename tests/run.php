<?php
require dirname(__DIR__) . '/mtr_runtime.php';

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
$command = escapeshellarg(PHP_BINARY) . ' -S 127.0.0.1:' . $port . ' ' . escapeshellarg($router);
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
        $response = $request($url, 'PHPSESSID=fixedattackerid');
        if (!empty($response['headers'])) {
            break;
        }
    }
    $cookie = implode("\n", array_filter($response['headers'], function ($header) {
        return stripos($header, 'Set-Cookie:') === 0;
    }));
    preg_match('/Set-Cookie:\s*([^;]+)/i', $cookie, $cookieMatch);
    $sessionCookie = $cookieMatch[1] ?? '';
    check($cookie !== '', 'poller-first request creates a session cookie');
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
    $request('http://127.0.0.1:' . $port . '/seed.php?run=' . $runId, $sessionCookie);
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

    proc_terminate($process);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);
} else {
    check(false, 'PHP test server starts');
}

if ($failures > 0) {
    fwrite(STDERR, "{$failures} of {$tests} checks failed.\n");
    exit(1);
}
echo "All {$tests} checks passed.\n";
