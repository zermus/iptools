<?php
// Only serve as the CLI-launched development server's router, never as a page.
if (PHP_SAPI !== 'cli-server' || preg_match('~(?:^|/)poller_router\.php(?:/|$)~', rawurldecode(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)))) {
    http_response_code(404);
    exit;
}

define('IPTOOLS_TRUST_PROXY', ($_GET['trust'] ?? 'yes') === 'yes');

$_SERVER['HTTPS'] = ($_GET['https'] ?? 'on') === 'off' ? 'off' : 'on';

if (in_array(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), ['/admission.php', '/dns.php'], true)) {
    $dns = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) === '/dns.php';
    $source = file_get_contents(dirname(__DIR__) . ($dns ? '/nslookup.php' : '/mtr.php'));
    // Local stand-ins expose the actual arguments without sending network traffic.
    $source = str_replace("'/usr/sbin/mtr'", "'/bin/echo'", $source);
    $source = str_replace('nslookup {$searchOption}', '/bin/echo {$searchOption}', $source);
    $source = str_replace('__DIR__', var_export(dirname(__DIR__), true), $source);
    eval('?>' . $source);
    exit;
}

if (parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) === '/seed.php') {
    require dirname(__DIR__) . '/iptools_common.php';
    iptools_start_session();
    $id = (string)($_GET['run'] ?? '');
    if (preg_match('/^[0-9a-f]{32}$/', $id) !== 1) {
        http_response_code(400);
        exit;
    }
    $_SESSION['iptools_mtr_runs'] = [$id => time()];
    echo 'seeded';
    exit;
}

require dirname(__DIR__) . '/mtr_output.php';
