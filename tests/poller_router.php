<?php
$_SERVER['HTTPS'] = ($_GET['https'] ?? 'on') === 'off' ? 'off' : 'on';

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
