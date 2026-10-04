<?php
/*
 * IPTOOLS :: mtr output poller (companion to mtr.php)
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 */
require __DIR__ . '/iptools_common.php';
require __DIR__ . '/mtr_runtime.php';
iptools_start_session();

// Returns a highlighted HTML fragment; escaping happens inside
// iptools_highlight(), so raw MTR output can never inject markup.
header('Content-Type: text/html; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

// A session may own several runs (for example, traces launched in two tabs).
// The requested random run id must still be present in that session's allowlist.
$id = (string)($_GET['run'] ?? '');
$owned = preg_match('/^[0-9a-f]{32}$/', $id) === 1
    && isset($_SESSION['iptools_mtr_runs'])
    && is_array($_SESSION['iptools_mtr_runs'])
    && isset($_SESSION['iptools_mtr_runs'][$id]);
session_write_close(); // don't hold the session lock while polling
if (!$owned) {
    http_response_code(404);
}
$result = $owned
    ? iptools_mtr_status(__DIR__ . '/tmp/', $id)
    : ['status' => 'missing', 'output' => ''];
header('X-IPTools-MTR-Status: ' . $result['status']);

if ($result['output'] !== '') {
    echo iptools_highlight($result['output'], 'mtr');
} elseif ($result['status'] === 'complete') {
    echo 'MTR completed without output.';
} elseif ($result['status'] === 'error') {
    echo 'Unable to read MTR status.';
} else {
    echo 'No output available yet.';
}
