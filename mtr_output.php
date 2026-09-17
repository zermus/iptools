<?php
/*
 * IPTOOLS :: mtr output poller (companion to mtr.php)
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 */
require __DIR__ . '/iptools_common.php'; // functions only, no side effects
session_start();

// Returns a highlighted HTML fragment; escaping happens inside
// iptools_highlight(), so raw MTR output can never inject markup.
header('Content-Type: text/html; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

// The output file is named by a random id mtr.php stored in the session
// (never the session id itself, which must not appear on disk).
$id       = (string)($_SESSION['iptools_mtr_id'] ?? '');
$tempFile = __DIR__ . '/tmp/mtr_' . $id . '.log';
session_write_close(); // don't hold the session lock while polling

if (preg_match('/^[0-9a-f]{32}$/', $id) && is_file($tempFile)) {
    echo iptools_highlight((string)file_get_contents($tempFile), 'mtr');
} else {
    echo 'No output available yet.';
}
