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

// Sanitize the session id before using it in a filesystem path, in case
// session.use_strict_mode is disabled and the client supplied its own id.
$sid      = preg_replace('/[^a-zA-Z0-9,-]/', '', session_id());
$tempFile = __DIR__ . '/tmp/mtr_' . $sid . '.log';

if ($sid !== '' && is_file($tempFile)) {
    echo iptools_highlight((string)file_get_contents($tempFile), 'mtr');
} else {
    echo 'No output available yet.';
}
