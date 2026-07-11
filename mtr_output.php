<?php
/*
 * IPTOOLS :: mtr output poller (companion to mtr.php)
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 */
session_start();

header('Content-Type: text/plain; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

// Sanitize the session id before using it in a filesystem path, in case
// session.use_strict_mode is disabled and the client supplied its own id.
$sid      = preg_replace('/[^a-zA-Z0-9,-]/', '', session_id());
$tempFile = __DIR__ . '/tmp/mtr_' . $sid . '.log';

if ($sid !== '' && is_file($tempFile)) {
    readfile($tempFile);
} else {
    echo 'No output available yet.';
}
