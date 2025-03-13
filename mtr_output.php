<?php
session_start();
$tempFile = __DIR__ . "/tmp/mtr_" . session_id() . ".log";
if (file_exists($tempFile)) {
    readfile($tempFile);
} else {
    echo "No output available yet.";
}
?>
