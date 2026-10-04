<?php
/*
 * IPTOOLS :: MTR run-state helpers
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 */

function iptools_mtr_with_lock(string $tempDir, callable $callback) {
    $lock = @fopen(rtrim($tempDir, '/\\') . '/.mtr.lock', 'c');
    if ($lock === false || !@flock($lock, LOCK_EX)) {
        if (is_resource($lock)) {
            fclose($lock);
        }
        return false;
    }

    try {
        return $callback();
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function iptools_mtr_claim(string $tempDir, string $id, int $deadline): bool {
    $prefix = rtrim($tempDir, '/\\') . DIRECTORY_SEPARATOR . 'mtr_' . $id;
    $outputHandle = @fopen($prefix . '.log', 'x');
    if ($outputHandle === false) {
        return false;
    }
    fclose($outputHandle);

    $markerHandle = @fopen($prefix . '.active', 'x');
    if ($markerHandle === false) {
        @unlink($prefix . '.log');
        return false;
    }
    $deadlineValue = (string)$deadline;
    $written = @fwrite($markerHandle, $deadlineValue);
    $flushed = $written === strlen($deadlineValue) && @fflush($markerHandle);
    fclose($markerHandle);
    if (!$flushed) {
        @unlink($prefix . '.active');
        @unlink($prefix . '.log');
        return false;
    }
    return true;
}

function iptools_mtr_deadline(string $marker) {
    $value = @file_get_contents($marker);
    if ($value === false || !preg_match('/^\d+$/', $value)) {
        return false;
    }
    return (int)$value;
}

function iptools_mtr_reserve(string $tempDir, int $maxConcurrent, int $timeout): array {
    $tempDir = rtrim($tempDir, '/\\') . DIRECTORY_SEPARATOR;
    $result = iptools_mtr_with_lock($tempDir, function () use ($tempDir, $maxConcurrent, $timeout) {
        $now = time();
        $active = [];
        foreach (glob($tempDir . 'mtr_*.active') ?: [] as $file) {
            $done = substr($file, 0, -7) . '.done';
            $deadline = iptools_mtr_deadline($file);
            if (is_file($done) || ($deadline !== false && $deadline <= $now)) {
                @unlink($file);
                @unlink($done);
            } elseif (is_file($file)) {
                $active[] = $file;
            }
        }

        if (count($active) >= $maxConcurrent) {
            return ['status' => 'busy'];
        }

        try {
            $id = bin2hex(random_bytes(16));
        } catch (Throwable $error) {
            return ['status' => 'error'];
        }
        if (!iptools_mtr_claim($tempDir, $id, $now + $timeout + 5)) {
            return ['status' => 'error'];
        }

        return ['status' => 'ok', 'id' => $id];
    });

    return $result === false ? ['status' => 'error'] : $result;
}

function iptools_mtr_release(string $tempDir, string $id, bool $removeOutput = false): bool {
    if (!preg_match('/^[0-9a-f]{32}$/', $id)) {
        return false;
    }
    $result = iptools_mtr_with_lock($tempDir, function () use ($tempDir, $id, $removeOutput) {
        $prefix = rtrim($tempDir, '/\\') . DIRECTORY_SEPARATOR . 'mtr_' . $id;
        @unlink($prefix . '.active');
        @unlink($prefix . '.done');
        if ($removeOutput) {
            @unlink($prefix . '.log');
        }
        return true;
    });
    return $result === true;
}

function iptools_mtr_launch(string $command, string $tempDir, string $id): bool {
    if (!preg_match('/^[0-9a-f]{32}$/', $id)) {
        return false;
    }
    $prefix = rtrim($tempDir, '/\\') . DIRECTORY_SEPARATOR . 'mtr_' . $id;
    $output = $prefix . '.log';
    $wrapper = '(' . $command . ') > ' . escapeshellarg($output)
        . ' 2>&1; touch -- ' . escapeshellarg($prefix . '.done');
    $lines = [];
    $status = 1;
    @exec('(' . $wrapper . ') > /dev/null 2>&1 &', $lines, $status);
    if ($status !== 0) {
        iptools_mtr_release($tempDir, $id, true);
        return false;
    }
    return true;
}

function iptools_mtr_status(string $tempDir, string $id): array {
    if (!preg_match('/^[0-9a-f]{32}$/', $id)) {
        return ['status' => 'missing', 'output' => ''];
    }

    $tempDir = rtrim($tempDir, '/\\') . DIRECTORY_SEPARATOR;
    $result = iptools_mtr_with_lock($tempDir, function () use ($tempDir, $id) {
        $prefix = $tempDir . 'mtr_' . $id;
        $marker = $prefix . '.active';
        $done = $prefix . '.done';
        if (is_file($marker)) {
            $deadline = iptools_mtr_deadline($marker);
            if ($deadline === false) {
                return ['status' => 'error', 'output' => ''];
            }
            if (is_file($done) || $deadline <= time()) {
                @unlink($marker);
                @unlink($done);
            }
        }
        if (!is_file($prefix . '.log')) {
            return ['status' => 'missing', 'output' => ''];
        }
        $output = @file_get_contents($prefix . '.log');
        if ($output === false) {
            return ['status' => 'error', 'output' => ''];
        }
        return [
            'status' => is_file($marker) ? 'running' : 'complete',
            'output' => $output,
        ];
    });

    return $result === false ? ['status' => 'error', 'output' => ''] : $result;
}
