<?php
/*
 * IPTOOLS :: mtr
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 */
require __DIR__ . '/iptools_common.php';

/**
 * Configuration
 */
$tempDir             = __DIR__ . '/tmp/'; // Directory for temporary MTR output logs
$expiryTime          = 3600;              // Remove output logs older than this (seconds)
$mtrPath             = '/usr/sbin/mtr';   // Full path to the mtr binary
$mtrUseSudo          = false;             // Most distros let mtr run unprivileged; see README before enabling
$tracerouteTimeout   = 60;                // Seconds before a run is killed and the browser stops polling
$maxConcurrent       = 5;                 // Max mtr runs in flight at once, across all clients
$mtrColumns          = 2000;              // Wide columns so hostnames aren't truncated
$enableLogging       = true;              // Log queries to logs/mtr.log
$allowPrivateTargets = false;             // Set true to permit tracing RFC1918/reserved addresses
$maxRequests         = 100;               // Rate limit: max requests ...
$timeFrame           = 3600;              // ... per this many seconds, per client IP
$showDiagnostics     = false;             // Show setup details (paths, web user, sudoers hint) to visitors.
                                          // Enable while installing, then turn it back off.

[$nonce, $csrf] = iptools_boot();

$mtrEnv     = 'COLUMNS=' . (int)$mtrColumns . ' TERM=xterm ';
$mtrCommand = ($mtrUseSudo ? 'sudo -n ' : '') . escapeshellarg($mtrPath);

// ===== Environment Checks =====
// Cheap checks only: no processes are spawned for ordinary page views.
$envErrors = [];

if (!is_dir($tempDir) || !is_writable($tempDir)) {
    $envErrors[] = $showDiagnostics
        ? 'Temporary directory (' . htmlspecialchars($tempDir) . ') is not writable.'
        : 'Temporary directory is not writable.';
} elseif (!is_file($tempDir . '.htaccess')) {
    // Output files must never be fetchable over HTTP (Apache; see README for Nginx)
    @file_put_contents($tempDir . '.htaccess', "Require all denied\n");
    @file_put_contents($tempDir . 'index.html', '');
}

if (!@is_executable($mtrPath)) {
    $envErrors[] = $showDiagnostics
        ? 'MTR binary not found or not executable at ' . htmlspecialchars($mtrPath) . '.'
        : 'MTR is not available on this server.';
} elseif ($showDiagnostics) {
    if ($mtrUseSudo) {
        // sudo -l checks the permission without running anything
        exec('sudo -n -l ' . escapeshellarg($mtrPath) . ' -rw -c 10 192.0.2.1 2>&1', $unused, $rc);
        if ($rc !== 0) {
            $envErrors[] = 'The web server user may not run MTR via sudo. Add this line via visudo:<br>'
                         . '<code>' . htmlspecialchars(trim((string)shell_exec('whoami')))
                         . ' ALL=(root) NOPASSWD: ' . htmlspecialchars($mtrPath) . ' -rw -c 10 *</code>';
        }
    } elseif (!shell_exec($mtrEnv . $mtrCommand . ' --version 2>/dev/null')) {
        $envErrors[] = 'MTR did not run as the web server user. Check that mtr-packet is setuid/has '
                     . 'cap_net_raw, or set <code>$mtrUseSudo = true</code> (see README).';
    }
}

if (!empty($envErrors) && !$showDiagnostics) {
    $envErrors[] = 'Set <code>$showDiagnostics = true</code> in mtr.php for details.';
}

// ===== Cleanup Old Output Logs =====
foreach (glob($tempDir . 'mtr_*.log') ?: [] as $file) {
    if (is_file($file) && (time() - filemtime($file)) > $expiryTime) {
        unlink($file);
    }
}

// ===== Process Form Submission =====
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!iptools_csrf_ok()) {
        $error = 'Invalid or expired form token. Please resubmit.';
    } elseif (!empty($envErrors)) {
        $error = 'MTR is not available on this server.';
    } elseif (iptools_rate_limited('mtr', $maxRequests, $timeFrame)) {
        $error = 'Rate limit exceeded. Please try again later.';
    } else {
        $target = iptools_validate_host((string)($_POST['domain'] ?? ''));
        $probe  = $target === false ? false : iptools_resolve_target($target, $allowPrivateTargets);
        if ($target === false) {
            $error = 'Invalid domain or IP address. Please enter a valid value.';
        } elseif ($probe === false) {
            $error = 'Target does not resolve, or resolves to a private/reserved address. Probe refused.';
        } else {
            // One output file per session, named by a random id rather than
            // the session id so a leaked tmp/ listing can't hijack sessions.
            if (empty($_SESSION['iptools_mtr_id'])) {
                $_SESSION['iptools_mtr_id'] = bin2hex(random_bytes(16));
            }
            $tempFile = $tempDir . 'mtr_' . $_SESSION['iptools_mtr_id'] . '.log';

            // Count runs in flight and claim a slot under a lock. Report mode
            // writes nothing until mtr finishes, so an empty, recent file is
            // a run still going.
            $lock = @fopen($tempDir . '.mtr.lock', 'c');
            if ($lock !== false) {
                flock($lock, LOCK_EX);
            }
            clearstatcache();
            $running = 0;
            foreach (glob($tempDir . 'mtr_*.log') ?: [] as $file) {
                if ($file !== $tempFile && filesize($file) === 0
                    && time() - filemtime($file) <= $tracerouteTimeout + 5) {
                    $running++;
                }
            }

            if ($running >= $maxConcurrent) {
                $error = 'The server is busy with other traces. Please try again in a minute.';
            } else {
                file_put_contents($tempFile, '');
                $cmd = '(' . $mtrEnv . iptools_timeout_prefix($tracerouteTimeout) . $mtrCommand
                     . ' -rw -c 10 ' . escapeshellarg($probe) . ') > ' . escapeshellarg($tempFile) . ' 2>&1 &';
                exec($cmd);
            }

            if ($lock !== false) {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
        }

        if ($error === null) {
            if ($enableLogging) {
                iptools_log('mtr', $target);
            }

            // ===== Results page (spinner + Ajax polling) =====
            iptools_page_open('mtr', $nonce, 'mtr.php');
            ?>
            <p class="tagline">tracing <?php echo htmlspecialchars($target);
                echo $probe !== $target ? ' (' . htmlspecialchars($probe) . ')' : ''; ?> — live for <?php echo (int)$tracerouteTimeout; ?>s</p>
            <div class="pre-wrapper">
                <pre id="output">Loading output...</pre>
                <div id="spinner" class="spinner"></div>
            </div>
            <script nonce="<?php echo $nonce; ?>">
                var pollingInterval;
                var tracerouteTimeout = <?php echo (int)$tracerouteTimeout * 1000; ?>; // ms

                function fetchOutput() {
                    fetch("mtr_output.php")
                        .then(function (response) { return response.text(); })
                        .then(function (data) {
                            // Server-highlighted fragment (escaped server-side)
                            document.getElementById("output").innerHTML = data;
                            if (data.trim() !== "" && !data.includes("No output available yet.")) {
                                document.getElementById("spinner").style.display = "none";
                            }
                        })
                        .catch(function (error) {
                            console.error("Error fetching output:", error);
                        });
                }

                window.onload = function () {
                    fetchOutput();
                    pollingInterval = setInterval(fetchOutput, 5000);
                    setTimeout(function () {
                        clearInterval(pollingInterval);
                        document.getElementById("spinner").style.display = "none";
                    }, tracerouteTimeout);
                };
            </script>
            <?php
            iptools_page_close();
            exit;
        }
    }
}

// ===== Form page =====
iptools_page_open('mtr', $nonce, 'mtr.php');

if (!empty($envErrors)) {
    echo '<div class="error-box"><strong>Environment errors:</strong><ul>';
    foreach ($envErrors as $envError) {
        echo '<li>' . $envError . '</li>'; // messages above are static/escaped
    }
    echo '</ul></div>';
}
?>
    <p class="tagline">my traceroute — 10 cycles, report mode</p>
    <form method="post" action="">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf); ?>">
        <label for="domain">target host / ip</label>
        <input type="text" id="domain" name="domain" required maxlength="253" placeholder="e.g., example.com or 8.8.8.8">
        <div class="submit-container">
            <input type="submit" value="trace">
        </div>
    </form>
<?php
if ($error !== null) {
    echo "<p class='error-message'>" . htmlspecialchars($error) . "</p>";
}
iptools_page_close();
