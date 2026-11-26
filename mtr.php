<?php
/*
 * IPTOOLS :: mtr
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 */
require __DIR__ . '/iptools_common.php';
require __DIR__ . '/mtr_runtime.php';

/**
 * Configuration
 */
$tempDir             = iptools_mtr_temp_dir(); // Shared with mtr_output.php; configure in mtr_runtime.php
$expiryTime          = 3600;              // Remove output logs older than this (seconds)
$mtrPath             = '/usr/sbin/mtr';   // Full path to the mtr binary
$mtrUseSudo          = false;             // Most distros let mtr run unprivileged; see README before enabling
$tracerouteTimeout   = iptools_mtr_timeout(); // Shared run deadline (seconds)
$maxConcurrent       = 5;                 // Max mtr runs in flight at once, across all clients
$mtrColumns          = 2000;              // Wide columns so hostnames aren't truncated
$enableLogging       = true;              // Log queries to logs/mtr.log
$allowPrivateTargets = false;             // Set true to permit tracing RFC1918/reserved addresses
$burstRequests       = 3;
$burstWindow         = 60;
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

if (!iptools_private_dir(rtrim($tempDir, '/\\'))) {
    $envErrors[] = $showDiagnostics
        ? 'Temporary directory (' . iptools_e($tempDir) . ') is not writable.'
        : 'Temporary directory is not writable.';
} else {
    foreach (['.htaccess' => "Require all denied\n", 'index.html' => ''] as $name => $contents) {
        $guard = iptools_state_open($tempDir . $name, 'MTR directory guard', false);
        if ($guard === false) {
            $envErrors[] = 'Unable to protect temporary output.';
            break;
        }
        if (flock($guard, LOCK_EX)) {
            if (fstat($guard)['size'] === 0) {
                fwrite($guard, $contents);
            }
            flock($guard, LOCK_UN);
        }
        fclose($guard);
    }
}

if (!@is_executable($mtrPath)) {
    $envErrors[] = $showDiagnostics
        ? 'MTR binary not found or not executable at ' . iptools_e($mtrPath) . '.'
        : 'MTR is not available on this server.';
} elseif ($showDiagnostics) {
    if ($mtrUseSudo) {
        $envErrors[] = 'Prefer cap_net_raw on mtr-packet: unprivileged timeout cannot signal root-owned '
                     . 'sudo mtr; sudo env_reset strips COLUMNS/TERM. The numeric sudoers rule requires '
                     . '<code>$allowPrivateTargets = false</code>.';
        // sudo -l checks the permission without running anything
        exec('sudo -n -l ' . escapeshellarg($mtrPath) . ' -rw -c 10 192.0.2.1 2>&1', $unused, $rc);
        if ($rc !== 0) {
            $envErrors[] = 'The web server user may not run MTR via sudo. Add this line via visudo:<br>'
                         . '<code>' . iptools_e(trim((string)shell_exec('whoami')))
                         . ' ALL=(root) NOPASSWD: ' . iptools_e($mtrPath) . ' ^-rw -c 10 [0-9A-Fa-f\\:.]+$</code>';
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
iptools_mtr_cleanup($tempDir, $expiryTime, $tracerouteTimeout);

// ===== Process Form Submission =====
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!iptools_csrf_ok()) {
        $error = 'Invalid or expired form token. Please resubmit.';
    } elseif (!empty($envErrors)) {
        $error = 'MTR is not available on this server.';
    } elseif (iptools_rate_limited('mtr-burst', $burstRequests, $burstWindow, true)) {
        $error = 'Rate limit exceeded or admission storage unavailable. Please try again later.';
    } elseif (iptools_rate_limited('mtr', $maxRequests, $timeFrame)) {
        $error = 'Rate limit exceeded. Please try again later.';
    } else {
        $target = iptools_validate_host(iptools_post_string('domain'));
        $probe  = $target === false ? false : iptools_resolve_target($target, $allowPrivateTargets);
        if ($target === false) {
            $error = 'Invalid domain or IP address. Please enter a valid value.';
        } elseif ($probe === false) {
            $error = 'Target does not resolve, or resolves to a private/reserved address. Probe refused.';
        } else {
            $reservation = iptools_mtr_reserve($tempDir, $maxConcurrent, $tracerouteTimeout);
            if ($reservation['status'] === 'busy') {
                $error = 'The server is busy with other traces. Please try again in a minute.';
            } elseif ($reservation['status'] !== 'ok') {
                $error = 'Unable to reserve a trace slot. Please try again later.';
            } else {
                $runId = $reservation['id'];
                $cmd = $mtrEnv . iptools_timeout_prefix($tracerouteTimeout) . $mtrCommand
                     . ' -rw -c 10 ' . escapeshellarg($probe);
                if (!iptools_mtr_launch($cmd, $tempDir, $runId)) {
                    $error = 'Unable to start MTR. Please try again later.';
                } else {
                    if (!isset($_SESSION['iptools_mtr_runs']) || !is_array($_SESSION['iptools_mtr_runs'])) {
                        $_SESSION['iptools_mtr_runs'] = [];
                    }
                    $_SESSION['iptools_mtr_runs'][$runId] = time();
                    if (count($_SESSION['iptools_mtr_runs']) > 20) {
                        asort($_SESSION['iptools_mtr_runs']);
                        $_SESSION['iptools_mtr_runs'] = array_slice(
                            $_SESSION['iptools_mtr_runs'],
                            -20,
                            null,
                            true
                        );
                    }
                }
            }
        }

        if ($error === null) {
            if ($enableLogging) {
                iptools_log('mtr', $target);
            }

            // ===== Results page (spinner + Ajax polling) =====
            iptools_page_open('mtr', $nonce, 'mtr.php');
            ?>
            <p class="tagline">tracing <?php echo iptools_e($target);
                echo $probe !== $target ? ' (' . iptools_e($probe) . ')' : ''; ?> — live for <?php echo (int)$tracerouteTimeout; ?>s</p>
            <div class="pre-wrapper">
                <pre id="output">Loading output...</pre>
                <div id="spinner" class="spinner"></div>
            </div>
            <script nonce="<?php echo $nonce; ?>">
                var pollingTimer, cutoffTimer;
                var stopped = false, failures = 0;
                var controller;

                function stopPolling(message) {
                    if (stopped) return;
                    stopped = true;
                    clearTimeout(pollingTimer);
                    clearTimeout(cutoffTimer);
                    if (controller) controller.abort();
                    document.getElementById("spinner").style.display = "none";
                    if (message) document.getElementById("output").textContent = message;
                }

                function fetchOutput() {
                    if (stopped) return;
                    controller = new AbortController();
                    var requestTimer = setTimeout(function () { controller.abort(); }, 10000);
                    fetch("mtr_output.php?run=<?php echo rawurlencode($runId); ?>", {signal: controller.signal})
                        .then(function (response) {
                            var status = response.headers.get("X-IPTools-MTR-Status");
                            if (!response.ok || ["running", "complete"].indexOf(status) === -1) {
                                throw new Error("MTR status unavailable");
                            }
                            return response.text().then(function (data) {
                                return { data: data, status: status };
                            });
                        })
                        .then(function (result) {
                            if (stopped) return;
                            failures = 0;
                            // Only the owned endpoint's recognized, server-escaped fragment is accepted.
                            document.getElementById("output").innerHTML = result.data;
                            if (result.status === "complete") stopPolling();
                        })
                        .catch(function () {
                            if (!stopped && ++failures >= 3) {
                                stopPolling("Unable to fetch MTR output. Please try again.");
                            }
                        })
                        .then(function () {
                            clearTimeout(requestTimer);
                            if (!stopped) pollingTimer = setTimeout(fetchOutput, 5000);
                        });
                }

                window.onload = function () {
                    cutoffTimer = setTimeout(function () {
                        stopPolling("MTR polling timed out. Please try again.");
                    }, <?php echo (int)($tracerouteTimeout + 10) * 1000; ?>);
                    fetchOutput();
                };
                window.addEventListener("pagehide", function () { stopPolling(); });
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
        <input type="hidden" name="csrf" value="<?php echo iptools_e($csrf); ?>">
        <label for="domain">target host / ip</label>
        <input type="text" id="domain" name="domain" required maxlength="253" placeholder="e.g., example.com or 8.8.8.8">
        <div class="submit-container">
            <input type="submit" value="trace">
        </div>
    </form>
<?php
if ($error !== null) {
    echo "<p class='error-message'>" . iptools_e($error) . "</p>";
}
iptools_page_close();
