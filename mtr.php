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
$tracerouteTimeout   = 60;                // Seconds the browser polls for output
$mtrColumns          = 2000;              // Wide columns so hostnames aren't truncated
$enableLogging       = true;              // Log queries to logs/mtr.log
$allowPrivateTargets = false;             // Set true to permit tracing RFC1918/reserved addresses
$maxRequests         = 100;               // Rate limit: max requests ...
$timeFrame           = 3600;              // ... per this many seconds, per client IP

[$nonce, $csrf] = iptools_boot();

// ===== Environment Checks =====
$envErrors = [];

if (!is_dir($tempDir) || !is_writable($tempDir)) {
    $envErrors[] = 'Temporary directory (' . htmlspecialchars($tempDir) . ') is not writable.';
}

$cmdMtrTest = "COLUMNS=$mtrColumns env TERM=xterm sudo " . escapeshellarg($mtrPath) . " --version";
if (!shell_exec($cmdMtrTest)) {
    $envErrors[] = 'MTR is not available or not executable via sudo. '
                 . 'Grant access by adding this line via visudo:<br>'
                 . '<code>apache ALL=(root) NOPASSWD: ' . htmlspecialchars($mtrPath) . '</code>';
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
    } elseif (iptools_rate_limited('mtr', $maxRequests, $timeFrame)) {
        $error = 'Rate limit exceeded. Please try again later.';
    } else {
        $target = iptools_validate_host((string)($_POST['domain'] ?? ''));
        if ($target === false) {
            $error = 'Invalid domain or IP address. Please enter a valid value.';
        } elseif (!iptools_target_allowed($target, $allowPrivateTargets)) {
            $error = 'Target is (or resolves to) a private/reserved address. Probe refused.';
        } else {
            // One output file per session; session ids are sanitized before
            // touching the filesystem in case strict mode is disabled.
            $sid      = preg_replace('/[^a-zA-Z0-9,-]/', '', session_id());
            $tempFile = $tempDir . 'mtr_' . $sid . '.log';

            $escapedTarget = escapeshellarg($target);
            $cmd = "(COLUMNS=$mtrColumns env TERM=xterm sudo " . escapeshellarg($mtrPath)
                 . " -rw -c 10 $escapedTarget) > " . escapeshellarg($tempFile) . " 2>&1 &";
            exec($cmd);

            if ($enableLogging) {
                iptools_log('mtr', $target);
            }

            // ===== Results page (spinner + Ajax polling) =====
            iptools_page_open('mtr', $nonce, 'mtr.php');
            ?>
            <p class="tagline">tracing <?php echo htmlspecialchars($target); ?> — live for <?php echo (int)$tracerouteTimeout; ?>s</p>
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
    echo '</ul><p>Current user: ' . htmlspecialchars(trim((string)shell_exec('whoami'))) . '</p></div>';
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
