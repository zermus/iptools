<?php
/*
 * IPTOOLS :: traceroute
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 */
require __DIR__ . '/iptools_common.php';

/**
 * Configuration
 */
$enableLogging       = true;  // Log queries to logs/traceroute.log
$allowPrivateTargets = false; // Set true to permit tracing to RFC1918/reserved addresses
$maxRequests         = 100;   // Rate limit: max requests ...
$timeFrame           = 3600;  // ... per this many seconds, per client IP
$maxHops             = 20;    // Cap hop count so runs can't hang the request

[$nonce, $csrf] = iptools_boot();

$error  = null;
$output = null;
$target = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!iptools_csrf_ok()) {
        $error = 'Invalid or expired form token. Please resubmit.';
    } elseif (iptools_rate_limited('traceroute', $maxRequests, $timeFrame)) {
        $error = 'Rate limit exceeded. Please try again later.';
    } else {
        $target = iptools_validate_host((string)($_POST['domain'] ?? ''));
        if ($target === false) {
            $error = 'Invalid domain or IP address. Please enter a valid input.';
        } elseif (!iptools_target_allowed($target, $allowPrivateTargets)) {
            $error = 'Target is (or resolves to) a private/reserved address. Probe refused.';
        } else {
            $escapedTarget = escapeshellarg($target);
            $hops          = (int)$maxHops;
            $isWindows     = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';

            if ($isWindows) {
                $cmd = "tracert -h $hops -w 2000 $escapedTarget";
            } else {
                $cmd = "traceroute -m $hops -w 2 $escapedTarget";
            }

            $output = shell_exec($cmd . ' 2>&1');
            if ($output) {
                if ($enableLogging) {
                    iptools_log('traceroute', $target);
                }
            } else {
                $error = 'Traceroute command returned no output.';
            }
        }
    }
}

iptools_page_open('traceroute', $nonce, 'traceroute.php');
?>
    <p class="tagline">hop-by-hop path discovery — max <?php echo (int)$maxHops; ?> hops</p>
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
} elseif ($output !== null) {
    echo "<div class='output-item'>";
    echo "<span class='out-label'>traceroute " . htmlspecialchars($target) . "</span>";
    echo "<pre>" . htmlspecialchars($output) . "</pre>";
    echo "</div>";
}
iptools_page_close();
