<?php
/*
 * IPTOOLS :: ping
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 */
require __DIR__ . '/iptools_common.php';

/**
 * Configuration
 */
$enableLogging       = true;  // Log queries to logs/ping.log
$allowPrivateTargets = false; // Set true to permit pinging RFC1918/reserved addresses
$maxRequests         = 100;   // Rate limit: max requests ...
$timeFrame           = 3600;  // ... per this many seconds, per client IP

[$nonce, $csrf] = iptools_boot();

$error  = null;
$output = null;
$target = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!iptools_csrf_ok()) {
        $error = 'Invalid or expired form token. Please resubmit.';
    } elseif (iptools_rate_limited('ping', $maxRequests, $timeFrame)) {
        $error = 'Rate limit exceeded. Please try again later.';
    } else {
        $target = iptools_validate_host((string)($_POST['domain'] ?? ''));
        if ($target === false) {
            $error = 'Invalid domain or IP address. Please enter a valid input.';
        } elseif (!iptools_target_allowed($target, $allowPrivateTargets)) {
            $error = 'Target is (or resolves to) a private/reserved address. Probe refused.';
        } else {
            $escapedTarget = escapeshellarg($target);
            $isWindows     = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
            $isIPv6        = filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;

            if ($isWindows) {
                $cmd = "ping -n 5 $escapedTarget";
            } elseif ($isIPv6) {
                $cmd = "ping -6 -c 5 $escapedTarget";
            } else {
                $cmd = "ping -c 5 $escapedTarget";
            }

            $output = shell_exec($cmd . ' 2>&1');
            if ($output) {
                if ($enableLogging) {
                    iptools_log('ping', $target);
                }
            } else {
                $error = 'Ping command returned no output.';
            }
        }
    }
}

iptools_page_open('ping', $nonce, 'ping.php');
?>
    <p class="tagline">ICMP echo — 5 packets, straight to the wire</p>
    <form method="post" action="">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf); ?>">
        <label for="domain">target host / ip</label>
        <input type="text" id="domain" name="domain" required maxlength="253" placeholder="e.g., example.com or 8.8.8.8">
        <div class="submit-container">
            <input type="submit" value="ping">
        </div>
    </form>
<?php
if ($error !== null) {
    echo "<p class='error-message'>" . htmlspecialchars($error) . "</p>";
} elseif ($output !== null) {
    echo "<div class='output-item'>";
    echo "<span class='out-label'>ping " . htmlspecialchars($target) . "</span>";
    echo "<pre>" . iptools_highlight($output, 'ping') . "</pre>";
    echo "</div>";
}
iptools_page_close();
