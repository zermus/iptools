<?php
/*
 * IPTOOLS :: whois
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 */
require __DIR__ . '/iptools_common.php';

/**
 * Configuration
 */
$enableLogging = true; // Log queries to logs/whois.log
$maxRequests   = 100;  // Rate limit: max requests ...
$timeFrame     = 3600; // ... per this many seconds, per client IP

[$nonce, $csrf] = iptools_boot();

$error  = null;
$output = null;
$target = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!iptools_csrf_ok()) {
        $error = 'Invalid or expired form token. Please resubmit.';
    } elseif (iptools_rate_limited('whois', $maxRequests, $timeFrame)) {
        $error = 'Rate limit exceeded. Please try again later.';
    } else {
        $target = iptools_validate_host((string)($_POST['domain'] ?? ''));
        if ($target === false) {
            $error = 'Invalid domain name or IP address. Please enter a valid input.';
        } else {
            $escapedTarget = escapeshellarg($target);
            $output = shell_exec("whois $escapedTarget 2>&1");

            if ($output) {
                if ($enableLogging) {
                    iptools_log('whois', $target);
                }
            } else {
                $error = 'No WHOIS information found for ' . $target . '.';
            }
        }
    }
}

iptools_page_open('whois', $nonce, 'whois.php');
?>
    <p class="tagline">registry recon — domains and IP allocations</p>
    <form method="post" action="">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf); ?>">
        <label for="domain">domain / ip address</label>
        <input type="text" name="domain" id="domain" required maxlength="253" placeholder="e.g., example.com or 8.8.8.8">
        <div class="submit-container">
            <input type="submit" value="lookup">
        </div>
    </form>
<?php
if ($error !== null) {
    echo "<p class='error-message'>" . htmlspecialchars($error) . "</p>";
} elseif ($output !== null) {
    echo "<div class='output-item'>";
    echo "<span class='out-label'>whois " . htmlspecialchars($target) . "</span>";
    echo "<pre>" . iptools_highlight($output, 'whois') . "</pre>";
    echo "</div>";
}
iptools_page_close();
