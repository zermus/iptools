<?php
/*
 * IPTOOLS :: nslookup
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 */
require __DIR__ . '/iptools_common.php';

/**
 * Configuration
 */
$dnsServer     = '1.1.1.1'; // DNS server used for queries
$enableLogging = true;      // Log queries to logs/nslookup.log
$maxRequests   = 100;       // Rate limit: max requests ...
$timeFrame     = 3600;      // ... per this many seconds, per client IP
$commandTimeout = 20;       // Kill the lookup after this many seconds

// Query types offered in the form. The submitted value is validated
// against this whitelist before ever touching a shell command.
$queryTypes = [
    'A'    => 'A - IPv4 Address',
    'AAAA' => 'AAAA - IPv6 Address',
    'MX'   => 'MX - Mail Exchange',
    'NS'   => 'NS - Name Server',
    'TXT'  => 'TXT - Text Record',
    'PTR'  => 'PTR - Reverse Lookup',
];

$maxConcurrent = 8;
$burstRequests = 5;
$burstWindow = 60;

[$nonce, $csrf] = iptools_boot();

$error     = null;
$output    = null;
$target    = null;
$queryType = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $queryType = iptools_post_string('queryType');
    if (!iptools_csrf_ok()) {
        $error = 'Invalid or expired form token. Please resubmit.';
    } elseif (iptools_rate_limited('nslookup-burst', $burstRequests, $burstWindow)) {
        $error = 'Rate limit exceeded. Please try again later.';
    } elseif (iptools_rate_limited('nslookup', $maxRequests, $timeFrame)) {
        $error = 'Rate limit exceeded. Please try again later.';
    } elseif (($slot = iptools_probe_acquire($maxConcurrent)) === false) {
        $error = 'The server is busy. Please try again in a minute.';
    } else {
        try {
            // Underscores allowed: _dmarc, _domainkey, _mta-sts etc. are DNS names
            $target = iptools_validate_host(iptools_post_string('domain'), true);
            if (!array_key_exists($queryType, $queryTypes)) {
                $error = 'Invalid query type.';
            } elseif ($target === false) {
                $error = 'Invalid domain name or IP address. Please enter a valid input.';
            } elseif ($queryType === 'PTR' && filter_var($target, FILTER_VALIDATE_IP) === false) {
                $error = 'PTR lookups require a valid IPv4 or IPv6 address.';
            } elseif ($queryType !== 'PTR' && filter_var($target, FILTER_VALIDATE_IP) !== false) {
                $error = 'Forward lookups require a domain name, not an IP address (use PTR for reverse).';
            } else {
                $queryValue = $target;

                // Convert PTR targets to their reverse-DNS form
                if ($queryType === 'PTR') {
                    if (filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                        $packed = inet_pton($target);
                        if ($packed === false) {
                            $error = 'Failed to process the IPv6 address.';
                        } else {
                            $hex        = bin2hex($packed);
                            $queryValue = implode('.', str_split(strrev($hex), 1)) . '.ip6.arpa.';
                        }
                    } else {
                        $queryValue = implode('.', array_reverse(explode('.', $target))) . '.in-addr.arpa.';
                    }
                }

                if ($error === null) {
                    $escapedQuery     = escapeshellarg($queryValue);
                    $escapedDnsServer = escapeshellarg($dnsServer);
                    // $queryType is whitelisted above, safe to interpolate
                    $searchOption = PHP_OS_FAMILY === 'Windows' ? '' : '-nosearch ';
                    $output = iptools_capture(iptools_timeout_prefix($commandTimeout)
                        . "nslookup {$searchOption}-type={$queryType} {$escapedQuery} {$escapedDnsServer} 2>&1");

                    if ($output) {
                        if ($enableLogging) {
                            iptools_log('nslookup', $queryType . ' - ' . $target);
                        }
                    } else {
                        $error = 'No response from the DNS server.';
                    }
                }
            }
        } finally {
            iptools_probe_release($slot);
        }
    }
}

iptools_page_open('nslookup', $nonce, 'nslookup.php');
?>
    <p class="tagline">DNS interrogation via <?php echo iptools_e($dnsServer); ?></p>
    <form action="" method="post">
        <input type="hidden" name="csrf" value="<?php echo iptools_e($csrf); ?>">
        <label for="queryType">query type</label>
        <select name="queryType" id="queryType">
            <?php foreach ($queryTypes as $value => $label) { ?>
                <option value="<?php echo iptools_e($value); ?>"<?php echo $value === $queryType ? ' selected' : ''; ?>><?php echo iptools_e($label); ?></option>
            <?php } ?>
        </select>

        <label for="domain">domain / ip address</label>
        <input type="text" id="domain" name="domain" required maxlength="253" placeholder="e.g., example.com or 2001:db8::1">

        <div class="submit-container">
            <input type="submit" value="lookup">
        </div>
    </form>
<?php
if ($error !== null) {
    echo "<p class='error-message'>" . iptools_e($error) . "</p>";
} elseif ($output !== null) {
    echo "<div class='output-item'>";
    echo "<span class='out-label'>nslookup -type=" . iptools_e($queryType) . " " . iptools_e($target) . "</span>";
    echo "<pre>" . iptools_highlight($output, 'nslookup') . "</pre>";
    echo "</div>";
}
iptools_page_close();
