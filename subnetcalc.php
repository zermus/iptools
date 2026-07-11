<?php
/*
 * IPTOOLS :: IPv4 subnet calculator
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 */
require __DIR__ . '/iptools_common.php';

/**
 * Configuration
 */
$enableLogging = true; // Log queries to logs/subnetcalc.log
$maxRequests   = 100;  // Rate limit: max requests ...
$timeFrame     = 3600; // ... per this many seconds, per client IP

[$nonce, $csrf] = iptools_boot();

/**
 * Sanitize and validate input as "a.b.c.d/nn" or "a.b.c.d w.x.y.z".
 * Returns the cleaned string, or false if invalid.
 */
function sanitizeInput($input) {
    $sanitizedInput = preg_replace('/\s+/', ' ', trim($input));
    if ($sanitizedInput === '') {
        return false;
    }

    // CIDR notation
    if (preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/', $sanitizedInput, $matches)) {
        $ip   = $matches[1];
        $mask = (int)$matches[2];
        if ($mask > 32 || !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }
        return $sanitizedInput;
    }

    // IP address with subnet mask
    if (preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})\s(\d{1,3}(?:\.\d{1,3}){3})$/', $sanitizedInput, $matches)) {
        $ip         = $matches[1];
        $subnetMask = $matches[2];
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ||
            !filter_var($subnetMask, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }
        // The mask must be contiguous ones followed by zeros
        // (e.g. 255.255.0.255 passes IP validation but is not a valid mask).
        $inverted = ~ip2long($subnetMask) & 0xFFFFFFFF;
        if ((($inverted + 1) & $inverted) !== 0) {
            return false;
        }
        return $sanitizedInput;
    }

    return false;
}

/**
 * Calculate subnet details for validated input.
 */
function calculateSubnetInfo($cidr) {
    if (strpos($cidr, '/') !== false) {
        list($ip, $mask) = explode('/', $cidr);
        $maskLength = (int)$mask;
        // /0 needs special handling: shifting by 32 is undefined behavior
        $maskLong   = $maskLength === 0 ? 0 : ((~0 << (32 - $maskLength)) & 0xFFFFFFFF);
        $subnetMask = long2ip($maskLong);
    } else {
        list($ip, $subnetMask) = explode(' ', $cidr);
        $maskLong   = ip2long($subnetMask) & 0xFFFFFFFF;
        $inverted   = ~$maskLong & 0xFFFFFFFF;
        $maskLength = 32 - (int)round(log($inverted + 1, 2));
    }

    $networkLong   = ip2long($ip) & $maskLong;
    $broadcastLong = $networkLong | (~$maskLong & 0xFFFFFFFF);

    $networkIP   = long2ip($networkLong);
    $broadcastIP = long2ip($broadcastLong);

    if ($maskLength >= 31) {
        $usableRange = 'N/A';
        $usableHosts = $maskLength === 31 ? '2 (point-to-point)' : '1 (host route)';
    } else {
        $usableRange = long2ip($networkLong + 1) . ' - ' . long2ip($broadcastLong - 1);
        $usableHosts = number_format(pow(2, 32 - $maskLength) - 2);
    }

    return [
        'Network IP'         => $networkIP,
        'Broadcast IP'       => $broadcastIP,
        'Subnet Mask'        => $subnetMask,
        'Subnet Mask Length' => '/' . $maskLength,
        'Usable Range'       => $usableRange,
        'Usable Hosts'       => $usableHosts,
    ];
}

$error  = null;
$result = null;
$query  = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!iptools_csrf_ok()) {
        $error = 'Invalid or expired form token. Please resubmit.';
    } elseif (iptools_rate_limited('subnetcalc', $maxRequests, $timeFrame)) {
        $error = 'Rate limit exceeded. Please try again later.';
    } else {
        $query = sanitizeInput((string)($_POST['cidr'] ?? ''));
        if ($query === false) {
            $error = 'Invalid input. Please enter a valid IPv4 CIDR notation or IP address with subnet mask.';
        } else {
            $result = calculateSubnetInfo($query);
            if ($enableLogging) {
                iptools_log('subnetcalc', $query);
            }
        }
    }
}

iptools_page_open('subnetcalc', $nonce, 'subnetcalc.php');
?>
    <p class="tagline">IPv4 subnet math — CIDR or dotted mask</p>
    <form method="post">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf); ?>">
        <label for="cidr">IPv4 CIDR or address + mask</label>
        <input type="text" id="cidr" name="cidr" placeholder="e.g., 192.168.1.0/24 or 192.168.1.0 255.255.255.0" required maxlength="253">
        <div class="submit-container">
            <input type="submit" value="calculate">
        </div>
    </form>
<?php
if ($error !== null) {
    echo "<p class='error-message'>" . htmlspecialchars($error) . "</p>";
} elseif ($result !== null) {
    echo "<div class='output-item'>";
    echo "<span class='out-label'>subnetcalc " . htmlspecialchars($query) . "</span>";
    echo "<ul class='results'>";
    foreach ($result as $key => $value) {
        echo "<li><strong>" . htmlspecialchars($key) . ":</strong> " . htmlspecialchars($value) . "</li>";
    }
    echo "</ul></div>";
}
iptools_page_close();
