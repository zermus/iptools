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
        return $ip . '/' . $mask;
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
        $bits = implode('', array_map(function ($octet) {
            return str_pad(decbin((int)$octet), 8, '0', STR_PAD_LEFT);
        }, explode('.', $subnetMask)));
        if (!preg_match('/^1*0*$/', $bits)) {
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
        $maskOctets = [];
        for ($i = 0; $i < 4; $i++) {
            $ones = max(0, min(8, $maskLength - $i * 8));
            $maskOctets[] = $ones === 0 ? 0 : (0xff << (8 - $ones)) & 0xff;
        }
        $subnetMask = implode('.', $maskOctets);
    } else {
        list($ip, $subnetMask) = explode(' ', $cidr);
        $maskOctets = array_map('intval', explode('.', $subnetMask));
        $maskLength = 0;
        foreach ($maskOctets as $octet) {
            $maskLength += substr_count(decbin($octet), '1');
        }
    }

    $octets = array_map('intval', explode('.', $ip));
    $network = $broadcast = [];
    foreach ($octets as $i => $octet) {
        $network[] = $octet & $maskOctets[$i];
        $broadcast[] = $network[$i] | (0xff ^ $maskOctets[$i]);
    }
    $networkIP = implode('.', $network);
    $broadcastIP = implode('.', $broadcast);

    if ($maskLength >= 31) {
        $usableRange = $maskLength === 31 ? $networkIP . ' - ' . $broadcastIP : 'N/A';
        $usableHosts = $maskLength === 31 ? '2 (point-to-point)' : '1 (host route)';
    } else {
        $network[3]++;
        $broadcast[3]--;
        $usableRange = implode('.', $network) . ' - ' . implode('.', $broadcast);
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
        $query = sanitizeInput(iptools_post_string('cidr'));
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
        <input type="hidden" name="csrf" value="<?php echo iptools_e($csrf); ?>">
        <label for="cidr">IPv4 CIDR or address + mask</label>
        <input type="text" id="cidr" name="cidr" placeholder="e.g., 192.168.1.0/24 or 192.168.1.0 255.255.255.0" required maxlength="253">
        <div class="submit-container">
            <input type="submit" value="calculate">
        </div>
    </form>
<?php
if ($error !== null) {
    echo "<p class='error-message'>" . iptools_e($error) . "</p>";
} elseif ($result !== null) {
    echo "<div class='output-item'>";
    echo "<span class='out-label'>subnetcalc " . iptools_e($query) . "</span>";
    echo "<ul class='results'>";
    foreach ($result as $key => $value) {
        echo "<li><strong>" . iptools_e($key) . ":</strong> " . iptools_e($value) . "</li>";
    }
    echo "</ul></div>";
}
iptools_page_close();
