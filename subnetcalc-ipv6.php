<?php
/*
 * IPTOOLS :: IPv6 subnet calculator
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 */
require __DIR__ . '/iptools_common.php';

/**
 * Configuration
 */
$enableLogging = true; // Log queries to logs/subnetcalc-ipv6.log
$maxRequests   = 100;  // Rate limit: max requests ...
$timeFrame     = 3600; // ... per this many seconds, per client IP

[$nonce, $csrf] = iptools_boot();

/**
 * Sanitize and validate IPv6 CIDR input. Returns the cleaned string or false.
 */
function sanitizeAndValidateIPv6CIDR($input) {
    $sanitizedInput = preg_replace('/\s+/', '', trim($input));
    if ($sanitizedInput === '') {
        return false;
    }
    if (preg_match('/^([a-fA-F0-9:]+)\/(\d{1,3})$/', $sanitizedInput, $matches)) {
        $ip     = $matches[1];
        $subnet = (int)$matches[2];
        if ($subnet <= 128 && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $sanitizedInput;
        }
    }
    return false;
}

/**
 * Expand an IPv6 address to full (uncompressed) notation.
 */
function expand_ipv6_address($ip) {
    $binary = inet_pton($ip);
    if ($binary === false) {
        return $ip;
    }
    return implode(':', str_split(bin2hex($binary), 4));
}

/**
 * Convert an IPv6 address to a GMP integer.
 */
function inet6_to_int($inet6) {
    $packed = inet_pton($inet6);
    if ($packed === false) {
        return false;
    }
    return gmp_init(bin2hex($packed), 16);
}

/**
 * Convert a GMP integer (as decimal string) back to an IPv6 address.
 */
function int_to_inet6($int_str) {
    $hex = str_pad(gmp_strval(gmp_init($int_str, 10), 16), 32, '0', STR_PAD_LEFT);
    return inet_ntop(pack('H*', $hex));
}

/**
 * Calculate subnet details for a validated IPv6 CIDR.
 */
function calculateSubnetInfo($cidr, $display_full) {
    list($network, $subnet) = explode('/', $cidr);
    $subnet = (int)$subnet;

    $network_int = inet6_to_int($network);
    if ($network_int === false) {
        return false;
    }

    $host_bits = 128 - $subnet;

    // Mask down to the true network address, then set all host bits for the end
    $prefix_mask = gmp_mul(gmp_sub(gmp_pow(2, $subnet), 1), gmp_pow(2, $host_bits));
    $network_start = gmp_and($network_int, $prefix_mask);
    $end_int       = gmp_add($network_start, gmp_sub(gmp_pow(2, $host_bits), 1));

    $start_ip = int_to_inet6(gmp_strval($network_start));
    $end_ip   = int_to_inet6(gmp_strval($end_int));

    if ($display_full) {
        $start_ip = expand_ipv6_address($start_ip);
        $end_ip   = expand_ipv6_address($end_ip);
    }

    return [
        'Received Input'       => $cidr,
        'Network'              => $start_ip,
        'Subnet'               => '/' . $subnet,
        'Usable Range'         => $start_ip . ' - ' . $end_ip,
        'Subnet Prefix Length' => $subnet,
    ];
}

$error             = null;
$result            = null;
$query             = null;
$calculate_subnets = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!iptools_csrf_ok()) {
        $error = 'Invalid or expired form token. Please resubmit.';
    } elseif (iptools_rate_limited('subnetcalc-ipv6', $maxRequests, $timeFrame)) {
        $error = 'Rate limit exceeded. Please try again later.';
    } else {
        $display_full      = isset($_POST['display_full']);
        $calculate_subnets = isset($_POST['calculate_subnets']);
        $query             = sanitizeAndValidateIPv6CIDR((string)($_POST['cidr'] ?? ''));

        if ($query === false) {
            $error = 'Invalid input. Please enter a valid IPv6 CIDR notation.';
        } else {
            $result = calculateSubnetInfo($query, $display_full);
            if ($result === false) {
                $error = 'Failed to calculate subnet information. Please ensure the CIDR notation is correct.';
            } elseif ($enableLogging) {
                iptools_log('subnetcalc-ipv6', $query);
            }
        }
    }
}

iptools_page_open('subnetcalc6', $nonce, 'subnetcalc-ipv6.php');
?>
    <p class="tagline">IPv6 subnet math — 128 bits of headroom</p>
    <form method="post">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf); ?>">
        <label for="cidr">IPv6 CIDR notation</label>
        <input type="text" id="cidr" name="cidr" placeholder="e.g., 2606:4700::/32" maxlength="43" required>

        <label><input type="checkbox" name="display_full" value="1"> display addresses in full notation</label>
        <label><input type="checkbox" name="calculate_subnets" value="1"> calculate subnets within the usable range</label>

        <div class="submit-container">
            <input type="submit" value="calculate">
        </div>
    </form>
<?php
if ($error !== null) {
    echo "<p class='error-message'>" . htmlspecialchars($error) . "</p>";
} elseif ($result !== null) {
    echo "<div class='output-item'>";
    echo "<span class='out-label'>subnetcalc6 " . htmlspecialchars($query) . "</span>";
    echo "<ul class='results'>";
    foreach ($result as $key => $value) {
        echo "<li><strong>" . htmlspecialchars($key) . ":</strong> " . htmlspecialchars($value) . "</li>";
    }
    echo "</ul>";

    if ($calculate_subnets) {
        $original_subnet = (int)$result['Subnet Prefix Length'];
        echo "<h4>Subnets within the usable range</h4>";
        echo "<table>";
        echo "<tr><th>Subnet Size</th><th>Number of Subnets</th></tr>";
        for ($smaller_subnet = $original_subnet + 1; $smaller_subnet <= 128; $smaller_subnet++) {
            $num_subnets = gmp_pow(2, $smaller_subnet - $original_subnet);
            $formatted   = number_format((float)gmp_strval($num_subnets), 0, '', ',');
            // number_format loses precision on huge counts; show raw digits instead
            if ($smaller_subnet - $original_subnet > 50) {
                $formatted = gmp_strval($num_subnets);
            }
            echo "<tr><td>/" . (int)$smaller_subnet . "</td><td>" . htmlspecialchars($formatted) . "</td></tr>";
        }
        echo "</table>";
    }
    echo "</div>";
}
iptools_page_close();
