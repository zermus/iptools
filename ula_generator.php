<?php
/*
 * IPTOOLS :: IPv6 ULA generator
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 */
require __DIR__ . '/iptools_common.php';

[$nonce, $csrf] = iptools_boot();

function format_ipv6_address($hex) {
    return implode(':', str_split($hex, 4));
}

$error       = null;
$subnet_size = null;
$results     = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['subnet_size'])) {
    $subnet_size = (int)$_POST['subnet_size'];
    if (!iptools_csrf_ok()) {
        $error = 'Invalid or expired form token. Please resubmit.';
    } elseif ($subnet_size < 48 || $subnet_size > 64) {
        $error = 'Invalid subnet size.';
    } else {
        // Random 40-bit Global ID per RFC 4193 (fd00::/8 + 40 random bits)
        $global_id = bin2hex(random_bytes(5));

        $ula_prefix_hex       = 'fd' . $global_id;
        $ula_prefix_formatted = format_ipv6_address($ula_prefix_hex);

        // First /64 subnet
        $first_subnet = $ula_prefix_formatted . '::/64';

        // Last /64 subnet: set all subnet bits (bits between the prefix and /64)
        $prefix_bin  = inet_pton($ula_prefix_formatted . '::');
        $prefix_int  = gmp_import($prefix_bin, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        $subnet_bits = 64 - $subnet_size;

        $subnet_mask_shifted = gmp_mul(gmp_sub(gmp_pow(2, $subnet_bits), 1), gmp_pow(2, 64));
        $last_subnet_int     = gmp_add($prefix_int, $subnet_mask_shifted);

        $last_subnet_hex = str_pad(gmp_strval($last_subnet_int, 16), 32, '0', STR_PAD_LEFT);
        $last_subnet     = inet_ntop(pack('H*', $last_subnet_hex)) . '/64';

        $results = [
            'prefix'      => $ula_prefix_formatted . '::/' . $subnet_size,
            'num_subnets' => number_format(pow(2, $subnet_bits)),
            'first'       => $first_subnet,
            'last'        => $last_subnet,
        ];
    }
}

iptools_page_open('ula-gen', $nonce, 'ula_generator.php');
?>
    <p class="tagline">RFC 4193 unique local addresses — 40 bits of entropy</p>
    <form method="post">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf); ?>">
        <label for="subnet_size">subnet size</label>
        <select id="subnet_size" name="subnet_size">
            <?php for ($size = 64; $size >= 48; $size--) {
                $count    = number_format(pow(2, 64 - $size));
                $selected = ($subnet_size === $size) ? ' selected' : '';
                echo "<option value=\"{$size}\"{$selected}>/{$size} - {$count} /64" . ($size < 64 ? 's' : '') . "</option>";
            } ?>
        </select>
        <div class="submit-container">
            <input type="submit" value="generate">
        </div>
    </form>
<?php
if ($error !== null) {
    echo "<p class='error-message'>" . htmlspecialchars($error) . "</p>";
} elseif ($results !== null) {
    echo "<div class='output-item'>";
    echo "<span class='out-label'>random ULA allocation</span>";
    echo "<ul class='results'>";
    echo "<li><strong>ULA Prefix:</strong> <input type='text' class='readonly-field copy-on-click' value='" . htmlspecialchars($results['prefix']) . "' readonly></li>";
    echo "<li><strong>/64 Subnets:</strong> " . htmlspecialchars($results['num_subnets']) . "</li>";
    echo "<li><strong>First /64:</strong> <input type='text' class='readonly-field copy-on-click' value='" . htmlspecialchars($results['first']) . "' readonly></li>";
    echo "<li><strong>Last /64:</strong> <input type='text' class='readonly-field copy-on-click' value='" . htmlspecialchars($results['last']) . "' readonly></li>";
    echo "</ul></div>";
    // CSP forbids inline handlers; select-on-click is wired up here instead
    echo "<script nonce=\"{$nonce}\">document.querySelectorAll('.copy-on-click').forEach(function (el) { el.addEventListener('click', function () { this.select(); }); });</script>";
}
iptools_page_close();
