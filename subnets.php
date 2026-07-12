<?php
/*
 * IPTOOLS :: IP subnet cheat sheet
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 *
 * All tables are generated, not hand-typed, so every count is exact —
 * including the 128-bit IPv6 numbers (via GMP).
 */
require __DIR__ . '/iptools_common.php';

[$nonce, $csrf] = iptools_boot();

/**
 * Comma-group an arbitrary-precision decimal string.
 */
function fmt_big(string $digits): string {
    return strrev(implode(',', str_split(strrev($digits), 3)));
}

/**
 * Exact 2^$exp as a comma-grouped string.
 */
function pow2(int $exp): string {
    return fmt_big(gmp_strval(gmp_pow(2, $exp)));
}

// Notable IPv6 allocations, flagged in the table
$ipv6Notes = [
    127 => 'Point-to-point link (RFC 6164)',
    104 => 'Equivalent to the entire IPv4 Internet (an IPv4 /0)',
    64  => 'Standard end-user / LAN segment allocation',
    56  => 'Common residential delegation',
    48  => 'Standard business / site allocation',
    32  => 'Standard ISP allocation',
];

iptools_page_open('cheatsheet', $nonce, 'subnets.php');
?>
    <p class="tagline">subnet reference tables — IPv4 and IPv6, exact values</p>

    <h3>IPv4 subnet masks</h3>
    <table>
        <tr><th>Prefix</th><th>Addresses</th><th>Netmask</th><th>Amount of a Class C</th></tr>
        <?php for ($p = 32; $p >= 8; $p--) {
            $addresses = 2 ** (32 - $p);
            $netmask   = long2ip($p === 0 ? 0 : ((~0 << (32 - $p)) & 0xFFFFFFFF));
            $classC    = $addresses >= 256
                ? number_format($addresses / 256)
                : '1/' . number_format(256 / $addresses);
            echo '<tr><th>/' . $p . '</th><td>' . number_format($addresses) . '</td><td>'
               . $netmask . '</td><td>' . $classC . '</td></tr>' . "\n";
        } ?>
    </table>

    <h3>IPv4 subnet guide — carving up a /24</h3>
    <p class="tagline">network / usable range / broadcast, per last octet</p>
    <div class="cheat-grid">
        <?php for ($p = 25; $p <= 30; $p++) {
            $size    = 2 ** (32 - $p);
            $subnets = 256 / $size;
            $hosts   = $size - 2;
            echo "<div class='cheat-panel'><strong>/{$p} — {$subnets} subnets — {$hosts} hosts/subnet</strong>";
            echo "<table><tr><th>Network #</th><th>IP Range</th><th>Broadcast</th></tr>";
            for ($net = 0; $net < 256; $net += $size) {
                $first     = $net + 1;
                $last      = $net + $size - 2;
                $broadcast = $net + $size - 1;
                echo "<tr><td>.{$net}</td><td>.{$first}-.{$last}</td><td>.{$broadcast}</td></tr>";
            }
            echo "</table></div>";
        } ?>
    </div>

    <h3>IPv6 subnets</h3>
    <p class="tagline">
        IPv6 subnetting is a different animal: allocations are driven by route
        aggregation and purpose, not host-count scarcity. Highlighted rows mark
        the allocations you'll actually encounter in the wild.
    </p>
    <table>
        <tr><th>Prefix</th><th>Addresses</th><th>Amount of a /64</th><th>Notes</th></tr>
        <?php for ($p = 128; $p >= 8; $p--) {
            $addresses = pow2(128 - $p);
            if ($p > 64) {
                $of64 = '1/' . pow2($p - 64);
            } elseif ($p === 64) {
                $of64 = '1';
            } else {
                $of64 = pow2(64 - $p);
            }
            $note  = $ipv6Notes[$p] ?? '';
            $class = $note !== '' ? " class='hilite'" : '';
            echo "<tr{$class}><th>/{$p}</th><td>{$addresses}</td><td>{$of64}</td><td>"
               . htmlspecialchars($note) . "</td></tr>\n";
        } ?>
    </table>
<?php
iptools_page_close();
