<?php
/*
 * IPTOOLS :: landing page
 * MIT License (c) 2024 Cody Gee — full text in LICENSE.txt
 */
require __DIR__ . '/iptools_common.php';

[$nonce, $csrf] = iptools_boot();

$tools = [
    ['whois.php',           'whois',      'Registry recon — domain and IP WHOIS lookups.'],
    ['nslookup.php',        'nslookup',   'DNS interrogation — A, AAAA, MX, NS, TXT, and PTR records.'],
    ['ping.php',            'ping',       'ICMP echo — 5 packets, IPv4 and IPv6.'],
    ['traceroute.php',      'traceroute', 'Hop-by-hop path discovery to any host.'],
    ['mtr.php',             'mtr',        'My Traceroute — live report mode with loss and latency per hop.'],
    ['subnetcalc.php',      'subnetcalc', 'IPv4 subnet math from CIDR or a dotted mask.'],
    ['subnetcalc-ipv6.php', 'subnetcalc6','IPv6 subnet math — 128 bits of headroom.'],
    ['ula_generator.php',   'ula-gen',    'Random RFC 4193 unique local address prefixes.'],
    ['subnets.php',         'cheatsheet', 'IPv4 + IPv6 subnet reference tables, exact values.'],
];

iptools_page_open('iptools', $nonce, 'index.php');
?>
    <p class="tagline">network recon, self-hosted — pick a tool</p>
    <div class="tool-grid">
        <?php foreach ($tools as $tool) {
            list($file, $name, $desc) = $tool;
            echo "<a class='tool-card' href='" . htmlspecialchars($file) . "'>"
               . "<span class='tool-name'>" . htmlspecialchars($name) . "</span>"
               . "<span class='tool-desc'>" . htmlspecialchars($desc) . "</span>"
               . "</a>\n";
        } ?>
    </div>
<?php
iptools_page_close();
