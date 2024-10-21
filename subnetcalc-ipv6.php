<!DOCTYPE html>
<!--
MIT License

Copyright (c) 2024 Cody Gee

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
-->
<html>
<head>
    <title>IPv6 Subnet Calculator</title>
    <style>
        body {
            background-color: #292929;
            color: white;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            text-align: center; /* Center all content */
        }

        .container {
            display: inline-block;
            padding: 20px;
            border-radius: 8px;
            background-color: #333333;
        }

        h2 {
            margin-top: 0;
        }

        form {
            margin-top: 20px;
        }

        label {
            display: block;
            margin-bottom: 5px;
        }

        input[type="text"],
        input[type="submit"],
        select {
            padding: 8px 15px;
            border-radius: 4px;
            border: 1px solid #444444;
            background-color: #555555;
            color: white;
            margin-bottom: 10px;
            transition: background-color 0.3s ease;
            text-align: center; /* Center text inside inputs */
            width: auto;
            display: inline-block;
        }

        input[type="text"]:hover,
        input[type="text"]:focus,
        select:hover,
        select:focus {
            background-color: #444444;
            border-color: #0000AA;
            outline: none;
        }

        input[type="submit"]:hover {
            background-color: #777777;
        }

        .output-item {
            margin-bottom: 15px;
            text-align: center;
        }

        .output-item label {
            display: block;
            margin-bottom: 5px;
        }

        table {
            margin: 0 auto;
            border-collapse: collapse;
            width: auto;
        }

        table th,
        table td {
            border: 1px solid #555555;
            padding: 8px 15px;
            text-align: center;
        }

        table th {
            background-color: #444444;
        }

        @media screen and (max-width: 600px) {
            input[type="text"],
            input[type="submit"],
            select {
                width: 100%;
            }

            table th,
            table td {
                font-size: 12px;
                padding: 6px 10px;
            }
        }
    </style>
</head>
<body>

<div class="container">
    <h2>IPv6 Subnet Calculator</h2>

    <form method="post">
        <label for="cidr">Enter IPv6 CIDR Notation:</label>
        <input type="text" id="cidr" name="cidr" placeholder="e.g., 2606:4700::/32" size="43" maxlength="43">
        <label><input type="checkbox" name="display_full" value="1"> Display IPv6 addresses in full notation</label>
        <label><input type="checkbox" name="calculate_subnets" value="1"> Calculate subnets within the usable range</label>
        <input type="submit" value="Calculate">
    </form>

    <?php
    function sanitizeAndValidateIPv6CIDR($input) {
        if (empty($input)) {
            return false;
        }

        if (preg_match('/^([a-fA-F0-9:]+)\/(\d{1,3})$/', trim($input), $matches)) {
            $network = $matches[1];
            $subnet = (int)$matches[2];

            if (filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) &&
                $subnet >= 0 && $subnet <= 128) {
                return $input;
            }
        }
        return false;
    }

    function expand_ipv6_address($ip) {
        $binary = inet_pton($ip);
        $hex = unpack('H*', $binary)[1];
        return implode(':', str_split($hex, 4));
    }

    function format_large_number($number_str) {
        return number_format($number_str, 0, '', ',');
    }

    function calculateSubnetInfo($cidr, $display_full) {
        list($network, $subnet) = explode('/', $cidr);
        $subnet = (int)$subnet;

        $network_bin = inet_pton($network);
        if ($network_bin === false) {
            return false;
        }

        $subnet_mask_bin = str_repeat("\xff", $subnet >> 3);
        if ($subnet % 8) {
            $subnet_mask_bin .= chr((0xff << (8 - ($subnet % 8))) & 0xff);
        }
        $subnet_mask_bin = str_pad($subnet_mask_bin, 16, "\x00");

        $start_bin = $network_bin & $subnet_mask_bin;
        $end_bin = $network_bin | ~$subnet_mask_bin;

        $start_ip = inet_ntop($start_bin);
        $end_ip = inet_ntop($end_bin);

        if ($display_full) {
            $network = expand_ipv6_address($network);
            $start_ip = expand_ipv6_address($start_ip);
            $end_ip = expand_ipv6_address($end_ip);
        }

        return [
            'Received Input' => $cidr,
            'Network' => $network,
            'Subnet' => '/' . $subnet,
            'Usable Range' => $start_ip . ' - ' . $end_ip,
            'Subnet Prefix Length' => $subnet,
        ];
    }

    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["cidr"])) {
        $cidrNotation = $_POST["cidr"];
        $display_full = isset($_POST['display_full']);
        $calculate_subnets = isset($_POST['calculate_subnets']);

        $validatedInput = sanitizeAndValidateIPv6CIDR($cidrNotation);

        if ($validatedInput !== false) {
            $result = calculateSubnetInfo($validatedInput, $display_full);

            if ($result !== false) {
                echo "<div class='result-section'>";

                foreach ($result as $key => $value) {
                    if ($key != 'Subnet Prefix Length') {
                        $size = strlen($value);
                        echo "<div class='output-item'>";
                        echo "<label>" . htmlspecialchars($key) . ":</label>";
                        echo "<input type='text' value='" . htmlspecialchars($value) . "' size='$size' readonly>";
                        echo "</div>";
                    }
                }

                if ($calculate_subnets) {
                    $original_subnet = (int)$result['Subnet Prefix Length'];
                    echo "<div class='result-section'>";
                    echo "<h3>Subnets within the Usable Range:</h3>";
                    echo "<table>";
                    echo "<tr><th>Subnet Size</th><th>Number of Subnets</th></tr>";
                    for ($smaller_subnet = $original_subnet + 1; $smaller_subnet <= 128; $smaller_subnet++) {
                        $num_subnets = gmp_pow(2, $smaller_subnet - $original_subnet);
                        $formatted_num_subnets = format_large_number(gmp_strval($num_subnets));
                        echo "<tr><td>/$smaller_subnet</td><td>$formatted_num_subnets</td></tr>";
                    }
                    echo "</table>";
                    echo "</div>";
                }

                echo "</div>";
            } else {
                echo "<p class='error-message'>Invalid input. Please enter a valid IPv6 CIDR notation.</p>";
            }
        } else {
            echo "<p class='error-message'>Invalid input. Please enter a valid IPv6 CIDR notation.</p>";
        }
    }
    ?>
</div>

</body>
</html>
