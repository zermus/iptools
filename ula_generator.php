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
<!DOCTYPE html>
<html>
<head>
    <title>ULA IPv6 Address Generator</title>
    <style>
        body {
            background-color: #292929;
            color: white;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }

        .container {
            width: 60%;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
            background-color: #333333;
            text-align: center;
            flex: 1;
            margin-bottom: 20px; /* Adjust the margin to accommodate the footer */
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

        select,
        input[type="submit"],
        input[type="text"] {
            padding: 8px 15px;
            border-radius: 4px;
            border: 1px solid #444444;
            background-color: #555555;
            color: white;
            margin-bottom: 10px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        select:hover, select:focus,
        input[type="text"]:hover, input[type="text"]:focus {
            background-color: #444444;
            border-color: #0000AA; /* Darker blue color */
            outline: none;
        }

        input[type="submit"]:hover {
            background-color: #777777;
        }

        input[type="text"] {
            width: auto;
            display: inline-block;
            cursor: text;
        }

        footer {
            text-align: center;
            padding: 5px 0;
            background-color: #333333;
            color: #fff;
            width: 100%;
        }

        .result-section {
            margin-top: 20px;
            text-align: center;
        }

        .result-section .output-item {
            margin-bottom: 15px;
        }

        .result-section label {
            display: block;
            margin-bottom: 5px;
        }

        .result-section input[type="text"] {
            width: auto;
            display: inline-block;
        }
    </style>
</head>
<body>

<div class="container">
    <h2>ULA IPv6 Address Generator</h2>

    <form method="post">
        <label for="subnet_size">Select Subnet Size:</label>
        <select id="subnet_size" name="subnet_size">
            <option value="64">/64 - 1 /64</option>
            <option value="63">/63 - 2 /64s</option>
            <option value="62">/62 - 4 /64s</option>
            <option value="61">/61 - 8 /64s</option>
            <option value="60">/60 - 16 /64s</option>
            <option value="59">/59 - 32 /64s</option>
            <option value="58">/58 - 64 /64s</option>
            <option value="57">/57 - 128 /64s</option>
            <option value="56">/56 - 256 /64s</option>
            <option value="55">/55 - 512 /64s</option>
            <option value="54">/54 - 1,024 /64s</option>
            <option value="53">/53 - 2,048 /64s</option>
            <option value="52">/52 - 4,096 /64s</option>
            <option value="51">/51 - 8,192 /64s</option>
            <option value="50">/50 - 16,384 /64s</option>
            <option value="49">/49 - 32,768 /64s</option>
            <option value="48">/48 - 65,536 /64s</option>
        </select><br>
        <input type="submit" value="Generate">
    </form>

    <?php
    function format_ipv6_address($hex) {
        return implode(':', str_split($hex, 4));
    }

    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["subnet_size"])) {
        $subnet_size = intval($_POST["subnet_size"]);

        // Server-side validation (optional)
        $valid_subnet_sizes = range(48, 64);
        if (in_array($subnet_size, $valid_subnet_sizes)) {
            // Generate random 40-bit Global ID
            $global_id = bin2hex(random_bytes(5)); // 40 bits = 5 bytes

            // Construct the ULA prefix
            $ula_prefix_hex = 'fd' . substr($global_id, 0, 10);
            $ula_prefix_formatted = format_ipv6_address($ula_prefix_hex);

            // Display the ULA prefix
            echo "<div class='result-section'>";

            echo "<div class='output-item'>";
            echo "<label>Your ULA Prefix:</label>";
            echo "<input type='text' value='" . htmlspecialchars($ula_prefix_formatted) . "::/" . $subnet_size . "' readonly onclick='this.select();'>";
            echo "</div>";

            // Calculate the number of /64s
            $num_subnets = pow(2, 64 - $subnet_size);
            echo "<p>This provides you with <strong>" . number_format($num_subnets) . "</strong> /64 subnet(s).</p>";

            // First /64 subnet
            $first_subnet = $ula_prefix_formatted . '::/64';
            echo "<div class='output-item'>";
            echo "<label>First Usable /64 Subnet:</label>";
            echo "<input type='text' value='" . htmlspecialchars($first_subnet) . "' readonly onclick='this.select();'>";
            echo "</div>";

            // Last /64 subnet
            // Convert the prefix to a GMP number
            $prefix_bin = inet_pton($ula_prefix_formatted . '::');
            $prefix_int = gmp_import($prefix_bin, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

            // Calculate the number of bits in the subnet portion
            $subnet_bits = 64 - $subnet_size;

            // Calculate the subnet mask (for the subnet bits)
            $subnet_mask = gmp_sub(gmp_pow(2, $subnet_bits), 1);

            // Shift the subnet mask to the correct position (bits 64 to 64 + subnet_bits)
            $subnet_mask_shifted = gmp_mul($subnet_mask, gmp_pow(2, 64));

            // Calculate the last subnet integer value
            $last_subnet_int = gmp_add($prefix_int, $subnet_mask_shifted);

            // Convert back to binary
            $last_subnet_hex = gmp_strval($last_subnet_int, 16);

            // Pad the hex string to 32 characters (128 bits)
            $last_subnet_hex = str_pad($last_subnet_hex, 32, '0', STR_PAD_LEFT);

            // Convert hex to binary data
            $last_subnet_bin = pack('H*', $last_subnet_hex);

            // Convert back to IPv6 address
            $last_subnet_addr = inet_ntop($last_subnet_bin);

            // Format the last subnet address
            $last_subnet_formatted = $last_subnet_addr . '/64';

            echo "<div class='output-item'>";
            echo "<label>Last Usable /64 Subnet:</label>";
            echo "<input type='text' value='" . htmlspecialchars($last_subnet_formatted) . "' readonly onclick='this.select();'>";
            echo "</div>";

            echo "</div>";
        }
        // Optional: else block to handle invalid subnet sizes, if desired.
    }
    ?>
</div>
</body>
</html>
