<!DOCTYPE html>
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
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }

        .container {
            width: 60%;
            margin: 0 auto;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
            background-color: #333333;
            text-align: center;
            flex: 1;
            margin-bottom: 20px; /* Adjust the margin to accomodate a footer */
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
        input[type="submit"] {
            padding: 8px 15px; /* Adjusted padding for better appearance */
            border-radius: 4px;
            border: 1px solid #444444;
            background-color: #555555;
            color: white;
            margin-bottom: 10px;
            cursor: pointer;
            transition: background-color 0.3s ease; /* Smooth transition for hover effect */
        }

        input[type="submit"]:hover {
            background-color: #777777; /* Lighter color on hover */
        }

        input[type="text"] {
            width: calc(100% - 22px);
        }

        ul {
            list-style: none;
            padding: 0;
        }

        li {
            margin-bottom: 5px;
        }

        li strong {
            margin-right: 5px;
        }

        p.error-message {
            color: #ff3333;
            font-weight: bold;
        }
    </style>
</head>
<body>

<div class="container">
    <h2>Subnet Calculator</h2>

    <form method="post">
        <label for="cidr">Enter IPv6 CIDR Notation:</label><br>
        <input type="text" id="cidr" name="cidr" placeholder="e.g., 2606:4700::/32"><br>
        <input type="submit" value="Calculate">
    </form>

    <?php
    function sanitizeAndValidateIPv6CIDR($input) {
        if (empty($input)) {
            return false;
        }

        // Strict validation for IPv6 CIDR format
        if (preg_match('/^([a-fA-F0-9:]+)\/(\d+)$/', $input, $matches)) {
            $network = $matches[1];
            $subnet = $matches[2];

            if (filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false &&
                filter_var($subnet, FILTER_VALIDATE_INT) !== false &&
                $subnet >= 0 && $subnet <= 128) {
                return $input;
            }
        }
        return false;
    }

    function calculateSubnetInfo($cidr) {
        $parts = explode('/', $cidr);
        $network = $parts[0];
        $subnet = $parts[1];

        $network_bin = inet_pton($network);
        if ($network_bin === false) {
            return false; // Handle inet_pton error
        }

        $subnet_mask = str_repeat('f', $subnet >> 2);
        $remainder = $subnet % 4;

        if ($remainder > 0) {
            $subnet_mask .= dechex(8 - $remainder);
        }
        $subnet_mask = str_pad($subnet_mask, 32, '0');

        $subnet_mask_bin = pack("H*", $subnet_mask);

        $start = $network_bin & $subnet_mask_bin;
        $end = $network_bin | ~$subnet_mask_bin;

        $start_ip = inet_ntop($start);
        $end_ip = inet_ntop($end);

        if ($start_ip === false || $end_ip === false) {
            return false; // Handle inet_ntop error
        }

        return [
            'Received Input' => htmlspecialchars($cidr),
            'Network' => htmlspecialchars($network),
            'Subnet' => htmlspecialchars($subnet),
            'Usable Range' => htmlspecialchars($start_ip) . ' - ' . htmlspecialchars($end_ip),
        ];
    }

    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["cidr"])) {
        $cidrNotation = $_POST["cidr"];
        $validatedInput = sanitizeAndValidateIPv6CIDR($cidrNotation);

        if ($validatedInput !== false) {
            $result = calculateSubnetInfo($validatedInput);

            if ($result !== false) {
                echo "<h3>Results for " . $result['Received Input'] . ":</h3>";
                echo "<ul>";
                foreach ($result as $key => $value) {
                    echo "<li><strong>" . $key . ":</strong> " . $value . "</li>";
                }
                echo "</ul>";
            } else {
                echo "<p class='error-message'>Invalid input. Please enter a valid IPv6 CIDR notation.</p>";
            }
        } else {
            echo "<p class='error-message'>Invalid input. Please enter a valid IPv6 CIDR notation.</p>";
        }
    } else {
        echo "<p>No input received.</p>";
    }
    ?>

</div>
</body>
</html>
