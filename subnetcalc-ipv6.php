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
            padding: 8px;
            border-radius: 4px;
            border: 1px solid #444444;
            background-color: #555555;
            color: white;
            margin-bottom: 10px;
        }

        input[type="text"] {
            width: calc(100% - 22px);
        }

        input[type="submit"] {
            width: 100%;
            cursor: pointer;
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
        function sanitizeInput($input) {
            $sanitizedInput = filter_var($input, FILTER_SANITIZE_STRING);

            if (empty($sanitizedInput)) {
                return false; // Empty input
            }

            return $sanitizedInput; // Return input without additional validation for IPv6 CIDR
        }

        function validateIPv6CIDR($cidr) {
            $parts = explode('/', $cidr);
            if (count($parts) !== 2) {
                return false;
            }

            $network = $parts[0];
            $subnet = $parts[1];

            if (filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false && $subnet >= 0 && $subnet <= 128) {
                return true; // Valid IPv6 CIDR notation
            }

            return false; // Invalid input
        }

        function calculateSubnetInfo($cidr) {
            $parts = explode('/', $cidr);
            $network = $parts[0];
            $subnet = $parts[1];

            if (validateIPv6CIDR($cidr)) {
                $network_bin = inet_pton($network);
                $subnet_mask = str_repeat('f', $subnet >> 2);
                $remainder = $subnet % 4;

                if ($remainder > 0) {
                    $subnet_mask .= dechex(8 - $remainder);
                }
                $subnet_mask = str_pad($subnet_mask, 32, '0');

                $subnet_mask_bin = pack("H*", $subnet_mask);

                $start = $network_bin & $subnet_mask_bin;
                $end = $network_bin | ~$subnet_mask_bin;

                return [
                    'Received Input' => htmlspecialchars($cidr),
                    'Network' => htmlspecialchars($network),
                    'Subnet' => htmlspecialchars($subnet),
                    'Usable Range' => htmlspecialchars(inet_ntop($start)) . ' - ' . htmlspecialchars(inet_ntop($end)),
                ];
            }

            return false; // Invalid input
        }

        if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["cidr"])) {
            $cidrNotation = $_POST["cidr"];
            $sanitizedInput = sanitizeInput($cidrNotation);

            if ($sanitizedInput !== false && validateIPv6CIDR($sanitizedInput)) {
                $result = calculateSubnetInfo($sanitizedInput);

                if ($result !== false) {
                    echo "<h3>Results for " . $result['Received Input'] . ":</h3>";
                    echo "<ul>";
                    foreach ($result as $key => $value) {
                        echo "<li><strong>" . htmlspecialchars($key) . ":</strong> " . $value . "</li>";
                    }
                    echo "</ul>";
                } else {
                    echo "<p>Invalid input. Please enter a valid IPv6 CIDR notation.</p>";
                }
            } else {
                echo "<p>Invalid input. Please enter a valid IPv6 CIDR notation.</p>";
            }
        } else {
            echo "<p>No input received.</p>";
        }
        ?>

</div>
</body>
</html>
