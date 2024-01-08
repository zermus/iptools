<!DOCTYPE html>
<html>
<head>
    <title>Subnet Calculator</title>
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
        <label for="cidr">Enter IPv4 CIDR Notation or IPv4 Address with Subnet Mask:</label><br>
        <input type="text" id="cidr" name="cidr" placeholder="e.g., 192.168.1.0/24 or 192.168.1.0 255.255.255.0"><br>
        <input type="submit" value="Calculate">
    </form>

    <?php
     function sanitizeInput($input) {
    // Remove leading/trailing spaces
    $sanitizedInput = trim($input);

    // Check if the input is not empty
    if (empty($sanitizedInput)) {
    return false; // Empty input
    }

    // Validate as IPv4 CIDR notation
    if (preg_match('/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/', $input)) {
        return $input; // Valid IPv4 CIDR notation
    }

    // Validate as IPv6 CIDR notation
    if (preg_match('/^([0-9a-fA-F]{0,4}:){1,7}(:[0-9a-fA-F]{0,4}){1,7}\/\d{1,3}$/', $input)) {
        return $input; // Valid IPv6 CIDR notation
    }

    // Validate as IP Address Space with Subnet Mask
    if (preg_match('/^(\d{1,3}\.){3}\d{1,3}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/', $input)) {
        return $input; // Valid IP Address Space with Subnet Mask
    }

    return false; // Invalid input
}

function calculateSubnetInfo($cidr) {
    list($ip, $mask) = strpos($cidr, '/') !== false ? explode('/', $cidr) : explode(' ', $cidr);

    if (strpos($cidr, '/') !== false) {
        $subnetMask = long2ip(-1 << (strpos($ip, ':') === false ? 32 : 128) - (int)$mask);
        $networkIP = long2ip((ip2long($ip)) & (ip2long($subnetMask)));
        $broadcastIP = long2ip((ip2long($networkIP)) | (~ip2long($subnetMask)));

        $usableStartIP = ip2long($networkIP) + 1;
        $usableEndIP = ip2long($broadcastIP) - 1;
    } else {
        list($networkIP, $subnetMask) = explode(' ', $cidr);

        $broadcastIP = long2ip((ip2long($networkIP) & ip2long($subnetMask)) | (~ip2long($subnetMask)));

        $usableStartIP = ip2long($networkIP) + 1;
        $usableEndIP = ip2long($broadcastIP) - 1;
    }

    return [
        'Network IP' => $networkIP,
        'Broadcast IP' => $broadcastIP,
        'Subnet Mask' => $subnetMask,
        'Usable Range' => ($usableStartIP <= $usableEndIP) ?
            long2ip($usableStartIP) . ' - ' . long2ip($usableEndIP) :
            'N/A'
    ];
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $cidrNotation = $_POST["cidr"];
    $sanitizedInput = sanitizeInput($cidrNotation);

    if ($sanitizedInput !== false) {
        $result = calculateSubnetInfo($sanitizedInput);

        echo "<h3>Results for $sanitizedInput:</h3>";
        echo "<ul>";
        foreach ($result as $key => $value) {
            echo "<li><strong>$key:</strong> $value</li>";
        }
        echo "</ul>";
    } else {
        echo "<p>Invalid input. Please enter a valid IPv4 or IPv6 CIDR notation or IP Address Space with Subnet Mask.</p>";
    }
}
     ?>

</div>
</body>
</html>
