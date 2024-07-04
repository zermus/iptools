<!DOCTYPE html>
<!-- SubnetCalc v0.5 -->
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
    <title>IPv4 Subnet Calculator</title>
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
            margin-bottom: 20px; /* Adjust the margin to accommodate a footer */
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
            padding: 8px; 15px; /* Provides padding around the text */
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
        <label for="cidr">Enter IPv4 CIDR Notation or IPv4 Address with Subnet Mask:</label><br>
        <input type="text" id="cidr" name="cidr" placeholder="e.g., 192.168.1.0/24 or 192.168.1.0 255.255.255.0"><br>
        <input type="submit" value="Calculate">
    </form>

        <?php
        // Function to sanitize user input
        function sanitizeInput($input) {
            $sanitizedInput = trim($input);
            if (empty($sanitizedInput)) {
                return false;
            }
            // Updated Regular Expression for more flexibility
            if (preg_match('/^(\d{1,3}(\.\d{1,3}){3})(\/\d{1,2}|\s\d{1,3}(\.\d{1,3}){3})$/', $input)) {
                return $sanitizedInput;
            }
            return false;
        }

        // Function to calculate subnet information
        function calculateSubnetInfo($cidr) {
            if (strpos($cidr, '/') !== false) {
                list($ip, $mask) = explode('/', $cidr);
                $subnetMask = long2ip(-1 << (32 - (int)$mask));
                $maskLength = $mask;
            } else {
                list($ip, $subnetMask) = explode(' ', $cidr);
                $maskLength = 32 - log((ip2long($subnetMask) ^ 0xFFFFFFFF) + 1, 2);
            }

            $networkIP = long2ip(ip2long($ip) & ip2long($subnetMask));
            $broadcastIP = long2ip(ip2long($networkIP) | ~ip2long($subnetMask));

            $usableStartIP = ip2long($networkIP) + 1;
            $usableEndIP = ip2long($broadcastIP) - 1;

            return [
                'Network IP' => $networkIP,
                'Broadcast IP' => $broadcastIP,
                'Subnet Mask' => $subnetMask,
                'Subnet Mask Length' => '/' . $maskLength,
                'Usable Range' => ($usableStartIP <= $usableEndIP) ?
                    long2ip($usableStartIP) . ' - ' . long2ip($usableEndIP) :
                    'N/A'
            ];
        }

        // Handling form submission
        if ($_SERVER["REQUEST_METHOD"] == "POST") {
            $cidrNotation = $_POST["cidr"];
            $sanitizedInput = sanitizeInput($cidrNotation);

            if ($sanitizedInput !== false) {
                $result = calculateSubnetInfo($sanitizedInput);

                echo "<h3>Results for " . htmlspecialchars($sanitizedInput) . ":</h3>";
                echo "<ul>";
                foreach ($result as $key => $value) {
                    echo "<li><strong>" . htmlspecialchars($key) . ":</strong> " . htmlspecialchars($value) . "</li>";
                }
                echo "</ul>";
            } else {
                echo "<p class='error-message'>Invalid input. Please enter a valid IPv4 CIDR notation or IP Address Space with Subnet Mask.</p>";
            }
        }
        ?>

</div>
</body>
</html>
