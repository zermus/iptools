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
<?php
// Start the session for rate limiting
session_start();

/**
 * Configuration Variables
 */
$serverFQDN = 'yourdomain.com'; // Replace with your server's FQDN

/**
 * Optional Logging Configuration
 *
 * File Name: subnet_logs.txt
 * Permissions: Writable by the web server (e.g., 660), stored securely and not publicly accessible
 */
$enableLogging = true; // Set to false to disable logging

/**
 * Set Content Security Policy (CSP) Headers
 *
 * - Allows scripts from 'self' and your server's FQDN.
 * - Allows styles from 'self', your server's FQDN, and inline styles ('unsafe-inline').
 * - Allows images from 'self' and your server's FQDN.
 *
 * Note: 'unsafe-inline' is used for styles to permit the use of <style> tags.
 * For enhanced security, consider moving styles to an external stylesheet and removing 'unsafe-inline'.
 */
header("Content-Security-Policy:
    default-src 'self';
    script-src 'self' https://{$serverFQDN};
    style-src 'self' 'unsafe-inline' https://{$serverFQDN};
    img-src 'self' https://{$serverFQDN};"
);

/**
 * Rate Limiting Configuration
 */
$maxRequests = 100; // Maximum number of requests
$timeFrame = 3600; // Time frame in seconds (e.g., 3600 seconds = 1 hour)

/**
 * Initialize Rate Limiting Data
 */
if (!isset($_SESSION['subnet_requests'])) {
    $_SESSION['subnet_requests'] = [];
}

/**
 * Clean Up Old Requests
 */
$_SESSION['subnet_requests'] = array_filter($_SESSION['subnet_requests'], function($timestamp) use ($timeFrame) {
    return $timestamp > time() - $timeFrame;
});

/**
 * Check Rate Limit
 */
if (count($_SESSION['subnet_requests']) >= $maxRequests) {
    // Rate limit exceeded
    $rateLimitExceeded = true;
} else {
    $rateLimitExceeded = false;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>IPv6 Subnet Calculator</title>
    <style>
        body {
            background-color: #1e1e1e;
            color: #fff;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
            align-items: center; /* Center horizontally */
            justify-content: flex-start; /* Align items to the top */
            padding-top: 50px; /* Add some top padding */
        }

        .container {
            width: 60%;
            max-width: 800px;
            padding: 20px;
            border-radius: 8px;
            box-sizing: border-box;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
            background-color: #333333;
            text-align: center;
            margin-bottom: 60px; /* Adjust the margin to accommodate the footer */
        }

        h2 {
            margin-top: 0;
        }

        form {
            margin-top: 20px;
            text-align: left; /* Align form elements to the left */
        }

        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }

        input[type="text"],
        input[type="submit"],
        select {
            padding: 8px 15px; /* Provides padding around the text */
            border-radius: 4px;
            border: 1px solid #444444;
            background-color: #555555;
            color: white;
            margin-bottom: 10px;
            transition: background-color 0.3s ease; /* Smooth transition for hover effect */
            text-align: left; /* Align text to the left inside inputs */
            width: 100%; /* Full width for better usability */
            display: block;
            box-sizing: border-box;
        }

        input[type="text"]:hover,
        input[type="text"]:focus,
        select:hover,
        select:focus {
            background-color: #444444;
            border-color: #0000AA; /* Darker blue color */
            outline: none;
        }

        /* Adjusted Submit Button Styles */
        .submit-container {
            text-align: center; /* Center the button */
        }

        input[type="submit"] {
            padding: 6px 12px; /* Reduced padding to match the size of the word "Calculate" */
            border-radius: 4px;
            border: 1px solid #444444;
            background-color: #555555;
            color: white;
            margin-bottom: 10px;
            transition: background-color 0.3s ease; /* Smooth transition for hover effect */
            text-align: center; /* Center text inside button */
            width: auto; /* Shrink to fit the content */
            display: inline-block; /* Allow the button to be centered within the container */
            box-sizing: border-box;
            cursor: pointer;
        }

        input[type="submit"]:hover {
            background-color: #777777; /* Lighter color on hover */
        }

        .output-item {
            margin-bottom: 15px;
            text-align: center;
        }

        .output-item label {
            display: block;
            margin-bottom: 5px;
            text-align: left; /* Align labels to the left within the container */
            font-weight: bold;
        }

        ul {
            list-style: none;
            padding: 0;
            text-align: left; /* Align text to the left for readability */
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

        footer {
            text-align: center;
            padding: 10px 0;
            background-color: #333333;
            color: #fff;
            width: 100%;
            position: fixed;
            bottom: 0;
        }

        @media screen and (max-width: 800px) {
            .container {
                width: 80%;
            }
        }

        @media screen and (max-width: 600px) {
            .container {
                width: 95%;
            }

            input[type="text"],
            input[type="submit"],
            select {
                width: 100%;
            }

            pre {
                font-size: 12px;
                max-height: 400px; /* Limit height on small screens */
                overflow: auto; /* Enable scrolling on small screens */
            }
        }

        pre {
            white-space: pre-wrap; /* Allow wrapping */
            text-align: left; /* Align text to the left for readability */
            background-color: #222222;
            padding: 10px;
            border-radius: 4px;
            overflow: auto; /* Add scroll if content overflows */
            max-height: 400px; /* Optional: Limit the maximum height */
            margin-top: 20px;
            font-family: Consolas, monospace;
            font-size: 14px;
            width: 100%; /* Full width on large screens */
            box-sizing: border-box;
        }

        /* Center the "Subnets within the Usable Range" section */
        .subnets-section {
            text-align: center;
        }

        .subnets-section table {
            margin: 0 auto; /* Center the table */
        }
    </style>
</head>
<body>

<div class="container">
    <h2>IPv6 Subnet Calculator</h2>

    <form method="post">
        <label for="cidr">Enter IPv6 CIDR Notation:</label>
        <input type="text" id="cidr" name="cidr" placeholder="e.g., 2606:4700::/32" size="43" maxlength="43" required>

        <label><input type="checkbox" name="display_full" value="1"> Display IPv6 addresses in full notation</label>
        <label><input type="checkbox" name="calculate_subnets" value="1"> Calculate subnets within the usable range</label>

        <!-- Wrapped the submit button in a div to center it -->
        <div class="submit-container">
            <input type="submit" value="Calculate">
        </div>
    </form>

    <?php
    /**
     * Function to sanitize and validate IPv6 CIDR input.
     *
     * @param string $input The raw user input.
     * @return string|false Returns sanitized input if valid, false otherwise.
     */
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

    /**
     * Function to expand IPv6 address to full notation.
     *
     * @param string $ip The IPv6 address.
     * @return string The expanded IPv6 address.
     */
    function expand_ipv6_address($ip) {
        $binary = inet_pton($ip);
        $hex = unpack('H*', $binary)[1];
        return implode(':', str_split($hex, 4));
    }

    /**
     * Function to format large numbers with commas.
     *
     * @param string $number_str The number as a string.
     * @return string The formatted number.
     */
    function format_large_number($number_str) {
        return number_format($number_str, 0, '', ',');
    }

    /**
     * Function to calculate subnet information.
     *
     * @param string $cidr The sanitized CIDR notation.
     * @param bool $display_full Whether to display IPv6 addresses in full notation.
     * @return array|false Returns an associative array with subnet details or false on failure.
     */
    function calculateSubnetInfo($cidr, $display_full) {
        list($network, $subnet) = explode('/', $cidr);
        $subnet = (int)$subnet;

        $network_bin = inet_pton($network);
        if ($network_bin === false) {
            return false;
        }

        // Create subnet mask
        $subnet_mask_bin = str_repeat("\xff", $subnet >> 3);
        if ($subnet % 8) {
            $subnet_mask_bin .= chr((0xff << (8 - ($subnet % 8))) & 0xff);
        }
        $subnet_mask_bin = str_pad($subnet_mask_bin, 16, "\x00");

        // Calculate network and broadcast addresses
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

    /**
     * Function to implement rate limiting.
     *
     * @return bool Returns true if rate limit is exceeded, false otherwise.
     */
    function isRateLimitExceeded() {
        global $maxRequests, $timeFrame;

        // Clean up old requests
        $_SESSION['subnet_requests'] = array_filter($_SESSION['subnet_requests'], function($timestamp) use ($timeFrame) {
            return $timestamp > time() - $timeFrame;
        });

        if (count($_SESSION['subnet_requests']) >= $maxRequests) {
            return true; // Rate limit exceeded
        } else {
            // Record the current request
            $_SESSION['subnet_requests'][] = time();
            return false; // Within rate limit
        }
    }

    // Handling form submission
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        if (isset($_POST["cidr"])) {
            // Check if rate limit is exceeded
            if (isRateLimitExceeded()) {
                echo "<p class='error-message'>Rate limit exceeded. Please try again later.</p>";
                exit;
            }

            $cidrNotation = $_POST["cidr"];
            $display_full = isset($_POST['display_full']);
            $calculate_subnets = isset($_POST['calculate_subnets']);

            $validatedInput = sanitizeAndValidateIPv6CIDR($cidrNotation);

            if ($validatedInput !== false) {
                $result = calculateSubnetInfo($validatedInput, $display_full);

                if ($result !== false) {
                    // Optional Logging
                    if ($enableLogging) {
                        // Log file details:
                        // File Name: subnet_logs.txt
                        // Permissions: Writable by the web server (e.g., 660), stored securely and not publicly accessible
                        $logFile = 'subnet_logs.txt'; // Adjust the path as needed
                        $logEntry = date('Y-m-d H:i:s') . " - " . $_SERVER['REMOTE_ADDR'] . " - " . htmlspecialchars($validatedInput) . "\n";
                        file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
                    }

                    echo "<h3>Results for " . htmlspecialchars($validatedInput) . ":</h3>";
                    echo "<ul>";
                    foreach ($result as $key => $value) {
                        echo "<li><strong>" . htmlspecialchars($key) . ":</strong> " . htmlspecialchars($value) . "</li>";
                    }
                    echo "</ul>";

                    if ($calculate_subnets) {
                        $original_subnet = (int)$result['Subnet Prefix Length'];
                        echo "<div class='subnets-section'>";
                        echo "<h4>Subnets within the Usable Range:</h4>";
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
                } else {
                    echo "<p class='error-message'>Failed to calculate subnet information. Please ensure the CIDR notation is correct.</p>";
                }
            } else {
                echo "<p class='error-message'>Invalid input. Please enter a valid IPv6 CIDR notation.</p>";
            }
        } else {
            echo "<p class='error-message'>Please enter a CIDR notation.</p>";
        }
    }
    ?>

</div>

</body>
</html>
