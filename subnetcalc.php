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
<!--
Copyright (c) 2024 Cody Gee
-->
<html lang="en">
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
        input[type="submit"] {
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
        input[type="text"]:focus {
            background-color: #444444;
            border-color: #0000AA; /* Darker blue color */
            outline: none;
        }

        /* Adjusted Submit Button Styles */
        .submit-container {
            text-align: center; /* Center the button */
            margin-top: 10px;
        }

        input[type="submit"] {
            padding: 6px 12px; /* Reduced padding to match the size of the word "Calculate" */
            border-radius: 4px;
            border: 1px solid #444444;
            background-color: #555555;
            color: white;
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

        /* Center the Results List */
        ul {
            list-style: none;
            padding: 0;
            text-align: center; /* Center-align the text */
            max-width: 600px; /* Optional: limit the width of the results for better readability */
            margin: 0 auto; /* Center the results list */
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
            input[type="submit"] {
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
            text-align: center; /* Center-align the text */
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
    </style>
</head>
<body>

<div class="container">
    <h2>Subnet Calculator</h2>

    <form method="post">
        <label for="cidr">Enter IPv4 CIDR Notation or IPv4 Address with Subnet Mask:</label>
        <input type="text" id="cidr" name="cidr" placeholder="e.g., 192.168.1.0/24 or 192.168.1.0 255.255.255.0" required maxlength="253">

        <!-- Wrapped the submit button in a div to center it -->
        <div class="submit-container">
            <input type="submit" value="Calculate">
        </div>
    </form>

    <?php
    /**
     * Function to sanitize user input.
     *
     * @param string $input The raw user input.
     * @return string|false Returns sanitized input if valid, false otherwise.
     */
    function sanitizeInput($input) {
        // Trim whitespace from beginning and end
        $sanitizedInput = trim($input);

        // Remove any remaining whitespace within the input
        $sanitizedInput = preg_replace('/\s+/', '', $sanitizedInput);

        // Check if input is empty after trimming
        if (empty($sanitizedInput)) {
            return false; // Empty input
        }

        // Validate as either a CIDR notation or IP address with subnet mask
        if (preg_match('/^(\d{1,3}(\.\d{1,3}){3})(\/\d{1,2})$/', $input) ||
            preg_match('/^(\d{1,3}(\.\d{1,3}){3})\s(\d{1,3}(\.\d{1,3}){3})$/', $input)) {
            return $sanitizedInput;
        }

        return false; // Invalid input
    }

    /**
     * Function to calculate subnet information.
     *
     * @param string $cidr The sanitized CIDR notation or IP with subnet mask.
     * @return array Returns an associative array with subnet details.
     */
    function calculateSubnetInfo($cidr) {
        if (strpos($cidr, '/') !== false) {
            // CIDR Notation
            list($ip, $mask) = explode('/', $cidr);
            $mask = (int)$mask;
            $subnetMask = long2ip(-1 << (32 - $mask));
            $maskLength = $mask;
        } else {
            // IP Address with Subnet Mask
            list($ip, $subnetMask) = explode(' ', $cidr);
            $maskLong = ip2long($subnetMask);
            $maskLength = 32 - log(($maskLong ^ 0xFFFFFFFF) + 1, 2);
            $maskLength = (int)$maskLength;
        }

        // Calculate Network IP
        $networkIP = long2ip(ip2long($ip) & ip2long($subnetMask));

        // Calculate Broadcast IP
        $broadcastIP = long2ip(ip2long($networkIP) | (~ip2long($subnetMask)));

        // Calculate Usable Range
        $usableStartIPLong = ip2long($networkIP) + 1;
        $usableEndIPLong = ip2long($broadcastIP) - 1;

        // Handle cases where subnet mask is /31 or /32
        if ($maskLength >= 31) {
            $usableRange = 'N/A';
        } else {
            $usableStartIP = long2ip($usableStartIPLong);
            $usableEndIP = long2ip($usableEndIPLong);
            $usableRange = "$usableStartIP - $usableEndIP";
        }

        return [
            'Network IP' => $networkIP,
            'Broadcast IP' => $broadcastIP,
            'Subnet Mask' => $subnetMask,
            'Subnet Mask Length' => '/' . $maskLength,
            'Usable Range' => $usableRange
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

    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        if (isset($_POST["cidr"])) {
            // Check if rate limit is exceeded
            if (isRateLimitExceeded()) {
                echo "<p class='error-message'>Rate limit exceeded. Please try again later.</p>";
                exit;
            }

            $cidrNotation = $_POST["cidr"];
            $sanitizedInput = sanitizeInput($cidrNotation);

            if ($sanitizedInput !== false) {
                $result = calculateSubnetInfo($sanitizedInput);

                // Optional Logging
                if ($enableLogging) {
                    // Log file details:
                    // File Name: subnet_logs.txt
                    // Permissions: Writable by the web server (e.g., 660), stored securely and not publicly accessible
                    $logFile = 'subnet_logs.txt'; // Adjust the path as needed
                    $logEntry = date('Y-m-d H:i:s') . " - " . $_SERVER['REMOTE_ADDR'] . " - " . htmlspecialchars($sanitizedInput) . "\n";
                    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
                }

                // Display Results
                echo "<h3>Results for " . htmlspecialchars($sanitizedInput) . ":</h3>";
                echo "<ul>";
                foreach ($result as $key => $value) {
                    echo "<li><strong>" . htmlspecialchars($key) . ":</strong> " . htmlspecialchars($value) . "</li>";
                }
                echo "</ul>";
            } else {
                echo "<p class='error-message'>Invalid input. Please enter a valid IPv4 CIDR notation or IP Address with Subnet Mask.</p>";
            }
        } else {
            echo "<p class='error-message'>Please enter a CIDR notation or IP Address with Subnet Mask.</p>";
        }
    }
    ?>

</div>

</body>
</html>
