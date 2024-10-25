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
$dnsServer = '1.1.1.1'; // Set your preferred DNS server here

/**
 * Optional Logging Configuration
 *
 * File Name: nslookup_logs.txt
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
$serverFQDN = 'yourdomain.com'; // Replace with your server's FQDN
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
if (!isset($_SESSION['nslookup_requests'])) {
    $_SESSION['nslookup_requests'] = [];
}

/**
 * Clean Up Old Requests
 */
$_SESSION['nslookup_requests'] = array_filter($_SESSION['nslookup_requests'], function($timestamp) use ($timeFrame) {
    return $timestamp > time() - $timeFrame;
});

/**
 * Check Rate Limit
 */
if (count($_SESSION['nslookup_requests']) >= $maxRequests) {
    // Rate limit exceeded
    $rateLimitExceeded = true;
} else {
    $rateLimitExceeded = false;
}
?>
<html lang="en">
<head>
    <title>NSLookup Tool</title>
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
            justify-content: center; /* Center vertically */
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
        }

        h1 {
            margin-top: 0;
        }

        form {
            margin-top: 20px;
        }

        label {
            display: block;
            margin-bottom: 5px;
            text-align: left; /* Align labels to the left within the container */
        }

        input[type="text"],
        input[type="submit"],
        select {
            padding: 8px 15px; /* Fixed padding */
            border-radius: 4px;
            border: 1px solid #444444;
            background-color: #555555;
            color: white;
            margin-bottom: 10px;
            transition: background-color 0.3s ease; /* Smooth transition for hover effect */
            text-align: center; /* Center text inside inputs */
            width: auto;
            display: inline-block;
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

        input[type="submit"]:hover {
            background-color: #777777; /* Lighter color on hover */
            cursor: pointer;
        }

        .output-item {
            margin-bottom: 15px;
            text-align: center;
        }

        .output-item label {
            display: block;
            margin-bottom: 5px;
            text-align: left; /* Align labels to the left within the container */
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
            .container {
                width: 95%;
            }

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

        pre {
            white-space: pre-wrap; /* Allow wrapping */
            text-align: left; /* Align text to the left for readability */
            background-color: #222222;
            padding: 10px;
            border-radius: 4px;
            overflow: auto; /* Add scroll if content overflows */
            max-height: 400px; /* Optional: Limit the maximum height */
            margin-top: 20px;
        }

        p.error-message {
            color: #ff3333;
            font-weight: bold;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>NSLookup Tool</h1>
    <form action="" method="post">
        <label for="queryType">Query Type:</label>
        <select name="queryType" id="queryType">
            <option value="A">A - IPv4 Address</option>
            <option value="AAAA">AAAA - IPv6 Address</option>
            <option value="MX">MX - Mail Exchange</option>
            <option value="NS">NS - Name Server</option>
            <option value="PTR">PTR - Reverse Lookup</option>
        </select>
        <br>

        <label for="domain">Domain/IP Address:</label>
        <!-- Increased size and maxlength to accommodate longer hostnames -->
        <input type="text" id="domain" name="domain" required maxlength="253" placeholder="e.g., example.com or 2001:db8::1" size="60">
        <br>

        <input type="submit" value="Lookup">
    </form>

    <?php
    /**
     * Function to sanitize and validate user input.
     *
     * @param string $input The raw user input.
     * @return string|false Returns sanitized input if valid, false otherwise.
     */
    function sanitizeAndValidateInput($input) {
        // Trim whitespace from beginning and end
        $sanitizedInput = trim($input);

        // Remove any remaining whitespace within the input
        $sanitizedInput = preg_replace('/\s+/', '', $sanitizedInput);

        // Check if input is empty after trimming
        if (empty($sanitizedInput)) {
            return false; // Empty input
        }

        // Validate as either a domain name or IP address
        if (filter_var($sanitizedInput, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false ||
            filter_var($sanitizedInput, FILTER_VALIDATE_IP) !== false) {
            return $sanitizedInput; // Valid domain name or IP address
        } else {
            return false; // Invalid input
        }
    }

    /**
     * Function to implement rate limiting.
     *
     * @return bool Returns true if rate limit is exceeded, false otherwise.
     */
    function isRateLimitExceeded() {
        global $maxRequests, $timeFrame;

        // Clean up old requests
        $_SESSION['nslookup_requests'] = array_filter($_SESSION['nslookup_requests'], function($timestamp) use ($timeFrame) {
            return $timestamp > time() - $timeFrame;
        });

        if (count($_SESSION['nslookup_requests']) >= $maxRequests) {
            return true; // Rate limit exceeded
        } else {
            // Record the current request
            $_SESSION['nslookup_requests'][] = time();
            return false; // Within rate limit
        }
    }

    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        if (isset($_POST["domain"]) && isset($_POST["queryType"])) {
            // Check if rate limit is exceeded
            if (isRateLimitExceeded()) {
                echo "<p class='error-message'>Rate limit exceeded. Please try again later.</p>";
                exit;
            }

            $queryType = $_POST["queryType"];
            $domain = $_POST["domain"];

            $validatedDomain = sanitizeAndValidateInput($domain);
            if ($validatedDomain !== false) {
                // Additional validation based on query type
                $isValid = false;
                $errorMessage = '';

                if ($queryType === "PTR") {
                    // Validate IPv4 or IPv6 address
                    if (filter_var($validatedDomain, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
                        $isValid = true;
                    } else {
                        $errorMessage = 'Invalid IPv4 or IPv6 address for PTR lookup.';
                    }
                } else {
                    // Validate domain name
                    if (filter_var($validatedDomain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                        $isValid = true;
                    } else {
                        $errorMessage = 'Invalid domain name.';
                    }
                }

                if ($isValid) {
                    // If PTR and IPv6, convert to reverse DNS format
                    if ($queryType === "PTR" && filter_var($validatedDomain, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        // Convert IPv6 address to reverse DNS
                        $ipv6 = inet_pton($validatedDomain);
                        if ($ipv6 !== false) {
                            // Unpack into hexadecimal
                            $hex = bin2hex($ipv6);
                            // Reverse each nibble and append .ip6.arpa
                            $reversed = implode('.', str_split(strrev($hex), 1)) . '.ip6.arpa';
                        } else {
                            $errorMessage = 'Failed to process the IPv6 address.';
                        }
                    } elseif ($queryType === "PTR" && filter_var($validatedDomain, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        // For IPv4, append .in-addr.arpa
                        $reversed = implode('.', array_reverse(explode('.', $validatedDomain))) . '.in-addr.arpa';
                    }

                    if ($isValid && ($queryType !== "PTR" || isset($reversed))) {
                        // Since $queryType is from a select box with fixed values, it's safe to use directly
                        // Escape $reversed or $validatedDomain
                        if ($queryType === "PTR") {
                            $escapedDomain = escapeshellarg($reversed);
                        } else {
                            $escapedDomain = escapeshellarg($validatedDomain);
                        }

                        // Escape $dnsServer
                        $escapedDnsServer = escapeshellarg($dnsServer);

                        // Execute nslookup with the specified DNS server and capture stderr
                        $command = "nslookup -type={$queryType} {$escapedDomain} {$escapedDnsServer} 2>&1";
                        $output = shell_exec($command);

                        if ($output) {
                            // Optional Logging
                            if ($enableLogging) {
                                // Log file details:
                                // File Name: nslookup_logs.txt
                                // Permissions: Writable by the web server (e.g., 660), stored securely and not publicly accessible
                                $logFile = 'nslookup_logs.txt'; // Adjust the path as needed
                                $logEntry = date('Y-m-d H:i:s') . " - " . $_SERVER['REMOTE_ADDR'] . " - " . $queryType . " - " . $validatedDomain . "\n";
                                file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
                            }

                            echo "<div class='output-item'>";
                            echo "<label>NSLookup Output:</label>";
                            echo "<pre>" . htmlspecialchars($output) . "</pre>";
                            echo "</div>";
                        } else {
                            echo "<p class='error-message'>No response from the DNS server.</p>";
                        }
                    } else {
                        echo "<p class='error-message'>Invalid input for the selected query type.</p>";
                    }
                } else {
                    echo "<p class='error-message'>{$errorMessage}</p>";
                }
            } else {
                echo "<p class='error-message'>Invalid domain name or IP address. Please enter a valid input.</p>";
            }
        } else {
            echo "<p class='error-message'>Please enter a domain name or IP address.</p>";
        }
    }
    ?>

</div>
</body>
</html>
