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
// Start the session for rate limiting and logging
session_start();

/**
 * Configuration Variables
 */
$serverFQDN = 'yourdomain.com'; // Replace with your server's FQDN

/**
 * Optional Logging Configuration
 *
 * File Name: traceroute_logs.txt
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
if (!isset($_SESSION['traceroute_requests'])) {
    $_SESSION['traceroute_requests'] = [];
}

/**
 * Clean Up Old Requests
 */
$_SESSION['traceroute_requests'] = array_filter($_SESSION['traceroute_requests'], function($timestamp) use ($timeFrame) {
    return $timestamp > time() - $timeFrame;
});

/**
 * Check Rate Limit
 */
if (count($_SESSION['traceroute_requests']) >= $maxRequests) {
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
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Traceroute Tool</title>
    <style>
        /* Reset some basic styles */
        * {
            box-sizing: border-box;
        }

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

        h1 {
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
            padding: 8px 15px; /* Fixed padding */
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
            padding: 6px 12px; /* Reduced padding to match the size of the word "Trace" */
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

        /* Center the Output */
        .output-item {
            margin-bottom: 15px;
            text-align: center; /* Center the entire output item */
        }

        .output-item label {
            display: block;
            margin-bottom: 5px;
            text-align: center; /* Center the label within the output item */
            font-weight: bold;
        }

        pre {
            white-space: pre-wrap; /* Allow wrapping */
            text-align: left; /* Keep text left-aligned for readability */
            background-color: #222222;
            padding: 10px;
            border-radius: 4px;
            overflow: visible; /* Remove scrolling */
            margin-top: 20px;
            font-family: Consolas, monospace;
            font-size: 14px;
            width: auto; /* Let the width adjust based on content */
            max-width: 100%; /* Ensure it doesn't exceed container width */
            margin-left: auto; /* Center horizontally */
            margin-right: auto; /* Center horizontally */
            box-sizing: border-box;
        }

        p.error-message {
            color: #ff3333;
            font-weight: bold;
            text-align: center; /* Center the error message */
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

            pre {
                font-size: 12px;
                width: 100%; /* Full width on small screens */
                max-width: 100%;
            }

            input[type="submit"] {
                width: 100%; /* Make button full width on small screens */
            }
        }
    </style>
</head>
<body>
<div class="container">
    <h1>Traceroute Tool</h1>
    <form method="post" action="">
        <label for="domain">Domain/IP Address:</label>
        <input type="text" id="domain" name="domain" required maxlength="253" placeholder="e.g., example.com or 8.8.8.8">

        <!-- Wrapped the submit button in a div to center it -->
        <div class="submit-container">
            <input type="submit" value="Trace">
        </div>
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

        // Use PHP's filter_var for domain and IP validation
        if (filter_var($sanitizedInput, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false ||
            filter_var($sanitizedInput, FILTER_VALIDATE_IP) !== false) {
            return $sanitizedInput; // Valid domain or IP address
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
        $_SESSION['traceroute_requests'] = array_filter($_SESSION['traceroute_requests'], function($timestamp) use ($timeFrame) {
            return $timestamp > time() - $timeFrame;
        });

        if (count($_SESSION['traceroute_requests']) >= $maxRequests) {
            return true; // Rate limit exceeded
        } else {
            // Record the current request
            $_SESSION['traceroute_requests'][] = time();
            return false; // Within rate limit
        }
    }

    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        if (isset($_POST["domain"])) {
            // Check if rate limit is exceeded
            if (isRateLimitExceeded()) {
                echo "<p class='error-message'>Rate limit exceeded. Please try again later.</p>";
                exit;
            }

            $domainInput = $_POST["domain"];
            $validatedDomain = sanitizeAndValidateInput($domainInput);

            if ($validatedDomain !== false) {
                // Escape shell arguments to prevent command injection
                $escapedDomain = escapeshellarg($validatedDomain);

                // Determine the traceroute command based on the operating system
                $os = strtoupper(substr(PHP_OS, 0, 3));
                if ($os === 'WIN') {
                    $cmd = "tracert $escapedDomain";
                } else {
                    $cmd = "traceroute $escapedDomain";
                }

                // Execute the traceroute command and capture the output
                $output = shell_exec($cmd);

                // Display the output
                if ($output) {
                    // Optional Logging
                    if ($enableLogging) {
                        // Log file details:
                        // File Name: traceroute_logs.txt
                        // Permissions: Writable by the web server (e.g., 660), stored securely and not publicly accessible
                        $logFile = 'traceroute_logs.txt'; // Adjust the path as needed
                        $logEntry = date('Y-m-d H:i:s') . " - " . $_SERVER['REMOTE_ADDR'] . " - " . htmlspecialchars($validatedDomain) . "\n";
                        file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
                    }

                    // Display Results
                    echo "<div class='output-item'>";
                    echo "<label>Traceroute Results for <em>" . htmlspecialchars($validatedDomain) . "</em>:</label>";
                    echo "<pre>" . htmlspecialchars($output) . "</pre>";
                    echo "</div>";
                } else {
                    echo "<p class='error-message'>Traceroute command returned no output.</p>";
                }
            } else {
                echo "<p class='error-message'>Invalid domain or IP address. Please enter a valid input.</p>";
            }
        } else {
            echo "<p class='error-message'>Please enter a domain name or IP address.</p>";
        }
    }
    ?>

</div>

</body>
</html>
