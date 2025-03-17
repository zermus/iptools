<?php
session_start();

/**
 * Configuration Variables
 */
$tempDir   = __DIR__ . '/tmp/';    // Directory for temporary logs
$expiryTime = 3600;                // Remove logs older than 1 hour
$mtrPath    = '/usr/sbin/mtr';     // Full path to the mtr command
$tracerouteTimeout = 60;           // Timeout in seconds
$mtrColumns = 2000;                // Number of columns for MTR output (large for full hostnames)
$serverFQDN = 'yourdomain.com';    // Replace with your server's FQDN
$maxRequests = 100;                // Maximum number of requests
$timeFrame = 3600;                 // Time frame in seconds (e.g., 3600 seconds = 1 hour)
$enableLogging = true;             // Set to false to disable logging

// Set Content Security Policy (CSP) Headers
header("Content-Security-Policy:
    default-src 'self';
    script-src 'self' https://{$serverFQDN};
    style-src 'self' 'unsafe-inline' https://{$serverFQDN};
    img-src 'self' https://{$serverFQDN};"
);

// Initialize Rate Limiting Data
if (!isset($_SESSION['subnet_requests'])) {
    $_SESSION['subnet_requests'] = [];
}

// Clean Up Old Requests for Rate Limiting
$_SESSION['subnet_requests'] = array_filter($_SESSION['subnet_requests'], function($timestamp) use ($timeFrame) {
    return $timestamp > time() - $timeFrame;
});

// Check Rate Limit
if (count($_SESSION['subnet_requests']) >= $maxRequests) {
    $rateLimitExceeded = true;
} else {
    $rateLimitExceeded = false;
}

// ===== Environment Checks =====
$envErrors = [];

// Ensure tmp directory is writable
if (!is_dir($tempDir) || !is_writable($tempDir)) {
    $envErrors[] = "Temporary directory ($tempDir) is not writable.";
}

// Test if MTR is available via sudo
$cmdMtrTest = "COLUMNS=$mtrColumns env TERM=xterm sudo $mtrPath --version";
$mtrVersion = shell_exec($cmdMtrTest);
if (!$mtrVersion) {
    $envErrors[] = "MTR command is not available or not executable via sudo. "
                 . "To grant access, add the following line to your sudoers file (using visudo):<br>"
                 . "<code>apache ALL=(root) NOPASSWD: $mtrPath</code>";
}

// ===== Cleanup Old Logs =====
foreach (glob($tempDir . "mtr_*.log") as $file) {
    if (is_file($file) && (time() - filemtime($file)) > $expiryTime) {
        unlink($file);
    }
}

// ===== Input Sanitization =====
function sanitizeAndValidate($input) {
    $input = trim($input);
    // Remove inner whitespace
    $input = preg_replace('/\s+/', '', $input);
    // Validate domain or IP
    if (filter_var($input, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false ||
        filter_var($input, FILTER_VALIDATE_IP) !== false) {
        return $input;
    }
    return false;
}

// ===== Rate Limiting Function =====
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

// ===== Process Form Submission =====
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["domain"])) {
    // Check if rate limit is exceeded
    if ($rateLimitExceeded) {
        echo "<p style='color: #ff3333; font-weight: bold; text-align: center;'>Rate limit exceeded. Please try again later.</p>";
        exit;
    }

    $validatedDomain = sanitizeAndValidate($_POST["domain"]);
    if ($validatedDomain === false) {
        echo "<p style='color: #ff3333; font-weight: bold; text-align: center;'>Invalid domain or IP address. Please enter a valid value.</p>";
        exit;
    }

    // Create unique temp file
    $tempFile = $tempDir . "mtr_" . session_id() . ".log";

    // Build MTR command in wide report mode (-rw), large columns, xterm, etc.
    $escapedDomain = escapeshellarg($validatedDomain);
    $cmd = "(COLUMNS=$mtrColumns env TERM=xterm sudo $mtrPath -rw -c 10 $escapedDomain; "
         . "sleep $tracerouteTimeout) > " . escapeshellarg($tempFile) . " 2>&1 &";
    exec($cmd);

    // Optional Logging (Updated to mtr_logs.txt)
    if ($enableLogging) {
        $logFile = 'mtr_logs.txt'; // Changed from subnet_logs.txt
        $logEntry = date('Y-m-d H:i:s') . " - " . $_SERVER['REMOTE_ADDR'] . " - " . htmlspecialchars($validatedDomain) . "\n";
        file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
    }

    // Render the results page (spinner + output)
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>MTR Traceroute Tool</title>
        <style>
            body {
                background-color: #1e1e1e;
                color: #fff;
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 20px 0 20px;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: flex-start;
                min-height: 100vh;
            }
            .results-container {
                width: 80%;
                max-width: 1000px;
                padding: 20px;
                border-radius: 8px;
                background-color: #333;
                text-align: center;
                margin-bottom: 20px;
            }
            .error-box {
                background-color: #fdd;
                color: #900;
                padding: 10px;
                margin-bottom: 20px;
                border: 1px solid #900;
                text-align: left;
            }
            .pre-wrapper {
                position: relative;
                margin-top: 20px;
                width: 100%;
                min-height: 200px;
            }
            .pre-wrapper pre {
                margin: 0;
                padding: 10px;
                border-radius: 4px;
                background-color: #222;
                white-space: pre;
                overflow-x: auto;
                font-family: Consolas, monospace;
                min-height: 200px;
                box-sizing: border-box;
            }
            .spinner {
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                border: 4px solid rgba(255, 255, 255, 0.3);
                border-top: 4px solid #fff;
                border-radius: 50%;
                width: 30px;
                height: 30px;
                animation: spin 1s linear infinite;
                z-index: 2;
            }
            @keyframes spin {
                0%   { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        </style>
        <script>
            var pollingInterval;
            var tracerouteTimeout = <?php echo $tracerouteTimeout * 1000; ?>; // ms

            function fetchOutput() {
                fetch("mtr_output.php")
                    .then(response => response.text())
                    .then(data => {
                        document.getElementById("output").innerText = data;
                        if (data.trim() !== "" && !data.includes("No output available yet.")) {
                            document.getElementById("spinner").style.display = 'none';
                        }
                    })
                    .catch(error => {
                        console.error("Error fetching output:", error);
                    });
            }

            window.onload = function() {
                fetchOutput();
                pollingInterval = setInterval(fetchOutput, 5000);
                setTimeout(function() {
                    clearInterval(pollingInterval);
                }, tracerouteTimeout);
            }
        </script>
    </head>
    <body>
        <?php if (!empty($envErrors)) { ?>
            <div class="results-container">
                <div class="error-box">
                    <h3>Environment Errors:</h3>
                    <ul>
                        <?php foreach ($envErrors as $error) { ?>
                            <li><?php echo $error; ?></li>
                        <?php } ?>
                    </ul>
                    <p>Current user: <?php echo htmlspecialchars(trim(shell_exec('whoami'))); ?></p>
                </div>
            </div>
        <?php } ?>
        <div class="results-container">
            <h1>MTR Traceroute for <?php echo htmlspecialchars($validatedDomain); ?></h1>
            <div class="pre-wrapper">
                <pre id="output">Loading output...</pre>
                <div id="spinner" class="spinner"></div>
            </div>
            <p>The session will attempt to traceroute for <?php echo $tracerouteTimeout; ?> seconds.</p>
        </div>
    </body>
    </html>
    <?php
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MTR Traceroute Tool</title>
    <style>
        body {
            background-color: #1e1e1e;
            color: #fff;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px 0 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: flex-start;
            min-height: 100vh;
        }
        .form-container {
            width: 60%;
            max-width: 600px;
            padding: 20px;
            border-radius: 8px;
            background-color: #333;
            text-align: center;
            margin-bottom: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.5);
        }
        .error-box {
            background-color: #fdd;
            color: #900;
            padding: 10px;
            margin-bottom: 20px;
            border: 1px solid #900;
            text-align: left;
        }
        form {
            margin: 20px 0;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"],
        input[type="submit"] {
            padding: 8px 15px;
            border-radius: 4px;
            border: 1px solid #444;
            background-color: #555;
            color: #fff;
            margin-bottom: 10px;
            transition: background-color 0.3s ease;
            width: 100%;
            box-sizing: border-box;
        }
        input[type="text"]:hover,
        input[type="text"]:focus {
            background-color: #444;
            border-color: #0000AA;
            outline: none;
        }
        .submit-container {
            text-align: center;
            margin-top: 10px;
        }
        input[type="submit"] {
            width: auto;
            display: inline-block;
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #777;
        }
        @media screen and (max-width: 600px) {
            .form-container {
                width: 90%;
            }
        }
    </style>
</head>
<body>
    <?php if (!empty($envErrors)) { ?>
        <div class="form-container">
            <div class="error-box">
                <h3>Environment Errors:</h3>
                <ul>
                    <?php foreach ($envErrors as $error) { ?>
                        <li><?php echo $error; ?></li>
                    <?php } ?>
                </ul>
                <p>Current user: <?php echo htmlspecialchars(trim(shell_exec('whoami'))); ?></p>
            </div>
        </div>
    <?php } ?>
    <div class="form-container">
        <h1>MTR Traceroute Tool</h1>
        <form method="post" action="">
            <label for="domain">Domain/IP Address:</label>
            <input type="text" id="domain" name="domain" required maxlength="253" placeholder="e.g., example.com or 8.8.8.8">

            <div class="submit-container">
                <input type="submit" value="Trace">
            </div>
        </form>
    </div>
</body>
</html>
