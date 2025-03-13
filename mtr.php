<?php
session_start();

// ===== Configuration Variables =====
// Directory where temporary logs will be stored. Ensure this directory exists and is writable.
$tempDir   = __DIR__ . '/tmp/';
// Time in seconds after which old logs will be removed (e.g., 3600 seconds = 1 hour)
$expiryTime = 3600;
// Full path to the mtr command. Adjust this if mtr is installed elsewhere.
$mtrPath    = '/usr/sbin/mtr';
// Traceroute timeout in seconds (how long to keep the traceroute active and output available)
$tracerouteTimeout = 60;

// ===== Environment Checks =====
$envErrors = [];

// Check if the temporary directory exists and is writable.
if (!is_dir($tempDir) || !is_writable($tempDir)) {
    $envErrors[] = "Temporary directory ($tempDir) is not writable.";
}

// Test if the mtr command is available/executable via sudo.
// We set TERM to xterm to avoid terminal errors.
$cmdMtrTest = "env TERM=xterm sudo $mtrPath --version";
$mtrVersion = shell_exec($cmdMtrTest);
if (!$mtrVersion) {
    $envErrors[] = "MTR command is not available or not executable via sudo. To grant access, add the following line to your sudoers file (using visudo):<br>
    <code>apache ALL=(root) NOPASSWD: $mtrPath</code>";
}

// ===== Cleanup Old Logs =====
foreach (glob($tempDir . "mtr_*.log") as $file) {
    if (is_file($file) && (time() - filemtime($file)) > $expiryTime) {
        unlink($file);
    }
}

// ===== Input Sanitization Function =====
function sanitizeAndValidate($input) {
    $input = trim($input);
    // Remove any inner whitespace
    $input = preg_replace('/\s+/', '', $input);
    // Validate as a domain or IP address
    if (filter_var($input, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false ||
        filter_var($input, FILTER_VALIDATE_IP) !== false) {
        return $input;
    }
    return false;
}

// ===== Process Form Submission =====
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["domain"])) {
    $validatedDomain = sanitizeAndValidate($_POST["domain"]);
    if ($validatedDomain === false) {
        echo "<p>Invalid domain or IP address. Please enter a valid value.</p>";
        exit;
    }

    // Create a unique temporary log file using the session ID.
    $tempFile = $tempDir . "mtr_" . session_id() . ".log";

    // Build the MTR command using sudo.
    // We force report mode (-r) with a count of 10 hops (-c 10), set TERM=xterm to avoid terminal errors,
    // and then sleep for $tracerouteTimeout seconds to keep the output available.
    // Output (including errors) is written to $tempFile, and the command runs in the background.
    $escapedDomain = escapeshellarg($validatedDomain);
    $cmd = "(env TERM=xterm sudo $mtrPath -r -c 10 $escapedDomain; sleep $tracerouteTimeout) > " . escapeshellarg($tempFile) . " 2>&1 &";
    exec($cmd);
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
                padding: 20px 0 0; /* Top padding for spacing */
                display: flex;
                flex-direction: column;
                align-items: center; /* Center horizontally */
                justify-content: flex-start; /* Align to top */
                min-height: 100vh;
            }
            .container {
                width: 60%;
                max-width: 800px;
                padding: 20px;
                border-radius: 8px;
                background-color: #333;
                text-align: center;
            }
            .error-box {
                background-color: #fdd;
                color: #900;
                padding: 10px;
                margin-bottom: 20px;
                border: 1px solid #900;
                text-align: left;
            }
            pre {
                background-color: #222;
                padding: 10px;
                border-radius: 4px;
                white-space: pre-wrap;
                font-family: Consolas, monospace;
            }
        </style>
        <script>
            // Poll the output endpoint every 5 seconds.
            // Stop polling after the tracerouteTimeout (passed from PHP) has elapsed.
            var pollingInterval;
            var tracerouteTimeout = <?php echo $tracerouteTimeout * 1000; ?>; // Convert seconds to milliseconds
            function fetchOutput(){
                fetch("mtr_output.php")
                    .then(response => response.text())
                    .then(data => {
                        document.getElementById("output").innerText = data;
                    })
                    .catch(error => {
                        console.error("Error fetching output:", error);
                    });
            }
            window.onload = function(){
                fetchOutput();
                pollingInterval = setInterval(fetchOutput, 5000);
                setTimeout(function(){
                    clearInterval(pollingInterval);
                }, tracerouteTimeout);
            }
        </script>
    </head>
    <body>
        <div class="container">
            <?php if (!empty($envErrors)) { ?>
                <div class="error-box">
                    <h3>Environment Errors:</h3>
                    <ul>
                        <?php foreach ($envErrors as $error) { ?>
                            <li><?php echo $error; ?></li>
                        <?php } ?>
                    </ul>
                    <p>Current user: <?php echo htmlspecialchars(trim(shell_exec('whoami'))); ?></p>
                </div>
            <?php } ?>
            <h1>MTR Traceroute for <?php echo htmlspecialchars($validatedDomain); ?></h1>
            <pre id="output">Loading output...</pre>
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
            padding: 20px 0 0; /* Top padding for spacing */
            display: flex;
            flex-direction: column;
            align-items: center; /* Center horizontally */
            justify-content: flex-start; /* Align to top */
            min-height: 100vh;
        }
        .container {
            width: 60%;
            max-width: 800px;
            padding: 20px;
            border-radius: 8px;
            background-color: #333;
            text-align: center;
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
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        /* Center text inside the input box */
        input[type="text"] {
            text-align: center;
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
        input[type="submit"] {
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #777;
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if (!empty($envErrors)) { ?>
            <div class="error-box">
                <h3>Environment Errors:</h3>
                <ul>
                    <?php foreach ($envErrors as $error) { ?>
                        <li><?php echo $error; ?></li>
                    <?php } ?>
                </ul>
                <p>Current user: <?php echo htmlspecialchars(trim(shell_exec('whoami'))); ?></p>
            </div>
        <?php } ?>
        <h1>MTR Traceroute Tool</h1>
        <form method="post" action="">
            <label for="domain">Domain or IP Address:</label>
            <input type="text" id="domain" name="domain" required placeholder="e.g., example.com or 8.8.8.8">
            <input type="submit" value="Trace">
        </form>
    </div>
</body>
</html>
