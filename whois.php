<!DOCTYPE html>
<html>
<head>
    <title>WHOIS Lookup</title>
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

        h1 {
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

        input[type="submit"] {
            width: 100%;
            cursor: pointer;
        }

        pre {
            white-space: pre-wrap;
            text-align: left;
        }

        p.error-message {
            color: #ff3333;
            font-weight: bold;
        }
    </style>
</head>
<body>

<div class="container">
    <h1>WHOIS Lookup</h1>
    <form method="post" action="">
        <label for="domain">Enter Domain/IP:</label><br>
        <input type="text" name="domain" id="domain" required><br>
        <input type="submit" value="Lookup">
    </form>

    <?php
    function sanitizeAndValidateInput($input) {
        $sanitizedInput = trim($input);

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

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_POST['domain'])) {
            $validatedDomain = sanitizeAndValidateInput($_POST['domain']);
            if ($validatedDomain !== false) {
                $domain = escapeshellarg($validatedDomain); // Escape shell arguments

                $output = shell_exec("whois $domain 2>&1"); // Execute the whois command

                if ($output) {
                    echo "<h2>WHOIS Information for $validatedDomain:</h2>";
                    echo "<pre>" . htmlspecialchars($output) . "</pre>";
                } else {
                    echo "<p>No WHOIS information found for $validatedDomain.</p>";
                }
            } else {
                echo "<p>Invalid domain name or IP address.</p>";
            }
        } else {
            echo "<p>Please enter a domain name or IP address.</p>";
        }
    }
    ?>

</div>
</body>
</html>
