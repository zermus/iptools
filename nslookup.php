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
$dnsServer = '8.8.8.8'; // Set your preferred DNS server here
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
    <h1>NSLookup Tool</h1>
    <form action="nslookup.php" method="post">
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
        <input type="text" id="domain" name="domain" required>
        <br>

        <input type="submit" value="Lookup">
    </form>

<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $queryType = $_POST["queryType"];
    $domain = $_POST["domain"];

    // Sanitize the input
    $sanitizedDomain = filter_var($domain, FILTER_SANITIZE_STRING);
    $sanitizedDomain = str_replace(' ', '', $sanitizedDomain); // Remove spaces

    // Regular expressions for validating domain name, IPv4 and IPv6 addresses
    $domainRegex = '/^(?:(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,63}))$/';
    $ipv4Regex = '/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/';
    $ipv6Regex = '/^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]
?)|:))|(([0-9A-Fa-f]{1,4}:){5}((:[0-9A-Fa-f]{1,4}){1,2}|:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|:))|(([0-9A-Fa-f]{1,4}:){4}((:[0-9A-Fa-f]{1,4}){
1,3}|:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|:))|(([0-9A-Fa-f]{1,4}:){3}((:[0-9A-Fa-f]{1,4}){1,4}|:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}
(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|:))|(([0-9A-Fa-f]{1,4}:){2}((:[0-9A-Fa-f]{1,4}){1,5}|:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|:))|(([0-9A-
Fa-f]{1,4}:){1}((:[0-9A-Fa-f]{1,4}){1,6}|:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|:))|(:((:[0-9A-Fa-f]{1,4}){1,7}|:)))(%.+)?$/';

    // Check if queryType is PTR, then accept only IP addresses (IPv4 or IPv6)
    // For other queryTypes, accept only domain names
    if (($queryType === "PTR" && (preg_match($ipv4Regex, $sanitizedDomain) || preg_match($ipv6Regex, $sanitizedDomain))) ||
        ($queryType !== "PTR" && preg_match($domainRegex, $sanitizedDomain))) {

        // Use escapeshellarg to prevent command injection
        $queryType = escapeshellarg($queryType);
        $sanitizedDomain = escapeshellarg($sanitizedDomain);
        $dnsServer = escapeshellarg($dnsServer);

        // Execute nslookup with the specified DNS server
        $output = shell_exec("nslookup -type=$queryType $sanitizedDomain $dnsServer");

        // Escape and display the output
        echo "<pre>" . htmlspecialchars($output) . "</pre>";
    } else {
        echo "<p class='error-message'>Invalid input for the selected query type.</p>";
    }
}
?>

</div>
</body>
</html>
