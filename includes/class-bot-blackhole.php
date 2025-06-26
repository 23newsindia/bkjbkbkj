<?php
// includes/class-bot-blackhole.php

if (!defined('ABSPATH')) {
    exit;
}

class BotBlackhole {
    private $options_cache = array();
    private $blocked_bots_cache = null;
    private $whitelisted_bots_cache = null;
    private $whitelisted_ips_cache = null;
    private $table_name;
    private static $is_admin = null;
    
    public function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'security_blocked_bots';
        
        // Initialize is_admin check once
        if (self::$is_admin === null) {
            self::$is_admin = is_admin();
        }
        
        // Only initialize if bot protection is enabled
        if ($this->get_option('security_enable_bot_protection', true)) {
            $this->init();
        }
    }
    
    private function get_option($key, $default = false) {
        if (!isset($this->options_cache[$key])) {
            $this->options_cache[$key] = get_option($key, $default);
        }
        return $this->options_cache[$key];
    }
    
    private function init() {
        // Only add frontend hooks if not in admin
        if (!self::$is_admin) {
            // Create blackhole trap
            add_action('wp_footer', array($this, 'add_blackhole_trap'));
            add_action('login_footer', array($this, 'add_blackhole_trap'));
            
            // Check for bot access - highest priority
            add_action('init', array($this, 'check_bot_access'), 1);
        }
        
        // Add to robots.txt
        add_filter('robots_txt', array($this, 'add_robots_disallow'), 11, 2);
        
        // Schedule cleanup
        add_action('admin_init', array($this, 'schedule_cleanup'));
        
        // Ensure table exists
        $this->ensure_table_exists();
    }
    
    private function ensure_table_exists() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS {$this->table_name} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            user_agent text NOT NULL,
            request_uri text NOT NULL,
            referrer text,
            timestamp datetime NOT NULL,
            block_reason varchar(100) NOT NULL,
            PRIMARY KEY  (id),
            KEY ip_timestamp (ip_address, timestamp),
            KEY user_agent_key (user_agent(100))
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }
    
    public function add_blackhole_trap() {
        // Don't show trap to logged-in users
        if (is_user_logged_in()) {
            return;
        }
        
        $trap_url = home_url('/blackhole-trap/');
        $nonce = wp_create_nonce('blackhole_trap');
        
        ?>
        <!-- Blackhole Trap for Bad Bots - Hidden from humans -->
        <div style="position: absolute; left: -9999px; top: -9999px; visibility: hidden; display: none;">
            <a href="<?php echo esc_url($trap_url . '?_wpnonce=' . $nonce); ?>" rel="nofollow">Do not follow this link</a>
        </div>
        <?php
    }
    
    public function add_robots_disallow($output, $public) {
        if ($public) {
            $output .= "\n# Blackhole trap for bad bots\n";
            $output .= "Disallow: /blackhole-trap/\n";
            $output .= "Disallow: /*blackhole*\n";
        }
        return $output;
    }
    
    public function check_bot_access() {
        // Skip all checks for logged-in users
        if (is_user_logged_in()) {
            return;
        }
        
        $ip = $this->get_client_ip();
        $user_agent = $this->get_user_agent();
        $request_uri = $_SERVER['REQUEST_URI'];
        
        // Fast IP block check using transient cache
        $blocked_transient = 'bot_blocked_' . md5($ip);
        if (get_transient($blocked_transient)) {
            $this->block_bot('IP previously blocked');
        }
        
        // Check if accessing blackhole trap
        if (strpos($request_uri, '/blackhole-trap/') !== false || strpos($request_uri, 'blackhole') !== false) {
            $this->trap_bot($ip, $user_agent, 'Accessed blackhole trap');
        }
        
        // Check if bot is whitelisted (fast check first)
        if ($this->is_bot_whitelisted($user_agent, $ip)) {
            return;
        }
        
        // Check for bad bot patterns
        if ($this->is_bad_bot($user_agent)) {
            $this->trap_bot($ip, $user_agent, 'Bad bot user agent detected');
        }
        
        // Check for suspicious behavior patterns
        if ($this->is_suspicious_behavior($ip, $user_agent, $request_uri)) {
            $this->trap_bot($ip, $user_agent, 'Suspicious behavior detected');
        }
    }
    
    private function is_bot_whitelisted($user_agent, $ip) {
        // Check whitelisted IPs first (faster)
        if ($this->whitelisted_ips_cache === null) {
            $whitelist_ips = $this->get_option('security_bot_whitelist_ips', $this->get_default_whitelist_ips());
            $this->whitelisted_ips_cache = array_filter(array_map('trim', explode("\n", $whitelist_ips)));
        }
        
        foreach ($this->whitelisted_ips_cache as $whitelisted_ip) {
            if (strpos($ip, $whitelisted_ip) === 0) {
                return true;
            }
        }
        
        // Check whitelisted user agents
        if ($this->whitelisted_bots_cache === null) {
            $whitelist_bots = $this->get_option('security_bot_whitelist_agents', $this->get_default_whitelist_bots());
            $this->whitelisted_bots_cache = array_filter(array_map('trim', explode("\n", strtolower($whitelist_bots))));
        }
        
        $user_agent_lower = strtolower($user_agent);
        foreach ($this->whitelisted_bots_cache as $whitelisted_bot) {
            if (strpos($user_agent_lower, strtolower($whitelisted_bot)) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function is_bad_bot($user_agent) {
        if ($this->blocked_bots_cache === null) {
            $blocked_bots = $this->get_option('security_bot_blacklist_agents', $this->get_default_bad_bots());
            $this->blocked_bots_cache = array_filter(array_map('trim', explode("\n", strtolower($blocked_bots))));
        }
        
        $user_agent_lower = strtolower($user_agent);
        foreach ($this->blocked_bots_cache as $bad_bot) {
            if (strpos($user_agent_lower, $bad_bot) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function is_suspicious_behavior($ip, $user_agent, $request_uri) {
        // Check for common bot patterns
        $suspicious_patterns = array(
            // Empty or suspicious user agents
            '/^$/',
            '/^-$/',
            '/bot/i',
            '/crawler/i',
            '/spider/i',
            '/scraper/i',
            '/scanner/i',
            '/harvester/i',
            '/extractor/i',
            '/libwww/i',
            '/curl/i',
            '/wget/i',
            '/python/i',
            '/perl/i',
            '/java/i',
            '/php/i',
        );
        
        foreach ($suspicious_patterns as $pattern) {
            if (preg_match($pattern, $user_agent)) {
                return true;
            }
        }
        
        // Check for suspicious request patterns
        $suspicious_uris = array(
            '/wp-config',
            '/xmlrpc',
            '/.env',
            '/admin',
            '/phpmyadmin',
            '/wp-admin/admin-ajax.php',
            '/wp-json/wp/v2/users',
        );
        
        foreach ($suspicious_uris as $uri) {
            if (strpos($request_uri, $uri) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function trap_bot($ip, $user_agent, $reason) {
        // Log the bot
        $this->log_blocked_bot($ip, $user_agent, $_SERVER['REQUEST_URI'], $reason);
        
        // Cache the block for 24 hours
        $blocked_transient = 'bot_blocked_' . md5($ip);
        set_transient($blocked_transient, true, 24 * HOUR_IN_SECONDS);
        
        // Send email alert if enabled
        if ($this->get_option('security_bot_email_alerts', false)) {
            $this->send_bot_alert($ip, $user_agent, $reason);
        }
        
        // Block the bot
        $this->block_bot($reason);
    }
    
    private function log_blocked_bot($ip, $user_agent, $request_uri, $reason) {
        global $wpdb;
        
        try {
            $wpdb->insert(
                $this->table_name,
                array(
                    'ip_address' => $ip,
                    'user_agent' => $user_agent,
                    'request_uri' => $request_uri,
                    'referrer' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
                    'timestamp' => current_time('mysql'),
                    'block_reason' => $reason
                ),
                array('%s', '%s', '%s', '%s', '%s', '%s')
            );
        } catch (Exception $e) {
            // Fail silently to avoid breaking the site
            error_log('Bot Blackhole Log Error: ' . $e->getMessage());
        }
    }
    
    private function send_bot_alert($ip, $user_agent, $reason) {
        $email = $this->get_option('security_bot_alert_email', get_option('admin_email'));
        $subject = '[' . get_bloginfo('name') . '] Bad Bot Blocked';
        
        $message = "A bad bot has been blocked on your website.\n\n";
        $message .= "IP Address: " . $ip . "\n";
        $message .= "User Agent: " . $user_agent . "\n";
        $message .= "Reason: " . $reason . "\n";
        $message .= "Time: " . current_time('mysql') . "\n";
        $message .= "Site: " . home_url() . "\n";
        
        wp_mail($email, $subject, $message);
    }
    
    private function block_bot($reason) {
        $status_code = $this->get_option('security_bot_block_status', 403);
        $message = $this->get_option('security_bot_block_message', 'Access Denied');
        
        status_header($status_code);
        nocache_headers();
        
        if ($status_code == 410) {
            header('HTTP/1.1 410 Gone');
            header('Status: 410 Gone');
        } elseif ($status_code == 444) {
            // Nginx-style "no response" - just close connection
            header('HTTP/1.1 444 No Response');
            header('Status: 444 No Response');
        } else {
            header('HTTP/1.1 403 Forbidden');
            header('Status: 403 Forbidden');
        }
        
        header('Content-Type: text/html; charset=utf-8');
        
        // For 444 status, don't send any content
        if ($status_code == 444) {
            exit;
        }
        
        // Custom block page
        $custom_message = $this->get_option('security_bot_custom_message', '');
        if (!empty($custom_message)) {
            echo $custom_message;
        } else {
            echo $this->get_default_block_page($message);
        }
        
        exit;
    }
    
    private function get_default_block_page($message) {
        return '<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <meta name="robots" content="noindex, nofollow">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
        .block-container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #d32f2f; margin-bottom: 20px; }
        p { color: #666; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="block-container">
        <h1>Access Denied</h1>
        <p>' . esc_html($message) . '</p>
        <p>If you believe this is an error, please contact the site administrator.</p>
    </div>
</body>
</html>';
    }
    
    private function get_client_ip() {
        $ip_keys = array('HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR');
        
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
    }
    
    private function get_user_agent() {
        return isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    }
    
    private function get_default_whitelist_bots() {
        return 'googlebot
bingbot
slurp
duckduckbot
baiduspider
yandexbot
facebookexternalhit
twitterbot
linkedinbot
pinterestbot
applebot
ia_archiver
msnbot
ahrefsbot
semrushbot
dotbot
rogerbot
uptimerobot
pingdom
gtmetrix
pagespeed
lighthouse
chrome-lighthouse
wordpress
wp-rocket
jetpack
wordfence';
    }
    
    private function get_default_whitelist_ips() {
        $server_ip = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '';
        $remote_ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
        
        $default_ips = array();
        if ($server_ip) $default_ips[] = $server_ip;
        if ($remote_ip) $default_ips[] = $remote_ip;
        
        // Add common CDN and service IPs
        $default_ips[] = '127.0.0.1';
        $default_ips[] = '::1';
        
        return implode("\n", array_unique($default_ips));
    }
    
    private function get_default_bad_bots() {
        return 'masscan
nmap
sqlmap
nikto
w3af
skipfish
openvas
nessus
acunetix
burpsuite
owasp
zap
havij
pangolin
sqlninja
bsqlbf
mole
bbqsql
jsql
sqlsus
safe3si
pangolin
havij
sqlpoizon
sqlbrute
sql power injector
marathon
nsauditor
netsparker
appscan
webinspect
paros
webscarab
grendel-scan
n-stealth
shadow security scanner
sara
saint
retina
cybercop
internet scanner
kane security analyst
x-scan
superscan
netscan
languard
gfi
eeye
foundstone
rapid7
qualys
tenable
beyondtrust
tripwire
alienvault
mcafee
symantec
trendmicro
kaspersky
bitdefender
avast
avg
eset
sophos
panda
f-secure
comodo
zonealarm
malwarebytes
spybot
adaware
ccleaner
regcleaner
registry mechanic
registry booster
registry easy
registry fix
registry first aid
registry patrol
registry repair
registry reviver
registry smart
registry winner
tuneup
advanced systemcare
iobit
glary
wise
auslogics
ashampoo
magix
nero
roxio
cyberlink
corel
adobe
microsoft
apple
google
mozilla
opera
safari
chrome
firefox
internet explorer
edge';
    }
    
    public function schedule_cleanup() {
        if (!wp_next_scheduled('bot_blackhole_cleanup')) {
            wp_schedule_event(time(), 'daily', 'bot_blackhole_cleanup');
        }
    }
    
    public function cleanup_logs() {
        global $wpdb;
        
        // Keep only last 30 days of logs
        $wpdb->query(
            "DELETE FROM {$this->table_name} WHERE timestamp < DATE_SUB(NOW(), INTERVAL 30 DAY)"
        );
        
        // Keep only 1000 most recent entries to prevent database bloat
        $wpdb->query(
            "DELETE FROM {$this->table_name} WHERE id NOT IN (
                SELECT id FROM (
                    SELECT id FROM {$this->table_name} ORDER BY timestamp DESC LIMIT 1000
                ) AS temp
            )"
        );
    }
    
    public function get_blocked_bots_stats() {
        global $wpdb;
        
        $stats = array();
        
        // Total blocked bots
        $stats['total'] = $wpdb->get_var("SELECT COUNT(*) FROM {$this->table_name}");
        
        // Blocked today
        $stats['today'] = $wpdb->get_var(
            "SELECT COUNT(*) FROM {$this->table_name} WHERE DATE(timestamp) = CURDATE()"
        );
        
        // Blocked this week
        $stats['week'] = $wpdb->get_var(
            "SELECT COUNT(*) FROM {$this->table_name} WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
        );
        
        // Top blocked IPs
        $stats['top_ips'] = $wpdb->get_results(
            "SELECT ip_address, COUNT(*) as count FROM {$this->table_name} 
             GROUP BY ip_address ORDER BY count DESC LIMIT 10",
            ARRAY_A
        );
        
        return $stats;
    }
}