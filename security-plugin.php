<?php
/*
Plugin Name: Enhanced Security Plugin
Description: Comprehensive security plugin with URL exclusion, blocking, SEO features, anti-spam protection, and bad bot blackhole
Version: 2.1
Author: Your Name
*/

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Load components
require_once plugin_dir_path(__FILE__) . 'includes/class-waf.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-headers.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-cookie-consent.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-sanitization.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-feature-manager.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-seo-manager.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-bot-blackhole.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-settings.php';

class CustomSecurityPlugin {
    private $waf;
    private $headers;
    private $cookie_consent;
    private $sanitization;
    private $feature_manager;
    private $seo_manager;
    private $bot_blackhole;
    private $settings;
    
    public function __construct() {
        // Hook into WordPress initialization
        add_action('plugins_loaded', array($this, 'init_components'), 1);
        
        // Add activation hook for database setup
        register_activation_hook(__FILE__, array($this, 'activate_plugin'));
        
        // Add cleanup hooks
        add_action('waf_cleanup_logs', array($this, 'cleanup_waf_logs'));
        add_action('bot_blackhole_cleanup', array($this, 'cleanup_bot_logs'));
    }

    public function activate_plugin() {
        // Set default options on activation
        $default_options = array(
            'security_enable_xss' => true,
            'security_enable_waf' => true,
            'security_enable_seo_features' => true,
            'security_enable_bot_protection' => true,
            'security_waf_request_limit' => 100,
            'security_waf_blacklist_threshold' => 5,
            'security_max_filter_colours' => 3,
            'security_max_filter_sizes' => 4,
            'security_max_filter_brands' => 2,
            'security_max_total_filters' => 8,
            'security_max_query_params' => 10,
            'security_max_query_length' => 500,
            'security_cookie_notice_text' => 'This website uses cookies to ensure you get the best experience. By continuing to use this site, you consent to our use of cookies.',
            'security_bot_block_status' => 403,
            'security_bot_block_message' => 'Access Denied - Bad Bot Detected',
            'security_bot_alert_email' => get_option('admin_email'),
            'security_bot_email_alerts' => false
        );

        foreach ($default_options as $option => $value) {
            if (get_option($option) === false) {
                update_option($option, $value);
            }
        }
    }

    public function init_components() {
        // Initialize components based on context
        if (!is_admin()) {
            // Frontend components
            if (get_option('security_enable_xss', true)) {
                $this->headers = new SecurityHeaders();
                add_action('init', array($this->headers, 'add_security_headers'));
            }
            
            if (get_option('security_enable_cookie_banner', false) && !isset($_COOKIE['cookie_consent'])) {
                $this->cookie_consent = new CookieConsent();
            }
            
            if (get_option('security_enable_waf', true)) {
                $this->waf = new SecurityWAF();
            }
            
            // Initialize bot blackhole protection
            if (get_option('security_enable_bot_protection', true)) {
                $this->bot_blackhole = new BotBlackhole();
            }
        }

        // Always load these components
        $this->sanitization = new SecuritySanitization();
        $this->feature_manager = new FeatureManager();
        
        // Load SEO manager if enabled
        if (get_option('security_enable_seo_features', true)) {
            $this->seo_manager = new SEOManager();
            add_action('init', array($this->seo_manager, 'init'));
        }
        
        // Admin components
        if (is_admin()) {
            $this->settings = new SecuritySettings();
            add_action('admin_menu', array($this->settings, 'add_admin_menu'));
            add_action('admin_init', array($this->settings, 'register_settings'));
        }
        
        // Initialize feature manager
        add_action('plugins_loaded', array($this->feature_manager, 'init'));
    }

    public function cleanup_waf_logs() {
        if ($this->waf) {
            $this->waf->cleanup_logs();
        }
    }
    
    public function cleanup_bot_logs() {
        if ($this->bot_blackhole) {
            $this->bot_blackhole->cleanup_logs();
        }
    }
}

// Initialize the plugin
new CustomSecurityPlugin();