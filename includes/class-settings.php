<?php
class SecuritySettings {
    public function add_admin_menu() {
        add_menu_page(
            'Security Settings',
            'Security Settings',
            'manage_options',
            'security-settings',
            array($this, 'render_settings_page'),
            'dashicons-shield'
        );
        
        // Add submenu for bot logs
        add_submenu_page(
            'security-settings',
            'Bot Protection Logs',
            'Bot Logs',
            'manage_options',
            'security-bot-logs',
            array($this, 'render_bot_logs_page')
        );
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (isset($_POST['save_settings']) && check_admin_referer('security_settings_nonce', 'security_nonce')) {
            $this->save_settings();
            echo '<div class="notice notice-success"><p>Settings saved successfully.</p></div>';
        }

        // Get all options with default values
        $options = array(
            'excluded_paths' => get_option('security_excluded_paths', ''),
            'blocked_patterns' => get_option('security_blocked_patterns', ''),
            'excluded_php_paths' => get_option('security_excluded_php_paths', ''),
            'remove_feeds' => get_option('security_remove_feeds', false),
            'remove_oembed' => get_option('security_remove_oembed', false),
            'remove_pingback' => get_option('security_remove_pingback', false),
            'remove_wp_json' => get_option('security_remove_wp_json', false),
            'remove_rsd' => get_option('security_remove_rsd', false),
            'remove_wp_generator' => get_option('security_remove_wp_generator', false),
            'allow_adsense' => get_option('security_allow_adsense', false),
            'allow_youtube' => get_option('security_allow_youtube', false),
            'allow_twitter' => get_option('security_allow_twitter', false),
            'enable_strict_csp' => get_option('security_enable_strict_csp', false),
            'remove_query_strings' => get_option('security_remove_query_strings', false),
            'cookie_notice_text' => get_option('security_cookie_notice_text', 'This website uses cookies to ensure you get the best experience. By continuing to use this site, you consent to our use of cookies.'),
            'enable_xss' => get_option('security_enable_xss', true),
            'enable_waf' => get_option('security_enable_waf', true),
            'waf_request_limit' => get_option('security_waf_request_limit', 100),
            'waf_blacklist_threshold' => get_option('security_waf_blacklist_threshold', 5),
            'allowed_script_domains' => get_option('security_allowed_script_domains', ''),
            'allowed_style_domains' => get_option('security_allowed_style_domains', ''),
            'allowed_image_domains' => get_option('security_allowed_image_domains', ''),
            'allowed_frame_domains' => get_option('security_allowed_frame_domains', ''),
            'enable_cookie_banner' => get_option('security_enable_cookie_banner', false),
            // SEO and Anti-Spam options
            'max_filter_colours' => get_option('security_max_filter_colours', 3),
            'max_filter_sizes' => get_option('security_max_filter_sizes', 4),
            'max_filter_brands' => get_option('security_max_filter_brands', 2),
            'max_total_filters' => get_option('security_max_total_filters', 8),
            'max_query_params' => get_option('security_max_query_params', 10),
            'max_query_length' => get_option('security_max_query_length', 500),
            '410_page_content' => get_option('security_410_page_content', ''),
            'enable_seo_features' => get_option('security_enable_seo_features', true),
            // Bot Protection options
            'enable_bot_protection' => get_option('security_enable_bot_protection', true),
            'bot_whitelist_agents' => get_option('security_bot_whitelist_agents', ''),
            'bot_whitelist_ips' => get_option('security_bot_whitelist_ips', ''),
            'bot_blacklist_agents' => get_option('security_bot_blacklist_agents', ''),
            'bot_email_alerts' => get_option('security_bot_email_alerts', false),
            'bot_alert_email' => get_option('security_bot_alert_email', get_option('admin_email')),
            'bot_block_status' => get_option('security_bot_block_status', 403),
            'bot_block_message' => get_option('security_bot_block_message', 'Access Denied - Bad Bot Detected'),
            'bot_custom_message' => get_option('security_bot_custom_message', '')
        );
        ?>
        <div class="wrap">
            <h1>Security Settings</h1>
            <form method="post" action="">
                <?php wp_nonce_field('security_settings_nonce', 'security_nonce'); ?>
                
                <h2 class="nav-tab-wrapper">
                    <a href="#security-tab" class="nav-tab nav-tab-active">Security</a>
                    <a href="#bot-protection-tab" class="nav-tab">Bot Protection</a>
                    <a href="#seo-tab" class="nav-tab">SEO & Anti-Spam</a>
                    <a href="#csp-tab" class="nav-tab">Content Security Policy</a>
                    <a href="#features-tab" class="nav-tab">WordPress Features</a>
                </h2>

                <div id="security-tab" class="tab-content">
                    <table class="form-table">
                        <tr>
                            <th>Security Features</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_xss" value="1" <?php checked($options['enable_xss']); ?>>
                                    Enable XSS Protection
                                </label>
                                <p class="description">Controls Content Security Policy and other XSS protection features</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>WAF Settings</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_waf" value="1" <?php checked($options['enable_waf']); ?>>
                                    Enable Web Application Firewall
                                </label>
                                <p class="description">Protects against common web attacks including SQL injection, XSS, and file inclusion attempts</p>
                                
                                <br><br>
                                <label>
                                    Request Limit per Minute:
                                    <input type="number" name="waf_request_limit" value="<?php echo esc_attr($options['waf_request_limit']); ?>" min="10" max="1000">
                                </label>
                                
                                <br><br>
                                <label>
                                    Blacklist Threshold (violations/24h):
                                    <input type="number" name="waf_blacklist_threshold" value="<?php echo esc_attr($options['waf_blacklist_threshold']); ?>" min="1" max="100">
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th>Blocked Patterns</th>
                            <td>
                                <textarea name="blocked_patterns" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['blocked_patterns']); ?></textarea>
                                <p class="description">Enter one pattern per line (e.g., %3C, %3E)</p>
                            </td>
                        </tr>

                        <tr>
                            <th>PHP Access Exclusions</th>
                            <td>
                                <textarea name="excluded_php_paths" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['excluded_php_paths']); ?></textarea>
                                <p class="description">Enter paths to allow PHP access (e.g., wp-admin, wp-login.php)</p>
                            </td>
                        </tr>
                    </table>
                </div>

                <div id="bot-protection-tab" class="tab-content" style="display:none;">
                    <table class="form-table">
                        <tr>
                            <th>Bot Protection</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_bot_protection" value="1" <?php checked($options['enable_bot_protection']); ?>>
                                    Enable Bad Bot Protection & Blackhole
                                </label>
                                <p class="description">🕳️ Creates invisible traps that catch bad bots while allowing good bots and humans</p>
                                
                                <div style="background: #f0f8ff; padding: 15px; margin: 10px 0; border-left: 4px solid #0073aa;">
                                    <strong>Features:</strong>
                                    <ul style="margin: 10px 0 0 20px;">
                                        <li>✅ Stops leeches, scanners, and spammers</li>
                                        <li>✅ Saves server resources for humans and good bots</li>
                                        <li>✅ Improves traffic quality and overall site security</li>
                                        <li>✅ Works silently behind the scenes with 0% performance impact</li>
                                        <li>✅ Automatic robots.txt integration</li>
                                        <li>✅ Real-time bot detection and blocking</li>
                                    </ul>
                                </div>
                            </td>
                        </tr>

                        <tr>
                            <th>Whitelisted Bots (User Agents)</th>
                            <td>
                                <textarea name="bot_whitelist_agents" rows="8" cols="50" class="large-text" placeholder="googlebot&#10;bingbot&#10;slurp&#10;duckduckbot"><?php echo esc_textarea($options['bot_whitelist_agents']); ?></textarea>
                                <p class="description">Enter one bot name per line. These bots will NEVER be blocked (e.g., googlebot, bingbot). Leave empty for defaults.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Whitelisted IPs</th>
                            <td>
                                <textarea name="bot_whitelist_ips" rows="5" cols="50" class="large-text" placeholder="127.0.0.1&#10;192.168.1.1"><?php echo esc_textarea($options['bot_whitelist_ips']); ?></textarea>
                                <p class="description">Enter one IP address per line. These IPs will never be blocked.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Blacklisted Bots (User Agents)</th>
                            <td>
                                <textarea name="bot_blacklist_agents" rows="8" cols="50" class="large-text" placeholder="masscan&#10;nmap&#10;sqlmap&#10;nikto"><?php echo esc_textarea($options['bot_blacklist_agents']); ?></textarea>
                                <p class="description">Enter one bot name per line. These bots will be immediately blocked. Leave empty for defaults.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Block Response</th>
                            <td>
                                <label>
                                    HTTP Status Code:
                                    <select name="bot_block_status">
                                        <option value="403" <?php selected($options['bot_block_status'], 403); ?>>403 Forbidden</option>
                                        <option value="410" <?php selected($options['bot_block_status'], 410); ?>>410 Gone</option>
                                        <option value="444" <?php selected($options['bot_block_status'], 444); ?>>444 No Response</option>
                                    </select>
                                </label>
                                <p class="description">HTTP status code to return to blocked bots</p>
                                
                                <br><br>
                                <label>
                                    Block Message:
                                    <input type="text" name="bot_block_message" value="<?php echo esc_attr($options['bot_block_message']); ?>" class="regular-text">
                                </label>
                                <p class="description">Message shown to blocked bots</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Custom Block Page</th>
                            <td>
                                <textarea name="bot_custom_message" rows="8" cols="50" class="large-text" placeholder="<h1>Access Denied</h1><p>Bad bot detected.</p>"><?php echo esc_textarea($options['bot_custom_message']); ?></textarea>
                                <p class="description">Custom HTML content for blocked bots. Leave empty for default page.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Email Alerts</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bot_email_alerts" value="1" <?php checked($options['bot_email_alerts']); ?>>
                                    Send email alerts when bots are blocked
                                </label>
                                
                                <br><br>
                                <label>
                                    Alert Email:
                                    <input type="email" name="bot_alert_email" value="<?php echo esc_attr($options['bot_alert_email']); ?>" class="regular-text">
                                </label>
                                <p class="description">Email address to receive bot blocking alerts</p>
                            </td>
                        </tr>
                    </table>
                </div>

                <div id="seo-tab" class="tab-content" style="display:none;">
                    <table class="form-table">
                        <tr>
                            <th>SEO Features</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_seo_features" value="1" <?php checked($options['enable_seo_features']); ?>>
                                    Enable SEO & Anti-Spam Features
                                </label>
                                <p class="description">Enables 410 responses for deleted content and spam URL detection</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Filter Limits (Anti-Spam)</th>
                            <td>
                                <label>
                                    Max Colors in Filter:
                                    <input type="number" name="max_filter_colours" value="<?php echo esc_attr($options['max_filter_colours']); ?>" min="1" max="10">
                                </label>
                                <p class="description">Maximum number of colors allowed in filter_colour parameter</p>
                                
                                <br><br>
                                <label>
                                    Max Sizes in Filter:
                                    <input type="number" name="max_filter_sizes" value="<?php echo esc_attr($options['max_filter_sizes']); ?>" min="1" max="10">
                                </label>
                                <p class="description">Maximum number of sizes allowed in filter_size parameter</p>
                                
                                <br><br>
                                <label>
                                    Max Brands in Filter:
                                    <input type="number" name="max_filter_brands" value="<?php echo esc_attr($options['max_filter_brands']); ?>" min="1" max="10">
                                </label>
                                <p class="description">Maximum number of brands allowed in filter_brand parameter</p>
                                
                                <br><br>
                                <label>
                                    Max Total Filters:
                                    <input type="number" name="max_total_filters" value="<?php echo esc_attr($options['max_total_filters']); ?>" min="1" max="20">
                                </label>
                                <p class="description">Maximum total number of filter values across all parameters</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Query String Limits</th>
                            <td>
                                <label>
                                    Max Query Parameters:
                                    <input type="number" name="max_query_params" value="<?php echo esc_attr($options['max_query_params']); ?>" min="5" max="50">
                                </label>
                                <p class="description">Maximum number of query parameters allowed</p>
                                
                                <br><br>
                                <label>
                                    Max Query String Length:
                                    <input type="number" name="max_query_length" value="<?php echo esc_attr($options['max_query_length']); ?>" min="100" max="2000">
                                </label>
                                <p class="description">Maximum length of query string in characters</p>
                            </td>
                        </tr>

                        <tr>
                            <th>410 Page Content</th>
                            <td>
                                <textarea name="410_page_content" rows="10" cols="50" class="large-text"><?php echo esc_textarea($options['410_page_content']); ?></textarea>
                                <p class="description">Custom HTML content for 410 (Gone) pages. Leave empty for default content.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Query String Settings</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="remove_query_strings" value="1" <?php checked($options['remove_query_strings']); ?>>
                                    Remove Excessive Query Strings from URLs
                                </label>
                                <p class="description">Automatically removes excessive query parameters while preserving essential WooCommerce filters</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Excluded Paths</th>
                            <td>
                                <textarea name="excluded_paths" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['excluded_paths']); ?></textarea>
                                <p class="description">Enter one path per line (e.g., /register/?action=check_email). These paths will keep their query strings.</p>
                            </td>
                        </tr>
                    </table>
                </div>

                <div id="csp-tab" class="tab-content" style="display:none;">
                    <table class="form-table">
                        <tr>
                            <th>Content Security Policy Domains</th>
                            <td>
                                <p><strong>Script Domains (script-src)</strong></p>
                                <textarea name="allowed_script_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_script_domains']); ?></textarea>
                                <p class="description">Enter one domain per line (e.g., checkout.razorpay.com). These domains will be allowed to load scripts.</p>
                                
                                <br><br>
                                <p><strong>Style Domains (style-src)</strong></p>
                                <textarea name="allowed_style_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_style_domains']); ?></textarea>
                                <p class="description">Enter one domain per line for custom style sources.</p>
                                
                                <br><br>
                                <p><strong>Image Domains (img-src)</strong></p>
                                <textarea name="allowed_image_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_image_domains']); ?></textarea>
                                <p class="description">Enter one domain per line (e.g., mellmon.in, cdn.razorpay.com). These domains will be allowed to load images.</p>
                                
                                <br><br>
                                <p><strong>Frame Domains (frame-src)</strong></p>
                                <textarea name="allowed_frame_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_frame_domains']); ?></textarea>
                                <p class="description">Enter one domain per line for allowed iframe sources.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Content Security Policy</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_strict_csp" value="1" <?php checked($options['enable_strict_csp']); ?>>
                                    Enable Strict Content Security Policy
                                </label>
                                <p class="description">When disabled, a more permissive policy is used that allows most third-party content. Enable for stricter security.</p>
                                
                                <br><br>
                                <strong>Allow Third-party Services (when strict CSP is enabled):</strong><br>
                                <label>
                                    <input type="checkbox" name="allow_adsense" value="1" <?php checked($options['allow_adsense']); ?>>
                                    Allow Google AdSense
                                </label><br>
                                <label>
                                    <input type="checkbox" name="allow_youtube" value="1" <?php checked($options['allow_youtube']); ?>>
                                    Allow YouTube Embeds
                                </label><br>
                                <label>
                                    <input type="checkbox" name="allow_twitter" value="1" <?php checked($options['allow_twitter']); ?>>
                                    Allow Twitter Embeds
                                </label>
                            </td>
                        </tr>
                    </table>
                </div>

                <div id="features-tab" class="tab-content" style="display:none;">
                    <table class="form-table">
                        <tr>
                            <th>Enable Cookie Consent Banner</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_cookie_banner" value="1" <?php checked($options['enable_cookie_banner']); ?>>
                                    Enable Cookie Consent Banner
                                </label>
                                <p class="description">Show or hide the cookie consent banner on your site.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Cookie Notice Text</th>
                            <td>
                                <textarea name="cookie_notice_text" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['cookie_notice_text']); ?></textarea>
                                <p class="description">Customize the cookie consent notice text</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Remove Features</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="remove_feeds" value="1" <?php checked($options['remove_feeds']); ?>>
                                    Remove RSS Feeds (Returns 410 Gone)
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_oembed" value="1" <?php checked($options['remove_oembed']); ?>>
                                    Remove oEmbed Links
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_pingback" value="1" <?php checked($options['remove_pingback']); ?>>
                                    Remove Pingback and Disable XMLRPC
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_wp_json" value="1" <?php checked($options['remove_wp_json']); ?>>
                                    Remove WP REST API Links (wp-json)
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_rsd" value="1" <?php checked($options['remove_rsd']); ?>>
                                    Remove RSD Link
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_wp_generator" value="1" <?php checked($options['remove_wp_generator']); ?>>
                                    Remove WordPress Generator Meta Tag
                                </label>
                            </td>
                        </tr>
                    </table>
                </div>
                
                <p class="submit">
                    <input type="submit" name="save_settings" class="button button-primary" value="Save Settings">
                </p>
            </form>
        </div>

        <style>
        .nav-tab-wrapper { margin-bottom: 20px; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        </style>

        <script>
        jQuery(document).ready(function($) {
            $('.nav-tab').click(function(e) {
                e.preventDefault();
                $('.nav-tab').removeClass('nav-tab-active');
                $('.tab-content').hide();
                $(this).addClass('nav-tab-active');
                $($(this).attr('href')).show();
            });
            
            // Show first tab by default
            $('#security-tab').show();
        });
        </script>
        <?php
    }

    public function render_bot_logs_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Initialize bot blackhole to get stats
        $bot_blackhole = new BotBlackhole();
        $stats = $bot_blackhole->get_blocked_bots_stats();
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'security_blocked_bots';
        
        // Handle actions
        if (isset($_POST['clear_logs']) && check_admin_referer('bot_logs_nonce', 'bot_nonce')) {
            $wpdb->query("TRUNCATE TABLE {$table_name}");
            echo '<div class="notice notice-success"><p>Bot logs cleared successfully.</p></div>';
        }
        
        // Get recent logs
        $logs = $wpdb->get_results(
            "SELECT * FROM {$table_name} ORDER BY timestamp DESC LIMIT 100",
            ARRAY_A
        );
        
        ?>
        <div class="wrap">
            <h1>🕳️ Bot Protection Logs</h1>
            
            <div class="bot-stats" style="display: flex; gap: 20px; margin: 20px 0;">
                <div class="stat-box" style="background: #f0f8ff; padding: 15px; border-radius: 8px; text-align: center; min-width: 120px;">
                    <h3 style="margin: 0; color: #0073aa;"><?php echo number_format($stats['total']); ?></h3>
                    <p style="margin: 5px 0 0 0;">Total Blocked</p>
                </div>
                <div class="stat-box" style="background: #f0fff0; padding: 15px; border-radius: 8px; text-align: center; min-width: 120px;">
                    <h3 style="margin: 0; color: #46b450;"><?php echo number_format($stats['today']); ?></h3>
                    <p style="margin: 5px 0 0 0;">Today</p>
                </div>
                <div class="stat-box" style="background: #fff8f0; padding: 15px; border-radius: 8px; text-align: center; min-width: 120px;">
                    <h3 style="margin: 0; color: #f56e28;"><?php echo number_format($stats['week']); ?></h3>
                    <p style="margin: 5px 0 0 0;">This Week</p>
                </div>
            </div>
            
            <?php if (!empty($stats['top_ips'])): ?>
            <div class="top-blocked-ips" style="margin: 20px 0;">
                <h3>Top Blocked IPs</h3>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Block Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($stats['top_ips'] as $ip_data): ?>
                        <tr>
                            <td><?php echo esc_html($ip_data['ip_address']); ?></td>
                            <td><?php echo number_format($ip_data['count']); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php endif; ?>
            
            <div class="bot-logs-actions" style="margin: 20px 0;">
                <form method="post" style="display: inline;">
                    <?php wp_nonce_field('bot_logs_nonce', 'bot_nonce'); ?>
                    <input type="submit" name="clear_logs" class="button button-secondary" value="Clear All Logs" onclick="return confirm('Are you sure you want to clear all bot logs?');">
                </form>
            </div>
            
            <h3>Recent Bot Blocks (Last 100)</h3>
            <?php if (empty($logs)): ?>
                <p>No bots have been blocked yet. The blackhole is ready and waiting! 🕳️</p>
            <?php else: ?>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th style="width: 15%;">Date/Time</th>
                        <th style="width: 12%;">IP Address</th>
                        <th style="width: 25%;">User Agent</th>
                        <th style="width: 25%;">Request URI</th>
                        <th style="width: 15%;">Referrer</th>
                        <th style="width: 8%;">Reason</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($logs as $log): ?>
                    <tr>
                        <td><?php echo esc_html(date('M j, Y H:i', strtotime($log['timestamp']))); ?></td>
                        <td><code><?php echo esc_html($log['ip_address']); ?></code></td>
                        <td style="word-break: break-all; font-size: 11px;"><?php echo esc_html(substr($log['user_agent'], 0, 100)); ?><?php echo strlen($log['user_agent']) > 100 ? '...' : ''; ?></td>
                        <td style="word-break: break-all; font-size: 11px;"><?php echo esc_html(substr($log['request_uri'], 0, 80)); ?><?php echo strlen($log['request_uri']) > 80 ? '...' : ''; ?></td>
                        <td style="word-break: break-all; font-size: 11px;"><?php echo esc_html(substr($log['referrer'], 0, 50)); ?><?php echo strlen($log['referrer']) > 50 ? '...' : ''; ?></td>
                        <td><span class="dashicons dashicons-warning" style="color: #d63638;"></span> <?php echo esc_html($log['block_reason']); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
            
            <div style="margin-top: 30px; padding: 20px; background: #f9f9f9; border-radius: 8px;">
                <h3>🛡️ How Bot Protection Works</h3>
                <ul style="list-style-type: disc; margin-left: 20px;">
                    <li><strong>Invisible Blackhole Traps:</strong> Hidden links that only bots follow</li>
                    <li><strong>User Agent Analysis:</strong> Detects known bad bots and suspicious patterns</li>
                    <li><strong>Behavioral Detection:</strong> Identifies bot-like behavior patterns</li>
                    <li><strong>IP Caching:</strong> Fast blocking of previously identified bad IPs</li>
                    <li><strong>Robots.txt Integration:</strong> Warns bots away from trap URLs</li>
                    <li><strong>Zero Performance Impact:</strong> Optimized for speed with smart caching</li>
                </ul>
            </div>
        </div>
        <?php
    }

    private function save_settings() {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (!isset($_POST['security_nonce']) || !wp_verify_nonce($_POST['security_nonce'], 'security_settings_nonce')) {
            wp_die('Security check failed');
        }

        // Save all settings
        update_option('security_enable_xss', isset($_POST['enable_xss']));
        update_option('security_enable_strict_csp', isset($_POST['enable_strict_csp']));
        update_option('security_allow_adsense', isset($_POST['allow_adsense']));
        update_option('security_allow_youtube', isset($_POST['allow_youtube']));
        update_option('security_allow_twitter', isset($_POST['allow_twitter']));
        update_option('security_cookie_notice_text', sanitize_textarea_field($_POST['cookie_notice_text']));
        update_option('security_excluded_paths', sanitize_textarea_field($_POST['excluded_paths']));
        update_option('security_blocked_patterns', sanitize_textarea_field($_POST['blocked_patterns']));
        update_option('security_excluded_php_paths', sanitize_textarea_field($_POST['excluded_php_paths']));
        update_option('security_remove_feeds', isset($_POST['remove_feeds']));
        update_option('security_remove_oembed', isset($_POST['remove_oembed']));
        update_option('security_remove_pingback', isset($_POST['remove_pingback']));
        update_option('security_remove_wp_json', isset($_POST['remove_wp_json']));
        update_option('security_remove_rsd', isset($_POST['remove_rsd']));
        update_option('security_remove_wp_generator', isset($_POST['remove_wp_generator']));
        update_option('security_enable_waf', isset($_POST['enable_waf']));
        update_option('security_waf_request_limit', intval($_POST['waf_request_limit']));
        update_option('security_waf_blacklist_threshold', intval($_POST['waf_blacklist_threshold']));
        update_option('security_remove_query_strings', isset($_POST['remove_query_strings']));
        update_option('security_allowed_script_domains', sanitize_textarea_field($_POST['allowed_script_domains']));
        update_option('security_allowed_style_domains', sanitize_textarea_field($_POST['allowed_style_domains']));
        update_option('security_allowed_image_domains', sanitize_textarea_field($_POST['allowed_image_domains']));
        update_option('security_allowed_frame_domains', sanitize_textarea_field($_POST['allowed_frame_domains']));
        update_option('security_enable_cookie_banner', isset($_POST['enable_cookie_banner']));
        
        // SEO and Anti-Spam settings
        update_option('security_enable_seo_features', isset($_POST['enable_seo_features']));
        update_option('security_max_filter_colours', intval($_POST['max_filter_colours']));
        update_option('security_max_filter_sizes', intval($_POST['max_filter_sizes']));
        update_option('security_max_filter_brands', intval($_POST['max_filter_brands']));
        update_option('security_max_total_filters', intval($_POST['max_total_filters']));
        update_option('security_max_query_params', intval($_POST['max_query_params']));
        update_option('security_max_query_length', intval($_POST['max_query_length']));
        update_option('security_410_page_content', wp_kses_post($_POST['410_page_content']));
        
        // Bot Protection settings
        update_option('security_enable_bot_protection', isset($_POST['enable_bot_protection']));
        update_option('security_bot_whitelist_agents', sanitize_textarea_field($_POST['bot_whitelist_agents']));
        update_option('security_bot_whitelist_ips', sanitize_textarea_field($_POST['bot_whitelist_ips']));
        update_option('security_bot_blacklist_agents', sanitize_textarea_field($_POST['bot_blacklist_agents']));
        update_option('security_bot_email_alerts', isset($_POST['bot_email_alerts']));
        update_option('security_bot_alert_email', sanitize_email($_POST['bot_alert_email']));
        update_option('security_bot_block_status', intval($_POST['bot_block_status']));
        update_option('security_bot_block_message', sanitize_text_field($_POST['bot_block_message']));
        update_option('security_bot_custom_message', wp_kses_post($_POST['bot_custom_message']));
    }

    public function register_settings() {
        $settings = array(
            'security_enable_waf', 'security_enable_xss', 'security_enable_strict_csp',
            'security_allow_adsense', 'security_allow_youtube', 'security_allow_twitter',
            'security_cookie_notice_text', 'security_excluded_paths', 'security_blocked_patterns',
            'security_excluded_php_paths', 'security_remove_feeds', 'security_remove_oembed',
            'security_remove_pingback', 'security_remove_query_strings', 'security_remove_wp_json',
            'security_remove_rsd', 'security_remove_wp_generator', 'security_waf_request_limit',
            'security_waf_blacklist_threshold', 'security_allowed_script_domains',
            'security_allowed_style_domains', 'security_allowed_image_domains',
            'security_allowed_frame_domains', 'security_enable_cookie_banner',
            'security_enable_seo_features', 'security_max_filter_colours',
            'security_max_filter_sizes', 'security_max_filter_brands',
            'security_max_total_filters', 'security_max_query_params',
            'security_max_query_length', 'security_410_page_content',
            // Bot Protection settings
            'security_enable_bot_protection', 'security_bot_whitelist_agents',
            'security_bot_whitelist_ips', 'security_bot_blacklist_agents',
            'security_bot_email_alerts', 'security_bot_alert_email',
            'security_bot_block_status', 'security_bot_block_message',
            'security_bot_custom_message'
        );

        foreach ($settings as $setting) {
            register_setting('security_settings', $setting);
        }
    }
}