<?php
/**
 * Plugin Name:       Printer Status Dashboard
 * Description:       Displays the status of 3D printers by fetching data from the Python Printer Dashboard application.
 * Version:           1.0
 * Author:            Your Name
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

// 1. Create the Admin Menu and Settings Page
function psd_add_admin_menu() {
    add_menu_page(
        'Printer Dashboard Settings',
        'Printer Dashboard',
        'manage_options',
        'printer_dashboard',
        'psd_settings_page_html',
        'dashicons-printer',
        100
    );
}
add_action('admin_menu', 'psd_add_admin_menu');

function psd_settings_page_html() {
    if (!current_user_can('manage_options')) {
        return;
    }
    ?>
    <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
        <p>Configure the connection to your Python Printer Dashboard application.</p>
        <form action="options.php" method="post">
            <?php
            settings_fields('psd_settings');
            do_settings_sections('psd_settings');
            submit_button('Save Settings');
            ?>
        </form>
    </div>
    <?php
}

function psd_settings_init() {
    register_setting('psd_settings', 'psd_api_url');

    add_settings_section(
        'psd_section_api',
        'API Settings',
        'psd_section_api_callback',
        'psd_settings'
    );

    add_settings_field(
        'psd_api_url_field',
        'Dashboard API URL',
        'psd_api_url_field_callback',
        'psd_settings',
        'psd_section_api'
    );
}
add_action('admin_init', 'psd_settings_init');

function psd_section_api_callback() {
    echo '<p>Enter the full URL to the <code>/status_json</code> endpoint of your running Python application.</p>';
}

function psd_api_url_field_callback() {
    $option = get_option('psd_api_url');
    ?>
    <input type="url" name="psd_api_url" value="<?php echo isset($option) ? esc_attr($option) : ''; ?>" class="regular-text" placeholder="http://192.168.1.100/status_json">
    <p class="description">Example: <code>http://your-server-ip/status_json</code></p>
    <?php
}


// 2. Create the Shortcode to Display the Dashboard
function psd_dashboard_shortcode() {
    $api_url = get_option('psd_api_url');

    if (empty($api_url)) {
        return '<div class="alert alert-warning">Printer Dashboard Plugin Error: Please set the API URL in the settings.</div>';
    }

    $response = wp_remote_get($api_url, ['timeout' => 10]);

    if (is_wp_error($response)) {
        return '<div class="alert alert-danger">Error connecting to the Printer Dashboard API. Please check the URL and ensure the Python application is running.</div>';
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        return '<div class="alert alert-danger">Error decoding API response.</div>';
    }
    
    // Pass PHP data to JavaScript
    wp_localize_script('psd-dashboard-js', 'psdData', array(
        'printers' => $data,
        'config' => $data['config'] ?? [],
    ));

    // The HTML structure is now much simpler, as JS will build everything.
    ob_start();
    ?>
    <div class="container psd-container">
        <div class="card mb-4">
            <div class="card-body">
                <div class="stats-grid">
                    <div class="stat-item stat-ready"><div class="stat-value text-success" id="stat-ready">0</div><div class="stat-label">Ready</div></div>
                    <div class="stat-item stat-printing"><div class="stat-value text-primary" id="stat-printing">0</div><div class="stat-label">Printing</div></div>
                    <div class="stat-item stat-maintenance"><div class="stat-value text-warning" id="stat-maintenance">0</div><div class="stat-label">Maintenance</div></div>
                    <div class="stat-item stat-offline"><div class="stat-value text-danger" id="stat-offline">0</div><div class="stat-label">Offline</div></div>
                    <div class="stat-item stat-total"><div class="stat-value text-info" id="stat-total">0</div><div class="stat-label">Total</div></div>
                </div>
            </div>
        </div>
        <div id="dash" class="mt-4">
            <!-- Skeleton loaders will be inserted here by JS -->
        </div>
    </div>
    <?php
    return ob_get_clean();
}
add_shortcode('printer_dashboard', 'psd_dashboard_shortcode');

// 3. Enqueue Scripts and Styles for the frontend
function psd_enqueue_scripts() {
    global $post;
    if (is_a($post, 'WP_Post') && has_shortcode($post->post_content, 'printer_dashboard')) {
        // Enqueue Bootstrap CSS (if your theme doesn't already have it)
        wp_enqueue_style('psd-bootstrap', 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css');
        // Enqueue Bootstrap Icons
        wp_enqueue_style('psd-bootstrap-icons', 'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css');
        // Enqueue our custom CSS and JS
        wp_enqueue_style('psd-dashboard-css', plugins_url('dashboard-style.css', __FILE__));
        wp_enqueue_script('psd-dashboard-js', plugins_url('dashboard-script.js', __FILE__), array('jquery'), '1.0', true);
    }
}
add_action('wp_enqueue_scripts', 'psd_enqueue_scripts');

// It's better to have separate CSS and JS files for WordPress.
// Let's create them dynamically if they don't exist.
function psd_create_asset_files() {
    $css_path = plugin_dir_path(__FILE__) . 'dashboard-style.css';
    $js_path = plugin_dir_path(__FILE__) . 'dashboard-script.js';

    if (!file_exists($css_path)) {
        $css_content = '
            /* Paste all the CSS from your public_dashboard.html <style> tag here */
            /* For example: */
            :root { /* ... theme variables ... */ }
            body[data-theme="dark"] { /* ... dark theme variables ... */ }
            .psd-container { /* ... container styles ... */ }
            /* ... etc ... */
        ';
        file_put_contents($css_path, $css_content);
    }

    if (!file_exists($js_path)) {
        $js_content = '
            jQuery(document).ready(function($) {
                // All the JavaScript from your public_dashboard.html goes here
                // but it will use `psdData` instead of fetching from the API.

                function render(data) {
                    // ... your existing render function ...
                }

                // Initial render
                if (typeof psdData !== "undefined") {
                    render(psdData.printers);
                } else {
                    $("#dash").html("<p>Error: Data not found.</p>");
                }
            });
        ';
        file_put_contents($js_path, $js_content);
    }
}
register_activation_hook(__FILE__, 'psd_create_asset_files');
