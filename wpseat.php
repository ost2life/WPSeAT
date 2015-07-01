<?php
/*

  Plugin Name: WPSeAT
  Description: Used to authenticate a user against the SeAT user database.
  Version: 1.0
  Author: Matt Latham (matt@codepixl.com)
  Author URI: http://matt.codepixl.com

 */

// If this file is called directly, abort.
if ( !defined('WPINC') ) {
	die;
}

require 'plugin-update-checker/plugin-update-checker.php';
$myUpdateChecker = PucFactory::buildUpdateChecker(
  'http://matt.codepixl.com/eve/wpseat/wpseat.json',
  __FILE__ );

/************************************
* Plugin Options
************************************/
add_action('admin_menu', 'wpseat_add_menu');
add_action('admin_init', 'wpseat_init');
register_activation_hook(__FILE__, 'wpseat_activate');

function wpseat_activate() {
	add_option('wpseat_app_user', "");
	add_option('wpseat_app_pass', "");
	add_option('wpseat_base_url', "");
  add_option('wpseat_seat_only', "");
}

function wpseat_init() {
	register_setting('wpseat', 'wpseat_app_user');
	register_setting('wpseat', 'wpseat_app_pass');
	register_setting('wpseat', 'wpseat_base_url');
  register_setting('wpseat', 'wpseat_seat_only');
}

// Add settings link to dashboard menu
function wpseat_add_menu() {
	add_options_page('WPSeAT Settings', 'WPSeAT Settings', 'manage_options', __FILE__, 'wpseat_display_options');
}

// Settings display page
function wpseat_display_options() {
	?>
	<div class="wrap">
		<h2>SeAT Auth Settings</h2>
		<form method="post" action="options.php">
		<?php settings_fields('wpseat'); ?>
		<table class="form-table">
			<tr valign="top">
				<th scope="row">SeAT API Authentication Username</th>
				<td><input type="text" name="wpseat_app_user" value="<?php echo get_option('wpseat_app_user'); ?>" /></td>
			</tr>
			<tr valign="top">
				<th scope="row">SeAT API Authentication Password</th>
				<td><input type="text" name="wpseat_app_pass" value="<?php echo get_option('wpseat_app_pass'); ?>" /></td>
			</tr>
			<tr valign="top">
				<th scope="row">SeAT Install Base URL</th>
				<td><input type="text" name="wpseat_base_url" value="<?php echo get_option('wpseat_base_url'); ?>" placeholder="ex. https://domain.com/seat/" /></td>
			</tr>
      <tr valign="top">
				<th scope="row">SeAT Only Logins</th>
				<td><input type="checkbox" name="wpseat_seat_only" value="true" <?php if (get_option('wpseat_seat_only') == "true") echo "checked=\"checked\""; ?>" /></td>
			</tr>
		</table>
		<p class="submit">
			<input type="submit" name="Submit" id="submit" class="button button-primary" value="Save" />
		</p>
		</form>
	</div>
	<?php

}


/************************************
* Authentication
************************************/
add_filter('authenticate', 'wpseat', 10, 3);

function wpseat( $user, $username, $password ) {

	// Make sure we have an endpoint
	if ( get_option('wpseat_base_url') == "" ) return;

	$endpoint = rtrim( get_option('wpseat_base_url'), "/" ) . "/api/v1/authenticate";
	$app_user = get_option('wpseat_app_user');
	$app_pass = get_option('wpseat_app_pass');

	// Build the POST request
	$login_data = array(
		'headers' 	=> array( 'Authorization' => 'Basic ' . base64_encode($app_user . ':' . $app_pass) ),
		'body'		=> array(
			'username' => $username,
			'password' => $password
			),
		'sslverify' => false // For self-signed SSL certs
		);

	$response = wp_remote_post($endpoint, $login_data);
	$ext_auth = json_decode($response['body'], true);

	if (true === $ext_auth['error']) {
		// User does not exist, send back an error message
		$user = new WP_Error( 'denied', __("<strong>Error</strong>: " . $ext_auth['message']) );

	} elseif (false === $ext_auth['error']) {
		// SeAT user exists, pull permission info
		foreach ($ext_auth['groups'] as $group) {
			if ($group['permissions']['superuser']) {
				$isadmin = true;
				break;
			}
		}

		// Try to load user info from the Wordpress user table
		$userobj = new WP_User();
		$user = $userobj->get_data_by('login', $username);
		$user = new WP_User($user->ID); // Attempt to load up the user with that ID

		// The user does not exist in the Wordpress user table, setup the minimum required user information
		if ( $user->ID == 0 ) {
			$userdata = array(
				'user_email' => $ext_auth['user']['email'],
				'user_login' => $username,
				);

			// Create the new user
			$new_user_id = wp_insert_user($userdata);

			// Load the new user
			$user = new WP_User($new_user_id);

		}

		// Check for admin permissions
		if ( $isadmin ) {
			$user->set_role('administrator');
		} else {
			$user->set_role(get_option('default_role'));
		}
	}

  // Disallow login to WP unique users
  if ( get_option('wpseat_seat_only') == "true" ) {
    remove_action('authenticate', 'wp_authenticate_username_password', 20);
  }

	return $user;
}
