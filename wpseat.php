<?php
/*

  Plugin Name: WPSeAT
  Description: Used to authenticate a user against the SeAT user database.
  Version: 0.1
  Author: BOVRIL
  Author URI: http://matt.codepixl.com
  
 */


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
}

function wpseat_init() {
	register_setting('wpseat', 'wpseat_app_user');
	register_setting('wpseat', 'wpseat_app_pass');
	register_setting('wpseat', 'wpseat_base_url');
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
				<td><input type="text" name="wpseat_base_url" value="<?php echo get_option('wpseat_base_url'); ?>" /></td>
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

	// Make sure we have en endpoint
	if (get_option('wpseat_base_url') == "") return;

	$endpoint = rtrim(get_option('wpseat_base_url'), "/") . "/api/v1/authenticate";
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
	$ext_auth = json_decode( $response['body'], true );

	if (true === $ext_auth['error']) {
		// User does not exist, send back an error message
		$user = new WP_Error( 'denied', __("<strong>Error</strong>: " . $ext_auth['message']) );
		
	} elseif (false === $ext_auth['error']) {
		// SeAT user exists, try to load user info from the Wordpress user table
		$userobj = new WP_User();
		$user = $userobj->get_data_by('email', $ext_auth['user']['email']);
		$user = new WP_User($user->ID); // Attempt to load up the user with that ID

		// The user does not exist in the Wordpress user table, setup the minimum required user information
		if ($user->ID == 0) {
			$userdata = array(
				'user_email' => $ext_auth['user']['email'],
				'user_login' => $ext_auth['user']['email'],
				'user_activation_key' => 'wpseat'
				);
			
			// Create the new user
			$new_user_id = wp_insert_user($userdata);

			// And load the new user
			$user = new WP_User($new_user_id);
		}
	}

	remove_action('authenticate', 'wp_authenticate_username_password', 20);

	return $user;
}