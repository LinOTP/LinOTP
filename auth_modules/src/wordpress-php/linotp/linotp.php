<?php
/*
Plugin Name: LinOTP authentication
Plugin URI: http://www.linotp.org
Description: Used to externally authenticate WP users with one time passwords against LinOTP. Derived from "External DB authentication" by "Charlene Barina".
Version: 0.1
Author: Cornelius Kölbel
Author URI: http://www.linotp.org
License:
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2016 KeyIdentity GmbH
 *
 *   This file is part of LinOTP authentication modules.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.

 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *    E-mail: linotp@lsexperts.de
 *    Contact: www.linotp.org
 *    Support: www.lsexperts.de
 *
*/

//backwords compatability with php < 5 for htmlspecialchars_decode
if ( !function_exists('htmlspecialchars_decode') )
{
    function htmlspecialchars_decode($text)
    {
        return strtr($text, array_flip(get_html_translation_table(HTML_SPECIALCHARS)));
    }
}

function linotp_auth_activate() {
	add_option('linotp_server',"","The FQDN of the LinOTP server. This server must be reached via https.");
	add_option('linotp_verify_host',0,"Wether the hostname of the certificate shall be verified (0 or 2)");
	add_option('linotp_verify_peer',0,"Wether the certificate shall be verified (0 or 2)");
	add_option('linotp_realm',"","The Realm in the LinOTP server. Leave empty if you want to use the default realm.");
}

function linotp_auth_init(){
	register_setting('linotp_auth','linotp_server');
	register_setting('linotp_auth','linotp_verify_host');
	register_setting('linotp_auth','linotp_verify_peer');
	register_setting('linotp_auth','linotp_realm');
}

//page for config menu
function linotp_auth_add_menu() {
	add_options_page("LinOTP settings", "LinOTP settings", 10, __FILE__,"linotp_auth_display_options");
}

//actual configuration screen
function linotp_auth_display_options() { 
?>
	<div class="wrap">
	<h2>LinOTP Authentication</h2>        
	<form method="post" action="options.php">
	<?php settings_fields('linotp_auth'); ?>
        <h3>LinOTP Settings</h3>
          <strong>Make sure your admin accounts also exist in the LinOTP server.</strong>
        <table class="form-table">
        <tr valign="top">
            <th scope="row"><label>LinOTP Server name</label></th>
				<td><input type="text" name="linotp_server" value="<?php echo get_option('linotp_server'); ?>" /> </td>
				<td><span class="description"><strong style="color:red;">required</strong>The FQDN of the LinOTP server.</span></td>
        </tr>
        <tr valign="top">
            <th scope="row"><label>Realm</label></th>
				<td><input type="text" name="linotp_realm" value="<?php echo get_option('linotp_realm'); ?>" /> </td>
				<td><span class="description">The realm of the user in the LinOTP server. Leave empty if you use default realm.</span> </td>
        </tr>
        <tr valign="top">
            <th scope="row"><label>Verify Host</label></th>
				<td><input type="text" name="linotp_verify_host" value="<?php echo get_option('linotp_verify_host'); ?>" /> </td>
				<td><span class="description">Verify SSL hostname. (0 or 2)</span></td>
        </tr>        
        <tr valign="top">
            <th scope="row"><label>Verify Peer</label></th>
				<td><input type="text" name="linotp_verify_peer" value="<?php echo get_option('linotp_verify_peer'); ?>" /> </td>
				<td><span class="description">Verify SSL certificate. (0 or 2)</span></td>
        </tr>        
        </table>	
	<p class="submit">
	<input type="submit" name="Submit" value="Save changes" />
	</p>
	</form>
	</div>
<?php
}

//actual meat of plugin - essentially, you're setting $username and $password to pass on to the system.
//You check from your external system and insert/update users into the WP system just before WP actually
//authenticates with its own database.
function linotp_auth_check_login($username,$password) {
	require_once('./wp-includes/registration.php');
	require_once('./wp-content/plugins/linotp/linotp-auth-class.php');
     
    //get the server name
    $server = get_option('linotp_server');
    
    // get SSL options
	$verify_peer = get_option('linotp_verify_peer');
	$verify_host = get_option('linotp_verify_host');
	$realm = get_option('linotp_realm');
	
	$l = new LinOTP( $server, $verify_peer, $verify_host );
	$r = $l->linotp_auth($username, $password, $realm);
	
	global $ext_error;
	if ($r) {
		$userarray['user_login'] = $username;
		$userarray['user_pass'] = $password;                    
		#$userarray['first_name'] = "test";
		#$userarray['last_name'] = "user";        
		#$userarray['user_url'] = "";
		#$userarray['user_email'] = "cornelius.koelbel@lsexperts.de";
		#$userarray['description'] = "";
		#$userarray['aim'] = "";
		#$userarray['yim'] = "";
		#$userarray['jabber'] = "";
		#$userarray['display_name'] = $extfields[$sqlfields['first_name']]." ".$extfields[$sqlfields['last_name']];            
		
		//also if no extended data fields
		#if ($userarray['display_name'] == " ") $userarray['display_name'] = $username;
		
		//looks like wp functions clean up data before entry, so I'm not going to try to clean out fields beforehand.
		if ($id = username_exists($username)) {   //just do an update
			 $userarray['ID'] = $id;
			 wp_update_user($userarray);
		}
		//else wp_insert_user($userarray);          //otherwise create
	} else {
		$ext_error = "wrongpw";
		$username = NULL;
	}
	
}

/*
 * Disable functions.  Idea taken from http auth plugin.
 */
function disable_function_register() {	
	$errors = new WP_Error();
	$errors->add('registerdisabled', __('User registration is not available from this site, so you can\'t create an account or retrieve your password from here. See the message above.'));
	?></form><br /><div id="login_error">User registration is not available from this site, so you can't create an account or retrieve your password from here. See the message above.</div>
		<p id="backtoblog"><a href="<?php bloginfo('url'); ?>/" title="<?php _e('Are you lost?') ?>"><?php printf(__('&larr; Back to %s'), get_bloginfo('title', 'display' )); ?></a></p>
	<?php
	exit();
}

function disable_function() {	
	$errors = new WP_Error();
	$errors->add('registerdisabled', __('User registration is not available from this site, so you can\'t create an account or retrieve your password from here. See the message above.'));
	login_header(__('Log In'), '', $errors);
	?>
	<p id="backtoblog"><a href="<?php bloginfo('url'); ?>/" title="<?php _e('Are you lost?') ?>"><?php printf(__('&larr; Back to %s'), get_bloginfo('title', 'display' )); ?></a></p>
	<?php
	exit();
}


add_action('admin_init', 'linotp_auth_init' );
add_action('admin_menu', 'linotp_auth_add_menu');
add_action('wp_authenticate', 'linotp_auth_check_login', 1, 2 );

register_activation_hook( __FILE__, 'linotp_auth_activate' );
