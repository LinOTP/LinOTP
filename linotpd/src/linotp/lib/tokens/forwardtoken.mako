# -*- coding: utf-8 -*-
<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2015 KeyIdentity GmbH
 *
 *   This file is part of LinOTP server.
 *
 *   This program is free software: you can redistribute it and/or
 *   modify it under the terms of the GNU Affero General Public
 *   License, version 3, as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the
 *              GNU Affero General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *    E-mail: linotp@keyidentity.com
 *    Contact: www.linotp.org
 *    Support: www.keyidentity.com
 *
 * contains the forward token web interface
</%doc>



%if c.scope == 'enroll.title' :
${_("Forwarding Token")}
%endif

%if c.scope == 'enroll' :
<script type="text/javascript">
/*
 * 'typ'_enroll_setup_defaults()
 *
 * this method is called, before the dialog is shown
 *
 */
function forward_enroll_setup_defaults(config, options){
    var rand_pin = options['otp_pin_random'];
    if (rand_pin > 0) {
        $("[name='set_pin_rows']").hide();
    } else {
        $("[name='set_pin_rows']").show();
    }

}

/*
 * 'typ'_get_enroll_params()
 *
 * this method is called, when the token  is submitted
 * - it will return a hash of parameters for admin/init call
 *
 */

function forward_get_enroll_params(){
	var params ={};

    params['forward.serial'] 		= $('#forward_serial').val();
    params['description'] 			= "forward:" + $('#forward_server').val();

    jQuery.extend(params, add_user_data());

    if ($('#forward_pin1').val() != '') {
        params['pin'] = $('#forward_pin1').val();
    }

	return params;
}

</script>
<hr>
<p>${_("Here you can define to which token the authentication request should be forwarded.")}</p>
<p>${_("You can forward the OTP to a target serial number.")}</p>
<table><tr>
	<td><label for="forward_serial">${_("forward serial")}</label></td>
	<td><input type="text" name="forward_serial" id="forward_serial" value="" class="text ui-widget-content ui-corner-all"></td>
	</tr><tr>

<tr name="set_pin_rows" class="space" title='${_("Protect your token with a static pin")}'><th colspan="2">${_("Token Pin:")}</th></tr>
	<tr name="set_pin_rows">
    <td class="description"><label for="forward_pin1" id="forward_pin1_label">${_("enter PIN")}:</label></td>
    <td><input type="password" autocomplete="off" name="pin1" id="forward_pin1"
            class="text ui-widget-content ui-corner-all"></td>
	</tr>
	<tr name="set_pin_rows">
    <td class="description"><label for="forward_pin2" id="forward_pin2_label">${_("confirm PIN")}:</label></td>
    <td><input type="password" autocomplete="off" name="pin2" id="forward_pin2"
            class="text ui-widget-content ui-corner-all"></td>
	</tr></table>


%endif