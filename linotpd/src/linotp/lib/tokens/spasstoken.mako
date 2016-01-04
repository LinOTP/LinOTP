# -*- coding: utf-8 -*-
<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
 *    E-mail: linotp@lsexperts.de
 *    Contact: www.linotp.org
 *    Support: www.lsexperts.de
 *
 * contains the simple pass token web interface
</%doc>


%if c.scope == 'enroll.title' :
${_("Simple Pass Token")}
%endif

%if c.scope == 'enroll' :
<script>
/*
 * 'typ'_enroll_setup_defaults()
 *
 * this method is called, before the dialog is shown
 *
 */
function spass_enroll_setup_defaults(config, options){
    spass_clear_input_fields();
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

function spass_get_enroll_params(){
    var params = {};
    params['type'] = 'spass';
    params['otpkey'] = "1234";
	params['description'] =  $('#enroll_spass_desc').val();

	jQuery.extend(params, add_user_data());

    if ($('#spass_pin1').val() != '') {
        params['pin'] = $('#spass_pin1').val();
    }

    spass_clear_input_fields();
    return params;
}

function spass_clear_input_fields() {
    // Empty input fields for PINs and Keys
    $('#spass_pin1').val('');
    $('#spass_pin2').val('');
}
</script>
<hr>
<p>${_("The Simple Pass token will not require any one time password component.")}
${_("Anyway, you can set an OTP PIN, so that using this token the user can "+
"authenticate always and only with this fixed PIN.")}</p>

<table>
<tr>
    <td><label for="enroll_spass_desc" id='enroll_spass_desc_label'>${_("Description")}</label></td>
    <td><input type="text" name="enroll_spass_desc" id="enroll_spass_desc" value="webGUI_generated" class="text" /></td>
</tr>
<tr name="set_pin_rows" class="space" title='${_("Protect your token with a static PIN")}'><th colspan="2">${_("Token PIN:")}</th></tr>
<tr name="set_pin_rows">
    <td class="description"><label for="spass_pin1" id="spass_opin1_label">${_("Enter PIN")}:</label></td>
    <td><input type="password" autocomplete="off" onkeyup="checkpins('spass_pin1','spass_pin2');" name="pin1" id="spass_pin1"
            class="text ui-widget-content ui-corner-all" /></td>
</tr>
<tr name="set_pin_rows">
    <td class="description"><label for="spass_pin2" id="spass_pin2_label">${_("Confirm PIN")}:</label></td>
    <td><input type="password" autocomplete="off" onkeyup="checkpins('spass_pin1','spass_pin2');" name="pin2" id="spass_pin2"
            class="text ui-widget-content ui-corner-all" /></td
</tr>
</table>

%endif
