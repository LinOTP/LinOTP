# -*- coding: utf-8 -*-
<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010-2019 KeyIdentity GmbH
 *   Copyright (C) 2019-     netgo software GmbH
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
 *    E-mail: info@linotp.de
 *    Contact: www.linotp.org
 *    Support: www.linotp.de
 *
 * contains the ocra2 token web interface
</%doc>

%if c.scope == 'config.title' :
 ${_("OCRA2 Token")}
%endif


%if c.scope == 'config' :
<script type="text/javascript">
/*
 * 'typ'_get_config_val()
 *
 * this method is called, when the token config dialog is opened
 * - it contains the mapping of config entries to the form id
 * - according to the Config entries, the form entries will be filled
 *
 */


function ocra2_get_config_val(){
    var id_map = {};

    id_map['Ocra2MaxChallengeRequests'] = 'ocra2_max_challenge';
    id_map['Ocra2ChallengeTimeout'] = 'ocra2_challenge_timeout';

    return id_map;

}

/*
 * 'typ'_get_config_params()
 *
 * this method is called, when the token config is submitted
 * - it will return a hash of parameters for system/setConfig call
 *
 */
function ocra2_get_config_params(){
	var url_params ={};

    url_params['Ocra2MaxChallengeRequests'] = $('#ocra2_max_challenge').val();
    url_params['Ocra2ChallengeTimeout'] = $('#ocra2_challenge_timeout').val();

	return url_params;
}
</script>

<form class="cmxform" id="form_ocra2_config" action="">
<fieldset>
	<legend>${_("OCRA2 token settings")}</legend>
<table>
	<tr><td><label for=ocra2_max_challenge>${_("Maximum concurrent OCRA2 challenges")}</label></td>
		<td><input type="text" id="ocra2_max_challenge" maxlength="4" class=integer
			title='${_("This is the maximum concurrent challenges per OCRA2 Token.")}'></td></tr>
	<tr><td><label for=ocra2_challenge_timeout>${_("OCRA2 challenge timeout")}</label></td>
		<td><input type="text" id="ocra2_challenge_timeout" maxlength="6"
			title='${_("After this time a challenge can not be used anymore. Valid entries are like 1D, 2H or 5M where D=day, H=hour, M=minute.")}'></td></tr>
</table>
</fieldset>
</form>
%endif


%if c.scope == 'enroll.title' :
${_("OCRA2 - challenge/response Token")}
%endif

%if c.scope == 'enroll' :
<script type="text/javascript">
/*
 * 'typ'_enroll_setup_defaults()
 *
 * this method is called, before the dialog is shown
 *
 */
function ocra2_enroll_setup_defaults(config, options){
    ocra2_clear_input_fields();
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
 * this method is called, when the token is submitted
 * - it will return a hash of parameters for admin/init call
 *
 */

function ocra2_get_enroll_params(){
    var url = {};
    url['type'] = 'ocra2';
   	url['description'] = $('#enroll_ocra2_desc').val();
   	url['sharedsecret'] = 1;
	url['ocrasuite'] = $('#ocrasuite_algorithm').val();

    // If we got to generate the ocra2 key, we do it here:
    if ( $('#ocra2_key_cb').is(':checked') ) {
    	url['genkey'] = 1;

    } else {
        // OTP Key
        url['otpkey'] = $('#ocra2_key').val();
    }

    jQuery.extend(url, add_user_data());

    if ($('#ocra2_pin1').val() != '') {
        url['pin'] = $('#ocra2_pin1').val();
    }

    ocra2_clear_input_fields();
    return url;
}

function ocra2_clear_input_fields() {
    // Empty input fields for PINs and Keys
    $('#ocra2_key').val('');
    $('#ocra2_pin1').val('');
    $('#ocra2_pin2').val('');
}
</script>
<hr>
<p><span id='ocra2_key_intro'>
	${_("Please enter or copy the OCRA2 key.")}</span></p>
<table>
<tr>
     <td><label for="ocra2_key" id='ocra2_key_label'>${_("OCRA2 key")}</label></td>
     <td><input type="text" name="ocra2_key" id="ocra2_key" value="" class="text ui-widget-content ui-corner-all"></td>
</tr>
<tr>
	<td> </td>
	<td><input type='checkbox' id='ocra2_key_cb' onclick="cb_changed('ocra2_key_cb',['ocra2_key','ocra2_key_label','ocra2_key_intro']);">
	    <label for=ocra2_key_cb>${_("Generate OCRA2 key.")}</label></td>
</tr>
<tr>
	<td><label for="ocrasuite_algorithm">${_("OCRA suite")}</label></td>
	<td><select name="algorithm" id='ocrasuite_algorithm' >
            <option selected value="OCRA-1:HOTP-SHA256-8:C-QN08">SHA256 - otplen 8 digits - numeric challenge 8 digits</option>
            <option value="OCRA-1:HOTP-SHA256-8:C-QA64">SHA256 - otplen 8 digits - numeric challenge 64 chars</option>
    </select></td>
</tr>
<tr>
    <td><label for="enroll_ocra2_desc" id='enroll_ocra2_desc_label'>${_("Description")}</label></td>
    <td><input type="text" name="enroll_ocra2_desc" id="enroll_ocra2_desc" value="webGUI_generated" class="text"></td>
</tr>

<tr name="set_pin_rows" class="space" title='${_("Protect your token with a static PIN")}'><th colspan="2">${_("Token PIN:")}</th></tr>
<tr name="set_pin_rows">
    <td class="description"><label for="ocra2_pin1" id="ocra2_pin1_label">${_("Enter PIN")}:</label></td>
    <td><input type="password" autocomplete="off" name="pin1" id="ocra2_pin1"
            class="text ui-widget-content ui-corner-all"></td>
</tr>
<tr name="set_pin_rows">
    <td class="description"><label for="ocra2_pin2" id="ocra2_pin2_label">${_("Confirm PIN")}:</label></td>
    <td><input type="password" autocomplete="off" name="pin2" id="ocra2_pin2"
            class="text ui-widget-content ui-corner-all"></td>
</tr>

</table>

% endif
