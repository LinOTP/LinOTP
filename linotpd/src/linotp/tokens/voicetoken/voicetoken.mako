# -*- coding: utf-8 -*-
<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2019 KeyIdentity GmbH
 *   Copyright (C) 2019 -      netgo software GmbH
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
 * contains the voice token web interface
</%doc>

%if c.scope == 'enroll.title' :
${_("Voice Token")}
%endif

%if c.scope == 'enroll' :
<script type="text/javascript">

function voice_enroll_setup_defaults(config,options){
    voice_clear_input_fields();
	// in case we enroll voice otp, we get the mobile number of the user
	mobiles = get_selected_mobile();
	$('#voice_phone').val($.trim(mobiles[0]));
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
function voice_get_enroll_params(){
    var params = {};

	params['phone'] 		= 'voice';
    // phone number
    params['phone'] 		= $('#voice_phone').val();
    params['description'] 	=  $('#voice_phone').val() + " " + $('#enroll_voice_desc').val();
    //params['serial'] 		= create_serial('LSSM');

    jQuery.extend(params, add_user_data());

    if ($('#voice_pin1').val() != '') {
        params['pin'] = $('#voice_pin1').val();
    }

    voice_clear_input_fields();
    return params;
}

function voice_clear_input_fields() {
    // Empty input fields for PINs and Keys
    $('#voice_pin1').val('');
    $('#voice_pin2').val('');
}
</script>
<hr>
<p>${_("Please enter the mobile phone number for the Voice token")}</p>
<table>
    <tr>
        <td><label for="voice_phone">${_("Phone number")}</label></td>
        <td><input type="text" name="voice_phone" id="voice_phone" value="" class="text ui-widget-content ui-corner-all"></td>
    </tr>
    <tr>
        <td><label for="enroll_voice_desc" id='enroll_voice_desc_label'>${_("Description")}</label></td>
        <td><input type="text" name="enroll_voice_desc" id="enroll_voice_desc" value="webGUI_generated" class="text"></td>
    </tr>
    <tr name="set_pin_rows" class="space" title='${_("Protect your token with a static PIN")}'><th colspan="2">${_("Token PIN:")}</th></tr>
    <tr name="set_pin_rows">
        <td class="description"><label for="voice_pin1" id="voice_pin1_label">${_("Enter PIN")}:</label></td>
        <td><input type="password" autocomplete="off" name="pin1" id="voice_pin1"
                class="text ui-widget-content ui-corner-all"></td>
    </tr>
    <tr name="set_pin_rows">
        <td class="description"><label for="voice_pin2" id="voice_pin2_label">${_("Confirm PIN")}:</label></td>
        <td><input type="password" autocomplete="off" name="pin2" id="voice_pin2"
                class="text ui-widget-content ui-corner-all"></td>
    </tr>
</table>

% endif



