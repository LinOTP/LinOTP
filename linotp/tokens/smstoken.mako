# -*- coding: utf-8 -*-
<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
 * contains the sms token web interface
</%doc>

%if c.scope == 'config.title' :
 ${_("SMS Token")}
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


function sms_get_config_val(){
    var id_map = {};
    id_map['smsChallengeValidityTime'] = 'sms_challenge_validity_time';
    id_map['SMSBlockingTimeout'] = 'sms_challenge_blocking_time';
    return id_map;

}

/*
 * 'typ'_get_config_params()
 *
 * this method is called, when the token config is submitted
 * - it will return a hash of parameters for system/setConfig call
 *
 */
function sms_get_config_params(){
    var url_params ={};
    url_params['smsChallengeValidityTime'] = $('#sms_challenge_validity_time').val();
    url_params['SMSBlockingTimeout'] = $('#sms_challenge_blocking_time').val();
    return url_params;
}
</script>

<form class="cmxform" id="form_sms_config" action="">
<fieldset>
    <legend>${_("SMS token settings")}</legend>
<table>
    <tr><td><label for="sms_challenge_validity_time">${_("Challenge expiration time (sec)")}</label></td>
        <td><input type="number" id="sms_challenge_validity_time" placeholder="120"
            title='${_("Default expiration time of a challenge in seconds.")}'>
        </td>
    </tr>
    <tr><td><label for="sms_challenge_blocking_time">${_("Challenge blocking time (sec)")}</label></td>
        <td><input type="number" id="sms_challenge_blocking_time" placeholder="60"
            title='${_("Time that needs to pass before another challenge can be triggered by the same user in seconds.")}'>
        </td>
    </tr>
</table>
</fieldset>
</form>
%endif



%if c.scope == 'enroll.title' :
${_("SMS OTP")}
%endif

%if c.scope == 'enroll' :
<script type="text/javascript">

function sms_enroll_setup_defaults(config,options){
    sms_clear_input_fields();
	// in case we enroll sms otp, we get the mobile number of the user
	mobiles = get_selected_mobile();
	$('#sms_phone').val($.trim(mobiles[0]));
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
function sms_get_enroll_params(){
    var params = {};

	params['phone'] 		= 'sms';
    // phone number
    params['phone'] 		= $('#sms_phone').val();
    params['description'] 	=  $('#sms_phone').val() + " " + $('#enroll_sms_desc').val();
    //params['serial'] 		= create_serial('LSSM');

    jQuery.extend(params, add_user_data());

    if ($('#sms_pin1').val() != '') {
        params['pin'] = $('#sms_pin1').val();
    }

    sms_clear_input_fields();
    return params;
}

function sms_clear_input_fields() {
    // Empty input fields for PINs and Keys
    $('#sms_pin1').val('');
    $('#sms_pin2').val('');
}
</script>
<hr>
<p>${_("Please enter the mobile phone number for the SMS token")}</p>
<table>
    <tr>
        <td><label for="sms_phone">${_("Phone number")}</label></td>
        <td><input type="text" name="sms_phone" id="sms_phone" value="" class="text ui-widget-content ui-corner-all"></td>
    </tr>
    <tr>
        <td><label for="enroll_sms_desc" id='enroll_sms_desc_label'>${_("Description")}</label></td>
        <td><input type="text" name="enroll_sms_desc" id="enroll_sms_desc" value="webGUI_generated" class="text"></td>
    </tr>
    <tr name="set_pin_rows" class="space" title='${_("Protect your token with a static PIN")}'><th colspan="2">${_("Token PIN:")}</th></tr>
    <tr name="set_pin_rows">
        <td class="description"><label for="sms_pin1" id="sms_pin1_label">${_("Enter PIN")}:</label></td>
        <td><input type="password" autocomplete="off" name="pin1" id="sms_pin1"
                class="text ui-widget-content ui-corner-all"></td>
    </tr>
    <tr name="set_pin_rows">
        <td class="description"><label for="sms_pin2" id="sms_pin2_label">${_("Confirm PIN")}:</label></td>
        <td><input type="password" autocomplete="off" name="pin2" id="sms_pin2"
                class="text ui-widget-content ui-corner-all"></td>
    </tr>
</table>

% endif



%if c.scope == 'selfservice.title.enroll':
${_("Register SMS")}
%endif


%if c.scope == 'selfservice.enroll':

<%!
	from linotp.lib.user import getUserPhone
%>
<%
	try:
		phonenumber = getUserPhone(c.authUser, 'mobile')
		if phonenumber == None or len(phonenumber) == 0:
			 phonenumber = ''
	except Exception as e:
		phonenumber = ''
%>

<script type="text/javascript">
	jQuery.extend(jQuery.validator.messages, {
		required:  "${_('required input field')}",
		minlength: "${_('minimum length must be greater than 10')}",
	});

	jQuery.validator.addMethod("phone", function(value, element, param){
        return value.match(/^[+0-9\/\ ]+$/i);
    }, '${_("Please enter a valid phone number. It may only contain numbers and + or /.")}' );

	$('#form_register_sms').validate({
        rules: {
            sms_mobilephone: {
                required: true,
                minlength: 10,
                number: false,
                phone: true
            }
        }
	});

function self_sms_get_param()
{
	var urlparam = {};
	var mobilephone = $('#sms_mobilephone').val();


	urlparam['type'] 		= 'sms';
	urlparam['phone']		= mobilephone;
	urlparam['description'] = mobilephone + '_' + $("#sms_self_desc").val();

	return urlparam;
}

function self_sms_clear()
{
	return true;
}
function self_sms_submit(){

	var ret = false;

	if ($('#form_register_sms').valid()) {
		var params =  self_sms_get_param();
		enroll_token( params );
		//self_sms_clear();
		ret = true;
	} else {
		alert('${_("Form data not valid.")}');
	}
	return ret;
}

</script>

<h1>${_("Register your SMS OTP Token / mobileTAN")}</h1>
<div id='register_sms_form'>
	<form class="cmxform" id='form_register_sms' action="">
	<fieldset>
		<table>
		<tr>
		<td><label for='sms_mobilephone'>${_("Your mobile phone number")}</label></td>
		<td><input id='sms_mobilephone'
                    name='sms_mobilephone'
                    class="required ui-widget-content ui-corner-all"
                    value='${phonenumber}'

                    %if c.edit_sms == 0:
                           readonly  disabled
                    %endif

                   >
		</td>
		</tr>
		<tr>
		    <td><label for="sms_self_desc" id='sms_self_desc_label'>${_("Description")}</label></td>
		    <td><input type="text" name="sms_self_desc" id="sms_self_desc" value="self_registered"; class="text"></td>
		</tr>
        </table>
        <button class='action-button' id='button_register_sms' onclick="self_sms_submit();">${_("register SMS Token")}</button>
    </fieldset>
    </form>
</div>
% endif


