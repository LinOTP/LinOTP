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
 *  contains the email token web interface
</%doc>


%if c.scope == 'config.title' :
${_("E-mail OTP Token")}
%endif


%if c.scope == 'config' :
<!-- #################### E-mail provider ################### -->
<script>
/*
 * 'typ'_get_config_val()
 *
 * this method is called, when the token config dialog is opened
 * - it contains the mapping of config entries to the form id
 * - according to the Config entries, the form entries will be filled
 *
 */
function email_get_config_val(){
	var ret = {};
	ret['EmailProvider'] = 'c_email_provider';
	ret['EmailProviderConfig'] = 'c_email_provider_config';
	ret['EmailChallengeValidityTime'] = 'c_email_challenge_validity';
	ret['EmailBlockingTimeout'] = 'c_email_blocking';
	return ret;
}
/*
 * 'typ'_get_config_params()
 *
 * this method is called, when the token config is submitted
 * - it will return a hash of parameters for system/setConfig call
 *
 */
function email_get_config_params(){
	var ret = {};
	ret['EmailProvider'] = $('#c_email_provider').val();
	ret['EmailProviderConfig'] = $('#c_email_provider_config').val();
	ret['EmailProviderConfig.type'] = 'password';
	ret['EmailChallengeValidityTime'] = $('#c_email_challenge_validity').val();
	ret['EmailBlockingTimeout'] = $('#c_email_blocking').val();
	return ret;
}

$(document).ready(function () {
    $("#form_emailconfig").validate({
        rules: {
            email_provider_config: {
                valid_json: true
            }
        }
       });
});



</script>

<form class="cmxform" id="form_emailconfig">
<fieldset>
    <legend>${_("E-mail provider config")}</legend>
    <table>
        <tr>
	        <td><label for="c_email_provider">${_("Provider")}</label>: </td>
	        <td><input type="text" name="email_provider" class="required"  id="c_email_provider" size="37" maxlength="80"
	                   placeholder="linotp.lib.emailprovider.SMTPEmailProvider"></td>
        </tr>
        <tr>
	        <td><label for="c_email_provider_config">${_("Provider config")}</label>: </td>
	        <td><textarea name="email_provider_config" class="required"  id="c_email_provider_config" cols='35' rows='6' maxlength="400"
	                      placeholder='{ "SMTP_SERVER":"mail.example.com", "SMTP_USER":"secret_user", "SMTP_PASSWORD":"secret_pasword" "EMAIL_FROM":"linotp@example.com" "EMAIL_SUBJECT":"Your OTP"}'
	            ></textarea></td>
        </tr>
        <tr>
	        <td><label for="c_email_challenge_validity">${_("Challenge validity (sec)")}</label>: </td>
	        <td><input type="text" name="email_challenge_validity" class="required"  id="c_email_challenge_validity" size="5" maxlength="5"></td>
        </tr>
        <tr>
	        <td><label for="c_email_blocking">${_("Time between e-mails (sec)")}</label>: </td>
	        <td><input type="text" name="email_blocking" class="required"  id="c_email_blocking" size="5" maxlength="5" value"30"></td>
	    </tr>
    </table>
</fieldset>
</form>

%endif

%if c.scope == 'enroll.title' :
${_("E-mail token")}
%endif

%if c.scope == 'enroll' :
<script>
function email_enroll_setup_defaults(config, options){
    email_clear_input_fields();
	// in case we enroll e-mail otp, we get the e-mail address of the user
	email_addresses = get_selected_email();
	$('#email_address').val($.trim(email_addresses[0]));
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
function email_get_enroll_params(){
    var params = {};
    // phone number
    params['email_address']	= $('#email_address').val();
    params['description'] = $('#email_address').val() + " " + $('#enroll_email_desc').val();
    jQuery.extend(params, add_user_data());
    if ($('#email_pin1').val() != '') {
        params['pin'] = $('#email_pin1').val();
    }
    email_clear_input_fields();
    return params;
}

function email_clear_input_fields() {
    // Empty input fields for PINs and Keys
    $('#email_pin1').val('');
    $('#email_pin2').val('');
}
</script>
<hr>
<table><tr>
	<td><label for="email_address">${_("E-mail address")}</label></td>
	<td><input type="text" name="email_address" id="email_address" value="" class="text ui-widget-content ui-corner-all"></td>
</tr>
<tr>
    <td><label for="enroll_email_desc" id='enroll_email_desc_label'>${_("Description")}</label></td>
    <td><input type="text" name="enroll_email_desc" id="enroll_email_desc" value="webGUI_generated" class="text" /></td>
</tr>
<tr name="set_pin_rows" class="space" title='${_("Protect your token with a static PIN")}'><th colspan="2">${_("Token PIN:")}</th></tr>
<tr  name='set_pin_rows'>
    <td class="description"><label for="email_pin1" id="email_pin1_label">${_("Enter PIN")}:</label></td>
    <td><input type="password" autocomplete="off" onkeyup="checkpins('email_pin1','email_pin2');" name="pin1" id="email_pin1"
            class="text ui-widget-content ui-corner-all" /></td>
</tr><tr name='set_pin_rows'>
    <td class="description"><label for="email_pin2" id="email_pin2_label">${_("Confirm PIN")}:</label></td>
    <td><input type="password" autocomplete="off" onkeyup="checkpins('email_pin1','email_pin2');" name="pin2" id="email_pin2"
            class="text ui-widget-content ui-corner-all" /></td
</tr>
</table>

%endif

#####
%if c.scope == 'selfservice.title.enroll':
${_("Enroll EMail Token")}
%endif


%if c.scope == 'selfservice.enroll':

<%!
    from linotp.lib.user import getUserDetail
%>
<%
    try:
        info = getUserDetail(c.authUser)
        emailaddress = info.get("email",'')
    except Exception as exx:
        emailaddress = ''
%>

<script>

    $('#form_register_email').validate({
        rules: {
            email_address: {
                required: true,
                minlength: 3,
                email: true
            }
        }
    });


function self_email_get_param()
{
    var urlparam = {};
    var emailaddress = $('#email_address').val();


    urlparam['type'] = 'email';
    urlparam['email_address'] = emailaddress;
    urlparam['description'] = emailaddress + '_' + $("#email_self_desc").val();

    return urlparam;
}

function self_email_clear()
{
    return true;
}
function self_email_submit(){

    var ret = false;

    if ($('#form_register_email').valid()) {
        var params =  self_email_get_param();
        enroll_token(params);
        ret = true;
    } else {
        alert('${_("Input data is not valid!")}');
    }
    return ret;
}

</script>

<h1>${_("Enroll your email token")}</h1>
<div id='register_email_form'>
    <form class="cmxform" id='form_register_email'>
    <fieldset>
        <table>
        <tr>
        <td><label for='email_address'>${_("Your email address")}</label></td>
        <td><input id='email_address'
                    name='email_address'
                    class="required ui-widget-content ui-corner-all"
                    value='${emailaddress}'

                    %if c.edit_email == 0:
                            readonly  disabled
                    %endif
                    />
        </td>
        </tr>
        <tr>
            <td><label for="email_self_desc" id='email_self_desc_label'>${_("Description")}</label></td>
            <td><input type="text" name="email_self_desc" id="email_self_desc"
                        value="self_registered"; class="text" /></td>
        </tr>
        </table>
        <button class='action-button' id='button_register_email'
                onclick="self_email_submit();">${_("enroll email token")}</button>
    </fieldset>
    </form>
</div>
% endif
