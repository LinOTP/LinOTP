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
 *  contains the email token web interface
</%doc>

%if c.scope == 'config.title' :
 ${_("E-Mail Token")}
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


function email_get_config_val(){
    var id_map = {};
    id_map['emailChallengeValidityTime'] = 'email_challenge_validity_time';
    return id_map;

}

/*
 * 'typ'_get_config_params()
 *
 * this method is called, when the token config is submitted
 * - it will return a hash of parameters for system/setConfig call
 *
 */
function email_get_config_params(){
    var url_params ={};
    url_params['emailChallengeValidityTime'] = $('#email_challenge_validity_time').val();
    return url_params;
}
</script>

<form class="cmxform" id="form_email_config" action="">
<fieldset>
    <legend>${_("E-Mail token settings")}</legend>
<table>
    <tr><td><label for=email_challenge_validity_time>${_("Challenge expiration time (sec)")}</label></td>
        <td><input type="number" id="email_challenge_validity_time" placeholder="120"
            title='${_("Default expiration time of a challenge in seconds.")}'></td></tr>
</table>
</fieldset>
</form>
%endif


%if c.scope == 'enroll.title' :
${_("E-mail token")}
%endif

%if c.scope == 'enroll' :
<script type="text/javascript">
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
 * this method is called, when the token is submitted
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
    <td><input type="text" name="enroll_email_desc" id="enroll_email_desc" value="webGUI_generated" class="text"></td>
</tr>
<tr name="set_pin_rows" class="space" title='${_("Protect your token with a static PIN")}'><th colspan="2">${_("Token PIN:")}</th></tr>
<tr name='set_pin_rows'>
    <td class="description"><label for="pin1" id="email_pin1_label">${_("Enter PIN")}:</label></td>
    <td><input type="password" autocomplete="off" name="pin1" id="email_pin1"
            class="text ui-widget-content ui-corner-all"></td>
</tr><tr name='set_pin_rows'>
    <td class="description"><label for="pin2" id="email_pin2_label">${_("Confirm PIN")}:</label></td>
    <td><input type="password" autocomplete="off" name="pin2" id="email_pin2"
            class="text ui-widget-content ui-corner-all"></td>
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

<script type="text/javascript">

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
    <form class="cmxform" id='form_register_email' action="">
    <fieldset>
        <table>
        <tr>
        <td><label for='email_address'>${_("Your email address")}</label></td>
        <td><input id='email_address'
                    name='email_address'
                    class="required ui-widget-content ui-corner-all"
                    value='${emailaddress}'

                    %if c.edit_email == 0:
                            readonly disabled
                    %endif
                   >
        </td>
        </tr>
        <tr>
            <td><label for="email_self_desc" id='email_self_desc_label'>${_("Description")}</label></td>
            <td><input type="text" name="email_self_desc" id="email_self_desc"
                        value="self_registered"; class="text"></td>
        </tr>
        </table>
        <button class='action-button' id='button_register_email'
                onclick="self_email_submit();">${_("enroll email token")}</button>
    </fieldset>
    </form>
</div>
% endif
