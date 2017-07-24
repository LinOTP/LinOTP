# -*- coding: utf-8 -*-
<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
 *   contains the password token web interface
</%doc>


%if c.scope == 'config.title' :
 ${_("Static Password Token Settings")}
%endif


%if c.scope == 'config' :
%endif


%if c.scope == 'enroll.title' :
${_("Static Password Token")}
%endif

%if c.scope == 'enroll' :
<script type="text/javascript">
/*
 * 'typ'_enroll_setup_defaults()
 *
 * this method is called, before the dialog is shown
 *
 */
function pw_enroll_setup_defaults(config, options){
    pw_clear_input_fields();

    var rand_pin = options['otp_pin_random'];
    if (rand_pin > 0) {
        $("[name='set_pin_rows']").hide();
    } else {
        $("[name='set_pin_rows']").show();
    }
}


function pw_clear_input_fields() {
    // Empty input fields for PINs and Keys
    $('#pw_key').val('');
    $('#pw_pin1').val('');
    $('#pw_pin2').val('');
}

/*
 * 'typ'_get_enroll_params()
 *
 * this method is called, when the token  is submitted
 * - it will return a hash of parameters for admin/init call
 *
 */
function pw_get_enroll_params(){
    var url = {};
    url['type'] = 'pw';
   	url['description'] = $('#enroll_pw_desc').val();

    // OTP Key
    url['otpkey'] = $('#pw_key').val();

    jQuery.extend(url, add_user_data());

    if ($('#pw_pin1').val() != '') {
        url['pin'] = $('#pw_pin1').val();
    }

    pw_clear_input_fields();
    return url;
}
$( document ).ready(function() {

});


</script>

<hr>
<table>
<tr><td colspan=2><span id='pw_key_intro'>${_("Create Static Password Token")}</span></td></tr>
<tr class="space">
    <th colspan="2" title='${_("The token seed is the password")}'
    >${_("Token Password:")}</th>
</tr>


<tr>
    <td class="description" >
        <label for="pw_key_rb_no">${_("Enter seed")}</label></td>
    <td>
        <input type="text" name="pw_key" id="pw_key" value="" class="text ui-widget-content ui-corner-all"></td>
</tr>

<tr class="space">
    <th colspan="2" title='${_("Token settings")}'>
    ${_("Token settings:")}</th>
</tr>
<tr>
    <td class="description"><label for="enroll_pw_desc" id='enroll_pw_desc_label'>${_("Description")}</label></td>
    <td><input type="text" id="enroll_pw_desc"
                value="web ui generated" class="text"></td>
</tr>

<tr name="set_pin_rows" class="space" title='${_("Protect your token with a static PIN")}'><th colspan="2">${_("Token PIN:")}</th></tr>
<tr name="set_pin_rows">
    <td class="description"><label for="pin1" id="pw_pin1_label">${_("Enter PIN")}:</label></td>
    <td><input type="password" autocomplete="off" name="pin1" id="pw_pin1"
            class="text ui-widget-content ui-corner-all"></td>
</tr>
<tr name="set_pin_rows">
    <td class="description"><label for="pin2" id="pw_pin2_label">${_("Confirm PIN")}:</label></td>
    <td><input type="password" autocomplete="off" name="pin2" id="pw_pin2"
            class="text ui-widget-content ui-corner-all"></td>
</tr>

</table>

% endif




%if c.scope == 'selfservice.title.enroll':
${_("Enroll Password Token")}
%endif


%if c.scope == 'selfservice.enroll':
<script type="text/javascript">
    jQuery.extend(jQuery.validator.messages, {
        required: "${_('required input field')}",
        minlength: "${_('minimum length must be greater than {0}')}",
        maxlength: "${_('maximum length must be lower than {0}')}",
        range: '${_("Please enter a valid init secret. It may only contain numbers and the letters A-F.")}',
    });

jQuery.validator.addMethod("content_check", function(value, element, param){
    //var res1 = value.match(/^[a-fA-F0-9]+$/i);
    //var res2 = !value;
    //return  res1 || res2 ;
    return true;
    }, '${_("Please enter a valid init secret. It may only contain numbers and the letters A-F.")}');

var pw_self_validator = $('#form_enroll_pw').validate({
    debug: true,
    rules: {
        pw_self_secret: {
            minlength: 6,
            maxlength: 64,
            number: false,
            content_check: true,
            required: function() {
                return ! $('#pw_key_rb2_gen').is(':checked');
            }
        }
    }
});

function self_pw_get_param()
{
    var urlparam = {};
    var typ = 'pw';

    // OTP Key
    urlparam['otpkey'] = $('#pw_self_secret').val();

    urlparam['type'] 	= typ;

    var desc = $("#pw_self_desc").val();
    if (desc.length > 0) {
       urlparam['description'] = $("#pw_self_desc").val();
    }

    return urlparam;
}

function self_pw_clear()
{
    $('#pw_secret').val('');
    pw_self_validator.resetForm();

}
function self_pw_submit(){

    var ret = false;
    var params =  self_pw_get_param();

    if ($('#form_enroll_pw').valid() === false) {
        alert('${_("Form data not valid.")}');
        return ret;
    }
    enroll_token( params );
    // reset the form
    $('#pw_self_secret').val('');

	return true;

}

$( document ).ready(function() {

    $('#button_enroll_pw').click(function (e){
        e.preventDefault();
        self_pw_submit();
    });

});

</script>
<h2>${_("Enroll static password token")}</h2>
<div id='enroll_pw_form'>
    <form class="cmxform" id='form_enroll_pw' action="">
    <fieldset>
        <table>
        <tr class="space"><th colspan="2">${_("Token Password:")}</th></tr>
        <tr>
            <td class="description">
                <label id='pw_self_secret_label'
                    for='pw_key_rb2_no'>${_("Enter static password:")}</label></td>
            <td><input id='pw_self_secret' name='pw_self_secret'
                class="required ui-widget-content ui-corner-all"></td>
        </tr>
        <tr class="space"><th>${_("Token Settings:")}</th></tr>
        <tr>
            <td class='description'><label for="pw_self_desc" id='pw_self_desc_label'>${_("Description")}</label></td>
            <td><input type="text" name="pw_self_desc" id="pw_self_desc" class="text" placeholder="${_('self enrolled')}"></td>
        </tr>
        <tr class="space"></tr>
        </table>

        <button class='action-button' id='button_enroll_pw'>${_("enroll password token")}</button>

    </fieldset>
    </form>
</div>

% endif
