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
 *   contains the hmac token web interface
</%doc>


%if c.scope == 'config.title' :
 ${_("HMAC Token Settings")}
%endif


%if c.scope == 'config' :
%endif


%if c.scope == 'enroll.title' :
${_("HMAC eventbased")}
%endif

%if c.scope == 'enroll' :
<script>
/*
 * 'typ'_enroll_setup_defaults()
 *
 * this method is called, before the dialog is shown
 *
 */
function hmac_enroll_setup_defaults(config, options){
    hmac_clear_input_fields();
    $('#hmac_key_rb_gen').prop('checked', true);
    $('#hmac_google_compliant').prop('checked', false);
    cb_changed_deactivate('hmac_key_rb_gen',['hmac_key']);
    google_constrains();
    var rand_pin = options['otp_pin_random'];
    if (rand_pin > 0) {
        $("[name='set_pin_rows']").hide();
    } else {
        $("[name='set_pin_rows']").show();
    }
    
}

/*
 * helper function to controll the constrains if 
 * token should be google authenticator compliant
 */
function google_constrains() {
    if ($('#hmac_key_rb_gen').is(':checked') === false) {
        $('#hmac_otplen').prop('disabled', false);
        $('#hmac_algorithm').prop('disabled', false);
        $('#hmac_google_compliant').prop('disabled', true);
        $('#hmac_google_label').prop('disabled', true);
        $('#hmac_google_label').addClass('disabled');
    } else {
        $('#hmac_google_compliant').prop('disabled', false);
        $('#hmac_google_label').prop('disabled', false);
        $('#hmac_google_label').removeClass('disabled');

        if ($('#hmac_google_compliant').is(":checked")) {
            // disable otplen and hash algo selction
            $('#hmac_otplen').prop('disabled', true);
            $('#hmac_algorithm').prop('disabled', true);
            // set defaults for ggogle auth
            $('#hmac_otplen').val('6');
            $('#hmac_algorithm').val("sha1");
        } else {
            $('#hmac_otplen').prop('disabled', false);
            $('#hmac_algorithm').prop('disabled', false);
        }
    }
}

function hmac_clear_input_fields() {
    // Empty input fields for PINs and Keys
    $('#hmac_key').val('');
    $('#hmac_pin1').val('');
    $('#hmac_pin2').val('');
}

/*
 * 'typ'_get_enroll_params()
 *
 * this method is called, when the token  is submitted
 * - it will return a hash of parameters for admin/init call
 *
 */
function hmac_get_enroll_params(){
    var url = {};
    url['type'] = 'hmac';
   	url['description'] = $('#enroll_hmac_desc').val();

    // If we got to generate the hmac key, we do it here:
    if  ( $('#hmac_key_rb_gen').is(':checked') ) {
    	url['genkey'] = 1;

    } else {
        // OTP Key
        url['otpkey'] = $('#hmac_key').val();
    }

    jQuery.extend(url, add_user_data());

    url['hashlib']	= $('#hmac_algorithm').val();
	url['otplen']	= $('#hmac_otplen').val();

    if ($('#hmac_pin1').val() != '') {
        url['pin'] = $('#hmac_pin1').val();
    }

    hmac_clear_input_fields();
    return url;
}
$( document ).ready(function() {

$('input[name="hmac_seed_gen_radiogroup"]').click(function() {
   cb_changed_deactivate('hmac_key_rb_gen',['hmac_key']);
   $('#hmac_google_compliant').prop('checked', false);
   google_constrains();
});

$('#hmac_google_compliant').click(function() {
   google_constrains();
});



});


</script>

<hr>
<table>
<tr><td colspan=2><span id='hmac_key_intro'>${_("Create a new OATH token - HMAC event based")}</span></td></tr>
<tr class="space">
    <th colspan="2" title='${_("The token seed is the secret that is used in the hmac algorithm to make your token unique. So please take care!")}'
    >${_("Token seed:")}</th>
</tr>

<tr>
    <td class="description" colspan='2'>
        <input type="radio" name="hmac_seed_gen_radiogroup" value="gen_key" id='hmac_key_rb_gen'/>
        <label for"hmac_key_rb_gen">${_("generate random seed")}</label></td>
 </tr>


<tr>
    <td class="description" >
        <input type="radio" name="hmac_seed_gen_radiogroup" value='no_gen_key' id='hmac_key_rb_no'/>
        <label for"hmac_key_rb_no">${_("Enter seed")}</label></td>
    <td>
        <input type="text" name="hmac_key" id="hmac_key" value="" class="text ui-widget-content ui-corner-all" /></td>
</tr>

<tr class="space">
    <th colspan="2" title='${_("The hmac algorithm could be controlled by the following settings. Make sure that these settings match your hardware token or software token capabilities.")}'>
    ${_("Token settings:")}</th>
</tr>
<tr>
    <td colspan="2" class="description description_w_space">
        <input type='checkbox' id='hmac_google_compliant'>
        <label for='hmac_google_compliant' id="hmac_google_label"
                title='${_("The Google Authenticator supports only 6 digits and SHA1 hashing.")}'
                >${_("Google Authenticator compliant")}</label>
    </td>

</tr>
<tr>
	<td class="description"><label for="hmac_otplen">${_("OTP Digits")}</label></td>
	<td><select name="pintype" id="hmac_otplen">
			<option  selected value="6">6</option>
			<option  value="8">8</option>
	</select></td>

</tr>
<tr>
	<td class="description"><label for="hmac_algorithm">${_("Hash algorithm")}</label></td>
	<td><select name="algorithm" id='hmac_algorithm' >
	        <option selected value="sha1">sha1</option>
	        <option value="sha256">sha256</option>
	        <option value="sha512">sha512</option>
    </select></td>
</tr>
<tr>
    <td class="description"><label for="enroll_hmac_desc" id='enroll_hmac_desc_label'>${_("Description")}</label></td>
    <td><input type="text" id="enroll_hmac_desc" 
                value="web ui generated" class="text" /></td>
</tr>

<tr name="set_pin_rows" class="space" title='${_("Protect your token with a static PIN")}'><th colspan="2">${_("Token PIN:")}</th></tr>
<tr name="set_pin_rows">
    <td class="description"><label for="hmac_pin1" id="hmac_pin1_label">${_("Enter PIN")}:</label></td>
    <td><input type="password" autocomplete="off" 
                onkeyup="checkpins('hmac_pin1','hmac_pin2');" name="pin1" id="hmac_pin1"
            class="text ui-widget-content ui-corner-all" /></td>
</tr>
<tr name="set_pin_rows">
    <td class="description"><label for="hmac_pin2" id="hmac_pin2_label">${_("Confirm PIN")}:</label></td>
    <td><input type="password" autocomplete="off" onkeyup="checkpins('hmac_pin1','hmac_pin2');" name="pin2" id="hmac_pin2"
            class="text ui-widget-content ui-corner-all" /></td
</tr>

</table>

% endif




%if c.scope == 'selfservice.title.enroll':
${_("Enroll HOTP Token")}
%endif


%if c.scope == 'selfservice.enroll':
<script>
    jQuery.extend(jQuery.validator.messages, {
        required: "${_('required input field')}",
        minlength: "${_('minimum length must be greater than {0}')}",
        maxlength: "${_('maximum length must be lower than {0}')}",
        range: '${_("Please enter a valid init secret. It may only contain numbers and the letters A-F.")}',
    });
    
jQuery.validator.addMethod("content_check", function(value, element, param){
    var res1 = value.match(/^[a-fA-F0-9]+$/i);
    var res2 = !value;
    return  res1 || res2 ;
    }, '${_("Please enter a valid init secret. It may only contain numbers and the letters A-F.")}');

var hmac_self_validator = $('#form_enroll_hmac').validate({
    debug: true,
    rules: {
        hmac_self_secret: {
            minlength: 40,
            maxlength: 64,
            number: false,
            content_check: true,
            required: function() {
                return ! $('#hmac_key_rb2_gen').is(':checked');
            }
        }
    }
});

function self_hmac_get_param()
{
    var urlparam = {};
    var typ = 'hmac';

    if  ( $('#hmac_key_rb2_gen').is(':checked') ) {
    	urlparam['genkey'] = 1;
    } else {
        // OTP Key
        urlparam['otpkey'] = $('#hmac_self_secret').val();
    }

    urlparam['type'] 	= typ;
    urlparam['hashlib'] = $('#hmac_self_hashlib').val();
    urlparam['otplen'] 	= $('#hmac_self_otplen').val();
    
    var desc = $("#hmac_self_desc").val();
    if (desc.length > 0) {
       urlparam['description'] = $("#hmac_self_desc").val();
    }
    
    return urlparam;
}

function self_hmac_clear()
{
    $('#hmac_secret').val('');
    hmac_self_validator.resetForm();

}
function self_hmac_submit(){

    var ret = false;
    var params =  self_hmac_get_param();

    if  ( ($('#hmac_key_rb2_gen').is(':checked') === false) 
           && ($('#form_enroll_hmac').valid() === false)) {
        alert('${_("Form data not valid.")}');
        return ret
    }
    enroll_token( params );
    // reset the form
    $("#hmac_key_rb2_gen").prop("checked", true);
    $('#hmac_self_secret').val('');
    $('#hmac_self_google_compliant').prop("checked", false);
    cb_changed_deactivate('hmac_key_rb2_gen',['hmac_self_secret']);
    $('#hmac_self_otplen').val('6');
    $('#hmac_self_hashlib').val("sha1");
    hmac_self_google_constrains()

	return true;

}

function hmac_self_google_constrains() {

    if ($('#hmac_self_google_compliant').is(":checked")) {
        // disable otplen and hash algo selction
        $('#hmac_self_otplen').prop('disabled', true);
        $('#hmac_self_hashlib').prop('disabled', true);
        // set defaults for ggogle auth
        $('#hmac_self_otplen').val('6');
        $('#hmac_self_hashlib').val("sha1");
    } else {
        $('#hmac_self_otplen').prop('disabled', false);
        $('#hmac_self_hashlib').prop('disabled', false);
    }
}


$( document ).ready(function() {

    $('input[name="hmac_seed_gen_radiogroup2"]').click(function() {
        cb_changed_deactivate('hmac_key_rb2_gen',['hmac_self_secret']);
        hmac_self_validator.resetForm();
    });

    $('#hmac_self_google_compliant').click(function() {
        hmac_self_google_constrains();
    });
    $("#hmac_key_rb2_gen").prop("checked", true);
    cb_changed_deactivate('hmac_key_rb2_gen',['hmac_self_secret']);

    $('#button_enroll_hmac').click(function (e){
        e.preventDefault();
        self_hmac_submit();
    });

});

</script>
<h2>${_("Enroll your HOTP token")}</h2>
<div id='enroll_hmac_form'>
    <form class="cmxform" id='form_enroll_hmac'>
    <fieldset>
        <table>
        <tr class="space"><th colspan="2">${_("Token Seed:")}</th></tr>
        <tr>
            <td class="description" >
                <input type='radio' id='hmac_key_rb2_gen' name='hmac_seed_gen_radiogroup2' selected="selected">
                <label for='hmac_key_rb2_gen'>${_("Generate random seed")}</label>
            </td>
        </tr>
        <tr>
            <td class="description">
                <input type='radio' id='hmac_key_rb2_no' name='hmac_seed_gen_radiogroup2'>
                <label id='hmac_self_secret_label'
                    for='hmac_key_rb2_no'>${_("Enter token seed")}</label></td>
            <td><input id='hmac_self_secret' name='hmac_self_secret' disabled="disabled"
                class="required ui-widget-content ui-corner-all"/></td>
        </tr>
        <tr class="space"><th>${_("Token Settings:")}</th></tr>
        <tr>

            <td colspan="2" class="description description_w_space">
                <input type='checkbox' id='hmac_self_google_compliant' name='hmac_self_google_compliant'>
                <label for='hmac_self_google_compliant' id="hmac_self_google_label"
                        title='${_("The Google Authenticator supports only 6 digits and SHA1 hashing.")}'
                        >${_("Google Authenticator compliant")}</label>
            </td>
        </tr>
        %if c.otplen == -1:
        <tr>
            <td class='description'><label for='hmac_self_otplen'>${_("OTP digits")}</label></td>
            <td><select id='hmac_self_otplen' name='hmac_self_otplen'>
                <option value='6' selected>6</option>
                <option value='8'>8</option>
                </select></td>
        </tr>
        %else:
            <input type='hidden' id='hmac_self_otplen' value='${c.otplen}'>
        %endif
        
        %if c.hmac_hashlib == -1:
        <tr>
            <td class='description'><label for='hmac_self_hashlib'>${_("Hash algorithm")}</label></td>
            <td><select id='hmac_self_hashlib' name='hmac_self_hashlib'>
                <option value='sha1' selected>sha1</option>
                <option value='sha256'>sha256</option>
                <option value='sha512'>sha512</option>
                </select></td>
        </tr>
        %endif
		%if c.hmac_hashlib == 1:
			<input type=hidden id='hmac_self_hashlib' value='sha1'>
		%endif
		%if c.hmac_hashlib == 2:
			<input type=hidden id='hmac_self_hashlib' value='sha256'>
		%endif
        %if c.hmac_hashlib == 3:
            <input type=hidden id='hmac_self_hashlib' value='sha512'>
        %endif

        <tr>
            <td class='description'><label for="hmac_self_desc" id='hmac_self_desc_label'>${_("Description")}</label></td>
            <td><input type="text" name="hmac_self_desc" id="hmac_self_desc" class="text" placeholder="${_('self enrolled')}"/></td>
        </tr>
        <tr class="space"></tr>
        </table>

        <button class='action-button' id='button_enroll_hmac'>${_("enroll hmac token")}</button>

    </fieldset>
    </form>
</div>

% endif
