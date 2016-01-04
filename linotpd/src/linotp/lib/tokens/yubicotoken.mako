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
 * contains the yubico token web interface
</%doc>



%if c.scope == 'config.title' :
 ${_("Yubico")}
%endif

%if c.scope == 'selfservice.title.enroll':
${_("Enroll YubiKey")}
%endif

%if c.scope == 'config' :
<script>

/*
 * 'typ'_get_config_val()
 *
 * this method is called, when the token config dialog is opened
 * - it contains the mapping of config entries to the form id
 * - according to the Config entries, the form entries will be filled
 *
 */


function yubico_get_config_val(){
	var id_map = {};

    id_map['yubico.id'] 		= 'sys_yubico_id';
    id_map['yubico.secret'] = 'sys_yubico_secret';

	return id_map;

}

/*
 * 'typ'_get_config_params()
 *
 * this method is called, when the token config is submitted
 * - it will return a hash of parameters for system/setConfig call
 *
 */
function yubico_get_config_params(){
	var url_params ={};

    url_params['yubico.id'] 	= $('#sys_yubico_id').val();
    url_params['yubico.secret'] 	= $('#sys_yubico_secret').val();

	return url_params;
}

</script>

<form class="cmxform" id='form_config_yubico'>
<fieldset>
	<legend>${_("Yubico settings")}</legend>
	<p>
		${_("You get your own API key from the yubico website ")}
		<a href="https://upgrade.yubico.com/getapikey/" target="yubico">upgrade.yubico.com</a>.
	</p>
	<p>
		${_("If you do not use your own API key, the LinOTP demo API key will be used!")}
	</p>
	<table>
	<tr>
	<td><label for="sys_yubico_id" title='${_("You need to enter a valid API id")}'>
		${_("Yubico ID")}</label></td>
	<td><input class="required" type="text" name="sys_yubico_id" id="sys_yubico_id"
		class="text ui-widget-content ui-corner-all"/></td>
	</tr>

	<tr>
	<td><label for="sys_yubico_secret" title='${_("You need to enter a valid API key")}'>
		${_("Yubico API key")}</label></td>
	<td><input class="required" type="text" name="sys_yubico_secret" id="sys_yubico_secret"
		class="text ui-widget-content ui-corner-all"/></td>
	</tr>

	</table>
</fieldset>
</form>
%endif


%if c.scope == 'enroll.title' :
${_("YubiKey")}
%endif

%if c.scope == 'enroll' :
<script>
/*
 * 'typ'_enroll_setup_defaults()
 *
 * this method is called, before the dialog is shown
 *
 */
function yubico_enroll_setup_defaults(config, options){
    yubico_clear_input_fields();
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

function yubico_get_enroll_params(){
	var params ={};

    params['yubico.tokenid'] 		= $('#yubico_token_id').val();
    params['description'] 			= $("#yubico_enroll_desc").val();

	jQuery.extend(params, add_user_data());

    if ($('#yubico_pin1').val() != '') {
        params['pin'] = $('#yubico_pin1').val();
    }

    yubico_clear_input_fields();
	return params;
}

function yubico_clear_input_fields() {
    // Empty input fields for PINs and Keys
    $('#yubico_token_id').val('');
    $('#yubico_pin1').val('');
    $('#yubico_pin2').val('');
}
</script>
<hr>
<p>${_("Here you need to enter the token ID of the YubiKey.")}</p>
<p>${_("You can do this by inserting the YubiKey and simply push the button.")}</p>
<table>
<tr>
	<td><label for="yubico_token_id" title='${_("You need to enter the YubiKey token ID")}'>
		${_("Token ID")}</label></td>
	<td><input class="required" type="text" name="yubico_token_id" id="yubico_token_id" min=12
		class="text ui-widget-content ui-corner-all"/></td>
</tr>
<tr>
    <td><label for="yubico_enroll_desc" id='yubico_enroll_desc_label'>${_("Description")}</label></td>
    <td><input type="text" name="yubico_enroll_desc" id="yubico_enroll_desc" value="Yubico Cloud token" class="text" /></td>
</tr>
<tr name="set_pin_rows" class="space" title='${_("Protect your token with a static PIN")}'><th colspan="2">${_("Token PIN:")}</th></tr>
<tr name="set_pin_rows">
    <td class="description"><label for="yubico_pin1" id="yubico_pin1_label">${_("Enter PIN")}:</label></td>
    <td><input type="password" autocomplete="off" onkeyup="checkpins('yubico_pin1','yubico_pin2');" name="pin1" id="yubico_pin1"
            class="text ui-widget-content ui-corner-all" /></td>
</tr>
<tr name="set_pin_rows">
    <td class="description"><label for="yubico_pin2" id="yubico_pin2_label">${_("Confirm PIN")}:</label></td>
    <td><input type="password" autocomplete="off" onkeyup="checkpins('yubico_pin1','yubico_pin2');" name="pin2" id="yubico_pin2"
            class="text ui-widget-content ui-corner-all" /></td
</tr>
</table>

%endif


%if c.scope == 'selfservice.enroll':
<script>

function self_yubico_get_param()
{
	var urlparam = {};
	var typ = 'yubico';

	urlparam['type'] 	= typ;
	urlparam['otplen'] 	= 44;
	urlparam['description']    = $("#yubico_self_desc").val();
	urlparam['yubico.tokenid'] = $('#yubico_tokenid').val();

	return urlparam;
}

function self_tokenid_clear()
{
	$('#yubico_tokenid').val('');

}
function self_yubico_submit(){

	var ret = false;
	var params =  self_yubico_get_param();

	enroll_token( params );
	ret = true;
	return ret;
}

</script>

<h1>${_("Enroll your YubiKey")}</h1>
<div id='enroll_yubico_form'>
	<form class="cmxform" id='form_enroll_yubico'>
		<p>
			${_("Enter the Token ID of your YubiKey. Simply insert the YubiKey and press the button.")}
		</p>
	<fieldset>
		<table>
		<tr>
			<td><label for='yubico_tokenid'>${_("YubiKey TokenId")+':'}</label></td>
			<td><input id='yubico_tokenid' name='yubico_tokenid'
				class="required ui-widget-content ui-corner-all" min="12" maxlength='44'/></td>
		</tr>
		<tr>
		    <td><label for="yubico_self_desc" id='yubico_self_desc_label'>${_("Description")}</label></td>
		    <td><input type="text" name="yubico_self_desc" id="yubico_self_desc" value="Yubico Cloud (self)" class="text" /></td>
		</tr>

        </table>
	    <button class='action-button' id='button_enroll_yubico'
	    	    onclick="self_yubico_submit();">${_("enroll yubico token")}</button>

    </fieldset>
    </form>
</div>

% endif
