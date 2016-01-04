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
 * contains the remote token web interface
</%doc>



%if c.scope == 'config.title' :
 ${_("Remote Token")}
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


function remote_get_config_val(){
    var id_map = {};

    id_map['remote.server'] 		= 'sys_remote_server';
    id_map['remote.local_checkpin'] = 'sys_remote_local_checkpin';
    id_map['remote.realm'] 			= 'sys_remote_realm';
    id_map['remote.resConf'] 		= 'sys_remote_resConf';

    return id_map;

}

/*
 * 'typ'_get_config_params()
 *
 * this method is called, when the token config is submitted
 * - it will return a hash of parameters for system/setConfig call
 *
 */
function remote_get_config_params(){
	var url_params ={};

    url_params['remote.server'] 	= $('#sys_remote_server').val();
    url_params['remote.realm'] 	    = $('#sys_remote_realm').val();
    url_params['remote.resConf'] 	= $('#sys_remote_resConf').val();
    url_params['remote.remote_checkpin'] 	= $('#sys_remote_local_checkpin').val();

	return url_params;
}


jQuery.validator.addMethod("sys_remote_server", function(value, element, param){
      return value.match(param);
}, "${_('Please enter a valid remote server specification. It needs to be of the form http://server or https://server')}");


$("#form_config_remote").validate({
         rules: {
            sys_remote_server: {
                required: true,
                number: false,
                	sys_remote_server: /^(http:\/\/|https:\/\/)/i
             }
         }
     });

</script>

<form class="cmxform" id='form_config_remote'>
<fieldset>
	<legend>${_("Remote token settings")}</legend>
	<table>
	<tr>
	<td><label for="sys_remote_server" title='${_("You need to enter the remote LinOTP server like https://remotelinotp")}'>
		${_("Remote server")}</label></td>
	<td><input class="required" type="text" name="sys_remote_server" id="sys_remote_server"
		class="text ui-widget-content ui-corner-all"/></td>
	</tr>

	<tr><td><label for="sys_remote_local_checkpin" title='${_("The PIN can either be verified on this local LinOTP server or forwarded to the remote server")}'>
		${_("Check PIN")}</label></td>
	<td><select name="sys_remote_local_checkpin" id="sys_remote_local_checkpin"
		title='${_("The PIN can either be verified on this local LinOTP server or on the remote server")}'>
			<option value=0>${_("on remote server")}</option>
			<option value=1>${_("locally")}</option>
		</select></td>
	</tr>

	<tr>
	<td><label for="sys_remote_realm">${_("Remote realm")}</label></td>
	<td><input type="text" name="sys_remote_realm" id="sys_remote_realm"
		class="text ui-widget-content ui-corner-all" /></td>
	</tr>

	<tr>
	<td><label for="sys_remote_resConf">${_("Remote resolver")}</label></td>
	<td><input type="text" name="sys_remote_resConf" id="sys_remote_resConf"
		class="text ui-widget-content ui-corner-all" /></td>
	</tr>
	</table>
</fieldset>
</form>
%endif


%if c.scope == 'enroll.title' :
${_("Remote token")}
%endif

%if c.scope == 'enroll' :
<script>
/*
 * 'typ'_enroll_setup_defaults()
 *
 * this method is called, before the dialog is shown
 *
 */
function remote_enroll_setup_defaults(config, options){
    remote_clear_input_fields();
    var rand_pin = options['otp_pin_random'];
    if (rand_pin > 0) {
        $("[name='set_pin_rows']").hide();
    } else {
        $("[name='set_pin_rows']").show();
    }

    $('#remote_server').val(config['remote.server']);
    $('#remote_serial').val(config['remote.serial']);
    $('#remote_user').val(config['remote.user']);
    $('#remote_realm').val(config['remote.realm']);
    $('#remote_resconf').val(config['remote.resConf']);
    var pin_check = config['remote.local_checkpin'];

    var pin_check = config['remote.remote_checkpin'];
    if (pin_check === '0') {
        $('#remote_local_checkpin option[value="0"]').prop('selected',true);
        /*$("#remote_otplen").prop('disabled', true);*/
    } else {
        $('#remote_local_checkpin option[value="1"]').prop('selected',true);
        /*$("#remote_otplen").prop('disabled', false);*/
    }
}

/*
 * 'typ'_get_enroll_params()
 *
 * this method is called, when the token  is submitted
 * - it will return a hash of parameters for admin/init call
 *
 */
function remote_get_enroll_params(){
	var params ={};

    //params['serial'] =  create_serial('LSRE');
    params['remote.server'] 		= $('#remote_server').val();
    params['remote.local_checkpin'] = $('#remote_local_checkpin').val();

    if (params['remote.local_checkpin'] == 1 ){
        otplen = $('#remote_otplen').val();
        if (otplen.length == 0) {
            otplen = 6;
        }
        var intValue = parseInt(otplen);
        if (intValue == Number.NaN) {
            otplen =  6;
        }
        if (intValue <= 0)
        {
            otplen = 6;
        }
        params['otplen']            = otplen;
    }
    params['remote.serial'] 		= $('#remote_serial').val();
    params['remote.user'] 			= $('#remote_user').val();
    params['remote.realm'] 			= $('#remote_realm').val();
    params['remote.resConf'] 		= $('#remote_resconf').val();
    params['description'] 			= "remote:" + $('#remote_server').val();


    jQuery.extend(params, add_user_data());

    if ($('#remote_pin1').val() != '') {
        params['pin'] = $('#remote_pin1').val();
    }

    remote_clear_input_fields();
	return params;
}

function remote_clear_input_fields() {
    // Empty input fields for PINs and Keys
    $('#remote_pin1').val('');
    $('#remote_pin2').val('');
}

jQuery.validator.addMethod("remote_server", function(value, element, param){
    return value.match(param);
}, "${_('Please enter a valid URL for the LinOTP server. It needs to start with http:// or https://')}");



$("#form_enroll_token").validate({
         rules: {
            remote_server: {
                required: true,
                number: false,
                remote_server: /^(http:\/\/|https:\/\/)/i
             }
         }
     });

<%
	from linotp.lib.config import getFromConfig
	sys_remote_server = ""
	sys_remote_realm = ""
	sys_remote_resConf = ""
	sys_checkpin_local = "selected"
	sys_checkpin_remote = ""

	try:
		sys_remote_server = getFromConfig("remote.server")
		sys_remote_realm = getFromConfig("remote.realm")
		sys_remote_resConf = getFromConfig("remote.resConf")
		sys_remote_local_checkpin = getFromConfig("remote.local_checkpin")

		if sys_remote_local_checkpin == 0:
			sys_checkpin_local = ""
			sys_checkpin_remote = "selected"
	except Exception:
		pass

%>
</script>
<hr>
<p>${_("Here you can define to which LinOTP Server the authentication request should be forwarded.")}</p>
<p>${_("You can either forward the OTP to a remote serial number or to a remote user.")}</p>
<p>${_("If you do not enter a remote serial or a remote user, the request will be forwarded to the remote user with the same username.")}</p>
<table><tr>
	<td><label for="remote_server" title='${_("You need to enter the server like \'https://linotp2.my.domain\'")}'>
		${_("Remote server")}</label></td>
	<td><input class="required" type="text" name="remote_server" id="remote_server"
		value="${sys_remote_server}" class="text ui-widget-content ui-corner-all"/></td>
	</tr><tr>
	<td><label for="remote_local_checkpin" title='{_("The PIN can either be verified on this local LinOTP server or on the remote LinOTP server")}'>
		${_("Check PIN")}</label></td>
	<td><select name="remote_local_checkpin" id="remote_local_checkpin"
		title='${_("The PIN can either be verified on this local LinOTP server or on the remote LinOTP server")}'>
		<option ${sys_checkpin_remote} value=0>${_("remotely")}</option>
		<option ${sys_checkpin_local} value=1>${_("locally")}</option>
	</select></td>
	</tr><tr>
    <td><label for="remote_otplen">${_("Remote OTP len")}</label></td>
    <td><input type="text" name="remote_otplen" id="remote_otplen" value="6" class="text ui-widget-content ui-corner-all" /></td>
    </tr><tr>
	<td><label for="remote_serial">${_("Remote serial")}</label></td>
	<td><input type="text" name="remote_serial" id="remote_serial" value="" class="text ui-widget-content ui-corner-all" /></td>
	</tr><tr>
	<td><label for="remote_user">${_("Remote user")}</label></td>
	<td><input type="text" name="remote_user" id="remote_user" value="" class="text ui-widget-content ui-corner-all" /></td>
	</tr><tr>
	<td><label for="remote_realm">${_("Remote user realm")}</label></td>
	<td><input type="text" name="remote_realm" id="remote_realm"
		value="${sys_remote_realm}" class="text ui-widget-content ui-corner-all" /></td>
	</tr><tr>
	<td><label for="remote_resconf">${_("Remote user UserIdResolver")}</label></td>
	<td><input type="text" name="remote_resconf" id="remote_resconf"
		value="${sys_remote_resConf}" class="text ui-widget-content ui-corner-all" /></td>
	</tr>
<tr name="set_pin_rows" class="space" title='${_("Protect your token with a static PIN")}'><th colspan="2">${_("Token PIN:")}</th></tr>
	<tr name="set_pin_rows">
    <td class="description"><label for="remote_pin1" id="remote_pin1_label">${_("Enter PIN")}:</label></td>
    <td><input type="password" autocomplete="off" onkeyup="checkpins('remote_pin1','remote_pin2');" name="pin1" id="remote_pin1"
            class="text ui-widget-content ui-corner-all" /></td>
	</tr>
	<tr name="set_pin_rows">
    <td class="description"><label for="remote_pin2" id="remote_pin2_label">${_("Confirm PIN")}:</label></td>
    <td><input type="password" autocomplete="off" onkeyup="checkpins('remote_pin1','remote_pin2');" name="pin2" id="remote_pin2"
            class="text ui-widget-content ui-corner-all" /></td
	</tr></table>


%endif