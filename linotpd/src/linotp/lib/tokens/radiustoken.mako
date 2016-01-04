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
 * contains the radius token web interface
</%doc>



%if c.scope == 'config.title' :
 ${_("RADIUS Token")}
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


function radius_get_config_val(){
    var id_map = {};

    id_map['radius.server']  = 'sys_radius_server';
    id_map['radius.secret']  = 'sys_radius_secret';
    id_map['radius.local_checkpin'] = 'sys_radius_local_checkpin';

    return id_map;

}

/*
 * 'typ'_get_config_params()
 *
 * this method is called, when the token config is submitted
 * - it will return a hash of parameters for system/setConfig call
 *
 */

function radius_get_config_params(){

	var url_params ={};

    url_params['radius.server'] 	= $('#sys_radius_server').val();
    url_params['radius.secret'] 	= $('#sys_radius_secret').val();
    url_params['radius.local_checkpin'] 	= $('#sys_radius_local_checkpin').val();

	return url_params;
}


jQuery.validator.addMethod("sys_radius_server", function(value, element, param){
      return value.match(param);
}, "${_('Please enter a valid RADIUS server specification. It needs to be of the form <name_or_ip>:<port>')}");


$("#form_config_radius").validate({
         rules: {
            sys_radius_server: {
                required: true,
                number: false,
                sys_radius_server: /^[a-z0-9.-_]*:\d*/i
             }
         }
     });

</script>

<form class="cmxform" id='form_config_radius'>
<fieldset>
	<legend>${_("RADIUS token settings")}</legend>
	<table>
	<tr>
	<td><label for="sys_radius_server" title='${_("You need to enter the server like myradius:1812")}'>
		${_("RADIUS server")}</label></td>
	<td><input class="required" type="text" name="sys_radius_server" id="sys_radius_server" class="text ui-widget-content ui-corner-all"/></td>
	</tr>

	<tr><td><label for="sys_radius_local_checkpin" title='${_("The PIN can either be verified on this local LinOTP server or forwarded to the RADIUS server")}'>
		${_("Check PIN")}</label></td>
	<td><select name="sys_radius_local_checkpin" id="sys_radius_local_checkpin"
		title='${_("The PIN can either be verified on this local LinOTP server or on the RADIUS server")}'>
			<option value=0>${_("on RADIUS server")}</option>
			<option value=1>${_("locally")}</option>
		</select></td>
	</tr><tr>
	<td><label for="sys_radius_secret">${_("RADIUS shared secret")}</label></td>
	<td><input type="password" name="sys_radius_secret" id="sys_radius_secret" class="text ui-widget-content ui-corner-all" /></td>
	</tr>
	</table>
</fieldset>
</form>
%endif


%if c.scope == 'enroll.title' :
${_("RADIUS token")}
%endif

%if c.scope == 'enroll' :
<script>
/*
 * 'typ'_enroll_setup_defaults()
 *
 * this method is called, before the dialog is shown
 *
 */
function radius_enroll_setup_defaults(config, options){
    radius_clear_input_fields();
    var rand_pin = options['otp_pin_random'];
    if (rand_pin > 0) {
        $("[name='set_pin_rows']").hide();
    } else {
        $("[name='set_pin_rows']").show();
    }

    $('#radius_server').val(config['radius.server']);
    $('#radius_secret').val(config['radius.secret']);

    var pin_check = config['radius.local_checkpin'];
    if (pin_check === '0') {
        $('#radius_local_checkpin option[value="0"]').prop('selected',true);
    } else {
        $('#radius_local_checkpin option[value="1"]').prop('selected',true);
    }
}
/*
 * 'typ'_get_enroll_params()
 *
 * this method is called, when the token  is submitted
 * - it will return a hash of parameters for admin/init call
 *
 */

function radius_get_enroll_params(){
    var params = {};
    params['type'] = 'radius';
    params['radius.server'] 		=  $('#radius_server').val();
    params['radius.local_checkpin'] =  $('#radius_local_checkpin').val();
    params['radius.user'] 			=  $('#radius_user').val();
    params['radius.secret'] 		=  $('#radius_secret').val();
    params['description'] 			=  "radius:" + $('#radius_server').val();

    jQuery.extend(params, add_user_data());

    if ($('#radius_pin1').val() != '') {
        params['pin'] = $('#radius_pin1').val();
    }

    radius_clear_input_fields();
    return params;
}

function radius_clear_input_fields() {
    // Empty input fields for PINs and Keys
    $('#radius_secret').val('');
    $('#radius_pin1').val('');
    $('#radius_pin2').val('');
}

jQuery.validator.addMethod("radius_server", function(value, element, param){
      return value.match(param);
}, "${_('Please enter a valid RADIUS server specification. It needs to be of the form <name_or_ip>:<port>')}");


$("#form_enroll_token").validate({
         rules: {
            radius_server: {
                required: true,
                number: false,
                radius_server: /^[a-z0-9.-_]*:\d*/i
             }
         }
     });

<%
    from linotp.lib.config import getFromConfig
    sys_radius_server = ""
    sys_radius_secret = ""
    sys_checkpin_local = "selected"
    sys_checkpin_remote = ""

    try:
        sys_radius_server = getFromConfig("radius.server")
        sys_radius_secret = getFromConfig("radius.secret")
        sys_radius_local_checkpin = getFromConfig("radius.local_checkpin")

        if sys_radius_local_checkpin == 0:
            sys_checkpin_local = ""
            sys_checkpin_remote = "selected"
    except Exception:
        pass

%>
</script>
<hr>
<p>${_("Here you can define, to which RADIUS server the request should be forwarded.")}</p>
<p>${_("Please specify the server, the secret and the username")}</p>
<table><tr>
    <td><label for="radius_server" title='${_("You need to enter the server like myradius:1812")}'>
        ${_("RADIUS server")}</label></td>
    <td><input class="required" type="text" name="radius_server" id="radius_server" value="${sys_radius_server}" class="text ui-widget-content ui-corner-all"/></td>
    </tr><tr>
    <td><label for="radius_local_checkpin" title='${_("The PIN can either be verified on this local LinOTP server or forwarded to the RADIUS server")}'>
        ${_("Check PIN")}</label></td>
    <td><select name="radius_local_checkpin" id="radius_local_checkpin"
        title='${_("The PIN can either be verified on this local LinOTP server or on the RADIUS server")}'>
            <option ${sys_checkpin_remote} value="0">${_("on RADIUS server")}</option>
            <option ${sys_checkpin_local} value="1">${_("locally")}</option>
        </select></td>
    </tr><tr>
    <td><label for="radius_secret">${_("RADIUS shared secret")}</label></td>
    <td><input type="password" name="radius_secret" id="radius_secret" value="${sys_radius_secret}" class="text ui-widget-content ui-corner-all" /></td>
    </tr><tr>
    <td><label for="radius_user">${_("RADIUS user")}</label></td>
    <td><input type="text" name="radius_user" id="radius_user" value="" class="text ui-widget-content ui-corner-all" /></td>
    </tr>
    <tr name="set_pin_rows" class="space" title='${_("Protect your token with a static PIN")}'><th colspan="2">${_("Token PIN:")}</th></tr>
    <tr name="set_pin_rows">
    <td class="description"><label for="radius_pin1" id="radius_pin1_label">${_("Enter PIN")}:</label></td>
    <td><input type="password" autocomplete="off" onkeyup="checkpins('radius_pin1','radius_pin2');" name="pin1" id="radius_pin1"
            class="text ui-widget-content ui-corner-all" /></td>
    </tr>
    <tr name="set_pin_rows">
    <td class="description"><label for="radius_pin2" id="radius_pin2_label">${_("Confirm PIN")}:</label></td>
    <td><input type="password" autocomplete="off" onkeyup="checkpins('radius_pin1','radius_pin2');" name="radius_pin2" id="radius_pin2"
            class="text ui-widget-content ui-corner-all" /></td
    </tr></table>

%endif