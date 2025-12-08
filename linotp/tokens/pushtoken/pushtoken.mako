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
 * contains the pushtoken token web interface
</%doc>

%if c.scope == 'config.title' :
 ${_("PushToken")}
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
function push_get_config_val(){
    var id_map = {};

    id_map['PushMaxChallenges'] = 'pushconfig_max_challenges';
    id_map['PushChallengeValidityTime'] = 'pushconfig_challenge_timeout';
    var cert_id = $('#pushconfig_cert_id').val();
    id_map['PublicKey.' + cert_id] = 'pushconfig_pub_cert';

    return id_map;

}

/*
 * 'typ'_get_config_params()
 *
 * this method is called, when the token config is submitted
 * - it will return a hash of parameters for system/setConfig call
 *
 */
function push_get_config_params(){

    var url_params ={};

    url_params['PushMaxChallenges'] = $('#pushconfig_max_challenges').val();
    url_params['PushChallengeValidityTime'] = $('#pushconfig_challenge_timeout').val();

    return url_params;
}

</script>
<form class="cmxform" id="form_pushtoken_config" action="">
    <fieldset>
        <legend>${_("PushToken Settings")}</legend>
        <table>
            <tr>
                <td>
                    <label for="pushconfig_max_challenges">
                        ${_("Maximum concurrent challenges")}
                    </label>
                </td>
                <td>
                    <input type="number" name="pushconfig_max_challenges" id="pushconfig_max_challenges" class="required text ui-widget-content ui-corner-all">
                </td>
            </tr>
            <tr>
                <td>
                    <label for="pushconfig_challenge_timeout">
                        ${_("Challenge expiration time (sec)")}
                    </label>
                </td>
                <td>
                    <input type="number" name="pushconfig_challenge_timeout" id="pushconfig_challenge_timeout" class="required text ui-widget-content ui-corner-all">
                </td>
            </tr>
            <tr>
                <td>
                    <label for="pushconfig_cert_id">${_("Public key certificate")}</label>
                </td>
                <td>
                    <input type="text" name="pushconfig_cert_id" id="pushconfig_cert_id" value="Partition.0" disabled="disabled" placeholder="${_('certificate id')}" class="required text ui-widget-content ui-corner-all">
                </td>
            </tr>
            <tr>
                <td>
                </td>
                <td>
                    <textarea disabled="disabled" name="pushconfig_pub_cert" id="pushconfig_pub_cert" cols="40" rows="6"></textarea>
                </td>
            </tr>
        </table>
    </fieldset>
</form>
%endif


%if c.scope == 'enroll.title' :
${_("PushToken - challenge/response Token")}
%endif

%if c.scope == 'enroll' :
<script type="text/javascript">
/*
 * 'typ'_enroll_setup_defaults()
 *
 * this method is called, before the dialog is shown
 *
 */
function push_enroll_setup_defaults(config, options){
    push_clear_input_fields();

    if (options['otp_pin_random'] > 0) {
        $(".pushtoken_pin_rows").hide();
    } else {
        $(".pushtoken_pin_rows").show();
    }
}

/*
 * 'typ'_get_enroll_params()
 *
 * this method is called, when the token is submitted
 * - it will return a hash of parameters for admin/init call
 *
 */

function push_get_enroll_params(){
    var url = {};
    url['type'] = 'push';
    url['description'] = $('#enroll_push_desc').val();
    if($('#pushtoken_pin1').val().length > 0) {
        url['pin'] = $('#pushtoken_pin1').val();
    }

    jQuery.extend(url, add_user_data());

    push_clear_input_fields();

    return url;
}

function push_clear_input_fields() {
    // Empty input fields for PINs and Keys
    $('#enroll_pushtoken_desc').val('${_("web ui generated")}')
    $('#pushtoken_pin1').val('')
    $('#pushtoken_pin2').val('')
}
</script>
<hr>
<table>
    <tr>
        <td><label for="enroll_pushtoken_desc">${_("Description")}</label></td>
        <td><input type="text" name="enroll_pushtoken_desc" id="enroll_pushtoken_desc" class="text"></td>
    </tr>
    <tr class="space">
        <td>
            <label for="pushtoken_pin1">${_("OTP Digits")}:</label>
        </td>
    </tr>
    <tr class="space pushtoken_pin_rows">
        <th colspan="2">
            ${_("Token PIN:")}
        </th>
    </tr>
    <tr class="pushtoken_pin_rows">
        <td class="description">
            <label for="pushtoken_pin1">${_("Enter PIN")}:</label>
        </td>
        <td>
            <input type="password" autocomplete="off" onkeyup="checkpins('pushtoken_pin1','pushtoken_pin2');" name="pushtoken_pin1" id="pushtoken_pin1" class="text">
        </td>
    </tr>
    <tr class="pushtoken_pin_rows">
        <td class="description">
            <label for="pushtoken_pin2">${_("Confirm PIN")}:</label>
        </td>
        <td>
            <input type="password" autocomplete="off" onkeyup="checkpins('pushtoken_pin1','pushtoken_pin2');" name="pushtoken_pin2" id="pushtoken_pin2" class="text">
        </td>
    </tr>
</table>

% endif
