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
 * contains the qrtoken token web interface
</%doc>

%if c.scope == 'config.title' :
 ${_("QRToken")}
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
function qr_get_config_val(){
    var id_map = {};

    id_map['QRTokenOtpLen'] = 'qrconfig_otplength';
    id_map['QRMaxChallenges'] = 'qrconfig_max_challenges';
    id_map['QRChallengeValidityTime'] = 'qrconfig_challenge_timeout';
    var cert_id = $('#qrconfig_cert_id').val();
    id_map['PublicKey.' + cert_id] = 'qrconfig_pub_cert';

    return id_map;

}

/*
 * 'typ'_get_config_params()
 *
 * this method is called, when the token config is submitted
 * - it will return a hash of parameters for system/setConfig call
 *
 */
function qr_get_config_params(){

    var url_params ={};

    url_params['QRTokenOtpLen'] = $('#qrconfig_otplength').val();
    url_params['QRMaxChallenges'] = $('#qrconfig_max_challenges').val();
    url_params['QRChallengeValidityTime'] = $('#qrconfig_challenge_timeout').val();

    return url_params;
}

</script>
<form class="cmxform" id="form_qrtoken_config" action="">
    <fieldset>
        <legend>${_("QRToken Settings")}</legend>
        <table>
            <tr>
                <td>
                    <label for="qrconfig_max_challenges">
                        ${_("Maximum concurrent challenges")}
                    </label>
                </td>
                <td>
                    <input type="number" name="qrconfig_max_challenges" id="qrconfig_max_challenges" class="required text ui-widget-content ui-corner-all">
                </td>
            </tr>
            <tr>
                <td>
                    <label for="qrconfig_challenge_timeout">
                        ${_("Challenge expiration time (sec)")}
                    </label>
                </td>
                <td>
                    <input type="number" name="qrconfig_challenge_timeout" id="qrconfig_challenge_timeout" class="required text ui-widget-content ui-corner-all">
                </td>
            </tr>
            <tr>
                <td>
                    <label for="qrconfig_otplength">
                        ${_("OTP length")}
                    </label>
                </td>
                <td>
                    <select name="qrconfig_potplength" id="qrconfig_otplength">
                        <option value=6>${_("6 digits")}</option>
                        <option value=8>${_("8 digits")}</option>
                        <option value=10>${_("10 digits")}</option>
                    </select>
                </td>
            </tr>
            <tr>
                <td>
                    <label for="qrconfig_cert_id">${_("Public key certificate")}</label>
                </td>
                <td>
                    <input type="text" name="qrconfig_cert_id" id="qrconfig_cert_id" value="Partition.0" disabled="disabled" placeholder="${_('certificate id')}" class="required text ui-widget-content ui-corner-all">
                </td>
            </tr>
            <tr>
                <td>
                </td>
                <td>
                    <textarea disabled="disabled" name="qrconfig_pub_cert" id="qrconfig_pub_cert" cols="40" rows="6"></textarea>
                </td>
            </tr>
        </table>
    </fieldset>
</form>
%endif


%if c.scope == 'enroll.title' :
${_("QRToken - challenge/response Token")}
%endif

%if c.scope == 'enroll' :
<script type="text/javascript">
/*
 * 'typ'_enroll_setup_defaults()
 *
 * this method is called, before the dialog is shown
 *
 */
function qr_enroll_setup_defaults(config, options){
    qr_clear_input_fields();

    if (options['otp_pin_random'] > 0) {
        $(".qrtoken_pin_rows").hide();
    } else {
        $(".qrtoken_pin_rows").show();
    }
}

/*
 * 'typ'_get_enroll_params()
 *
 * this method is called, when the token is submitted
 * - it will return a hash of parameters for admin/init call
 *
 */

function qr_get_enroll_params(){
    var url = {};
    url['type'] = 'qrtan';
    url['description'] = $('#enroll_qrtan_desc').val();
    if($('#qrtoken_pin1').val().length > 0) {
        url['pin'] = $('#qrtoken_pin1').val();
    }
    url['otplen'] = $('#qrtoken_otplength').val();

    jQuery.extend(url, add_user_data());

    qr_clear_input_fields();

    return url;
}

function qr_clear_input_fields() {
    // Empty input fields for PINs and Keys
    $('#enroll_qrtoken_desc').val('${_("web ui generated")}')
    $('#qrtoken_pin1').val('')
    $('#qrtoken_pin2').val('')
}
</script>
<hr>
<table>
    <tr>
        <td><label for="enroll_qrtoken_desc">${_("Description")}</label></td>
        <td><input type="text" name="enroll_qrtoken_desc" id="enroll_qrtoken_desc" class="text"></td>
    </tr>
    <tr class="space">
        <td>
            <label for="qrtoken_otplength">${_("OTP Digits")}:</label>
        </td>
        <td>
            <select name="qrtoken_otplength" id="qrtoken_otplength">
                <option value=6>${_("6 digits")}</option>
                <option value=8>${_("8 digits")}</option>
                <option value=10>${_("10 digits")}</option>
            </select>
        </td>
    </tr>
    <tr class="space qrtoken_pin_rows">
        <th colspan="2">
            ${_("Token PIN:")}
        </th>
    </tr>
    <tr class="qrtoken_pin_rows">
        <td class="description">
            <label for="pin1">${_("Enter PIN")}:</label>
        </td>
        <td>
            <input type="password" autocomplete="off" name="pin1" id="qrtoken_pin1" class="text">
        </td>
    </tr>
    <tr class="qrtoken_pin_rows">
        <td class="description">
            <label for="pin2">${_("Confirm PIN")}:</label>
        </td>
        <td>
            <input type="password" autocomplete="off" name="pin2" id="qrtoken_pin2" class="text">
        </td>
    </tr>
</table>

% endif
