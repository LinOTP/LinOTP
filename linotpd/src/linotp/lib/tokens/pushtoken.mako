# -*- coding: utf-8 -*-
<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2016 KeyIdentity GmbH
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
                        ${_("Challenge Timeout")}
                    </label>
                </td>
                <td>
                    <input type="number" name="qrconfig_challenge_timeout" id="qrconfig_challenge_timeout" class="required text ui-widget-content ui-corner-all">
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
 * this method is called, when the token  is submitted
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




%if c.scope == 'selfservice.title.enroll':
${_("Enroll your PushToken")}
%endif


%if c.scope == 'selfservice.enroll':
<script type="text/javascript">
    jQuery.extend(jQuery.validator.messages, {
        required: "${_('required input field')}",
        minlength: "${_('minimum length must be greater than {0}')}",
        maxlength: "${_('maximum length must be lower than {0}')}",
    });


function self_pushtoken_get_param() {
	var urlparam = {};

	urlparam['type'] = 'push';
	urlparam['description'] = $('#pushtoken_desc').val();
	urlparam['pin'] = $('#pushtoken_pin1').val();
	return urlparam;
}

function self_pushtoken_clear() {
	$('#pushtoken_desc').val('');
}

function self_pushtoken_submit() {
	var params =  self_pushtoken_get_param();
	enroll_token( params );
	return true;

};

function self_pushtoken_enroll_details(data) {
	return;
};

$( document ).ready(function() {
    $('#button_enroll_pushtoken').click(function (e){
        e.preventDefault();
        if($("#form_enroll_pushtoken").valid()){
            self_pushtoken_submit();
        }
    });

    $("#form_enroll_pushtoken").validate({
        rules: {
            pushtoken_pin1: {
                required: true,
                minlength: 3
            },
            pushtoken_pin2: {
                equalTo: "#pushtoken_pin1"
            }
        }
    });
});

</script>
<h1>${_("Enroll your PushToken")}</h1>
<div id='enroll_pushtoken_form'>
	<form class="cmxform" id="form_enroll_pushtoken" action="">
	<fieldset>
		<table>
            <tr>
                <td><label id='pushtoken_desc_label2' for='pushtoken_desc'>${_("Token description")}</label></td>
                <td><input id='pushtoken_desc' name='pushtoken_desc' class="ui-widget-content ui-corner-all" value='self enrolled'></td>
            </tr>
            <tr>
                <td colspan="2">
                    <b>${_("Token PIN:")}</b>
                </td>
            </tr>
            <tr>
                <td class="description">
                    <label for="pushtoken_pin1">${_("Enter PIN")}:</label>
                </td>
                <td>
                    <input type="password" autocomplete="off" onkeyup="checkpins('pushtoken_pin1','pushtoken_pin2');" name="pushtoken_pin1" id="pushtoken_pin1" class="text">
                </td>
            </tr>
            <tr>
                <td class="description">
                    <label for="pushtoken_pin2">${_("Confirm PIN")}:</label>
                </td>
                <td>
                    <input type="password" autocomplete="off" onkeyup="checkpins('pushtoken_pin1','pushtoken_pin2');" name="pushtoken_pin2" id="pushtoken_pin2" class="text">
                </td>
            </tr>
        </table>
	    <button class='action-button' id='button_enroll_pushtoken'>${_("enroll pushtoken")}</button>
    </fieldset>
    </form>
</div>

%endif

%if c.scope == 'selfservice.title.activate':
${_("Activate your PushToken")}
%endif

%if c.scope == 'selfservice.activate':

<script type="text/javascript">

$( document ).ready(function() {
    $('#button_activate_pushtoken_start').click(function (e){
        e.preventDefault();
        self_pushtoken_activate_get_challenge();
    });

    $('#button_activate_pushtoken_finish').click(function (e){
        e.preventDefault();
        self_pushtoken_activate_submit_result();
    });
});

function self_pushtoken_activate_get_challenge() {
    var serial = $('#activate_pushtoken_serial').val();
    var pin = $('#activate_pushtoken_pin').val();
    var message = $('#activate_pushtoken_serial').val();

    var targetselector = "#pushtoken_qr_code"

    var params = {};
    params['serial'] = serial;
    params['pass'] = pin;
    params['data'] = message;
    params['qr'] = 'html';

    var url = '/validate/check_s';

    try {
        var data = clientUrlFetchSync(url, params);
        if ( data.responseJSON !== undefined ) {
            self_alert_box({'title':i18n.gettext("Token activation failed"),
                   'text': i18n.gettext("PushToken challenge for token activation could not be triggered."),
                   'escaped': true});
        } else {
            data = data.responseText;
            var img = $(data).find('#challenge_qrcode');
            $(targetselector).html(img);

            var lseqrurl = $(data).find('#challenge_qrcode').attr("alt");
            lseqrurl = decodeURIComponent(lseqrurl);
            $(targetselector).append("<p><a href=\"" + lseqrurl + "\">" + lseqrurl + "</a></p>");

            pushtoken_activation_transactionid = $(data).find('#challenge_data .transactionid').text();

            self_pushtoken_activate_switch_phase("two");
        }
    } catch (e) {
        alert(e);
    }
}

function self_pushtoken_activate_submit_result() {
    var otpvalue = $('#activate_pushtoken_otp_value').val();

    var targetselector = "#pushtoken_qr_code"

    var params = {};
    params['transactionid'] = pushtoken_activation_transactionid;
    params['pass'] = otpvalue;

    var url = '/validate/check_t';

    try {
        var data = clientUrlFetchSync(url, params).responseJSON;

        if ( data.result.status === false || data.result.value.value === false) {
            self_alert_box({'title':i18n.gettext("PushToken Activation"),
                   'text': i18n.gettext("PushToken activation failed."),
                   'escaped': true});
        } else {
            self_alert_box({'title':i18n.gettext("PushToken Activation"),
                   'text': i18n.gettext("PushToken successfully activated."),
                   'escaped': true});
        }
        self_pushtoken_activate_switch_phase("one");
    } catch (e) {
        alert(e);
    }
    showTokenlist();
}

function self_pushtoken_activate_switch_phase(phase) {
    $('.activate_pushtoken_phase')
        .not("#activate_pushtoken_phase_" + phase)
        .addClass("hidden");
    $("#activate_pushtoken_phase_" + phase).removeClass("hidden");
    $("#activate_pushtoken_phase_" + phase).find("input").each(function(){
        $( this ).val('');
    })
}

</script>

<h1>${_("Activate your PushToken")}</h1>

<div id="activate_pushtoken_phase_one" class="activate_pushtoken_phase">
    <form class="cmxform" action="">
        <table>
            <tr>
                <td>${_("Select PushToken: ")}</td>
                <td>
                    <input type="text" class="selectedToken ui-corner-all" disabled
                        id="activate_pushtoken_serial">
                </td>
            </tr>
            <tr>
                <td>${_("Enter pin: ")}</td>
                <td>
                    <input type="password" class="text ui-widget-content ui-corner-all"
                        id="activate_pushtoken_pin">
                </td>
            </tr>
            <tr>
                <td>
                    <div id='qr2_activate'>
                        <button class="action-button" id="button_activate_pushtoken_start">${_("activate token")}</button>
                    </div>
                </td>
            </tr>
        </table>
    </form>
</div>
<div id="activate_pushtoken_phase_two" class="activate_pushtoken_phase hidden">
    <form class="cmxform" action="">
        <table>
            <tr>
                <td>
                    <h2>${_('Challenge triggered successfully')}</h2>
                    <p>${_('Please scan the qr code and submit your response or enter the otp value in the form below.')}</p>
                </td>
                <td>
                    <div id="pushtoken_qr_code" class="qrcode-inline"></div>
                </td>
            </tr>
            <tr>
                <td>${_("OTP Value: ")}</td>
                <td>
                    <input type="text" class="ui-corner-all"
                        id="activate_pushtoken_otp_value">
                </td>
            </tr>
            <tr>
                <td>
                    <div id='qr2_activate'>
                        <button class="action-button" id="button_activate_pushtoken_finish">${_("finalize activation")}</button>
                    </div>
                </td>
            </tr>
        </table>
    </form>
</div>
% endif
