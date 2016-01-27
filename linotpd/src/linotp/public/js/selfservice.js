/*!
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
 */


/* For compatibility with <=IE8 */
if (!Object.keys) Object.keys = function(o) {
	if (o !== Object(o))
	throw new TypeError('Object.keys called on a non-object');
	 var k=[],p;
	for (p in o) if (Object.prototype.hasOwnProperty.call(o,p)) k.push(p);
	return k;
};

window.onerror = error_handling;

/* Use Jed for i18n. The correct JSON file is dynamically loaded later. */
var i18n = new Jed({});
var sprintf = Jed.sprintf;

if (!String.sprintf) {
    String.sprintf = Jed.sprintf;
}

/* The HTTP status code, that determines that
 * the Login to the selfservice portal is required.
 * Is also defined in controllers/account.py
 */
LOGIN_CODE = 576

function SelfLogout(logout_url) {
/* clear the admin cookie and
   * for IE try to clean the ClearAuthenticationCache and reload same page
   * for Firefox redirect to a location, with
*/

    var done = false;
    done = document.execCommand("ClearAuthenticationCache", false);
    $.cookie("linotp_selfservice", "invalid", {expires: 0,  path: '/'});

    if (done == true) {
        window.location.href = document.URL;
    } else {
        window.location.href = logout_url;
    }

}




function self_alert_box(params /* dict or parameters */){
	/*
	 * alert_box - pop up an dialog to show some info, which could contain html
	 *
	 * :param params: the dictionary with the parameters, which could be
	 * 				  - title: the title to show
	 *                - text: the text to show
	 *                - param1: which is a replacement parameter
	 *                - escaped (bool): if the text++ contains pre escaped text
	 */
	var escaped = params['escaped'] || false;
    var p_title = params['title'] || '';
    var s = params['text'] || '';
    var param1 = params['param1'] || '';

    if (escaped == false)
    {
    	p_title = escape(p_title);
		s = escape(s);
		param1 = escape(param1);
	}

    var str = s;
    try {
		s = str;

	    // If the parameter is the ID of an element, we pass the text of this very element
        if ( $('#'+s).length > 0 ) { // Element exists!
	        if (param1) {
	            $('#'+s+' .text_param1').html(param1);
	        }
            s=$('#'+s).html();
        }

    }
    catch (e) {
        s = str;
    }

    $('#alert_box_text').html(s);

    $( "#alert_box" ).dialog({
        title : p_title,
        width: 450,
        modal: true,
        buttons: {
                Ok: function() {
                    $( this ).dialog( "close" );
                }
            }
     });
}


function error_handling(message, file, line) {
    Fehler = "We are sorry. An internal error occurred:\n" + message + "\nin file:" + file + "\nin line:" + line;
    alert(Fehler);
    return true;
}

/*
 * Retrieve session cookie if it does not exist
 */

function get_selfservice_session() {
    var session = "";
    if (document.cookie) {
        session = getcookie("linotp_selfservice");
        if (session == "") {
            alert(i18n.gettext("there is no linotp_selfservice cookie"));
        }
    }
    return session;
}

function run_sync_request(url,params){
    /*
     * run_sync_request - to submit a syncronous  http request
     *
     * @remark: introduced the params (:dict:) so we could switch to
     *          a POST request, which will allow more and secure data
     */
    var def_resp = {
        'result' : { 'status' : false }
    };
    var resp = def_resp;

    params['session'] = get_selfservice_session();

    try{
        show_waiting();

        resp = $.ajax({
            url: url,
            data : params,
            dataType : "json",
            cache : false,
            async: false,
            type: 'POST',
            error : function(data) {
                if (data.status == LOGIN_CODE) {
                    alert(i18n.gettext("Your session has expired!"));
                    location.reload();
                    def_resp['result'] = { 'error' :
                        { 'message' : i18n.gettext("Your session has expired!")}};
                } else {
                    def_resp['result'] = { 'error' :
                        { 'message' : data.statusText}};
                }
                resp = def_resp;
           },
        }).responseJSON;
    }
    catch(e) {
        alert(i18n.gettext('Error ') + escape(e));
        resp = def_resp;
    }
    finally {
        hide_waiting();
        if (typeof resp == 'undefined') {
            resp = def_resp;
        }
        return resp;
    }
}


// Old functions from the tokenhandling and prototype

function resync() {
    show_waiting();
    var otp1 = $('#otp1').val();
    var otp2 = $('#otp2').val();
    var serial = $('.selectedToken').val();

    if (otp1 == "" || otp2 == "" || serial == "") {
        alert(i18n.gettext("You need to select a Token and enter two OTP values."));
        hide_waiting();
    } else {
        var params = {
            'otp1' : otp1,
            'otp2' : otp2,
            'serial' : serial,
        };
        var data = run_sync_request('/userservice/resync', params);
        if (data.result.status == true) {
            if (data.result.value['resync Token']) {
                alert(i18n.gettext("Token resynced successfully"));
            } else {
                alert(i18n.gettext("Failed to resync Token"));
            }
        } else {
            alert(i18n.gettext("Error resyncing Token: ") + escape(data.result.error.message));
        }
    }
    return false;
}

function assign() {
    show_waiting();
    var serial = $('#assign_serial').val();
    if (serial == "") {
        alert(i18n.gettext("You need to enter a serial number"));
        hide_waiting();
    } else {
        Check = confirm(i18n.gettext("You are going to assign a new token to you. Is this the correct serial: ") + escape(serial) + "?");
        if (Check == false) {
            hide_waiting();
            return false;
        } else {
            var params = {
                'serial' : serial,
                'description' : 'self assigned',
            };
            var data = run_sync_request('/userservice/assign', params);

            if (data.result.status == true) {
                alert(i18n.gettext("Token assigned successfully"));
                showTokenlist();
                $('#assign_serial').val('');
            } else {
                alert(i18n.gettext("Error assigning Token: ") + escape(data.result.error.message));
            }
        } // end of else
    }
    showTokenlist();
    return false;
}

function getserial() {
    /*
     * Get the serial number for a given OTP value and fill the corresponding input
     */
    show_waiting();
    var otp = $('#otp_serial').val();
    if (otp == "") {
        alert(i18n.gettext("You need to enter an OTP value"));
        hide_waiting();
    } else {
        var data = run_sync_request('/userservice/getSerialByOtp',
                            {'otp' : otp});
        if (data.result.status == true) {
            var serial = data.result.value.serial;
            if (serial != "") {
                $('#assign_serial').val(serial);
            } else {
                alert(i18n.gettext("No Token with this OTP value found!"));
            }
        } else {
            alert(i18n.gettext("Error getting serial: ") + escape(data.result.error.message));
        }
    }
    return false;
}

function token_call(formid, params) {

    var typ = params['type'];
    params['session'] = get_selfservice_session();

    if ($('#' + formid).valid()) {
        var data = run_sync_request('/userservice/token_call', params)
        if (data.result.status == true) {
            showTokenlist();
        } else {
            alert(i18n.gettext("Error calling token:") + escape(data.result.error.message));
        }
    } else {
        alert(i18n.gettext("Form data not valid."));
    }
    showTokenlist();
    return false;

}

function enroll_token(params) {
    /*
     * call the userinit to enroll a token
     *
     */
    var token_enroll_ok = $('#token_enroll_ok').val();
    var token_enroll_fail = $('#token_enroll_fail').val();
    var typ = params['type'];

    if (params['description'] === undefined) {
        params['description'] = "self enrolled";
    }
    var data = run_sync_request('/userservice/enroll',params);
    if (data.result.status == true) {
        var details = '<ul>';
        if (data.hasOwnProperty('detail')) {
            var detail = data.detail;

            /*
             * Support U2F token enrollment (challenge response enrollment)
             * Return the registerrequest and abort the enrollment of the token
             * in the first step of the challenge/response enrollment
             */
            if (detail.hasOwnProperty('registerrequest')) {
                var returnObj = null;
                if (detail.hasOwnProperty('serial')) {
                    returnObj = {registerrequest: detail.registerrequest, serial: detail.serial};
                }
                return returnObj;
            }

            if (detail.hasOwnProperty('serial')) {
                details = details + '<li>Serial number: ' + escape(detail.serial) + '</li>';
            }
            if (detail.hasOwnProperty('otpkey')) {
                try {
                    if (detail.hasOwnProperty('googleurl')) {
                        details = details + '<li> Enrollment: <br>';
                        details = details + '<a href="' + detail.googleurl.value +'">' + detail.googleurl.img + '</a>';
                        details = details + '<br><a href="' + detail.googleurl.value + '">' + detail.googleurl.value + '</a></li>';
                        details = details + '<li> Seed: ' +
                            escape(detail.otpkey.value.substring('seed://'.length, detail.otpkey.value.length)) +
                            '</li>';
                    }
                }
                catch (e){
                    details = details + '<li> otpkey: ' + escape(detail.otpkey) + '</li>';
                }
            }
            if (detail.hasOwnProperty('ocraurl')) {
                details = details + '<li>OCRA QR Code</li>';
                if (detail.ocraurl.hasOwnProperty('img')) {
                   details = details + '<p>' + detail.ocraurl.img + '</p>';
                }
            }

        }
        details = details + '</ul>';
        self_alert_box({'title':i18n.gettext("Token enrollment result"),
                   'text': i18n.gettext("Token enrolled successfully ") + details,
                   'escaped': true});
        /*
        * the dynamic tokens must provide a function to gather all data from the form
        */
        var functionString = "self_" + typ + '_enroll_details';
        var funct = window[functionString];
        var exi = typeof funct;
        if (exi == 'function') {
            var res = window[functionString](data);
        }
    } else {
        alert(i18n.gettext("Failed to enroll token: ") + escape(data.result.error.message));
    };


    showTokenlist();
    return false;

}

function reset_failcounter() {
    show_waiting();
    var serial = $('.selectedToken').val();
    var params = {serial : serial};

    var data = run_sync_request("/userservice/reset", params);
    if (data.result.status == true) {
        alert(i18n.gettext("Failcounter resetted successfully"));
        showTokenlist();
        $('.selectedToken').val("");
    } else {
        alert(i18n.gettext("Failed to reset failcounter!\n") + escape(data.result.error.message));
    }
    return false;
}

function disable() {
    var serial = $('.selectedToken').val();
    var params = { serial : serial};

    var data = run_sync_request("/userservice/disable",params);
    if (data.result.status == true) {
        alert(i18n.gettext("Token disabled successfully"));
        showTokenlist();
        $('.selectedToken').val("");
    } else {
        alert(i18n.gettext("Error disabling Token!\n") + escape(data.result.error.message));
    }
    return false;
}

function enable() {
    var serial = $('.selectedToken').val();
    var param = {serial : serial };

    var data = run_sync_request("/userservice/enable", param);
    if (data.result.status == true) {
        alert(i18n.gettext("Token enabled successfully"));
        showTokenlist();
        $('.selectedToken').val("");
    } else {
        alert(i18n.gettext("Error enabling Token!\n") + escape(data.result.error.message));
    }

    return false;
}

function getotp() {
    show_waiting();
    var serial = $('.selectedToken').val();
    var count = $('#otp_count').val();
    var session = get_selfservice_session();
    var params = {'serial' :  serial,
                   'count' : count,
               };
    var data = run_sync_request("/userservice/getmultiotp", params);
    if (data.result.status == true) {
        var ht = "<h3>" + i18n.gettext("OTP values for token ") + escape(data.result.value.serial) +"</h3>";
        if (data.result.value.result === true) {
            ht += "<table class='getotp'>";
            var id_head = i18n.gettext('Time');
            if (data.result.value.type === 'HMAC') {
                id_head = i18n.gettext('Counter');
            }
            ht += "<tr><th>" + escape(id_head) + "</th>";
            ht +="<th>" + i18n.gettext('Otp Value') +"</th></tr>";
            var keys = Object.keys(data.result.value.otp);
            var i = 0;
            for (var id in keys) {
                key = escape(keys[id]);
                otp = escape(data.result.value.otp[key]);
                if (i%2 == 0 ){
                    ht += "<tr class='even'>";
                } else {
                    ht += "<tr class='odd'>";
                }
                ht += "<td>" + key + "</td><td>" + otp +"</td></tr>";
                i++;
            }
            ht += "</table>";
            self_alert_box({'title': "OTP Values", 'text': ht, 'escaped': true});
        } else {
            alert(i18n.gettext("Error getting otp values") + ":\n" + escape(data.result.value.error));
        }
        showTokenlist();
        $('.selectedToken').val("");
    } else {
        alert(i18n.gettext("Error getting otp values") + ":\n" + escape(data.result.error.message));
    }
    return false;
}

function unassign() {
    show_waiting();
    var serial = $('.selectedToken').val();
    var params = {serial : serial};

    var data = run_sync_request("/userservice/unassign", params);
    if (data.result.status == true) {
        alert(i18n.gettext("Token unassigned successfully"));
        showTokenlist();
        $('.selectedToken').val("");
    } else {
        alert(i18n.gettext("Error unassigning Token!\n") + escape(data.result.error.message));
    }
    return false;
}

function token_delete() {
    var serial = $('.selectedToken').val();
    var params = {serial : serial};

    var data = run_sync_request("/userservice/delete", params);
    if (data.result.status == true) {
        alert(i18n.gettext("Token deleted successfully"));
        showTokenlist();
        $('.selectedToken').val("");
    } else {
        alert(i18n.gettext("Failed to delete token!\n") + escape(data.result.error.message));
    }
    return false;
}

function provisionOath() {
    show_waiting();
    var params = {'type' : 'oathtoken'}
    var data = run_sync_request("/userservice/webprovision", params);
    if (data.result.status == true) {
        if (data.result.value.init == true) {
            // The token was successfully initialized and we will display the url
            showTokenlist();
            //$('#oath_info').hide();
            var url = data.result.value.oathtoken.url;
            var img = data.result.value.oathtoken.img;
            $('#oath_link').attr("href", url);
            $('#oath_qr_code').html($.parseHTML(img));
            $('#provisionresultDiv').show();
            $('#qr_code_iphone_download_oath').hide();
        }
    } else {
        alert(i18n.gettext("Failed to enroll token!\n") + escape(data.result.error.message));
    }
}

function provisionOcra() {

    var acode = $('#activationcode').val();
    var serial = $('#serial').val();
    var activation_fail = $('#ocra_activate_fail').val();
    var genkey = 1;

    var params = {
        'type' : 'ocra',
        'serial' : serial,
        'genkey' : 1,
        'activationcode' : acode,
    };
    var data = run_sync_request("/userservice/activateocratoken", params);
    if (data.result.status == true) {
        if (data.result.value.activate == true) {
            // The token was successfully initialized and we will display the url
            showTokenlist();
            // console_log(data.result.value)
            var img = data.result.value.ocratoken.img;
            var url = data.result.value.ocratoken.url;
            var trans = data.result.value.ocratoken.transaction;
            $('#ocra_link').attr("href", url);
            $('#ocra_qr_code').html($.parseHTML(img));
            $('#qr_activate').hide();
            //$('#activationcode').attr("disabled","disabled");
            $('#transactionid').attr("value", trans);
            $('#qr_finish').show();
            $('#qr_confirm1').show();
            $('#qr_confirm2').show();
        }
    } else {
        alert(i18n.gettext("Failed to activate token! \n") + escape(data.result.error.message));
    }
}

function finishOcra() {
    var trans = $('#transactionid').val();
    var serial = $('#serial').val();
    var ocra_check = $('#ocra_check').val();
    var ocra_finish_ok = $('#ocra_finish_ok').val();
    var ocra_finish_fail = $('#ocra_finish_fail').val();

    var params = {
        'type' : 'ocra',
        'serial' : serial,
        'transactionid' : trans,
        'pass' : ocra_check,
        'from' : 'finishOcra',
    }
    var data = run_sync_request("/userservice/finshocratoken", params);
    if (data.result.status == true) {
        // The token was successfully initialized and we will display the url
        // if not (false) display an ocra_finish_fail message for retry
        showTokenlist();
        if (data.result.value.result == false) {
            alert(ocra_finish_fail);
        } else {
            alert(String.sprintf(ocra_finish_ok, serial));
            $('#qr_completed').show();
            $('#qr_finish').hide();
            //$('#ocra_check').attr("disabled","disabled");
            $('#ocra_qr_code').html('<div/>');
            $('#qr_completed').html(escape(String.sprintf(ocra_finish_ok, serial)));
        }
    } else {
        alert(i18n.gettext("Failed to enroll token!\n") + escape(data.result.error.message));
    }
}


function provisionGoogle() {
    show_waiting();
    var type = "googleauthenticator";
    if ($('#google_type').val() == "totp") {
        type = "googleauthenticator_time";
    }
    var params = {"type" : type};
    var data = run_sync_request("/userservice/webprovision", params);
    if (data.result.status == true) {
        if (data.result.value.init == true) {
            showTokenlist();
            // The token was successfully initialized and we will display the url
            //var qr_code = generate_qrcode(10, data.result.value.oathtoken.url);
            var url = data.result.value.oathtoken.url;
            var img = data.result.value.oathtoken.img;
            $('#google_link').attr("href", url);
            $('#google_qr_code').html($.parseHTML(img));
            $('#provisionGoogleResultDiv').show();
            $('#qr_code_iphone_download').hide();
        }
    } else {
        alert(i18n.gettext("Failed to enroll token!\n") + escape(data.result.error.message));
    }
}

function setpin() {
    show_waiting();
    var pin1 = $('#pin1').val();
    var pin2 = $('#pin2').val();
    var serial = $('.selectedToken').val();
    var setpin_failed = $('#setpin_fail').val();
    var setpin_error = $('#setpin_error').val();
    var setpin_ok = $('#setpin_ok').val();

    if (pin1 != pin2) {
        alert(setpin_failed);
        hide_waiting();
    } else {
        var params = {
            userpin : pin1,
            serial : serial,
        };
        var data = run_sync_request('/userservice/setpin', params);
        if (data.result.status == true) {
            alert(setpin_ok);
            $('#pin1').val("");
            $('#pin2').val("");
        } else {
            alert(setpin_error + escape(data.result.error.message));
        };

    }
    return false;
}

function setmpin() {
    show_waiting();
    var pin1 = $('#mpin1').val();
    var pin2 = $('#mpin2').val();
    var serial = $('.selectedToken').val();
    var setpin_failed = $('#setpin_fail').val();
    var setpin_error = $('#setpin_error').val();
    var setpin_ok = $('#setpin_ok').val();

    if (pin1 != pin2) {
        alert(setpin_failed);
        hide_waiting();
    } else {
        var param = {
                pin : pin1,
                serial : serial,
        };
        var data = run_sync_request('/userservice/setmpin', param);
        if (data.result.status == true) {
            alert(setpin_ok);
            $('#mpin1').val("");
            $('#mpin2').val("");
        } else {
            alert(setpin_error + escape(data.result.error.message));
        }
    }
    return false;
}

function selectToken(serial) {
    $('.selectedToken').val(serial);
    $('#errorDiv').val("");
    $('#successDiv').val("");
}

function showTokenlist() {
    $.ajax({
        url : '/selfservice/usertokenlist',
        dataType : "html",
        data : { 'session' : get_selfservice_session() },
        cache : false,
        type: 'POST',
        success: function(dataString) {
             $('#tokenDiv').html($.parseHTML(dataString));
            }
    });
}

// =================================================================
// =================================================================
// Document ready
// =================================================================
// =================================================================

$(document).ready(function() {

    showTokenlist();

    $.ajaxSetup({
        error: function(xhr, status, error) {
            if (xhr.status == LOGIN_CODE) {
                alert(i18n.gettext("Your session has expired!"));
                location.reload();
            }
        }
    }
    );

    $("#tabs").tabs({
        collapsible : true,
        spinner : 'Retrieving data...',
        beforeLoad: function( event, ui ) {
            // The purpose of the following is to prevent automatic reloads
            // of the tab. When the tab loads for the first time the 'loaded'
            // option is set.
            // The tab can be reloaded by reloading the whole page
            // Tab Option 'cache: true' (used before for this same purpose)
            // was removed in jQuery UI version 1.10
            if ( ui.tab.data( "loaded" )  ) {
                event.preventDefault();
            }
            else {
                ui.jqXHR.success(function() {
                    ui.tab.data ( "loaded", true );
                });
                // Following replaces ajaxOptions error function. ajaxOptions was
                // removed in jQuery UI 1.10
                ui.jqXHR.error(function( jqXHR ){
                    if (jqXHR.status == LOGIN_CODE) {
                        alert(i18n.gettext("Your session has expired!"));
                        location.reload();
                    } else {
                        ui.panel.html(escape("Couldn't load this tab. Please respond to the administrator:" + jqXHR.statusText + " (" + jqXHR.status + ")"));
                    }
                });
            }
            return;
        }
    });

    // Log Div
    $("#logAccordion").accordion({
        fillSpace : true
    });

    // delegated event
    // The list of tokens is dynamic and can change after page load
    // If it were static one could use $("#tokenDiv ul li").click(function ...
    $("#tokenDiv").on("click", "ul li", function(event) {
        event.preventDefault();
        selectToken($.trim($(this).text()));
    });
});

$.fn.slideFadeToggle = function(easing, callback) {
    return this.animate({
        opacity : 'toggle',
        height : 'toggle'
    }, "fast", easing, callback);
};

//--------------------------------------------------------------------------------------
// End of document ready

function error_flexi(data){
    // we might do some mods here...
    if (data.status == LOGIN_CODE) {
        alert(i18n.gettext("Your session has expired!"));
        location.reload();
    } else {
        alert(i18n.gettext("Error loading history:\n") + escape(data.status));
    }
}

function pre_flexi(data){
    // we might do some mods here...
    if (data.result) {
        if (data.result.status == false) {
            alert(escape(data.result.error.message));
        }
    }
    else {
        return data;
    }
}

function load_flexi(){
    return true;
}

function view_audit_selfservice() {
       $("#audit_selfservice_table").flexigrid({
            url : '/userservice/history',
            method: 'POST',
            params: [{name:'session', value: get_selfservice_session()}],
            dataType : 'json',
            colModel : [{display: 'date', name : 'date', width : 160, sortable : true},
                        {display: 'action', name : 'action', width : 120, sortable : true},
                        {display: 'success', name : 'success', width : 40, sortable : true},
                        {display: 'serial', name : 'serial', width : 100, sortable : true},
                        {display: 'tokentype', name : 'tokentype', width : 50, sortable : true},
                        {display: 'administrator', name : 'administrator', width : 100, sortable : true},
                        {display: 'action_detail', name : 'action_detail', width : 200, sortable : true},
                        {display: 'info', name : 'info', width : 200, sortable : true}
            ],
            height: 400,
            searchitems : [
                {display: 'serial', name : 'serial', isdefault: true},
                {display: 'date', name: 'date' },
                {display: 'action', name: 'action' },
                {display: 'action detail', name: 'action_detail' },
                {display: 'tokentype', name: 'token_type' },
                {display: 'administrator', name: 'administrator' },
                {display: 'successful action', name: 'success' },
                {display: 'info', name: 'info' },
                {display: 'extended search', name: 'extsearch' }
            ],
            rpOptions: [10,15,30,50],
            sortname: "number",
            sortorder: "desc",
            useRp: true,
            singleSelect: true,
            rp: 15,
            usepager: true,
            showTableToggleBtn: true,
            preProcess: pre_flexi,
            onError: error_flexi,
            onSubmit: load_flexi,
            addTitleToCell: true
    });
}

/*
 * window.CURRENT_LANGUAGE is set in the template from the mako lib.
 * Here, we dynamically load the desired language JSON file for Jed.
 */
var browser_lang = window.CURRENT_LANGUAGE || 'en';
if (browser_lang && browser_lang !== 'en') {
    try {
        var url = sprintf("/i18n/%s.json", browser_lang);
        $.get(
            url,
            {},
            function(data, textStatus) {
                i18n.options.locale_data.messages = data;
            },
            "json"
        );
    } catch(e) {
        alert('Unsupported localisation for ' + escape(browser_lang));
    }
}

