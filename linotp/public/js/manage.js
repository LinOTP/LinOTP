/*!
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
 */


if (!jwt_getCookie("csrf_access_token")) {
    // user was not logged in, directly navigating to login view
    // If the jwt is invalid but the cookie is still set, the first
    // API request will result in a 401 response and we will then do
    // the redirect anyway.

    window.location = 'login';
}

window.onerror = error_handling;

var password_placeholder_required = "<" + i18n.gettext("password required") + ">";
var password_placeholder_not_changed = "<" + i18n.gettext("not changed") + ">";


function error_handling(message, file, line) {
    error_message = `We are sorry. An internal error occurred:\n${message}\nin file:${file}\nin line:${line}\nTo go on, reload this web page.`;
    alert(escape(error_message));
    return true;
}

/**
 * Make an API request to handle the logout in the backend.
 *
 * If the logout is successful, we reload the page to let
 * the backend decide where to redirect the user to.
 */
function logout() {
    $.get('/admin/logout').done(function (data, status, response) {
        window.location = 'login';
    }).fail(function (response, status) {
        alert_box({
            'title': i18n.gettext('Logout failed'),
            'text': escape(response.responseJSON.msg),
            'type': ERROR,
            'is_escaped': true
        });
    });
}

// We need this dialogs globally, so that we do not create more than one instance!
var $dialog_ldap_resolver;
var $dialog_http_resolver;
var $dialog_file_resolver;
var $dialog_sql_resolver;
var $dialog_edit_realms;
var $dialog_ask_new_resolvertype;
var $dialog_resolvers;
var $dialog_realms;
var $dialog_resolver_ask_delete;
var $dialog_realm_ask_delete;
var $dialog_show_enroll_url;
var $dialog_token_info;
var $dialog_setpin_token;
var $dialog_view_temporary_token;


var $dialog_import_policy;
var $dialog_tokeninfo_set;

var $tokentypes;

var $tokenConfigCallbacks = {};
var $tokenConfigInbacks = {};

var $form_validator_ldap;
var $form_validator_sql;
var $form_validator_http;
var $form_validator_file;

// FIXME: global variable should be worked out
var g = {
    enroll_display_qrcodes: false,
    running_requests: 0,
    resolver_to_edit: null,
    realm_to_edit: "",
    resolvers_in_realm_to_edit: "",
    realms_of_token: [],
    current_resolver_name: ""
};

var ERROR = "error";

var support_license_dict = {
    'comment': i18n.gettext('Description'),
    'issuer': i18n.gettext('Issuer'),
    'token-num': i18n.gettext('Number of tokens'),
    'licensee': i18n.gettext('Licensee'),
    'address': i18n.gettext('Address'),
    'contact-name': i18n.gettext('Contact name'),
    'contact-email': i18n.gettext('Contact EMail'),
    'contact-phone': i18n.gettext('Contact phone'),
    'date': i18n.gettext('Date'),
    'expire': i18n.gettext('Expiration'),
    'subscription': i18n.gettext('Subscription'),
    'version': i18n.gettext('Version'),
};

function error_flexi(data) {
    // we might do some mods here...
    alert_info_text({
        'text': "text_error_fetching_list",
        "type": ERROR,
        'is_escaped': true
    });
}

function pre_flexi(data) {
    // adjust the input for the linotp api version >= 2.0
    if (data.result) {
        if (data.result.status === false) {
            alert_info_text({
                'text': escape(data.result.error.message),
                'is_escaped': true
            });
            return;
        } else if (data.jsonrpc) {
            var api_version = parseFloat(data.jsonrpc);
            if (api_version >= 2.0) {
                return data.result.value;
            }
        }
    }
    return data;
}

/*
 * callback, to add in parameters to the flexi grid
 */
function on_submit_flexi() {
    var active_realm = $('#realm').val();

    var params = [
        { name: 'realm', value: active_realm },
    ];

    $('#user_table').flexOptions({ params: params });
    $('#audit_table').flexOptions({ params: params });
    $('#token_table').flexOptions({ params: params });
    $('#policy_table').flexOptions({ params: [] });

    return true;
}

/*
 * write into the report line
 * :param params: dictionary with
 * text - If the parameter is the ID of an element, we pass the text
 *       of this very element
 * param - replace parameter
 * display_type: report or ERROR
 */
function alert_info_text(params) {

    var s = params['text'] || '';
    var text_container = params['param'] || '';
    var display_type = params['type'] || '';
    var is_escaped = params['is_escaped'] || false;

    if (is_escaped == false) {
        text_container = escape(text_container);
        s = escape(s);
    }
    /*
     * If the parameter is the ID of an element, we pass the text from this very element
     */
    str = s;
    try {
        if (text_container) {
            $('#' + s + ' .text_param1').html(text_container);
        }
        if ($('#' + s).length > 0) { // Element exists!
            s = $('#' + s).html();
        } else {
            s = str;
        }

    }
    catch (e) {
        s = str;
    }

    new_info_bar = $('#info_bar').clone(true, true);
    new_info_bar.removeAttr('id');
    new_info_bar.children('span').removeAttr('id');

    pp = $('#info_bar').parent();
    new_info_bar.appendTo(pp);

    if (display_type == ERROR) {
        new_info_bar.addClass("error_box");
        new_info_bar.removeClass("info_box");
    } else {
        new_info_bar.addClass("info_box");
        new_info_bar.removeClass("error_box");
    }

    new_info_bar.children('span').html(s);
    new_info_bar.show();

    toggle_close_all_link();

    $('#info_box').show();

    // Scroll to the bottom of the info box
    $('#info_box').animate(
        { scrollTop: $('#info_box').prop("scrollHeight") },
        'slow'
    );
}

/*
 * This function counts the number of visible info boxes and error boxes and
 * if more than 1 are displayed it shows the "Close all" link. Otherwise it
 * hides the link.
 */
function toggle_close_all_link() {
    visible_boxes = $("#info_box > div").filter(":visible");
    close_all = $("a.close_all");
    if (visible_boxes.length > 1) {
        close_all.click(function (event) {
            event.preventDefault();
            visible_boxes.hide('blind', {}, 500);
            $(this).hide('blind', {}, 500);
        });
        close_all.show('blind', {}, 500);
        close_all.css("display", "block");
    }
    else {
        close_all.hide('blind', {}, 500);
    }
}

/**
 * set this value to `true` if you want to prevent new alert_boxes
 * from overriding the current alert_box
 */
alert_box_is_locked = false;

/*
 * pop up an alert box
 * :param params: dictionary
 * s - If the parameter is the ID of an element, we pass the text
 *     of this very element
 */
function alert_box(params) {
    if (alert_box_is_locked) {
        return;
    }
    var escaped = params['is_escaped'] || false;
    var title = params['title'] || '';
    var s = params['text'] || '';
    var param1 = params['param'] || '';

    if (escaped == false) {
        title = escape(title);
        s = escape(s);
        param1 = escape(param1);
    }

    str = s;
    try {
        if (param1) {
            $('#' + s + ' .text_param1').html(param1);
        }
        if ($('#' + s).length > 0) { // Element exists!
            s = $('#' + s).html();
        } else {
            s = str;
        }

    }
    catch (e) {
        s = str;
    }
    title_t = title;
    try {
        if ($('#' + title).length > 0) {
            title_t = $('#' + title).text();
        } else {
            title_t = title;
        }
    } catch (e) {
        title_t = title;
    }

    $('#alert_box').dialog("option", "title", title_t);
    $('#alert_box_text').html(s);
    $('#alert_box').dialog("open");

}

// #################################################
//
//  functions for selected tokens and selected users
//

function get_selected_tokens() {
    var selectedTokenItems = new Array();
    var tt = $("#token_table");
    $('.trSelected', tt).each(function () {
        var id = $(this).attr('id');
        var serial = id.replace(/row/, "");
        //var serial = $(this).attr('cells')[0].textContent;
        selectedTokenItems.push(serial);
    });
    return selectedTokenItems;
}

/*
 * This function returns the list of selected users.
 * Each list element is an object with
 *  - login
 *  - resolver
 */
function get_selected_user() {
    var selectedUserItems = new Array();
    var tt = $("#user_table");
    var selected = $('.trSelected', tt);
    if (selected.length > 1) {
        // unselect all selected users - as the last selected could not be identified easily
        selected.removeClass('trSelected');
        alert_box({
            'title': i18n.gettext("User selection:"),
            'text': i18n.gettext("Selection of more than one user is not supported!") + "<p>"
                + i18n.gettext("Please select only one user.") + "</p>",
            'is_escaped': true
        });
        return selectedUserItems;
    }
    var actual_realm = $('#realm').val();
    selected.each(function () {
        var user = new Object();
        user = { resolver: "", login: "", realm: actual_realm };
        column = $('td', $(this));
        column.each(function () {
            var attr = $(this).attr("abbr");
            if (attr == "useridresolver") {
                var loc = $('div', $(this)).html();
                var resolver = escape(loc.split('.'));
                user.resolver = resolver[resolver.length - 1];
            }
        });

        var id = $(this).attr('id');
        user.login = id.replace(/row/, "");
        selectedUserItems.push(user);
    });
    return selectedUserItems;
}

function get_selected_policy() {
    var selectedPolicy = new Array();
    var pt = $('#policy_table');
    $('.trSelected', pt).each(function () {
        var id = $(this).attr('id');
        var policy = id.replace(/row/, "");
        selectedPolicy.push(policy);
    });
    return selectedPolicy;
}

/*
 * This function returns the allowed actions within a scope
 */
function get_scope_actions(scope) {
    var actions = Array();
    var resp = clientUrlFetchSync("/system/getPolicyDef",
        { "scope": scope },
        true, "Error fetching policy definitions:");
    var obj = jQuery.parseJSON(resp);
    if (obj.result.status) {
        for (var k in obj.result.value) {
            action = k;
            if ("int" == obj.result.value[k].type) {
                action = k + "=<int>";
            } else
                if ("str" == obj.result.value[k].type) {
                    action = k + "=<string>";
                } else
                    if ("set" == obj.result.value[k].type) {
                        var values = obj.result.value[k].value || obj.result.value[k].range;
                        var arrayLength = values.length;
                        var desc = "";
                        var sep = "";
                        for (var i = 0; i < arrayLength; i++) {
                            if (i != 0) { sep = " "; }
                            desc = desc + sep + "<" + values[i] + ">";
                        }
                        action = k + "= <" + desc + ">";
                    };
            actions.push(action);
        }
    }
    return actions.sort();
}

/*
 * This function returns the policies which conform to the
 * set of definitions: scope, action, user, realm
 */
function get_policy(definition) {
    var policies = Array();
    var resp = clientUrlFetchSync("/system/getPolicy",
        definition,
        true, "Error fetching policy definitions:");
    var obj = jQuery.parseJSON(resp);
    if (obj.result.status) {
        for (var k in obj.result.value) {
            policy = obj.result.value[k];
            policies.push(policy);
        }
    }
    return policies;
}

function get_selected_mobile() {
    var selectedMobileItems = new Array();
    var tt = $("#user_table");

    var yourAbbr = "mobile";
    var column = tt.parent(".bDiv").siblings(".hDiv").find("table tr th").index($("th[abbr='" + yourAbbr + "']",
        ".flexigrid:has(#user_table)"));

    $('.trSelected', tt).each(function () {
        //var value = tt.children("td").eq(column).text();
        var value = $('.trSelected td:eq(5)', tt).text();
        selectedMobileItems.push(value);
    });
    return selectedMobileItems;
}

function get_selected_email() {
    var selectedEmailItems = new Array();
    var tt = $('#user_table');
    var yourAbbr = "email";
    var column = tt.parent(".bDiv").siblings(".hDiv").find("table tr th").index($("th[abbr='" + yourAbbr + "']",
        ".flexigrid:has(#user_table)"));
    $('.trSelected', tt).each(function () {
        //var value = tt.children("td").eq(column).text();
        var value = $('.trSelected td:eq(4)', tt).text();
        selectedEmailItems.push(value);
    });
    return selectedEmailItems;
}

function get_token_owner(token_serial) {

    // sorry: we need to do this synchronously
    var resp = clientUrlFetchSync('/admin/getTokenOwner',
        { 'serial': token_serial });
    if (resp == undefined) {
        alert('Server is not responding');
        return 0;
    }
    var obj = jQuery.parseJSON(resp);
    return obj.result.value;

}

function show_selected_status() {
    var selectedUserItems = get_selected_user();
    var selectedTokenItems = get_selected_tokens();
    $('#selected_tokens').html(escape(selectedTokenItems.join(", ")));
    // we can only select a single user
    if (selectedUserItems.length > 0)
        $('#selected_users').html(escape(selectedUserItems[0].login));
    else
        $('#selected_users').html("");
}

function get_selected() {
    var selectedUserItems = get_selected_user();
    var selectedTokenItems = get_selected_tokens();
    $('#selected_tokens').html(escape(selectedTokenItems.join(", ")));
    // we can only select a single user
    if (selectedUserItems.length > 0)
        $('#selected_users').html(escape(selectedUserItems[0].login));
    else
        $('#selected_users').html("");

    if (selectedTokenItems.length > 0) {
        if (selectedUserItems.length == 1) {
            $("#button_assign").button("enable");
        }
        else {
            $("#button_assign").button("disable");
        }

        $("#button_unassign").button("enable");
        $("#button_tokenrealm").button("enable");
        $("#button_getmuli").button("enable");
        $("#button_enable").button("enable");
        $("#button_disable").button("enable");
        $("#button_delete").button("enable");
        $("#button_setpin").button("enable");
        $("#button_resetcounter").button("enable");
        $("#button_setexpiration").button("enable");

        if (selectedTokenItems.length == 1) {
            $("#button_resync").button("enable");
            $('#button_losttoken').button("enable");
            $('#button_getmulti').button("enable");
            $("#button_tokeninfo").button("enable");
        }
        else if (selectedTokenItems.length > 1) {
            $("#button_resync").button("disable");
            $("#button_losttoken").button("disable");
            $('#button_getmulti').button("disable");
            $("#button_tokeninfo").button("disable");
        }
    }
    else {
        disable_all_buttons();
    }
    $("#button_enroll").button("enable");

    // The policies (we can select only one)
    if ($('#tabs').tabs('option', 'active') == 2) {
        policy = get_selected_policy().join(',');
        if (policy) {
            var params = {
                'name': policy,
                'display_inactive': '1',
            };
            $.post('/system/getPolicy', params,
                function (data, textStatus, XMLHttpRequest) {
                    if (data.result.status == true) {
                        policies = policy.split(',');
                        pol = policies[0];
                        var pol_active = data.result.value[pol].active;
                        if (pol_active == undefined) {
                            pol_active = "True";
                        }
                        $('#policy_active').prop('checked', pol_active == "True");
                        $('#policy_name').val(pol);
                        $('#policy_action').val(data.result.value[pol].action);
                        $('#policy_scope').val(data.result.value[pol].scope);
                        $('#policy_scope_combo').val(data.result.value[pol].scope);
                        $('#policy_realm').val(data.result.value[pol].realm);
                        $('#policy_user').val(data.result.value[pol].user);
                        $('#policy_time').val(data.result.value[pol].time);
                        $('#policy_client').val(data.result.value[pol].client || "");
                        renew_policy_actions();
                    }
                });
        }
    }
};

function disable_all_buttons() {
    $('#button_assign').button("disable");
    $('#button_unassign').button("disable");
    $('#button_tokenrealm').button("disable");
    $('#button_getmulti').button("disable");
    $('#button_enable').button("disable");
    $('#button_disable').button("disable");
    $('#button_setpin').button("disable");
    $('#button_delete').button("disable");
    $('#button_resetcounter').button("disable");
    $("#button_setexpiration").button("disable");
    $("#button_resync").button("disable");
    $("#button_tokeninfo").button("disable");
    $("#button_losttoken").button("disable");
}

/*
 * initialize the list of all available token types
 * - required to show and hide the dynamic enrollment section
 */
function init_$tokentypes() {
    var options = $('#tokentype > option');
    if ($tokentypes == undefined) { $tokentypes = {}; };
    options.each(
        function (i) {
            var key = $(this).val();
            var title = $(this).text();
            $tokentypes[key] = title;
        }
    );
}

/*
 * retrieve the linotp server config
 *
 * return the config as dict
 * or raise an exception
 *
 */
function get_server_config(search_key) {
    if (search_key) {
        var params = { 'key': search_key };
    } else {
        var params = {};
    }

    var $systemConfig = {};
    var resp = clientUrlFetchSync('/system/getConfig', params);

    var data;
    try {
        data = jQuery.parseJSON(resp);
    } catch (error) {
        throw i18n.gettext("Unable to load the server configuration.");
    }
    if (!data || !data.result || !data.result.status) {
        var message = data && data.result && data.result.error && data.result.error.message;
        if (!message) {
            message = i18n.gettext("Unable to load the server configuration.");
        }
        throw message;
    } else {
        if (search_key) {
            var config_dict = data.result.value;
            for (var key in config_dict) {
                key_replace = key.replace('getConfig ', '');
                $systemConfig[key_replace] = config_dict[key];
            }
        } else {
            $systemConfig = data.result.value;
        }
    }
    return $systemConfig;
}

var $token_config_changed = [];

function load_token_config() {

    var selectTag = $('#tab_token_settings');
    selectTag.find('div').each(
        function () {
            var attr = $(this).attr('id');
            var n = attr.split("_");
            var tt = n[0];
            $tokenConfigCallbacks[tt] = tt + '_get_config_params';
            $tokenConfigInbacks[tt] = tt + '_get_config_val';
        }
    );
    $('#tab_token_settings div form :input').change(
        function () {
            var attr = $(this).closest("form").closest("div").attr('id');
            var n = attr.split("_");
            var tt = n[0];
            $token_config_changed.push(tt);
            var nn = "#" + tt + "_token_settings";
            var label = $("#tab_token_settings [href='" + nn + "']").closest('a').text();

            var marker = "* ";

            if (label.substring(0, marker.length) !== marker) {
                $("#tab_token_settings [href='" + nn + "']").closest('a').text(marker + label);
                //$("#tab_token_settings [href='"+nn+"']").closest('a').attr( "class", 'token_config_changed');
            }
        }
    );

    // reset form validation
    $('#tab_token_settings div form').each(function () {
        var validator = $(this).validate();
        validator.resetForm();
    });

    // might raise an error, which must be caught by the caller
    $systemConfig = get_server_config();

    for (tt in $tokenConfigInbacks) {
        try {
            var functionString = '' + $tokenConfigInbacks[tt] + '';
            var funct = window[functionString];
            var exi = typeof funct;
            var l_params = {};
            if (exi == 'function') {
                l_params = window[functionString]();
            }

            for (var key in l_params) {
                var elem = $('#' + l_params[key]);
                if (key in $systemConfig) {
                    try {
                        if (elem.is(":checkbox")) {
                            var checked = $systemConfig[key].toLowerCase() == "true";
                            elem.prop('checked', checked);
                        }
                        else {
                            elem.val($systemConfig[key]);
                        }
                    } catch (err) {
                        //console_log('error ' + err + "  " + key + ": " + l_params[key] + '  ' + 'not found!')
                    }
                }
                else if (elem.is("select")) {
                    var defaultselected = $("option:first", elem).val();
                    // check if a different than the first option is default
                    $("option", elem).each(function () {
                        if (this.defaultSelected) {
                            defaultselected = $(this).val();
                            return false;
                        }
                    });
                    elem.val(defaultselected);
                }
            }
        }
        catch (err) {
            //console_log('callback for ' + tt + ' not found!')
        }
    }
    return;
}

/*
callback save_token_config()
*/
function save_token_config() {
    show_waiting();

    /* for every token call the getParamCallback */
    var params = {};
    for (tt in $tokenConfigCallbacks) {
        try {
            if ($.inArray(tt, $token_config_changed) !== -1) {
                var functionString = '' + $tokenConfigCallbacks[tt];
                var funct = window[functionString];
                var exi = typeof funct;
                var l_params = {};
                if (exi == 'function') {
                    l_params = window[functionString]();
                }
                for (var key in l_params) {
                    params[key] = l_params[key];
                }
            }
        }
        catch (err) { }
    }

    setSystemConfig(params);
}

function reset_waiting() {
    g.running_requests = 0;
    hide_waiting();
}

// ####################################################
//
//  URL fetching
// The myURL needs to end with ? if it has no parameters!


function jwt_getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

$.ajaxSetup({
    beforeSend: function (jqXHR, settings) {
        jqXHR.setRequestHeader(
            'X-CSRF-TOKEN',
            jwt_getCookie('csrf_access_token')
        );
    },
    statusCode: {
        401: function () {
            alert_box({
                'title': i18n.gettext('Your session expired'),
                'text': i18n.gettext('You are required to log in again. Redirecting…'),
                'type': ERROR,
                'is_escaped': true
            });
            alert_box_is_locked = true;
            setTimeout(function () {
                window.location = 'login';
            }, 1000);
            return false;
        }
    }
});

/*
 * clientUrlFetch - to submit a asyncronous http request
 *
 * @remark: introduced the params (:dict:) so we could switch to
 *          a POST request, which will allow more and secure data
 */
function clientUrlFetch(myUrl, params, callback, parameter) {

    show_waiting();

    g.running_requests = g.running_requests + 1;

    promise = $.ajax({
        url: myUrl,
        data: params,
        async: true,
        type: 'POST',
        complete: function (xhdr, textStatus) {
            g.running_requests = g.running_requests - 1;
            if (g.running_requests <= 0) {
                hide_waiting();
                g.running_requests = 0;
            }
            if (callback != null) {
                callback(xhdr, textStatus, parameter);
            }
        }
    });
    return promise;
}

/*
 * clientUrlFetchSync - to submit a synchronous http request
 *
 * @remark: introduced the params (:dict:) so we could switch to
 *          a POST request, which will allow more and secure data
 */
function clientUrlFetchSync(myUrl, params) {

    show_waiting();

    var resp = $.ajax({
        url: myUrl,
        data: params,
        async: false,
        type: 'POST',
    }
    ).responseText;
    hide_waiting();
    return resp;
}


// ####################################################
// get overall number of tokens
function get_tokennum() {
    // sorry: we need to do this synchronously
    var resp = clientUrlFetchSync('/admin/show', {
        'page': 1, 'pagesize': 1,
        'filter': '/:token is active:/'
    });
    if (resp == undefined) {
        alert('Server is not responding');
        return 0;
    }
    var obj = jQuery.parseJSON(resp);
    return obj.result.value.resultset.tokens;
}

/* call the server license check*/
function check_license() {
    var resp = clientUrlFetchSync('/system/isSupportValid', {});
    var obj = jQuery.parseJSON(resp);
    if (obj.result.value === false) {
        var message = escape(obj.detail.reason);
        var intro = escape($('#text_support_lic_error').html());
        alert_info_text({
            'text': intro + " " + message,
            'type': ERROR,
            'is_escaped': true
        });
    }
    if ("detail" in obj && "reason" in obj.detail) {
        var message = escape(obj.detail.reason);
        var intro = escape($('#text_support_lic_error').html());
        alert_info_text({
            'text': intro + " " + message,
            'is_escaped': true
        });
    }
    if (obj['detail'] && obj.detail['download_licence_info']) {
        $('#dialog_support_contact').html(obj.detail['download_licence_info']);
        $dialog_support_contact.dialog('open');
    }
    return;
}

/**
 * checks the license status for enterprise subscription
 * @return {Boolean} true if a valid license was found
 */
function is_license_valid() {
    var resp = clientUrlFetchSync('/system/isSupportValid', {});
    var obj = jQuery.parseJSON(resp);
    if ("detail" in obj && "reason" in obj.detail) {
        var message = escape(obj.detail.reason);
        var intro = escape($('#text_support_lic_error').html());
        alert_info_text({
            'text': intro + " " + message,
            'is_escaped': true
        });
    }
    return obj.result.value === true;
}

// ####################################################
//
//  Token functions
//

function reset_buttons() {
    $("#token_table").flexReload();
    $('#selected_tokens').html('');
    disable_all_buttons();
}

function assign_callback(xhdr, textStatus, serials) {
    resp = xhdr.responseText;
    obj = jQuery.parseJSON(resp);
    if (obj.result.status == false) {
        alert_info_text({
            'text': escape(obj.result.error.message),
            'type': ERROR,
            'is_escaped': true
        });
    } else {
        alert_info_text({
            'text': "text_operation_success",
            'param': "assign",
            'is_escaped': true
        });
        view_setpin_after_assigning(serials);
    }
    reset_buttons();
}

/*
 * Evaluates a list of responses, displays a list of all the errors found
 * and finally reloads the page.
 */
function token_operations_callback(responses, url) {
    var error_messages = [];
    $.each(responses, function (index, responseData) {
        // "responseData" will contain an array of response information for each specific request
        if (responseData.length !== 3 || responseData[1] !== 'success') {
            error_messages.push('Request ' + index + ' unsuccessful');
            return true; // skip to next item of each loop
        }
        var obj = responseData[0];
        if (obj.result.status == false) {
            error_messages.push(obj.result.error.message);
        }
        else if (obj.result.value == 0) {
            // No operation performed on token
            error_messages.push(obj.detail.message);
        }
    });

    if (error_messages.length > 0) {
        alert_info_text({
            'text': escape(error_messages.join(" -- ")),
            'type': ERROR,
            'is_escaped': true
        });
    } else {
        alert_info_text({
            'text': "text_operation_success",
            'param': escape(url.split("/").pop()),
            'is_escaped': true
        });
    }
    reset_buttons();
}

/*
 * Performs an operation on a list of tokens
 *
 * tokens is a list of tokens (serial numbers)
 * url is the operation to perform. For example "/admin/remove"
 * params are any parameters required for the requests. You DON'T need to
 * pass in the session. Token serial is set inside this function as well.
 */
function token_operation(tokens, url, params) {
    var requests = Array();
    for (var i = 0; i < tokens.length; i++) {
        params['serial'] = tokens[i];
        var promise = clientUrlFetch(url, params);
        requests.push(promise);
    }

    // By using the 'when' function (that takes a list of promises/deferreds as
    // input) we make sure 'reset_buttons()' is execute ONCE after ALL the
    // deletion requests have finished.
    var defer = $.when.apply($, requests);
    defer.done(function () {
        var responses = [];
        if (requests.length == 1) {
            // "arguments" will be the array of response information for the request
            responses = [arguments];
        }
        else {
            responses = arguments;
        }
        token_operations_callback(responses, url);
    });
}

/*
 * Performs one operation on a list of tokens
 *
 * tokens is a list of tokens (serial numbers)
 * url is the operation to perform. For example "/admin/remove"
 * params are any parameters required for the requests. You DON'T need to
 * pass in the session.
 */
function tokens_operation(tokens, url, params) {
    var requests = Array();
    params['serial'] = tokens;
    var promise = clientUrlFetch(url, params);
    requests.push(promise);

    // By using the 'when' function (that takes a list of promises/deferreds as
    // input) we make sure 'reset_buttons()' is execute ONCE after ALL the
    // deletion requests have finished.
    var defer = $.when.apply($, requests);
    defer.done(function () {
        var responses = [];
        if (requests.length == 1) {
            // "arguments" will be the array of response information for the request
            responses = [arguments];
        }
        else {
            responses = arguments;
        }
        token_operations_callback(responses, url);
    });
}


function token_delete() {
    var tokens = get_selected_tokens();
    tokens_operation(tokens, "/admin/remove", {});
}

function token_unassign() {
    var tokens = get_selected_tokens();
    token_operation(tokens, "/admin/unassign", {});
}

function token_reset() {
    var tokens = get_selected_tokens();
    token_operation(tokens, "/admin/reset", {});
}

function token_disable() {
    var tokens = get_selected_tokens();
    token_operation(tokens, "/admin/disable", {});
}

function token_enable() {
    var tokens = get_selected_tokens();
    check_license();
    token_operation(tokens, "/admin/enable", {});
}

function token_assign() {

    tokentab = 0;
    tokens = get_selected_tokens();
    user = get_selected_user();
    count = tokens.length;
    clientUrlFetch("/admin/assign", {
        "serial": tokens,
        "user": user[0].login,
        'resConf': user[0].resolver,
        'realm': $('#realm').val()
    },
        assign_callback, tokens);
}

function token_resync_callback(xhdr, textStatus) {
    var resp = xhdr.responseText;
    var obj = jQuery.parseJSON(resp);
    if (obj.result.status) {
        if (obj.result.value)
            alert_info_text({
                'text': "text_resync_success",
                'is_escaped': true,
            });
        else
            alert_info_text({
                'text': "text_resync_fail",
                'type': ERROR,
                'is_escaped': true,
            });
    } else {
        message = escape(obj.result.error.message);
        alert_info_text({ 'text': message, 'type': ERROR, 'is_escaped': true });
    }

    reset_buttons();
}

function token_resync() {
    var tokentab = 0;
    var tokens = get_selected_tokens();
    var count = tokens.length;
    for (i = 0; i < count; i++) {
        var serial = tokens[i];
        clientUrlFetch("/admin/resync", { "serial": serial, "otp1": $('#otp1').val(), "otp2": $('#otp2').val() }, token_resync_callback);
    }
}

function losttoken_callback(xhdr, textStatus) {
    var resp = xhdr.responseText;

    obj = jQuery.parseJSON(resp);
    if (obj.result.status) {
        var serial = obj.result.value.serial;
        var end_date = obj.result.value.end_date;
        var password = '';
        if ('password' in obj.result.value) {
            password = obj.result.value.password;
            $('#temp_token_password').text(password);
        }
        $('#temp_token_serial').html(escape(serial));
        $('#temp_token_enddate').html(escape(end_date));
        $dialog_view_temporary_token.dialog("open");
    } else {
        alert_info_text({
            'text': "text_losttoken_failed",
            'param': escape(obj.result.error.message),
            'type': ERROR,
            'is_escaped': true
        });
    }
    $("#token_table").flexReload();
    $('#selected_tokens').html('');
    disable_all_buttons();
}

/*
 * token_losttoken - request enrollment of losttoken
 */
function token_losttoken(token_type) {
    var tokens = get_selected_tokens();
    var count = tokens.length;

    /* this for loop is unused as the gui allows only the losttoken action
     * if only one token is selected (count is 1) */
    for (i = 0; i < count; i++) {
        var params = { "serial": tokens[i] };

        if (token_type === 'password' ||
            token_type === 'email' ||
            token_type === 'sms')
            params['type'] = token_type;

        resp = clientUrlFetch("/admin/losttoken",
            params, losttoken_callback);
    }
}


/****************************************************************************
 * PIN setting
 */

function setpin_callback(xhdr, textStatus) {
    var resp = xhdr.responseText;
    var obj = jQuery.parseJSON(resp);
    if (obj.result.status) {
        if (obj.result.value)
            alert_info_text({
                'text': "text_setpin_success",
                'is_escaped': true
            });
        else
            alert_info_text({
                'text': "text_setpin_failed",
                'param': escape(obj.result.error.message),
                'type': ERROR,
                'is_escaped': true,
            });
    }
}

/**
 * token_setpin is used to process the "set pin" dialog in the token view
 * @throws {PinMatchError} both entered pins must be equal
 **/
function token_setpin() {
    var token_string = $('#setpin_tokens').val();
    var tokens = token_string.split(",");
    var count = tokens.length;

    if (!checkpins('#pin1, #pin2')) {
        throw "PinMatchError";
    }

    var pin = $('#pin1').val();

    var pintype = $('#pintype').val();

    for (i = 0; i < count; i++) {
        var serial = tokens[i];
        if (pintype.toLowerCase() == "otp") {
            clientUrlFetch("/admin/set", { "serial": serial, "pin": pin }, setpin_callback);
        } else if ((pintype.toLowerCase() == "motp")) {
            clientUrlFetch("/admin/setPin", { "serial": serial, "userpin": pin }, setpin_callback);
        } else if ((pintype.toLowerCase() == "ocrapin")) {
            clientUrlFetch("/admin/setPin", { "serial": serial, "userpin": pin }, setpin_callback);
        } else
            alert_info_text({
                'text': "text_unknown_pintype",
                'param': pintype,
                'type': ERROR,
                'is_escaped': true
            });
    }
    return true;
}

/*
 * This function encapsulates the set pin dialog and is
 * called by the button "set pin" and can be called
 * after enrolling or assigning tokesn.
 *
 * Parameter: array of serial numbers
 */
function view_setpin_dialog(tokens) {
    var token_string = tokens.join(", ");
    $('#dialog_set_pin_token_string').text(token_string);
    $('#setpin_tokens').val(tokens);
    $dialog_setpin_token.dialog('open');
}

/*
 * depending on the policies
 * - random pin
 * we can display or not display it.
 * TODO: should this be disabled on otppin != 0 as well?
 */
function view_setpin_after_assigning(tokens) {
    var display_setPin = true;

    var selected_users = get_selected_user();
    var policy_def = {
        'scope': 'enrollment',
        'action': 'otp_pin_random'
    };
    policy_def['realm'] = selected_users[0].realm;
    policy_def['user'] = selected_users[0].login;

    var rand_pin = get_policy(policy_def);
    if (rand_pin.length > 0) {
        display_setPin = false;
    }

    if (display_setPin === true) {
        view_setpin_dialog(tokens);
    }

}

/**
 * load token info in html presentation
 * @return {string|boolean} the html string containing the token info
 *                          or false if # of selected tokens not feasible
 */

function token_info() {
    var tokens = get_selected_tokens();

    if (tokens.length !== 1) {
        alert_info_text({
            'text': "text_only_one_token_ti",
            'is_escaped': true
        });
        return false;
    }

    var params = {
        "serial": tokens[0]
    };

    return clientUrlFetchSync("/manage/tokeninfo", params);
}

/**
 * load token object from linotp
 * @param  {string} serial    the serial of the token to match
 * @return {Promise.<Object>} returns a promise that resolves the token object requested from LinOTP
 */
function getTokenDetails(serial) {
    return $.ajax({
        url: '/admin/show',
        type: 'post',
        data: {
            "serial": serial,
            "tokeninfo_format": "json",
        }
    }).then(function (response, status, promise) {
        var result = response.result.value;
        if (result && result.data && result.data.length === 1) {
            return $.Deferred().resolve(result.data[0]).promise();
        }
        return $.Deferred().reject("Request failed").promise();
    });
}


function get_token_type() {
    var tokentab = 0;
    var tokens = get_selected_tokens();
    var count = tokens.length;
    var ttype = "";
    if (count != 1) {
        alert_info_text({
            'text': "text_only_one_token_type",
            'is_escaped': true
        });
        return false;
    }
    else {
        var serial = tokens[0];
        var resp = clientUrlFetchSync("/admin/show", { "serial": serial });
        try {
            var obj = jQuery.parseJSON(resp);
            ttype = obj['result']['value']['data'][0]['LinOtp.TokenType'];
        }
        catch (e) {
            alert_info_text({
                'text': "text_fetching_tokentype_failed",
                'param': escape(e),
                'type': ERROR,
                'is_escaped': true
            });
        }
        return ttype;
    }
}

function tokeninfo_redisplay() {
    var tokeninfo = token_info();
    $dialog_token_info.html($.parseHTML(tokeninfo));
    set_tokeninfo_buttons();
}

function token_info_save() {
    var info_type = $('input[name="info_type"]').val();
    var info_value = $('#info_value').val();

    var tokens = get_selected_tokens();
    var count = tokens.length;
    var serial = tokens[0];
    if (count != 1) {
        alert_info_text({
            'text': "text_only_one_token_ti",
            'is_escaped': true
        });
        return false;
    }
    else {
        // see: http://stackoverflow.com/questions/10640159/key-for-javascript-dictionary-is-not-stored-as-value-but-as-variable-name
        var param = { "serial": serial };
        param[info_type] = info_value;
        var resp = clientUrlFetchSync("/admin/set", param);
        var rObj = jQuery.parseJSON(resp);
        if (rObj.result.status == false) {
            alert(escape(rObj.result.error.message));
        }
    }
    // re-display
    tokeninfo_redisplay();
    return true;
}


function enroll_callback(xhdr, textStatus, p_serial) {
    var resp = xhdr.responseText;
    var obj = jQuery.parseJSON(resp);
    var serial = p_serial;

    //enroll_callback - return from init the values, which makes this easier

    $('#dialog_enroll').hide();
    if (obj.result.status) {
        if (obj.hasOwnProperty('detail')) {
            var detail = obj.detail;
            if (detail.hasOwnProperty('serial')) {
                serial = detail.serial;
            }
        }
        alert_info_text({
            'text': "text_created_token",
            'param': escape(serial),
            'is_escaped': true
        });
        if (true == g.enroll_display_qrcodes) {

            // display the QR-Code of the URL. tab
            var users = get_selected_user();
            var emails = get_selected_email();
            $('#token_enroll_serial').html(escape(serial));
            if (users.length >= 1) {
                var login = escape(users[0].login);
                var user = login;
                var email = escape(jQuery.trim(emails[0]));
                if (email.length > 0) {
                    user = "<a href=mailto:" + email + ">" + login + "</a>";
                }
                // the input parts for the fragment are already escaped
                $('#token_enroll_user').html(user);
            } else {
                $('#token_enroll_user').html("---");
            }

            var dia_tabs = {};
            var dia_tabs_content = {};

            // here we compose the HMAC reply dialog with multiple tabs
            // while the content is defined in mako files
            for (var k in obj.detail) {
                var theDetail = obj.detail[k];
                if (theDetail != null && theDetail.hasOwnProperty('description')) {
                    // fallback, if no ordering is defined
                    if (theDetail.hasOwnProperty('order')) {
                        order = theDetail.order;
                    } else {
                        order = k;
                    }
                    var description = escape(theDetail.description);
                    if ($("#description_" + k).length !== 0) {
                        // we only require the text value of the description
                        description = $("#description_" + k).text();
                    }
                    dia_tabs[order] = '<li><a href="#url_content_' + k + '">' + description + '</a></li>';
                    dia_tabs_content[order] = _extract_tab_content(theDetail, k);
                }
            };
            // now extract all orders and sort them
            var keys = [];
            for (var key in dia_tabs) {
                keys.push(key);
            }
            keys.sort();

            // create the TAB header
            var dia_text = '<div id="qr_url_tabs">';
            dia_text += '<ul>';
            for (var i = 0; i < keys.length; i++) {
                order = keys[i];
                dia_text += dia_tabs[order];
            }
            dia_text += '</ul>';

            // create the TAB content
            for (var i = 0; i < keys.length; i++) {
                order = keys[i];
                dia_text += dia_tabs_content[order];
            }
            // serial number
            dia_text += '<input type=hidden id=enroll_token_serial value=' + serial + '>';
            // end of qr_url_tabs
            dia_text += '</div>';

            // the output fragments of dia_text ae already escaped
            $('#enroll_url').html($.parseHTML(dia_text));
            $('#qr_url_tabs').tabs();
            $dialog_show_enroll_url.dialog("open");
        }
    }
    else {
        alert_info_text({
            'text': "text_error_creating_token",
            'param': escape(obj.result.error.message),
            'type': ERROR,
            'is_escaped': true
        });
    }
    reset_buttons();
}

function _extract_tab_content(theDetail, k) {
    var value = theDetail.value;
    var img = theDetail.img;

    var annotation = '';
    if ($('#annotation_' + k).length !== 0) {
        annotation = $('#annotation_' + k).html();
    }
    annotation = escape(annotation);

    var dia_text = '';
    dia_text += '<div id="url_content_' + k + '">';
    dia_text += "<p>";
    dia_text += "<div class='enrollment_annotation'>" + annotation + "</div>";
    dia_text += "<a href='" + value + "'>" + img + "</a>";
    dia_text += "<br/>";
    dia_text += "<div class='enrollment_value'>" + value + "</div>";
    dia_text += "</p></div>";
    return dia_text;
}

/**
 * @throws {PinMatchError} token pins must match
 */
function token_enroll() {
    check_license();

    // stop here if pins do not match
    var pin_inputs = $('.token_enroll_frame.active-frame [name="pin1"],' +
        '.token_enroll_frame.active-frame [name="pin2"]');
    if (!checkpins(pin_inputs)) {
        throw "PinMatchError";
    }

    var users = get_selected_user();
    var url = '/admin/init';
    var params = {};
    var serial = '';
    // User
    if (users[0]) {
        params['user'] = users[0].login;
        params['resConf'] = users[0].resolver;
        params['realm'] = $('#realm').val();
    }
    // when the init process generated a key, this will be displayed to the administrator
    g.enroll_display_qrcodes = false;
    // get the token type and call the geturl_params() method for this token - if exist
    var typ = $('#tokentype').val();
    // dynamic tokens might overwrite this description
    params['description'] = 'webGUI_generated';

    /* switch can be removed by default, if token migration is completed*/

    switch (typ) {
        case 'ocra':
            params['sharedsecret'] = 1;
            // If we got to generate the hmac key, we do it here:
            if ($('#ocra_key_cb').is(':checked')) {
                params['genkey'] = 1;
            } else {
                // OTP Key
                params['otpkey'] = $('#ocra_key').val();
            }
            if ($('#ocra_pin1').val() != '') {
                params['pin'] = $('#ocra_pin1').val();
            }
            break;

        default:
            if (typ in $tokentypes) {  /*
                * the dynamic tokens must provide a function to gather all data from the form
                */
                var params = {};
                var functionString = typ + '_get_enroll_params';
                var funct = window[functionString];
                var exi = typeof funct;

                if (exi == 'undefined') {
                    alert('undefined function ' + escape(functionString) +
                        ' for tokentype ' + escape(typ));
                }
                if (exi == 'function') {
                    params = window[functionString]();
                }
            } else {
                alert_info_text({
                    'text': "text_enroll_type_error",
                    'type': ERROR,
                    'is_escaped': true
                });
                return false;
            }
    }
    params['type'] = typ;
    if (params['genkey'] == 1 || typ == "qr") {
        g.enroll_display_qrcodes = true;
    }
    clientUrlFetch(url, params, enroll_callback, serial);
    return true;
}

function get_enroll_infotext() {
    var users = get_selected_user();
    $("#enroll_info_text_user").hide();
    $("#enroll_info_text_nouser").hide();
    $("#enroll_info_text_multiuser").hide();
    if (users.length == 1) {
        $("#enroll_info_text_user").show();
        var login = escape(users[0].login);
        var resolver = escape(users[0].resolver);
        $('#enroll_info_user').html($.parseHTML(login + " (" + resolver + ")"));
    }
    else
        if (users.length == 0) {
            $("#enroll_info_text_nouser").show();
        }
        else {
            $("#enroll_info_text_multiuser").show();
        }
}

function tokentype_changed() {
    var $tokentype = $("#tokentype").val();

    // might raise an error, which must be catched by the caller
    $systemConfig = get_server_config();

    try {
        $('.token_enroll_frame').not('#token_enroll_' + $tokentype).removeClass('active-frame').hide();
        $('#token_enroll_' + $tokentype).addClass('active-frame').show();

        if ($tokentype !== "ocra") {
            var functionString = '' + $tokentype + '_enroll_setup_defaults';
            var funct = window[functionString];
            var exi = typeof funct;

            if (exi == 'function') {
                var rand_pin = 0;
                var options = {};
                var selected_users = get_selected_user();
                if (selected_users.length == 1) {
                    var policy_def = {
                        'scope': 'enrollment',
                        'action': 'otp_pin_random'
                    };
                    policy_def['realm'] = selected_users[0].realm;
                    policy_def['user'] = selected_users[0].login;
                    rand_pin = get_policy(policy_def).length;
                    options = { 'otp_pin_random': rand_pin };
                }
                var l_params = window[functionString]($systemConfig, options);
            }
        }

        // enable visual pin validation and trigger it for the first time
        var pin_inputs = $('.token_enroll_frame.active-frame [name="pin1"],' +
            '.token_enroll_frame.active-frame [name="pin2"]');

        pin_inputs.on('change keyup', function (e) {
            checkpins(pin_inputs);
        }).change();
    }
    catch (err) {
        alert_box({
            'title': i18n.gettext('unknown token type'),
            'text': i18n.gettext('Error during token type change processing for type "' + $tokentype + '".<br><pre>' + err + "</pre>"),
            'type': ERROR,
            'is_escaped': true
        });
    }
}

/**
 * enables jquery ui components
 */
$.fn.enableUIComponents = function () {
    $('.ui-button', this).each(function () {
        var config = {};

        if ($(this).attr("data-ui-icon"))
            config.icons = { primary: $(this).attr("data-ui-icon") };

        $(this).button(config);
    });

    return this;
};

/**
 * adds icons to the given dialogs buttons
 */
$.fn.dialog_icons = function () {
    var buttons = this.parent().find('.ui-dialog-buttonpane');

    buttons.find('button:contains("Cancel")').button({
        icons: {
            primary: 'ui-icon-cancel'
        }
    });
    buttons.find('button:contains("New")').button({
        icons: {
            primary: 'ui-icon-plusthick'
        }
    });
    buttons.find('button:contains("Delete")').button({
        icons: {
            primary: 'ui-icon-trash'
        }
    });
    buttons.find('button:contains("Save")').button({
        icons: {
            primary: 'ui-icon-disk'
        }
    });
    buttons.find('button:contains("Set PIN")').button({
        icons: {
            primary: 'ui-icon-pin-s'
        }
    });
    buttons.find('button:contains("Edit")').button({
        icons: {
            primary: 'ui-icon-pencil'
        }
    });
    buttons.find('button:contains("load tokenfile")').button({
        icons: {
            primary: 'ui-icon-folder-open'
        }
    });
    buttons.find('button:contains("load token file"), button:contains("Load Token File")').button({
        icons: {
            primary: 'ui-icon-folder-open'
        }
    });
    buttons.find('button:contains("Set subscription"), button:contains("Setup support")').button({
        icons: {
            primary: 'ui-icon-document-b'
        }
    });
    buttons.find('button:contains("Set Default"), button:contains("Set as default")').button({
        icons: {
            primary: 'ui-icon-flag'
        }
    });
    buttons.find('button:contains("Enroll")').button({
        icons: {
            primary: 'ui-icon-plusthick'
        }
    });
    buttons.find('button:contains("Resync")').button({
        icons: {
            primary: 'ui-icon-refresh'
        }
    });
    buttons.find('button:contains("unassign token")').button({
        icons: {
            primary: 'ui-icon-pin-arrowthick-1-w'
        }
    });
    buttons.find('button:contains("delete token")').button({
        icons: {
            primary: 'ui-icon-pin-trash'
        }
    });
    buttons.find('button:contains("Close")').button({
        icons: {
            primary: 'ui-icon-closethick'
        }
    });
    buttons.find('button:contains("Duplicate"), button:contains("Copy"), button:contains("Export"), button:contains("Migrate")').button({
        icons: {
            primary: 'ui-icon-arrowreturnthick-1-e'
        }
    });
    buttons.find('button:contains("Import")').button({
        icons: {
            primary: 'ui-icon-play'
        }
    });

    return this;
};

// #################################################
//
// realms and resolver functions
//
function _fill_resolvers(widget) {
    $.post('/system/getResolvers', {},
        function (data, textStatus, XMLHttpRequest) {
            var resolversOptions = "";
            var value = {};
            if (data.hasOwnProperty('result')) {
                value = data.result.value;
            }
            for (var i in value) {
                var resolver_val = escape(i);
                resolversOptions += "<option>";
                resolversOptions += resolver_val;
                resolversOptions += "</option>";
            }
            widget.html(resolversOptions);
        });
    return;
}

function _fill_realms(widget, also_none_realm) {
    var defaultRealm = "";
    $.post('/system/getRealms', {},
        function (data, textStatus, XMLHttpRequest) {
            // value._default_.realmname
            // value.XXXX.realmname
            //var realms = "Realms: <select id=realm>"
            var realms = "";
            // we need to calculate the length:
            if (1 == also_none_realm) {
                realms += "<option></option>";
            }
            var realmCount = 0;
            var value = {};
            if (data.hasOwnProperty('result')) {
                value = data.result.value;
            }
            for (var i in value) {
                realmCount += 1;
            }
            var defaultRealm;
            for (var i in value) {
                var realm_val = escape(i);
                if (value[i]['default']) {
                    realms += "<option selected>";
                    defaultRealm = realm_val;
                }
                else
                    if (realmCount == 1) {
                        realms += "<option selected>";
                        defaultRealm = realm_val;
                    }
                    else {
                        realms += "<option>";
                    }
                //realms += data.result.value[i].realmname;
                // we use the lowercase realm name
                realms += realm_val;
                realms += "</option>";
            }

            //realms += "</select>";
            widget.html(realms);
        });
    return defaultRealm;
}

function fill_realms() {
    var defaultRealm = _fill_realms($('#realm'), 0);
    return defaultRealm;
}

function get_defaulrealm() {
    var realms = new Array();
    var url = '/system/getDefaultRealm';

    var resp = $.ajax({
        url: url,
        async: false,
        data: {},
        type: "GET"
    }).responseText;
    var data = jQuery.parseJSON(resp);
    for (var i in data.result.value) {
        realms.push(i);
    };
    return realms;
}

function get_realms() {
    var realms = new Array();
    var resp = $.ajax({
        url: '/system/getRealms',
        async: false,
        data: {},
        type: "GET"
    }).responseText;
    var data = jQuery.parseJSON(resp);
    for (var i in data.result.value) {
        realms.push(i);
    };
    return realms;
}

/*
 * return the list of the resolver names
 */
function get_resolvers() {
    var resolvers = new Array();
    var resp = $.ajax({
        url: '/system/getResolvers',
        async: false,
        data: {},
        type: "POST"
    }).responseText;
    var data = jQuery.parseJSON(resp);
    for (var i in data.result.value) {
        resolvers.push(i);
    };
    return resolvers;
}


// ####################################################
//
//  jQuery stuff
//

function get_serial_by_otp_callback(xhdr, textStatus) {
    var resp = xhdr.responseText;
    var obj = jQuery.parseJSON(resp);
    if (obj.result.status == true) {
        if (obj.result.value.success == true) {
            if ("" != obj.result.value.serial) {

                var text = i18n.gettext("Found the token: ") +
                    escape(obj.result.value.serial);

                if (obj.result.value.user_login != "") {

                    text += "\n" +
                        i18n.gettext("The token belongs to ") +
                        escape(obj.result.value.user_login) +
                        " (" + escape(obj.result.value.user_resolver) + ")";
                }
                alert_info_text({
                    'text': text,
                    'is_escaped': true
                });
            }
            else
                alert_info_text({
                    'text': "text_get_serial_no_otp",
                    'is_escaped': true
                });
        } else {
            alert_info_text({
                "text": "text_get_serial_error",
                'type': ERROR,
                'is_escaped': true
            });
        }
    } else {
        alert_info_text({
            'text': "text_failed",
            'param': escape(obj.result.error.message),
            'type': ERROR,
            'is_escaped': true
        });
    }
}

/*
 * get Serial by OTP
 */
function getSerialByOtp(otp, type, assigned, realm) {
    var param = {};
    param["otp"] = otp;
    if ("" != type) {
        param["type"] = type;
    }
    if ("" != assigned) {
        param["assigned"] = assigned;
    }
    if ("" != realm) {
        param["realm"] = realm;
    }
    clientUrlFetch('/admin/getSerialByOtp', param, get_serial_by_otp_callback);

}

/**
 * handler for the ldap resolver form keyup event of the ldap uri and enforce tls flag,
 * which checks whether the enforce tls should be shown
 */
function handler_ldaps_starttls_show() {
    var onlyLdapsURI = $("#ldap_uri").val().toLowerCase().match(/ldap:/) === null;
    var onlyLdapURI = $("#ldap_uri").val().toLowerCase().match(/ldaps:/) === null;

    var useStarttlsIsDisabled = $("#ldap_enforce_tls").prop("disabled");
    var useStarttlsIsChecked = $("#ldap_enforce_tls").prop("checked");

    // disable start_tls option if no server using "ldap://" URI
    $("#ldap_enforce_tls").prop("disabled", onlyLdapsURI);
    $("#ldap_enforce_tls_label").toggleClass("disabled", onlyLdapsURI);
    if (onlyLdapsURI) {
        $("#ldap_enforce_tls").prop("checked", false);
    }

    if (onlyLdapsURI || useStarttlsIsChecked) {
        $("#ldap_enforce_tls_warning").hide();
    } else {
        $("#ldap_enforce_tls_warning").show();
    }

    if (!onlyLdapsURI && useStarttlsIsDisabled) {
        // reset to default value (that is true)
        $("#ldap_enforce_tls").prop("checked", true);
        $("#ldap_enforce_tls_warning").hide();
    }

    useStarttlsIsChecked = $("#ldap_enforce_tls").prop("checked");

    var onlyTrustedCertsIsDisabled = $("#ldap_only_trusted_certs").prop("disabled");
    var onlyTrustedCertsIsChecked = $("#ldap_only_trusted_certs").prop("checked");

    var noEncryptionSelected = onlyLdapURI && !useStarttlsIsChecked;

    // disable only_trusted_certs option if no encryption used
    $("#ldap_only_trusted_certs").prop("disabled", noEncryptionSelected);
    $("#ldap_only_trusted_certs_label").toggleClass("disabled", noEncryptionSelected);
    if (noEncryptionSelected) {
        $("#ldap_only_trusted_certs").prop("checked", false);
    }

    if (noEncryptionSelected || onlyTrustedCertsIsChecked) {
        $("#ldap_only_trusted_certs_warning").hide();
    } else {
        $("#ldap_only_trusted_certs_warning").show();
    }

    if (!noEncryptionSelected && onlyTrustedCertsIsDisabled) {
        // reset to default value (that is true)
        $("#ldap_only_trusted_certs").prop("checked", true);
        $("#ldap_only_trusted_certs_warning").hide();
    }
}

/*
 * This function checks if the HTTP URI is using SSL.
 * If so, it displays the CA certificate entry field.
 */
function http_resolver_https() {
    var http_uri = $('#http_uri').val();
    if (http_uri.toLowerCase().match(/^https:/)) {
        $('#http_resolver_certificate').show();
    } else {
        $('#http_resolver_certificate').hide();
    }
    return false;
}


function parseXML(xml, textStatus) {
    var version = $(xml).find('version').text();
    var status = $(xml).find('status').text();
    var value = $(xml).find('value').text();
    var message = $(xml).find('message').text();

    textStatus = textStatus.toLowerCase();
    status = status.toLowerCase();

    /* no xml response: try to interpret the result as json */
    if (textStatus == "parsererror") {
        var json_response = JSON.parse(xml.responseText);

        var error_message = json_response
            && json_response.result
            && json_response.result.error
            && json_response.result.error.message
            || xml.responseText;

        if (error_message.length > 200) {
            error_message = error_message.substring(0, 200) + "…";
        }

        alert_info_text({
            text: "Token import failed: " + error_message,
            type: ERROR,
            is_escaped: false
        });

    } else if (textStatus == "error") {
        alert_info_text({
            text: "text_linotp_comm_fail",
            type: ERROR,
            is_escaped: true
        });
    } else if (status == "false") {
        alert_info_text({
            text: "text_token_import_failed",
            param: escape(message),
            type: ERROR,
            is_escaped: true,
        });
    } else {
        // reload the token_table
        $('#token_table').flexReload();
        $('#selected_tokens').html('');
        disable_all_buttons();
        alert_info_text({
            text: "text_token_import_result",
            param: escape(value),
            is_escaped: true,
        });

    }
    hide_waiting();
};

function parsePolicyImport(xml, textStatus) {
    var version = $(xml).find('version').text();
    var status = $(xml).find('status').text();
    var value = $(xml).find('value').text();
    var message = $(xml).find('message').text();

    if ("error" == textStatus) {
        alert_info_text({
            'text': "text_linotp_comm_fail",
            'type': ERROR,
            'is_escaped': true
        });
    }
    else {
        if ("False" == status) {
            alert_info_text({
                'text': "text_policy_import_failed",
                'param': escape(message),
                'is_escaped': true
            });
        }
        else {
            // reload the token_table
            $('#policy_table').flexReload();
            alert_info_text({
                'text': "text_policy_import_result",
                'param': escape(value),
                'is_escaped': true
            });
        }
    }
    hide_waiting();
};

//calback to handle response when license has been submitted
function parseLicense(response, textStatus, xhr) {

    if (response &&
        response.result &&
        response.result.status &&
        response.result.value) {

        alert_info_text({
            text: i18n.gettext("Support license installed successfully."),
            is_escaped: true
        });

    } else {

        var message = i18n.gettext('The upload of your support and ' +
            'subscription license failed: ');

        if (response &&
            response.result &&
            response.result.error &&
            response.result.error.message) {

            message += '<br>' + escape(response.result.error.message);
        } else {
            message += i18n.gettext('Unknown error');
        }

        alert_info_text({
            'text': message,
            'type': ERROR,
            'is_escaped': true
        });

        alert_box({
            'title': i18n.gettext('License upload'),
            'text': message,
            'is_escaped': true
        });

    }

    hide_waiting();
};

function testXMLObject(xml) {
    try {
        if ($(xml).find('version').text() == "") {
            throw "Error: xml needs reparsing";
        }
        else {
            state = "successful";
            return true;
        }
    } catch (e) {
        return false;
    }
}

function import_policy() {
    show_waiting();
    $('#load_policies').ajaxSubmit({
        data: {},
        type: "POST",
        error: parsePolicyImport,
        success: parsePolicyImport,
        dataType: 'xml'
    });
    return false;
}

function load_tokenfile(type) {
    show_waiting();
    if ("aladdin-xml" == type) {
        $('#load_tokenfile_form_aladdin').ajaxSubmit({
            data: {},
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: 'xml'
        });
    }
    else if ("feitian" == type) {
        $('#load_tokenfile_form_feitian').ajaxSubmit({
            data: {},
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: 'xml'
        });
    }
    else if ("pskc" == type) {
        $('#load_tokenfile_form_pskc').ajaxSubmit({
            data: {},
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: 'xml'
        });
    }
    else if ("dpw" == type) {
        $('#load_tokenfile_form_dpw').ajaxSubmit({
            data: {},
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: "xml"
        });
    }
    else if ("dat" == type) {
        $('#load_tokenfile_form_dat').ajaxSubmit({
            data: {},
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: "dat"
        });
    }
    else if ("oathcsv" == type) {
        $('#load_tokenfile_form_oathcsv').ajaxSubmit({
            data: {},
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: "xml"
        });
    }
    else if ("yubikeycsv" == type) {
        $('#load_tokenfile_form_yubikeycsv').ajaxSubmit({
            data: {},
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: "xml"
        });
    }
    else {
        alert_info_text({
            'text': "text_import_unknown_type",
            'type': ERROR,
            'is_escaped': true
        });
    };
    return false;
}

function support_set() {
    show_waiting();
    //check for extension .pem:
    var filename = $('#license_file').val();
    var extension = /\.pem$/;
    if (extension.exec(filename)) {
        $('#set_support_form').ajaxSubmit({
            data: {},
            type: "POST",
            error: parseLicense,
            success: parseLicense,
            dataType: 'json'
        });
    } else {
        alert_info_text({
            'text': "text_import_pem",
            'type': ERROR,
            'is_escaped': true
        });
    }
    hide_waiting();
    return false;
}

function support_view() {

    // clean out old data
    $("#dialog_support_view").html("");

    $.post('/system/getSupportInfo', {},
        function (data, textStatus, XMLHttpRequest) {
            support_info = data.result.value;

            if ($.isEmptyObject(support_info)) {
                var info = "";
                info += '<h2 class="contact_info center-text">' + i18n.gettext('Professional LinOTP support and enterprise subscription') + '</h2>';
                info += sprintf(i18n.gettext('For professional LinOTP support and enterprise subscription, feel free to contact %s for support agreement purchases.'),
                    '<a href="mailto:sales@linotp.de">netgo software GmbH</a>');
                $("#dialog_support_view").html($.parseHTML(info));

            } else {
                var info = "";
                info += '<h2 class="contact_info center-text">' + i18n.gettext('Your LinOTP support subscription') + '</h2>';
                info += "<table><tbody>";
                $.map(support_info, function (value, key) {
                    if (support_license_dict.hasOwnProperty(key)) {
                        key = i18n.gettext(support_license_dict[key]);
                    }
                    if (value && value.length > 0) {
                        info += "<tr><td class='subscription_detail'>" + key + "</td><td class='subscription_detail'>" + value + "</td></tr>";
                    }
                });
                info += "</tbody></table>";
                info += "<div class='subscription_info'><br>" +
                    i18n.gettext("For support and subscription please contact us at") +
                    " <a href='https://www.linotp.de/' rel='noreferrer' target='_blank'>linotp.de</a> <br>" +
                    i18n.gettext("by phone") + " <a href='tel:0049615186086115'>+49 6151 86086-115</a> " + i18n.gettext("or email") + " <a href='mailto:support@linotp.de'>support@linotp.de</a></div>";
                $("#dialog_support_view").html($.parseHTML(info));
            }
        });
    return false;
}

/**
 * determines if some sort of welcome screen should be shown and does it
 */
function check_for_welcome_screen() {

    if (is_license_valid()) {
        return;
    }

    var serverConfig = get_server_config();
    var currenttime = new Date().getTime();

    var currentMinorVersion = parseMinorVersionNumber(g.linotp_version);

    if (!isDefinedKey(serverConfig, "welcome_screen.version")) {

        setSystemConfig({
            "welcome_screen.version": currentMinorVersion,
            "welcome_screen.last_shown": currenttime,
            "welcome_screen.opt_out": false
        });

        var title = i18n.gettext("Welcome to LinOTP");
        var text = '<p>' + i18n.gettext("Welcome to your fresh LinOTP installation.") + '</p>'
            + '<p>' + i18n.gettext("If you have questions about the setup or installation of LinOTP, please <a href='https://linotp.org/doc' target='_blank'>refer to our documentation</a>.") + '</p>'
            + '<p>' + i18n.gettext("<a href='https://linotp.de'>netgo provides LinOTP</a> as an enterprise MFA solution.") + '</p>'
            + '<p>' + i18n.gettext("If you are interested in our MFA platform using LinOTP at its core and want to know more, feel free to <a href='https://linotp.de/en/contact.html'>contact us</a>.")
            + '</p>'
            + '<br/>';
        var button = i18n.gettext("OK");

        show_welcome_screen(title, text, button);
    }
    else {
        var currentMajorVersion = parseMajorVersionNumber(g.linotp_version);
        var welcomeScreenVersion = parseMajorVersionNumber(serverConfig["welcome_screen.version"]);

        var timedelta = 1000 * 60 * 60 * 24 * 7;

        if (compareVersionNumbers(currentMajorVersion, welcomeScreenVersion) !== 0) {

            setSystemConfig({
                "welcome_screen.version": currentMinorVersion,
                "welcome_screen.last_shown": currenttime
            });

            var title = i18n.gettext("Changelog");
            var text = '<p>'
                + sprintf(i18n.gettext("Your installation of LinOTP was updated to version %s. You can find the changelog and further information about this release at:"), currentMinorVersion)
                + '</p>'
                + '<p><a href="https://www.linotp.org/resources/changelogs.html" target="_blank">https://www.linotp.org/resources/changelogs.html</a></p>'
                + '<p>' + i18n.gettext("We would be happy to receive your feedback about LinOTP.") + '</p>'
                + '<br/>'
                + '<div id="welcome-buttons">'
                + '<a class="light-text-color feedback-button" href="https://linotp.de/en/contact.html" target="_blank">' + i18n.gettext("Feedback") + '</a>'
                + '</div>';
            var button = i18n.gettext("Close");

            show_welcome_screen(title, text, button);
        }
        else if (serverConfig["welcome_screen.opt_out"].toLowerCase() !== "true" &&
            parseInt(serverConfig["welcome_screen.last_shown"]) + timedelta < currenttime) {

            setSystemConfig({
                "welcome_screen.last_shown": currenttime
            });

            var title = i18n.gettext("Thank you for using LinOTP");
            var text = '<p>' + i18n.gettext("We are pleased that you are using <a href='https://linotp.de'>LinOTP powered by netgo</a> as your MFA solution.") + '</p>'
                + '<p>' + i18n.gettext("If you are interested in our MFA platform using LinOTP at its core and want to know more, feel free to <a href='https://linotp.de/en/contact.html'>contact us</a>.")
                + '<p>' + i18n.gettext("We would be happy to receive your feedback about LinOTP.") + '</p>'
                + '<br/>'
                + '<div id="welcome-buttons">'
                + '<a class="light-text-color feedback-button" href="https://linotp.de/en/contact.html" target="_blank">' + i18n.gettext("Feedback") + '</a>'
                + '</div>';
            var button = i18n.gettext("OK");

            var dialog = show_welcome_screen(title, text, button);

            var optOutLabel =
                '<div class="ui-dialog-buttonset welcome-screen-option-buttonset">'
                + '<label><input type="checkbox" id="welcome_screen_option" name="welcome_screen_option">'
                + i18n.gettext("Do not show this reminder again")
                + '</label>'
                + '</div>';
            $(dialog)
                .parent()
                .find('.ui-dialog-buttonpane')
                .prepend(optOutLabel);
        }
    }
}

function show_welcome_screen(title, text, button_text) {
    var dialog_body =
        '<div id="welcome_screen"><br/>'
        + text
        + '<br/></div>';

    return $(dialog_body).dialog({
        title: title,
        width: 600,
        minHeight: 400,
        modal: true,
        buttons: [
            {
                text: button_text,
                id: 'welcome_screen_close',
                click: function () {
                    if ($('#welcome_screen_option').is(':checked')) {
                        setSystemConfig({
                            "welcome_screen.opt_out": true
                        });
                    }
                    $(this).dialog("close");
                }
            }
        ],
        create: function () {
            $('#welcome-buttons .newsletter-button').button({
                icons: { primary: 'ui-icon-mail-closed' },
                classes: {
                    "ui-button": "ui-corner-all"
                }
            });
            $('#welcome-buttons .feedback-button').button({
                icons: { primary: 'ui-icon-pencil' },
                classes: {
                    "ui-button": "ui-corner-all"
                }
            });
        },
        open: function () {
            $('#welcome-buttons').children().first().focus();
        }
    });
}

function load_sms_providers() {
    show_waiting();
    var params = {
        'type': 'sms',
    };
    $.get('/system/getProvider', params,
        function (data, textStatus, XMLHttpRequest) {
            smsProviders = data.result.value;

            // Set selected provider globally
            selectedSMSProvider = null;

            var providers = $('<ol id="sms_providers_select" class="select_list ui-selectable"></ol>');
            var count = 0;

            $.each(smsProviders, function (key, provider) {
                var element = '<li class="ui-widget-content"><span class="name">' + escape(key) + '</span>';
                if (provider.Default === true) {
                    element += ' <span class="default">(Default)</span>';
                }
                element += '</li>';
                providers.append(element);
                count++;
            });

            $("#button_sms_provider_edit").button("disable");
            $("#button_sms_provider_delete").button("disable");
            $("#button_sms_provider_set_default").button("disable");

            if (count > 0) {
                $('#sms_providers_list').html(providers);

                $('#sms_providers_select').selectable({
                    stop: function (event, ui) {
                        if ($("#sms_providers_select .ui-selected").length > 0) {
                            selectedSMSProvider = escape($("#sms_providers_select .ui-selected .name").html());
                            $("#button_sms_provider_edit").button("enable");
                            $("#button_sms_provider_delete").button("enable");
                            if (smsProviders[selectedSMSProvider].Default !== true) {
                                $("#button_sms_provider_set_default").button("enable");
                            }
                            else {
                                $("#button_sms_provider_set_default").button("disable");
                            }
                        }
                        else {
                            selectedSMSProvider = null;
                            $("#button_sms_provider_edit").button("disable");
                            $("#button_sms_provider_delete").button("disable");
                            $("#button_sms_provider_set_default").button("disable");
                        }
                    },
                    selected: function (event, ui) {
                        // Prevent the selection of multiple items
                        $(ui.selected).siblings().removeClass("ui-selected");
                    }
                });
            }
            else {
                $('#sms_providers_list').html("");
            };
            hide_waiting();
        });
}

function load_email_providers() {
    show_waiting();

    var params = { 'type': 'email' };
    $.post('/system/getProvider', params,
        function (data, textStatus, XMLHttpRequest) {
            emailProviders = data.result.value;

            // Set selected provider globally
            selectedEmailProvider = null;

            var providers = $('<ol id="email_providers_select" class="select_list ui-selectable"></ol>');
            var count = 0;

            $.each(emailProviders, function (key, provider) {
                var element = '<li class="ui-widget-content"><span class="name">' + escape(key) + '</span>';
                if (provider.Default === true) {
                    element += ' <span class="default">(Default)</span>';
                }
                element += '</li>';
                providers.append(element);
                count++;
            });

            $("#button_email_provider_edit").button("disable");
            $("#button_email_provider_delete").button("disable");
            $("#button_email_provider_set_default").button("disable");

            if (count > 0) {
                $('#email_providers_list').html(providers);

                $('#email_providers_select').selectable({
                    stop: function (event, ui) {
                        if ($("#email_providers_select .ui-selected").length > 0) {
                            selectedEmailProvider = escape($("#email_providers_select .ui-selected .name").html());
                            $("#button_email_provider_edit").button("enable");
                            $("#button_email_provider_delete").button("enable");
                            if (emailProviders[selectedEmailProvider].Default !== true) {
                                $("#button_email_provider_set_default").button("enable");
                            }
                            else {
                                $("#button_email_provider_set_default").button("disable");
                            }
                        }
                        else {
                            selectedEmailProvider = null;
                            $("#button_email_provider_edit").button("disable");
                            $("#button_email_provider_delete").button("disable");
                            $("#button_email_provider_set_default").button("disable");
                        }
                    },
                    selected: function (event, ui) {
                        // Prevent the selection of multiple items
                        $(ui.selected).addClass("ui-selected").siblings().removeClass("ui-selected").each(
                            function (key, value) {
                                $(value).find('*').removeClass("ui-selected");
                            }
                        );
                    }
                });
            }
            else {
                $('#email_providers_list').html("");
            };
            hide_waiting();
        });
}

function load_push_providers() {
    show_waiting();

    var params = { 'type': 'push' };
    $.post('/system/getProvider', params,
        function (data, textStatus, XMLHttpRequest) {
            pushProviders = data.result.value;

            // Set selected provider globally
            selectedPushProvider = null;

            var providers = $('<ol id="push_providers_select" class="select_list ui-selectable"></ol>');
            var count = 0;

            $.each(pushProviders, function (key, provider) {
                var element = '<li class="ui-widget-content"><span class="name">' + escape(key) + '</span>';
                if (provider.Default === true) {
                    element += ' <span class="default">(Default)</span>';
                }
                element += '</li>';
                providers.append(element);
                count++;
            });

            $("#button_push_provider_edit").button("disable");
            $("#button_push_provider_delete").button("disable");
            $("#button_push_provider_set_default").button("disable");

            if (count > 0) {
                $('#push_providers_list').html(providers);

                $('#push_providers_select').selectable({
                    stop: function (event, ui) {
                        if ($("#push_providers_select .ui-selected").length > 0) {
                            selectedPushProvider = escape($("#push_providers_select .ui-selected .name").html());
                            $("#button_push_provider_edit").button("enable");
                            $("#button_push_provider_delete").button("enable");
                            if (pushProviders[selectedPushProvider].Default !== true) {
                                $("#button_push_provider_set_default").button("enable");
                            }
                            else {
                                $("#button_push_provider_set_default").button("disable");
                            }
                        }
                        else {
                            selectedEmailProvider = null;
                            $("#button_push_provider_edit").button("disable");
                            $("#button_push_provider_delete").button("disable");
                            $("#button_push_provider_set_default").button("disable");
                        }
                    },
                    selected: function (event, ui) {
                        // Prevent the selection of multiple items
                        $(ui.selected).addClass("ui-selected").siblings().removeClass("ui-selected").each(
                            function (key, value) {
                                $(value).find('*').removeClass("ui-selected");
                            }
                        );
                    }
                });
            }
            else {
                $('#push_providers_list').html("");
            };
            hide_waiting();
        });
}

/* voice provider */
function load_voice_providers() {
    show_waiting();

    var params = { 'type': 'voice' };
    $.post('/system/getProvider', params,
        function (data, textStatus, XMLHttpRequest) {
            voiceProviders = data.result.value;

            // Set selected provider globally
            selectedPushProvider = null;

            var providers = $('<ol id="voice_providers_select" class="select_list ui-selectable"></ol>');
            var count = 0;

            $.each(voiceProviders, function (key, provider) {
                var element = '<li class="ui-widget-content"><span class="name">' + escape(key) + '</span>';
                if (provider.Default === true) {
                    element += ' <span class="default">(Default)</span>';
                }
                element += '</li>';
                providers.append(element);
                count++;
            });

            $("#button_voice_provider_edit").button("disable");
            $("#button_voice_provider_delete").button("disable");
            $("#button_voice_provider_set_default").button("disable");

            if (count > 0) {
                $('#voice_providers_list').html(providers);

                $('#voice_providers_select').selectable({
                    stop: function (event, ui) {
                        if ($("#voice_providers_select .ui-selected").length > 0) {
                            selectedVoiceProvider = escape($("#voice_providers_select .ui-selected .name").html());
                            $("#button_voice_provider_edit").button("enable");
                            $("#button_voice_provider_delete").button("enable");
                            if (voiceProviders[selectedVoiceProvider].Default !== true) {
                                $("#button_voice_provider_set_default").button("enable");
                            }
                            else {
                                $("#button_voice_provider_set_default").button("disable");
                            }
                        }
                        else {
                            selectedVoiceProvider = null;
                            $("#button_voice_provider_edit").button("disable");
                            $("#button_voice_provider_delete").button("disable");
                            $("#button_voice_provider_set_default").button("disable");
                        }
                    },
                    selected: function (event, ui) {
                        // Prevent the selection of multiple items
                        $(ui.selected).addClass("ui-selected").siblings().removeClass("ui-selected").each(
                            function (key, value) {
                                $(value).find('*').removeClass("ui-selected");
                            }
                        );
                    }
                });
            }
            else {
                $('#voice_providers_list').html("");
            };
            hide_waiting();
        });
}
/* voice provider end*/

function load_system_config() {
    show_waiting();
    $.post('/system/getConfig', {},
        function (data, textStatus, XMLHttpRequest) {
            // checkboxes this way:
            checkBoxes = new Array();
            if (data.result.value.allowSamlAttributes == "True") {
                checkBoxes.push("sys_allowSamlAttributes");
            };
            if (data.result.value.PrependPin == "True") {
                checkBoxes.push("sys_prependPin");
            };
            if (data.result.value.FailCounterIncOnFalsePin == "True") {
                checkBoxes.push("sys_failCounterInc");
            };
            if (data.result.value.AutoResync == "True") {
                checkBoxes.push("sys_autoResync");
            };
            if (data.result.value.PassOnUserNotFound == "True") {
                checkBoxes.push("sys_passOnUserNotFound");
            };
            if (data.result.value.PassOnUserNoToken == "True") {
                checkBoxes.push("sys_passOnUserNoToken");
            };
            if (data.result.value['selfservice.realmbox'] == "True") {
                checkBoxes.push("sys_realmbox");
            }
            $("input:checkbox").val(checkBoxes);

            /* *****************************************************************
             * handle the tri state token.last_access, which are
             *     False, True, or date time format
             */

            $('#token_last_access_check').prop('checked', false);
            $('#token_last_access_entry').attr({ 'disabled': true });
            $('#token_last_access_entry').val('');

            var token_last_access = data.result.value['token.last_access'];

            if (token_last_access !== undefined && token_last_access.toLowerCase() !== 'false') {

                $('#token_last_access_check').prop('checked', true);
                $('#token_last_access_entry').attr({ 'disabled': false });

                if (token_last_access.toLowerCase() !== 'true') {
                    $('#token_last_access_entry').val(token_last_access);
                }
            }

            /* ***************************************************************** */

            $('#sys_autoResyncTimeout').val(data.result.value.AutoResyncTimeout);
            $('#sys_mayOverwriteClient').val(data.result.value.mayOverwriteClient);

            if (data.result.value.splitAtSign === "False") {
                $('#sys_splitAtSign').prop('checked', false);
            } else {
                $('#sys_splitAtSign').prop('checked', true);
            };

            if (data.result.value['client.X_FORWARDED_FOR'] == "True") {
                $('#sys_x_forwarded_for').prop('checked', true);
            }
            else {
                $('#sys_x_forwarded_for').prop('checked', false);
            }

            if (data.result.value['client.FORWARDED'] == "True") {
                $('#sys_forwarded').prop('checked', true);
            } else {
                $('#sys_forwarded').prop('checked', false);
            }

            $('#sys_forwarded_proxy').val(data.result.value['client.FORWARDED_PROXY']);

            /*todo call the 'tok_fill_config.js */

            /* caching settings */
            if (data.result.value['resolver_lookup_cache.enabled'] == "True") {
                $('#sys_resolver_cache_enable').prop('checked', true);
            } else {
                $('#sys_resolver_cache_enable').prop('checked', false);
            }

            var exp = data.result.value['resolver_lookup_cache.expiration'];
            $('#sys_resolver_cache_expiration').val(exp || 123600);

            if (data.result.value['user_lookup_cache.enabled'] == "True") {
                $('#sys_user_cache_enable').prop('checked', true);
            } else {
                $('#sys_user_cache_enable').prop('checked', false);
            }
            var exp = data.result.value['user_lookup_cache.expiration'];
            $('#sys_user_cache_expiration').val(exp || 123600);
            hide_waiting();
        });
}

/*
 * click event handler for token.last_access
 *  - will be called when the last_access_check checkbox is pressed
 */
function token_last_access_constrain() {

    if ($('#token_last_access_check').is(':checked')) {
        $('#token_last_access_entry').prop('disabled', false);
    } else {
        $('#token_last_access_entry').prop('disabled', true);
    }
}

function save_system_config() {
    show_waiting();

    var allowsaml = "False";
    if ($("#sys_allowSamlAttributes").is(':checked')) {
        allowsaml = "True";
    }
    var fcounter = "False";
    if ($("#sys_failCounterInc").is(':checked')) {
        fcounter = "True";
    }
    var splitatsign = "False";
    if ($("#sys_splitAtSign").is(':checked')) {
        splitatsign = "True";
    }
    var prepend = "False";
    if ($("#sys_prependPin").is(':checked')) {
        prepend = "True";
    }
    var autoresync = "False";
    if ($('#sys_autoResync').is(':checked')) {
        autoresync = "True";
    }
    var passOUNFound = "False";
    if ($('#sys_passOnUserNotFound').is(':checked')) {
        passOUNFound = "True";
    }
    var passOUNToken = "False";
    if ($('#sys_passOnUserNoToken').is(':checked')) {
        passOUNToken = "True";
    }

    /* parse the ui elements to prepare setting the token.last_access config value */
    var token_last_access = "False";
    if ($('#token_last_access_check').is(':checked')) {
        token_last_access = "True";
        var token_last_access_entry = $('#token_last_access_entry').val();
        if (token_last_access_entry.length > 0) {
            token_last_access = token_last_access_entry;
        }
    }

    var realmbox = "False";
    if ($("#sys_realmbox").is(':checked')) {
        realmbox = "True";
    }
    var client_forward = "False";
    if ($("#sys_forwarded").is(':checked')) {
        client_forward = "True";
    }
    var client_x_forward = "False";
    if ($("#sys_x_forwarded_for").is(':checked')) {
        client_x_forward = "True";
    }

    var user_cache_enabled = "False";
    if ($("#sys_user_cache_enable").is(':checked')) {
        user_cache_enabled = "True";
    }
    var resolver_cache_enabled = "False";
    if ($("#sys_resolver_cache_enable").is(':checked')) {
        resolver_cache_enabled = "True";
    }

    var params = {
        'PrependPin': prepend,
        'FailCounterIncOnFalsePin': fcounter,
        'splitAtSign': splitatsign,
        'AutoResync': autoresync,
        'PassOnUserNotFound': passOUNFound,
        'PassOnUserNoToken': passOUNToken,
        'selfservice.realmbox': realmbox,
        'allowSamlAttributes': allowsaml,
        'client.FORWARDED': client_forward,
        'client.X_FORWARDED_FOR': client_x_forward,
        'allowSamlAttributes': allowsaml,
        'user_lookup_cache.enabled': user_cache_enabled,
        'resolver_lookup_cache.enabled': resolver_cache_enabled,
        'user_lookup_cache.enabled': user_cache_enabled,
        'token.last_access': token_last_access,
        'AutoResyncTimeout': $('#sys_autoResyncTimeout').val(),
        'mayOverwriteClient': $('#sys_mayOverwriteClient').val(),
        'totp.timeShift': $('#totp_timeShift').val(),
        'totp.timeStep': $('#totp_timeStep').val(),
        'totp.timeWindow': $('#totp_timeWindow').val(),
        'client.FORWARDED_PROXY': $('#sys_forwarded_proxy').val(),
        'user_lookup_cache.expiration': $('#sys_user_cache_expiration').val(),
        'resolver_lookup_cache.expiration': $('#sys_resolver_cache_expiration').val()
    };

    setSystemConfig(params);
}

/**
 * sends the object containing system config entries
 * to the server to save them in the database
 * @param {Object.<string, *>} values - the key value pairs representing the config to save
 */
function setSystemConfig(values) {
    $.post('/system/setConfig', values,
        function (data, textStatus, XMLHttpRequest) {
            if (data.result.status == false) {
                var message = "Error saving system configuration. Please check your configuration and your server.";
                // if a more specific server error is available use this one
                if (data.result.error && data.result.error.message)
                    message += "<br>" + escape(data.result.error.message);

                alert_info_text({
                    'text': message,
                    'type': ERROR,
                    'is_escaped': true
                });
            }
            hide_waiting();
        });
}

function test_ldap_config() {
    $('#progress_test_ldap').show();
    var url = '/admin/testresolver';
    var params = {};
    params['name'] = $('#ldap_resolvername').val();

    clientUrlFetch(url, params, processLDAPTestResponse);
}

function save_ldap_config(callback = null) {
    // Save all LDAP config
    var resolvername = $('#ldap_resolvername').val();
    var resolvertype = "ldapresolver";
    var ldap_map = {
        '#ldap_uri': 'LDAPURI',
        '#ldap_basedn': 'LDAPBASE',
        '#ldap_binddn': 'BINDDN',
        '#ldap_timeout': 'TIMEOUT',
        '#ldap_sizelimit': 'SIZELIMIT',
        '#ldap_loginattr': 'LOGINNAMEATTRIBUTE',
        '#ldap_searchfilter': 'LDAPSEARCHFILTER',
        '#ldap_userfilter': 'LDAPFILTER',
        '#ldap_mapping': 'USERINFO',
        '#ldap_uidtype': 'UIDTYPE',
        '#ldap_noreferrals': 'NOREFERRALS',
        '#ldap_enforce_tls': 'EnforceTLS',
        '#ldap_only_trusted_certs': 'only_trusted_certs',
    };
    var url = '/system/setResolver';
    var params = {};

    params['name'] = resolvername;
    params['previous_name'] = g.current_resolver_name;

    params['type'] = resolvertype;
    for (var key in ldap_map) {
        var new_key = ldap_map[key];
        var value = $(key).val();
        params[new_key] = value;
    }

    // checkboxes
    params["NOREFERRALS"] = $("#ldap_noreferrals").is(':checked') ? "True" : "False";
    params["EnforceTLS"] = $("#ldap_enforce_tls").is(':checked') ? "True" : "False";
    params["only_trusted_certs"] = $("#ldap_only_trusted_certs").is(':checked') ? "True" : "False";

    if ($('#ldap_password').val().length > 0) {
        params["BINDPW"] = $('#ldap_password').val();
    }

    show_waiting();

    $.post(url, params, function (data, textStatus, XMLHttpRequest) {
        hide_waiting();
        if (data.result.status == false) {
            alert_box({
                'title': i18n.gettext("LDAP resolver"),
                'text': "text_error_ldap",
                'param': escape(data.result.error.message),
                'type': ERROR,
                'is_escaped': true
            });
        } else {
            g.current_resolver_name = resolvername;
            originalLdapFormData = $('#form_ldapconfig').serialize();
            $('#form_ldapconfig').trigger("change");
            resolvers_load();

            if (callback) {
                callback();
            } else {
                $dialog_ldap_resolver.dialog('close');
            }
        }
    });
}


function save_http_config() {
    // Save all HTTP config
    var resolvername = $('#http_resolvername').val();
    var resolvertype = "httpresolver";

    var url = '/system/setResolver';
    var params = get_form_input('form_httpconfig');

    params['name'] = resolvername;
    params['previous_name'] = g.current_resolver_name;

    params['type'] = resolvertype;

    show_waiting();

    clientUrlFetch(url, params,
        function (xhdr, textStatus, XMLHttpRequest) {
            var resp = xhdr.responseText;
            var data = jQuery.parseJSON(resp);
            if (data.result.status == false) {
                alert_info_text("text_error_http", data.result.error.message, ERROR);
            } else {
                resolvers_load();
                $dialog_http_resolver.dialog('close');
            }
            hide_waiting();
        }
    );
    return false;
}

/*
 * set the default realm
 *
 * @param realm - as string
 */
function set_default_realm(realm) {
    var params = {
        'realm': realm,
    };

    $.post('/system/setDefaultRealm', params,
        function () {
            realms_load();
            fill_realms();
        });
}

/*
 * save the realm config from the realm edit dialog
 *
 * @param - #realm_name is extracted from form entry
 */
function save_realm_config() {
    check_license();
    var realm = $('#realm_name').val();
    show_waiting();
    var params = {
        'realm': realm,
        'resolvers': g.resolvers_in_realm_to_edit,
    };

    $.post('/system/setRealm', params,
        function (data, textStatus, XMLHttpRequest) {
            if (data.result.status == false) {
                alert_info_text({
                    'text': "text_error_realm",
                    'param': escape(data.result.error.message),
                    'type': ERROR,
                    'is_escaped': true
                });
            } else {
                fill_realms();
                realms_load();
                alert_info_text({
                    'text': "text_realm_created",
                    'param': escape(realm),
                    'is_escaped': true
                });
            }
            hide_waiting();
        });
}

function save_tokenrealm_config() {
    var tokens = get_selected_tokens();
    var realms = g.realms_of_token.join(",");
    var params = {
        'realms': realms,
    };
    for (var i = 0; i < tokens.length; ++i) {
        serial = tokens[i];
        params['serial'] = serial;

        show_waiting();

        $.post('/admin/tokenrealm', params,
            function (data, textStatus, XMLHttpRequest) {
                if (data.result.status == false) {
                    alert_info_text({
                        'text': "text_error_set_realm",
                        'param': escape(data.result.error.message),
                        'type': ERROR,
                        'is_escaped': true
                    });
                }
                else {
                    $('#token_table').flexReload();
                    $('#selected_tokens').html('');
                }
                hide_waiting();
            });
    }
}

/*
* save the passwd resolver config
*/
function save_file_config() {
    var url = '/system/setResolver';
    var resolvername = $('#file_resolvername').val();
    var resolvertype = "passwdresolver";
    var fileName = $('#file_filename').val();
    var params = {};

    params['name'] = resolvername;
    params['previous_name'] = g.current_resolver_name;

    params['type'] = resolvertype;
    params['fileName'] = fileName;
    show_waiting();
    $.post(url, params, function (data, textStatus, XMLHttpRequest) {
        hide_waiting();
        if (data.result.status == false) {
            alert_box({
                'title': i18n.gettext("File resolver"),
                'text': "text_error_save_file",
                'param': escape(data.result.error.message),
                'is_escaped': true
            });
        } else {
            resolvers_load();
            $dialog_file_resolver.dialog('close');
        }
    });
}

function test_sql_config() {
    $('#progress_test_sql').show();
    var url = '/admin/testresolver';
    var params = {};
    params['name'] = $('#sql_resolvername').val();

    clientUrlFetch(url, params, function (xhdr, textStatus) {
        var resp = xhdr.responseText;
        var obj = jQuery.parseJSON(resp);
        $('#progress_test_sql').hide();
        if (obj.result.status) {
            rows = obj.result.value.desc.rows;
            if (rows >= 0) { // show number of found users
                alert_box({
                    title: "SQL Test",
                    text: "text_sql_config_success",
                    param: escape(rows),
                    is_escaped: true
                });
            } else {
                alert_box({
                    title: "SQL Test",
                    text: "text_sql_config_fail",
                    param: escape(obj.result.value.desc.err_string),
                    is_escaped: true
                });
            }
        } else {
            alert_box({
                title: "SQL Test",
                text: escape(obj.result.error.message),
                is_escaped: true
            });
        }
    });
}

function save_sql_config(callback = null) {
    // Save all SQL config
    var resolvername = $('#sql_resolvername').val();
    var resolvertype = "sqlresolver";
    var map = {
        '#sql_database': 'Database',
        '#sql_driver': 'Driver',
        '#sql_server': 'Server',
        '#sql_port': 'Port',
        '#sql_limit': 'Limit',
        '#sql_user': 'User',
        '#sql_table': 'Table',
        '#sql_mapping': 'Map',
        '#sql_where': 'Where',
        '#sql_conparams': 'conParams',
        '#sql_encoding': 'Encoding'
    };
    var url = '/system/setResolver';
    var params = {};

    params['name'] = resolvername;
    params['previous_name'] = g.current_resolver_name;

    params['type'] = resolvertype;

    for (var key in map) {
        var value = $(key).val();
        var new_key = map[key];
        params[new_key] = value;
    }

    if ($('#sql_password').val().length > 0) {
        params["Password"] = $('#sql_password').val();
    }

    show_waiting();

    $.post(url, params, function (data, textStatus, XMLHttpRequest) {
        hide_waiting();
        if (data.result.status == false) {
            alert_box({
                'title': i18n.gettext("SQL resolver"),
                'text': "text_error_save_sql",
                'param': escape(data.result.error.message),
                'is_escaped': true
            });
        } else {
            g.current_resolver_name = resolvername;
            originalSqlFormData = $('#form_sqlconfig').serialize();
            $('#form_sqlconfig').trigger("change");
            resolvers_load();

            if (callback) {
                callback();
            } else {
                $dialog_sql_resolver.dialog('close');
            }
        }
    });
}


// ----------------------------------------------------------------
//   Realms
function realms_load() {
    g.realm_to_edit = {};
    show_waiting();
    $.post('/system/getRealms', {},
        function (data, textStatus, XMLHttpRequest) {
            var realms = '<ol id="realms_select" class="select_list" class="ui-selectable">';
            for (var realmName in data.result.value) {
                var realm = data.result.value[realmName];

                var resolvers = realm.useridresolver
                    .map(function (resolver) {
                        return resolver.split(".").pop();
                    })
                    .join(" ");

                var isDefault = realm.default && realm.default === "true";
                var isAdmin = realm.admin;

                realms += '<li class="ui-widget-content' + (isDefault ? ' default' : '') + (isAdmin ? ' admin' : '') + '">'
                    + '<span class="name">' + escape(realmName) + '</span>'
                    + ' [' + escape(resolvers) + ']'
                    + (isDefault ? ' <span class="tag" title="'
                        + i18n.gettext("This realm is used for validation and selfservice login if no realm is specified.")
                        + '">' + i18n.gettext("default ") + '</span>' : '')
                    + (isAdmin ? ' <span class="tag" title="'
                        + i18n.gettext("This realm is used to authenticate LinOTP administrators.")
                        + '">' + i18n.gettext("admin") + '</span>' : '')
                    + '</li>';
            }
            realms += '</ol>';
            $('#realm_list').html($.parseHTML(realms));
            $('#realms_select').selectable({
                stop: function () {
                    var selectedRealm = $(".ui-selected", this).first();
                    g.realm_to_edit = {
                        isDefault: selectedRealm.hasClass("default"),
                        name: escape($('.name', selectedRealm).text())
                    };
                    var realm = data.result.value[g.realm_to_edit.name];
                    if (realm.admin) {
                        $("#button_realms_delete").button('disable');
                    } else {
                        $("#button_realms_delete").button('enable');
                    }
                } // end of stop function
            }); // end of selectable

            $("#realm_list .tag").tooltip({
                position: {
                    my: "right top",
                    at: "right+10 bottom+10",
                }
            });

            hide_waiting();
        }); // end of $.post
}

function realm_ask_delete() {
    $("#realm_delete_name").html(escape(g.realm_to_edit.name));
    $dialog_realm_ask_delete.dialog('open');
}

// -----------------------------------------------------------------
//   Resolvers


function resolvers_load() {
    show_waiting();
    $.post('/system/getResolvers', {},
        function (data, textStatus, XMLHttpRequest) {
            var resolvers = '<ol id="resolvers_select" class="select_list" class="ui-selectable">';
            var count = 0;
            for (var key in data.result.value) {
                resolver = data.result.value[key];
                var e_key = escape(key);
                var e_reolver_type = escape(resolver.type);
                var managed = escape(resolver.readonly);
                var isAdmin = resolver.admin;
                resolvers += '<li class="ui-widget-content' + (managed ? " managed" : "") + (isAdmin ? ' admin' : '') + '">'
                    + '<span class="name">' + e_key + '</span> [<span class="type">' + e_reolver_type + '</span>]'
                    + (managed ? ' <span class="tag" title="'
                        + i18n.gettext("This resolver contains locally managed users, managed by LinOTP.") + ' '
                        + (isAdmin ? i18n.gettext("Manage administrators via the `linotp local-admins` CLI.")
                            : i18n.gettext("Manage users via ”Tools -> Import Users”."))
                        + '">' + i18n.gettext("managed") + '</span>' : '')
                    + (isAdmin ? ' <span class="tag" title="'
                        + i18n.gettext("This resolver is used to authenticate LinOTP administrators.")
                        + '">' + i18n.gettext("admin") + '</span>' : '')
                    + '</li>';
                count = count + 1;
            }
            resolvers += '</ol>';

            g.resolver_to_edit = null;
            $("#button_resolver_edit").button("disable");
            $("#button_resolver_duplicate").button("disable");
            $("#button_resolver_delete").button("disable");

            if (count > 0) {
                $('#resolvers_list').html(resolvers);

                $('#resolvers_select').selectable({
                    stop: function () {
                        if ($("#resolvers_select .ui-selected:not(.managed)").length > 0) {
                            $("#button_resolver_edit").button("enable");
                            $("#button_resolver_duplicate").button("enable");
                            $("#button_resolver_delete").button("enable");
                        }
                        else {
                            $("#button_resolver_edit").button("disable");
                            $("#button_resolver_duplicate").button("disable");
                            $("#button_resolver_delete").button("disable");
                        }

                        if ($("#resolvers_select .ui-selected").length > 0) {
                            g.resolver_to_edit = {
                                name: escape($("#resolvers_select .ui-selected .name").text()),
                                type: escape($("#resolvers_select .ui-selected .type").text())
                            };
                            $("#button_resolver_delete").button("enable");
                        }
                        else {
                            g.resolver_to_edit = null;
                            $("#button_resolver_delete").button("disable");
                        }
                    },
                    selected: function (event, ui) {
                        // Prevent the selection of multiple items
                        $(ui.selected).siblings().removeClass("ui-selected");
                    }
                });
            }
            else {
                $('#resolvers_list').html("");
                g.resolver_to_edit = null;
            };

            $("#resolvers_list .tag").tooltip({
                position: {
                    my: "right top",
                    at: "right+10 bottom+10",
                }
            });

            hide_waiting();
        }); // end of $.post
}


function resolver_delete() {
    var reso = $('#delete_resolver_name').html();
    var params = { 'resolver': reso };

    show_waiting();
    $.post('/system/delResolver', params,
        function (data, textStatus, XMLHttpRequest) {
            if (data.result.status == true) {
                resolvers_load();
                if (data.result.value == true)
                    alert_info_text({
                        'text': "text_resolver_delete_success",
                        'param': escape(reso),
                        'is_escaped': true
                    });
                else
                    alert_info_text({
                        'text': "text_resolver_delete_fail",
                        'param': escape(reso),
                        'type': ERROR,
                        'is_escaped': true
                    });
            }
            else {
                alert_info_text({
                    'text': "text_resolver_delete_fail",
                    'param': escape(data.result.error.message),
                    'type': ERROR,
                    'is_escaped': true
                });
            }
            hide_waiting();
        });
}

function realm_delete() {
    var realm = g.realm_to_edit.name;
    var params = { 'realm': realm };
    $.post('/system/delRealm', params,
        function (data, textStatus, XMLHttpRequest) {
            if (data.result.status == true) {
                fill_realms();
                realms_load();
                alert_info_text({
                    'text': "text_realm_delete_success",
                    'param': escape(realm),
                    'is_escaped': true
                });
            }
            else {
                alert_info_text({
                    'text': "text_realm_delete_fail",
                    'param': escape(data.result.error.message),
                    'type': ERROR,
                    'is_escaped': true
                });
            }
            hide_waiting();
        });
}

function resolver_ask_delete() {
    $('#delete_resolver_name').html(g.resolver_to_edit.name);
    $('#delete_resolver_type').html(g.resolver_to_edit.type);
    $dialog_resolver_ask_delete.dialog('open');
}

function resolver_edit_type() {
    var reso = g.resolver_to_edit.name;
    var type = g.resolver_to_edit.type;
    switch (type) {
        case "ldapresolver":
            resolver_ldap(reso, false);
            break;
        case "httpresolver":
            resolver_http(reso, false);
            break;
        case "sqlresolver":
            resolver_sql(reso, false);
            break;
        case "passwdresolver":
            resolver_file(reso, false);
            break;
    }
}

function resolver_duplicate() {
    var reso = g.resolver_to_edit.name;
    var type = g.resolver_to_edit.type;

    switch (type) {
        case "ldapresolver":
            resolver_ldap(reso, true);
            break;
        case "httpresolver":
            resolver_http(reso, true);
            break;
        case "sqlresolver":
            resolver_sql(reso, true);
            break;
        case "passwdresolver":
            resolver_file(reso, true);
            break;
    }
}

function resolver_new_type() {
    check_license();
    $dialog_ask_new_resolvertype.dialog('open');
}

/*
 * enables the tokeninfo buttons.
 * As tokeninfo HTML is read from the server via /manage/tokeninfo
 * jqeuery needs to activate the buttons after each call.
 */
function set_tokeninfo_buttons() {
    $('#ti_button_desc').button({
        icons: { primary: 'ui-icon-pencil' },
        text: false
    });
    $('#ti_button_desc').click(function () {
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="description">\
                <input id=info_value name=info_value></input>\
                ');
        translate_dialog_ti_description();
        $dialog_tokeninfo_set.dialog('open');
    });

    $('#ti_button_otplen').button({
        icons: { primary: 'ui-icon-pencil' },
        text: false
    });
    $('#ti_button_otplen').click(function () {
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="otpLen">\
            <select id=info_value name=info_value>\
            <option value=6>6 digits</option>\
            <option value=8>8 digits</option>\
            </select>');
        translate_dialog_ti_otplength();
        $dialog_tokeninfo_set.dialog('open');
    });

    $('#ti_button_sync').button({
        icons: { primary: 'ui-icon-pencil' },
        text: false
    });
    $('#ti_button_sync').click(function () {
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="syncWindow">\
            <input id=info_value name=info_value></input>\
            ');
        translate_dialog_ti_syncwindow();
        $dialog_tokeninfo_set.dialog('open');
    });


    $('#ti_button_countwindow').button({
        icons: { primary: 'ui-icon-pencil' },
        text: false
    });
    $('#ti_button_countwindow').click(function () {
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="counterWindow">\
                    <input id=info_value name=info_value></input>\
                    ');
        translate_dialog_ti_counterwindow();
        $dialog_tokeninfo_set.dialog('open');
    });

    $('#ti_button_maxfail').button({
        icons: { primary: 'ui-icon-pencil' },
        text: false
    });
    $('#ti_button_maxfail').click(function () {
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="maxFailCount">\
            <input id=info_value name=info_value></input>\
            ');
        translate_dialog_ti_maxfailcount();
        $dialog_tokeninfo_set.dialog('open');
    });

    $('#ti_button_failcount').button({
        icons: { primary: 'ui-icon-arrowrefresh-1-s' },
        text: false
        //label: "Reset Failcounter"
    });
    $('#ti_button_failcount').click(function () {
        serial = get_selected_tokens()[0];
        clientUrlFetchSync("/admin/reset", { "serial": serial });
        tokeninfo_redisplay();
    });

    $('#ti_button_hashlib').button({
        icons: { primary: 'ui-icon-locked' },
        text: false,
        label: "hashlib"
    });
    $('#ti_button_hashlib').click(function () {
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="hashlib">\
            <select id=info_value name=info_value>\
            <option value=sha1>sha1</option>\
            <option value=sha256>sha256</option>\
            </select>');
        translate_dialog_ti_hashlib();
        $dialog_tokeninfo_set.dialog('open');
    });

    $('#ti_button_expiration').button({
        icons: { primary: 'ui-icon-calendar' }
    }).click(function () {
        $().dialog('close');
        openExpirationDialog();
    });

    $('#ti_button_mobile_phone').button({
        icons: { primary: 'ui-icon-signal' },
        text: false,
        label: "mobile phone"
    });
    $('#ti_button_mobile_phone').click(function () {
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="phone">\
            <input id=info_value name=info_value></input>\
            ');
        translate_dialog_ti_phone();
        $dialog_tokeninfo_set.dialog('open');
    });

    /*
     * time buttons
     */
    $('#ti_button_time_window').button({
        icons: { primary: 'ui-icon-newwin' },
        text: false,
        label: "time window"
    });
    $('#ti_button_time_window').click(function () {
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="timeWindow">\
            <input id=info_value name=info_value></input>\
            ');
        translate_dialog_ti_timewindow();
        $dialog_tokeninfo_set.dialog('open');
    });

    $('#ti_button_time_shift').button({
        icons: { primary: 'ui-icon-seek-next' },
        text: false,
        label: "time shift"
    });
    $('#ti_button_time_shift').click(function () {
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="timeShift">\
            <input id=info_value name=info_value></input>\
            ');
        translate_dialog_ti_timeshift();
        $dialog_tokeninfo_set.dialog('open');
    });

    $('#ti_button_time_step').button({
        icons: { primary: 'ui-icon-clock' },
        text: false,
        label: "time step"
    });
    $('#ti_button_time_step').click(function () {
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="timeStep">\
            <select id=info_value name=info_value>\
            <option value=30>30 seconds</option>\
            <option value=60>60 seconds</option>\
            </select>');
        translate_dialog_ti_timestep();
        $dialog_tokeninfo_set.dialog('open');
    });

}

/*
 * enables the tokeninfo buttons.
 * As tokeninfo HTML is read from the server via /manage/tokeninfo
 * jqeuery needs to activate the buttons after each call.
 */
function tokenbuttons() {
    $('#button_tokenrealm').button({
        icons: {
            primary: 'ui-icon-home'
        }
    });
    $('#button_getmulti').button({
        icons: {
            primary: 'ui-icon-question'
        }
    });
    $('#button_losttoken').button({
        icons: {
            primary: 'ui-icon-notice'
        }
    });
    $("#button_resync").button({
        icons: {
            primary: 'ui-icon-refresh'
        }
    });
    $('#button_tokeninfo').button({
        icons: {
            primary: 'ui-icon-info'
        }
    });

    disable_all_buttons();

    var $dialog_losttoken = $('#dialog_lost_token').dialog({
        autoOpen: false,
        title: 'Lost Token',
        resizeable: false,
        width: 400,
        modal: true,
        buttons: {
            'Get Temporary Token': {
                click: function () {
                    var token_type = $('#dialog_lost_token select').val();
                    if (token_type == "password_token") {
                        token_losttoken('password');
                    }
                    if (token_type == "email_token") {
                        token_losttoken('email');
                    }
                    if (token_type == "sms_token") {
                        token_losttoken('sms');
                    }
                    $(this).dialog('close');
                },
                id: "button_losttoken_ok",
                text: i18n.gettext("Get Temporary Token")
            },
            'Cancel': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_losttoken_cancel",
                text: i18n.gettext("Cancel")
            }
        },
        open: function () {
            /* get_selected_tokens() returns a list of tokens.
             * We can only handle one selected token (token == 1).
             */
            var tokens = get_selected_tokens();
            if (tokens.length == 1) {
                $("#dialog_lost_token select option[value=email_token]").
                    attr('disabled', 'disabled');
                $("#dialog_lost_token select option[value=sms_token]").
                    attr('disabled', 'disabled');

                // as the spass token has only a password, it could only be
                // replaced by a pw token
                if (get_token_type() != 'spass') {
                    var token_string = tokens[0];
                    var user_info = get_token_owner(tokens[0]);
                    if ('email' in user_info && "" != user_info['email']) {
                        $("#dialog_lost_token select option[value=email_token]").
                            removeAttr('disabled');
                    }
                    if ('mobile' in user_info && "" != user_info['mobile']) {
                        $("#dialog_lost_token select option[value=sms_token]").
                            removeAttr('disabled');
                    }
                }
                $("#dialog_lost_token select option[value=select_token]").
                    attr('selected', true);
                $('#lost_token_serial').html(escape(token_string));

                $(this).dialog_icons();
                translate_dialog_lost_token();
            } else {
                $(this).dialog('close');
            }
        }
    });
    $('#button_losttoken').click(function () {
        $('#dialog_lost_token_select').prop('selectedIndex', 0);
        $dialog_losttoken.dialog('open');
    });


    var $dialog_resync_token = $('#dialog_resync_token').dialog({
        autoOpen: false,
        title: 'Resync Token',
        resizeable: false,
        width: 400,
        modal: true,
        buttons: {
            'Resync': {
                click: function () {
                    token_resync();
                    $(this).dialog('close');
                },
                id: "button_resync_resync",
                text: "Resync"
            },
            Cancel: {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_resync_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            tokens = get_selected_tokens();
            token_string = tokens.join(", ");
            /* delete otp values in dialog */
            $("#otp1").val("");
            $("#otp2").val("");
            $('#tokenid_resync').html(escape(token_string));

            $(this).dialog_icons();
            translate_dialog_resync_token();
        }
    });
    $('#button_resync').click(function () {
        $dialog_resync_token.dialog('open');
        return false;
    });


    $('#button_tokeninfo').click(function () {
        var tokeninfo = token_info();
        if (false != tokeninfo) {
            var pHtml = $.parseHTML(tokeninfo);
            $dialog_token_info.html(pHtml);
            buttons = {
                Close: {
                    click: function () {
                        $(this).dialog('close');
                    },
                    id: "button_ti_close",
                    text: "Close"
                }
            };
            $dialog_token_info.dialog('option', 'buttons', buttons);
            $dialog_token_info.dialog('open');

            set_tokeninfo_buttons();
        }
        /* event.preventDefault(); */
        return false;
    }
    );

    $dialog_edit_tokenrealm = $('#dialog_edit_tokenrealm').dialog({
        autoOpen: false,
        title: 'Edit Realms of Token',
        width: 600,
        modal: true,
        maxHeight: 400,
        buttons: {
            'Cancel': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_tokenrealm_cancel",
                text: "Cancel"
            },
            'Save': {
                click: function () {
                    save_tokenrealm_config();
                    $(this).dialog('close');
                },
                id: "button_tokenrealm_save",
                text: "Set Realm"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_dialog_token_realm();
        }
    });

    var $dialog_getmulti = $('#dialog_getmulti').dialog({
        autoOpen: false,
        title: 'Get OTP values',
        resizeable: false,
        width: 400,
        modal: true,
        buttons: {
            'Get OTP values': {
                click: function () {
                    var serial = get_selected_tokens()[0];
                    var count = $('#otp_values_count').val();
                    window.open('/gettoken/getmultiotp?serial=' + serial + '&count=' + count + '&view=1', 'getotp_window', "status=1,toolbar=1,menubar=1");
                    $(this).dialog('close');
                },
                id: "button_getmulti_ok",
                text: "Get OTP values"
            },
            Cancel: {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_getmulti_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            token_string = get_selected_tokens()[0];
            $('#tokenid_getmulti').html(escape(token_string));

            $(this).dialog_icons();
            translate_dialog_getmulti();
        }
    });
    $('#button_getmulti').click(function () {
        $dialog_getmulti.dialog('open');
    });

    $('#button_tokenrealm').click(function (event) {
        var tokens = get_selected_tokens();
        var token_string = tokens.join(", ");
        g.realms_of_token = Array();

        // get all realms the admin is allowed to view
        var realms = '';
        $.post('/system/getRealms', {},
            function (data, textStatus, XMLHttpRequest) {
                realms = '<ol id="tokenrealm_select" class="select_list" class="ui-selectable">';
                for (var key in data.result.value) {
                    var klass = 'class="ui-widget-content"';
                    var e_key = escape(key);
                    realms += '<li ' + klass + '>' + e_key + '</li>';
                }
                realms += '</ol>';

                $('#tokenid_realm').html(escape(token_string));
                $('#realm_name').val(token_string);
                $('#token_realm_list').html(realms);

                $('#tokenrealm_select').selectable({
                    stop: function () {
                        $(".ui-selected", this).each(function () {
                            // fill realms of token
                            var index = $("#tokenrealm_select li").index(this);
                            var realm = escape($(this).html());
                            g.realms_of_token.push(realm);

                        }); // end of stop function
                    } // end stop function
                }); // end of selectable
            }); // end of $.post
        if (tokens.length === 0) {
            alert_box({
                'title': i18n.gettext("Set Token Realm"),
                'text': i18n.gettext("Please select the token first."),
                'is_escaped': true
            });
        } else {
            $dialog_edit_tokenrealm.dialog('open');
        }
        return false;
    });
}

// =================================================================
// =================================================================
// Document ready
// =================================================================
// =================================================================

$(document).ready(function () {
    document.getElementById("wrap").classList.remove('page-load');

    // initialize the logout button first to prevent a deadlock
    // where the user can no longer logout
    $('#login-status-logout').click(logout);

    $("#alert_box").dialog({
        autoOpen: false,
        modal: true,
        buttons: {
            Ok: function () {
                $(this).dialog("close");
            }
        }
    });


    // load the logged in admin user info to show its name
    $.ajax({ url: '/manage/context' }).then(function (response) {
        var user = response.detail.user;
        $(".admin_user").text(
            user.username + "@" + user.realm + " (" + user.resolver + ")"
        );
    });

    // load the server config
    var server_config;
    try {
        server_config = get_server_config();
    } catch (e) {
        // the alert_box dialog needs to be prepared here to be able to show the
        // error message this early.
        alert_box({
            'title': i18n.gettext("Configuration error"),
            'text': escape(e),
            'is_escaped': true
        });
        return;
    }

    // set linotp version to global object as dom is loaded now
    g.linotp_version = $('#linotp_version').text();

    $("button").button();

    // install handler for https certificate entry field
    $('#http_uri').keyup(http_resolver_https);

    $('ul.sf-menu').superfish({
        delay: 0,
        speed: 'fast'
    });

    // Button functions
    $('#button_assign').click(function (event) {
        token_assign();
        event.preventDefault();
    });

    $('#button_enable').click(function (event) {
        token_enable();
        //event.preventDefault();
        return false;
    });

    $('#button_disable').click(function (event) {
        token_disable();
        event.preventDefault();
    });

    $('#button_resetcounter').click(function (event) {
        token_reset();
        event.preventDefault();
    });

    $('#button_setexpiration').click(function (e) {
        openExpirationDialog();
    });

    /* register the token.last_access click event handler for the checkbox*/
    $("#token_last_access_check").click(
        function (event) {
            token_last_access_constrain();
        }
    );

    // Set icons for buttons
    $('body').enableUIComponents();

    // Info box
    $('.button_info_text').click(function () {
        $(this).parent().hide('blind', {}, 500, toggle_close_all_link);
    });


    /*****************************************************************************************
     * Realms editing dialog
     */
    // there's the gallery and the trash
    var $gallery = $('#gallery'), $trash = $('#trash');

    // let the gallery items be draggable
    $('li', $gallery).draggable({
        cancel: 'a.ui-icon',// clicking an icon won't initiate dragging
        revert: 'invalid', // when not dropped, the item will revert back to its initial position
        containment: $('#demo-frame').length ? '#demo-frame' : 'document', // stick to demo-frame if present
        helper: 'clone',
        cursor: 'move'
    });

    // let the trash be droppable, accepting the gallery items
    $trash.droppable({
        accept: '#gallery > li',
        activeClass: 'ui-state-highlight',
        drop: function (ev, ui) {
            deleteImage(ui.draggable);
        }
    });

    // let the gallery be droppable as well, accepting items from the trash
    $gallery.droppable({
        accept: '#trash li',
        activeClass: 'custom-state-active',
        drop: function (ev, ui) {
            recycleImage(ui.draggable);
        }
    });

    $dialog_edit_realms = $('#dialog_edit_realms').dialog({
        autoOpen: false,
        title: 'Edit Realm',
        width: 600,
        modal: true,
        maxHeight: 400,
        buttons: {
            'Cancel': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_editrealms_cancel",
                text: "Cancel"
            },
            'Save': {
                click: function () {
                    if ($("#form_realmconfig").valid()) {
                        if (!g.resolvers_in_realm_to_edit.length) {
                            alert_box({
                                'title': i18n.gettext("Cannot save realm"),
                                'text': i18n.gettext("Please select at least one UserIdResolver from the list"),
                                'is_escaped': true
                            });
                            return;
                        }
                        /* first check if there is at least one resolver selected */
                        var resolvers = g.resolvers_in_realm_to_edit.split(',');
                        if (resolvers.length == 1 &&
                            resolvers[0].length == 0) {
                            alert_box({
                                'title': i18n.gettext("No resolver selected"),
                                'text': i18n.gettext("Please select at least one resolver from the resolver list."),
                                'is_escaped': true
                            });

                        } else {
                            save_realm_config();
                            $(this).dialog('close');
                        }
                    }
                },
                id: "button_editrealms_save",
                text: "Save"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_dialog_realm_edit();
        }
    });

    /**********************************************************************
    * Temporary token dialog
    */
    $dialog_view_temporary_token = $('#dialog_view_temporary_token').dialog({
        autoOpen: false,
        resizeable: true,
        width: 400,
        modal: false,
        buttons: {
            Close: {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_view_temporary_token_close",
                text: i18n.gettext("Close")
            },
        },
        open: function () {
            translate_dialog_view_temptoken();
        }
    });
    /***********************************************
     * Special resolver dialogs.
     */
    $dialog_resolver_ask_delete = $('#dialog_resolver_ask_delete').dialog({
        autoOpen: false,
        title: 'Deleting resolver',
        width: 600,
        height: 500,
        modal: true,
        buttons: {
            'Delete': {
                click: function () {
                    resolver_delete();
                    $(this).dialog('close');
                },
                id: "button_resolver_ask_delete_delete",
                text: "Delete"
            },
            "Cancel": {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_resolver_ask_delete_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_dialog_resolver_ask_delete();
        }
    });

    var dialog_resolver_create_config = {
        autoOpen: false,
        title: 'Creating a new UserIdResolver',
        width: 600,
        height: 500,
        modal: true,
        buttons: {
            'Cancel': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_new_resolver_type_cancel",
                text: "Cancel"
            },
            'LDAP': {
                click: function () {
                    // calling with no parameter, creates a new resolver
                    resolver_ldap("", false);
                    $(this).dialog('close');
                },
                id: "button_new_resolver_type_ldap",
                text: "LDAP"

            },
            'SQL': {
                click: function () {
                    // calling with no parameter, creates a new resolver
                    resolver_sql("", false);
                    $(this).dialog('close');
                },
                id: "button_new_resolver_type_sql",
                text: "SQL"
            },
            'Flatfile': {
                click: function () {
                    // calling with no parameter, creates a new resolver
                    resolver_file("", false);
                    $(this).dialog('close');
                },
                id: "button_new_resolver_type_file",
                text: "Flatfile"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_dialog_resolver_create();
        }
    };

    if (server_config['httpresolver_active'] == "True") {
        dialog_resolver_create_config.buttons.HTTP = {
            click: function () {
                // calling with no parameter, creates a new resolver
                resolver_http("", false);
                $(this).dialog('close');
            },
            id: "button_new_resolver_type_http",
            text: "HTTP"
        };
    }

    $dialog_ask_new_resolvertype = $('#dialog_resolver_create').dialog(dialog_resolver_create_config);

    $dialog_import_policy = $('#dialog_import_policy').dialog({
        autoOpen: false,
        title: 'Import policy file',
        width: 600,
        modal: true,
        buttons: {
            'import policy file': {
                click: function () {
                    import_policy();
                    $(this).dialog('close');
                },
                id: "button_policy_load",
                text: "Import policy file"
            },
            Cancel: {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_policy_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_import_policy();
        }
    });


    $dialog_ldap_resolver = $('#dialog_ldap_resolver').dialog({
        autoOpen: false,
        title: 'LDAP Resolver',
        width: 700,
        modal: true,
        buttons: {
            'Test': {
                click: function () {
                    if ($("#form_ldapconfig").valid()) {
                        if ($("#button_test_ldap").data("save-resolver")) {
                            save_ldap_config(function () {
                                test_ldap_config();
                            });
                        } else {
                            test_ldap_config();
                        }
                    }
                },
                id: "button_test_ldap",
                icon: "ui-icon-check",
                text: i18n.gettext("Test connection")
            },
            'Cancel': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_ldap_resolver_cancel",
                text: "Cancel"
            },
            'Save': {
                click: function () {
                    if ($("#form_ldapconfig").valid()) {
                        save_ldap_config();
                    }
                },
                id: "button_ldap_resolver_save",
                text: "Save"
            }
        },
        open: function () {
            // fix table after the browser balances the widths
            $("table tr:first-child td", this).each(function () {
                $(this).css("width", $(this).width());
            });

            $(this).dialog_icons();
        },
        close: function () {
            $("#form_ldapconfig").off("change");
        }
    });

    $('#button_preset_ad').click(function (event) {
        $('#ldap_loginattr').val('sAMAccountName');
        $('#ldap_searchfilter').val('(sAMAccountName=*)(objectClass=user)');
        $('#ldap_userfilter').val('(&(sAMAccountName=%s)(objectClass=user))');
        $('#ldap_mapping').val('{ "username": "sAMAccountName", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }');
        $('#ldap_uidtype').val('objectGUID');

        $('#form_ldapconfig').trigger("change");
    });
    $('#button_preset_ldap').click(function (event) {
        $('#ldap_loginattr').val('uid');
        $('#ldap_searchfilter').val('(uid=*)(objectClass=inetOrgPerson)');
        $('#ldap_userfilter').val('(&(uid=%s)(objectClass=inetOrgPerson))');
        $('#ldap_mapping').val('{ "username": "uid", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }');
        $('#ldap_uidtype').val('entryUUID');

        $('#form_ldapconfig').trigger("change");
    });


    $dialog_http_resolver = $('#dialog_http_resolver').dialog({
        autoOpen: false,
        title: 'HTTP Resolver',
        width: 700,
        modal: true,
        buttons: {
            'Cancel': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_http_resolver_cancel",
                text: "Cancel"
            },
            'Save': {
                click: function () {
                    if ($("#form_httpconfig").valid()) {
                        save_http_config();
                    }
                    else {
                        // get error list
                        var error = $("#form_httpconfig").validate().errorList[0];
                        if (error !== undefined) {
                            // open tab that contains the first faulty input if it is hidden in another tab
                            var tab_id = $(error.element.closest(".ui-tabs-panel")).attr("id");
                            if (tab_id !== undefined) {
                                var index = $('#http_setting_tabs a[href="#' + tab_id + '"]').parent().index();
                                $("#http_setting_tabs").tabs("option", "active", index);
                            }
                            $(error.element).focus();
                        }
                    }

                },
                id: "button_http_resolver_save",
                text: "Save"
            }
        },
        open: function () {
            http_resolver_https();

            // fix table after the browser balances the widths
            $("table tr:first-child td", this).each(function () {
                $(this).css("width", $(this).width());
            });

            $(this).dialog_icons();
        }
    });

    $('#button_test_http').click(function (event) {
        $('#progress_test_http').show();

        var params = get_form_input("form_httpconfig");

        var url = '/admin/testresolver';
        params['type'] = 'http';
        params['previous_name'] = g.current_resolver_name;

        clientUrlFetch(url, params, function (xhdr, textStatus) {
            var resp = xhdr.responseText;
            var obj = jQuery.parseJSON(resp);
            $('#progress_test_http').hide();
            if (obj.result.status == true) {
                result = obj.result.value.result;
                if (result.lastIndexOf("success", 0) === 0) {
                    var limit = "";
                    // show number of found users
                    var userarray = obj.result.value.desc;
                    var usr_msg = sprintf(i18n.gettext("Number of users found: %d"), userarray.length);
                    var msg = i18n.gettext("Connection Test: successful") +
                        "<p>" + usr_msg + "</p><p class='hint'>" + limit + "</p>";
                    alert_box({
                        'title': i18n.gettext("HTTP Connection Test"),
                        'text': msg,
                        'is_escaped': true
                    });
                }
                else {
                    alert_box({
                        'title': i18n.gettext("HTTP Test"),
                        'text': obj.result.value.desc,
                        'is_escaped': true
                    });
                }
            }
            else {
                alert_box({
                    'title': i18n.gettext("HTTP Test"),
                    'text': obj.result.error.message,
                    'is_escaped': true
                });
            }
            return false;
        });
        return false;
    });

    $dialog_sql_resolver = $('#dialog_sql_resolver').dialog({
        autoOpen: false,
        title: 'SQL Resolver',
        width: 700,
        modal: true,
        buttons: {
            'Test': {
                click: function () {
                    if ($("#form_sqlconfig").valid()) {
                        if ($("#button_test_sql").data("save-resolver")) {
                            save_sql_config(function () {
                                test_sql_config();
                            });
                        } else {
                            test_sql_config();
                        }
                    }
                },
                id: "button_test_sql",
                icon: "ui-icon-check",
                text: i18n.gettext("Test connection")
            },
            'Cancel': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_resolver_sql_cancel",
                text: "Cancel"
            },
            'Save': {
                click: function () {
                    if ($("#form_sqlconfig").valid()) {
                        save_sql_config();
                    }
                },
                id: "button_resolver_sql_save",
                text: "Save"
            }
        },
        open: function () {
            // fix table after the browser balances the widths
            $("table tr:first-child td", this).each(function () {
                $(this).css("width", $(this).width());
            });

            $(this).dialog_icons();
        },
        close: function () {
            $("#form_sqlconfig").off("change");
        }
    });


    $dialog_file_resolver = $('#dialog_file_resolver').dialog({
        autoOpen: false,
        title: 'File Resolver',
        width: 700,
        modal: true,
        maxHeight: 500,
        buttons: {
            'Cancel': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_resolver_file_cancel",
                text: "Cancel"
            },
            'Save': {
                click: function () {
                    if ($("#form_fileconfig").valid()) {
                        save_file_config();
                    }
                },
                id: "button_resolver_file_save",
                text: "Save"
            }
        },
        open: function () {
            // fix table after the browser balances the widths
            $("table tr:first-child td", this).each(function () {
                $(this).css("width", $(this).width());
            });

            $(this).dialog_icons();
        }
    });


    $dialog_resolvers = $('#dialog_resolvers').dialog({
        autoOpen: false,
        title: 'Resolvers',
        width: 600,
        height: 500,
        modal: true,
        buttons: {
            'New': {
                click: function () {
                    resolver_new_type();
                    resolvers_load();
                },
                id: "button_resolver_new",
                text: "New"
            },
            'Edit': {
                click: function () {
                    resolver_edit_type();
                    resolvers_load();
                },
                id: "button_resolver_edit",
                text: "Edit"
            },
            'Duplicate': {
                click: function () {
                    resolver_duplicate();
                    resolvers_load();
                },
                id: "button_resolver_duplicate",
                text: "Duplicate"
            },
            'Delete': {
                click: function () {
                    resolver_ask_delete();
                    resolvers_load();
                },
                id: "button_resolver_delete",
                text: "Delete"
            },
            'Close': {
                click: function () {
                    $(this).dialog('close');
                    var resolvers = get_resolvers();
                    if (resolvers.length > 0) {
                        var realms = get_realms();
                        if (realms.length == 0) {
                            $('#text_no_realm').dialog('open');
                        }
                    }
                },
                id: "button_resolver_close",
                text: "Close"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_dialog_resolvers();
        }
    });
    $('#menu_edit_resolvers').click(function () {
        resolvers_load();
        $dialog_resolvers.dialog('open');
    });


    /**************************************************
     *  Tools
     */
    $dialog_tools_getserial = create_tools_getserial_dialog();
    $('#menu_tools_getserial').click(function () {
        _fill_realms($('#tools_getserial_realm'), 1);
        $dialog_tools_getserial.dialog('open');
    });

    $dialog_tools_copytokenpin = create_tools_copytokenpin_dialog();
    $('#menu_tools_copytokenpin').click(function () {
        //_fill_realms($('#tools_getserial_realm'),1)
        $dialog_tools_copytokenpin.dialog('open');
    });

    $dialog_tools_checkpolicy = create_tools_checkpolicy_dialog();
    $('#menu_tools_checkpolicy').click(function () {
        $dialog_tools_checkpolicy.dialog('open');
        $('#cp_allowed').hide();
        $('#cp_forbidden').hide();
        $('#cp_policy').html("");
    });

    var $dialog_tools_exporttoken = create_tools_exporttoken_dialog();
    $('#menu_tools_exporttoken').click(function () {
        $dialog_tools_exporttoken.dialog('open');
    });

    var $dialog_tools_exportaudit = create_tools_exportaudit_dialog();
    $('#menu_tools_exportaudit').click(function () {
        $dialog_tools_exportaudit.dialog('open');
    });

    var $dialog_tools_importusers = create_tools_importusers_dialog();
    $('#menu_tools_importusers').click(function () {
        $dialog_tools_importusers.dialog('open');
    });

    var $dialog_tools_migrateresolver = create_tools_migrateresolver_dialog();
    $('#menu_tools_migrateresolver').click(function () {
        //_fill_realms($('#tools_getserial_realm'),1)
        _fill_resolvers($('#copy_to_resolver'));
        _fill_resolvers($('#copy_from_resolver'));
        $dialog_tools_migrateresolver.dialog('open');
    });


    /************************************************************
     * Enrollment Dialog with response url
     *
     */

    $dialog_show_enroll_url = $('#dialog_show_enroll_url').dialog({
        autoOpen: false,
        title: 'token enrollment',
        width: 750,
        modal: false,
        buttons: {
            'OK': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_show_enroll_ok",
                text: "Ok"
            }
        },
        open: function () {
            translate_dialog_show_enroll_url();
        }
    });
    /************************************************************
     * Realm Dialogs
     *
     */
    $dialog_realm_ask_delete = $('#dialog_realm_ask_delete').dialog({
        autoOpen: false,
        title: 'Deleting realm',
        width: 600,
        modal: true,
        buttons: {
            'Delete': {
                click: function () {
                    $(this).dialog('close');
                    show_waiting();
                    realm_delete();
                },
                id: "button_realm_ask_delete_delete",
                text: "Delete"
            },
            Cancel: {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_realm_ask_delete_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_dialog_realm_ask_delete();
        }
    });

    $dialog_realms = $('#dialog_realms').dialog({
        autoOpen: false,
        title: 'Realms',
        width: 600,
        height: 500,
        modal: true,
        buttons: {
            'New': {
                click: function () {
                    realm_modify('');
                },
                id: "button_realms_new",
                text: "New"
            },
            'Edit': {
                click: function () {
                    realm_modify(g.realm_to_edit.name);
                },
                id: "button_realms_edit",
                text: "Edit"
            },
            'Delete': {
                click: realm_ask_delete,
                id: "button_realms_delete",
                text: "Delete"
            },
            'Close': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_realms_close",
                text: "Close"
            },
            'Set Default': {
                click: function () {
                    if (!g.realm_to_edit.isDefault) {
                        set_default_realm(g.realm_to_edit.name);
                    }
                    else {
                        alert_info_text({
                            'text': "text_already_default_realm",
                            "type": ERROR,
                            'is_escaped': true
                        });
                    }
                },
                id: "button_realms_setdefault",
                text: "Set Default"
            },
            'Clear Default': {
                click: function () {
                    $.post('/system/setDefaultRealm', {},
                        function () {
                            realms_load();
                            fill_realms();
                        });
                },
                id: "button_realms_cleardefault",
                text: "Clear Default"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_dialog_realms();
        }
    });
    $('#menu_edit_realms').click(function () {
        realms_load();
        $dialog_realms.dialog('open');
    });

    /*********************************************************************
     * Token config
     */

    var $tokenConfigCallbacks = {};
    var $tokenConfigInbacks = {};


    var $dialog_token_config = $('#dialog_token_settings').dialog({
        autoOpen: false,
        title: 'Token Config',
        width: 900,
        modal: true,
        buttons: {
            'Save config': {
                click: function () {
                    var validation_fails = "";
                    $('#dialog_token_settings').find('form').each(
                        function (index) {
                            var attr = $(this).closest("form").closest("div").attr('id');
                            var tt = attr.split("_")[0];

                            if ($.inArray(tt, $token_config_changed) !== -1) {
                                var valid = $(this).valid();
                                if (valid != true) {
                                    formName = $(this).find('legend').text();
                                    if (formName.length == 0) {
                                        formName = $(this).find('label').first().text();
                                    }
                                    validation_fails = validation_fails +
                                        "<li>" + escape(jQuery.trim(formName)) + "</li>";
                                }
                            }
                        }
                    );
                    if (validation_fails.length > 0) {
                        alert_box({
                            'title': i18n.gettext("Form Validation Error"),
                            'text': "text_form_validation_error1",
                            'param': validation_fails,
                            'is_escaped': true
                        });
                    }
                    else {
                        save_token_config();
                        dialog_force_close = true;
                        $(this).dialog('close');
                    }
                },
                id: "button_token_save",
                text: "Save Token config"
            },
            Cancel: {
                click: function () {
                    $dialog_token_config.dialog('close');
                },
                id: "button_token_cancel",
                text: "Cancel"
            }
        },
        open: function (event, ui) {

            load_token_config();

            /**
             * we reset all tab labels to not contain the leading star, which shows
             * something has changed before
             */
            var tabs = $('#tab_token_settings li a').each(function () {
                var label = $(this).text().replace("* ", "");
                $(this).text(label);
            });

            $token_config_changed = [];
            dialog_force_close = false;

            /* sort token config tabs */
            sortChildsOfElement("#token_tab_index");

            $(this).dialog_icons();
            translate_token_settings();
        },
        beforeClose: function (event, ui) {
            if (dialog_force_close != true && $token_config_changed.length !== 0) {
                var dialog_name = i18n.gettext("Token Config");
                var defer = confirm_cancel_dialog(dialog_name);

                // if dialog should really be closed, do it!
                defer.done(function () {
                    dialog_force_close = true;
                    $dialog_token_config.dialog('close');
                });
                return false;
            }
            else {
                return true;
            }
        }
    });
    $('#tab_token_settings').tabs();

    $("#form_default_token_config").validate({
        ignoreTitle: true,
        rules: {
            default_token_maxFailCount: {
                required: true,
                min: 1,
                max: 100,
                number: true
            },
            default_token_countWindow: {
                required: true,
                min: 10,
                max: 100,
                number: true
            },
            default_token_syncWindow: {
                required: true,
                min: 100,
                max: 9999,
                number: true
            },
            default_token_challengeTimeout: {
                required: true,
                min: 60,
                max: 600,
                number: true
            }
        }
    });

    /*********************************************************************
     * SMS Provider config
     */

    var $dialog_sms_provider_config = $('#dialog_sms_providers').dialog({
        autoOpen: false,
        title: 'SMS Provider Config',
        dialogClass: "dialog-sms-provider",
        width: 600,
        maxHeight: 600,
        minHeight: 300,
        modal: true,
        buttons: {
            'New': {
                click: function () {
                    sms_provider_form_dialog("");
                },
                id: "button_sms_provider_new",
                text: "New"
            },
            'Edit': {
                click: function () {
                    if (selectedSMSProvider) {
                        sms_provider_form_dialog(selectedSMSProvider);
                    }
                },
                id: "button_sms_provider_edit",
                text: "Edit"
            },
            'Delete': {
                click: function () {
                    if (selectedSMSProvider) {
                        $('#dialog_sms_provider_delete').dialog("open");
                    }
                },
                id: "button_sms_provider_delete",
                text: "Delete"
            },
            'Close': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_sms_providers_close",
                text: "Close"
            }
        },
        open: function (event, ui) {
            $('.ui-dialog :button', this).blur();

            $(this).dialog_icons();
            translate_dialog_sms_providers();
        }
    });

    $dialog_sms_provider_edit = $('#dialog_sms_provider_edit').dialog({
        autoOpen: false,
        title: 'SMS Provider',
        width: 600,
        modal: true,
        buttons: {
            'Cancel': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_sms_provider_cancel",
                text: "Cancel"
            },
            'Save': {
                click: function () {
                    if ($("#form_smsprovider").valid()) {
                        save_sms_provider_config();
                    }
                },
                id: "button_sms_provider_save",
                text: "Save"
            }
        },
        open: function (event, ui) {
            $(this).dialog_icons();
            translate_dialog_sms_provider_edit();
        },
        close: function (event, ui) {
            load_sms_providers();
        }
    });

    $dialog_sms_provider_delete = $('#dialog_sms_provider_delete').dialog({
        autoOpen: false,
        title: 'Deleting provider',
        width: 600,
        modal: true,
        buttons: {
            'Delete': {
                click: function () {
                    delete_sms_provider(selectedSMSProvider);
                    $(this).dialog('close');
                },
                id: "button_sms_provider_delete_delete",
                text: "Delete"
            },
            "Cancel": {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_sms_provider_delete_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_dialog_sms_provider_delete();
        },
        close: function (event, ui) {
            load_sms_providers();
        }
    });

    $('#button_sms_provider_set_default').click(function () {
        if (selectedSMSProvider) {
            set_default_provider('sms', selectedSMSProvider);
        }
    });


    /*********************************************************************
     * Email provider config
     */

    var $dialog_email_provider_config = $('#dialog_email_providers').dialog({
        autoOpen: false,
        title: 'Email Provider Config',
        dialogClass: "dialog-email-provider",
        width: 600,
        maxHeight: 600,
        minHeight: 300,
        modal: true,
        buttons: {
            'New': {
                click: function () {
                    email_provider_form_dialog("");
                },
                id: "button_email_provider_new",
                text: "New"
            },
            'Edit': {
                click: function () {
                    if (selectedEmailProvider) {
                        email_provider_form_dialog(selectedEmailProvider);
                    }
                },
                id: "button_email_provider_edit",
                text: "Edit"
            },
            'Delete': {
                click: function () {
                    if (selectedEmailProvider) {
                        $('#dialog_email_provider_delete').dialog("open");
                    }
                },
                id: "button_email_provider_delete",
                text: "Delete"
            },
            'Close': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_email_providers_close",
                text: "Close"
            }
        },
        open: function (event, ui) {
            $('.ui-dialog :button', this).blur();

            $(this).dialog_icons();
            translate_dialog_email_providers();
        }
    });

    $dialog_email_provider_edit = $('#dialog_email_provider_edit').dialog({
        autoOpen: false,
        title: 'Email Provider',
        width: 600,
        modal: true,
        buttons: {
            'Cancel': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_email_provider_cancel",
                text: "Cancel"
            },
            'Save': {
                click: function () {
                    if ($("#form_emailprovider").valid()) {
                        save_email_provider_config();
                    }
                },
                id: "button_email_provider_save",
                text: "Save"
            }
        },
        open: function (event, ui) {
            $(this).dialog_icons();
            translate_dialog_email_provider_edit();
        },
        close: function (event, ui) {
            load_email_providers();
        }
    });

    $dialog_email_provider_delete = $('#dialog_email_provider_delete').dialog({
        autoOpen: false,
        title: 'Deleting EMail provider',
        width: 600,
        modal: true,
        buttons: {
            'Delete': {
                click: function () {
                    delete_email_provider(selectedEmailProvider);
                    $(this).dialog('close');
                },
                id: "button_email_provider_delete_delete",
                text: "Delete"
            },
            "Cancel": {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_email_provider_delete_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_dialog_email_provider_delete();
        },
        close: function (event, ui) {
            load_email_providers();
        }
    });

    $('#button_email_provider_set_default').click(function () {
        if (selectedEmailProvider) {
            set_default_provider('email', selectedEmailProvider);
        }
    });

    /*********************************************************************
     * Push provider config
     */

    var $dialog_push_provider_config = $('#dialog_push_providers').dialog({
        autoOpen: false,
        title: 'Push Provider Config',
        dialogClass: "dialog-push-provider",
        width: 600,
        maxHeight: 600,
        minHeight: 300,
        modal: true,
        buttons: {
            'New': {
                click: function () {
                    push_provider_form_dialog("");
                },
                id: "button_push_provider_new",
                text: "New"
            },
            'Edit': {
                click: function () {
                    if (selectedPushProvider) {
                        push_provider_form_dialog(selectedPushProvider);
                    }
                },
                id: "button_push_provider_edit",
                text: "Edit"
            },
            'Delete': {
                click: function () {
                    if (selectedPushProvider) {
                        $('#dialog_push_provider_delete').dialog("open");
                    }
                },
                id: "button_push_provider_delete",
                text: "Delete"
            },
            'Close': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_push_providers_close",
                text: "Close"
            }
        },
        open: function (event, ui) {
            $('.ui-dialog :button', this).blur();

            $(this).dialog_icons();
            translate_dialog_push_providers();
        }
    });

    $dialog_push_provider_edit = $('#dialog_push_provider_edit').dialog({
        autoOpen: false,
        title: 'Push Provider',
        width: 700,
        modal: true,
        buttons: {
            'Cancel': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_push_provider_cancel",
                text: "Cancel"
            },
            'Save': {
                click: function () {
                    if ($("#form_pushprovider").valid()) {
                        save_push_provider_config();
                    }
                },
                id: "button_push_provider_save",
                text: "Save"
            }
        },
        open: function (event, ui) {
            $(this).dialog_icons();
            translate_dialog_push_provider_edit();
        },
        close: function (event, ui) {
            load_push_providers();
        }
    });

    $dialog_push_provider_delete = $('#dialog_push_provider_delete').dialog({
        autoOpen: false,
        title: 'Deleting Push provider',
        width: 600,
        modal: true,
        buttons: {
            'Delete': {
                click: function () {
                    delete_push_provider(selectedPushProvider);
                    $(this).dialog('close');
                },
                id: "button_push_provider_delete_delete",
                text: "Delete"
            },
            "Cancel": {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_push_provider_delete_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_dialog_push_provider_delete();
        },
        close: function (event, ui) {
            load_push_providers();
        }
    });

    $('#button_push_provider_set_default').click(function () {
        if (selectedPushProvider) {
            set_default_provider('push', selectedPushProvider);
        }
    });

    /*********************************************************************
     * voice provider config
     */

    var $dialog_voice_provider_config = $('#dialog_voice_providers').dialog({
        autoOpen: false,
        title: 'Voice Provider Config',
        dialogClass: "dialog-voice-provider",
        width: 600,
        maxHeight: 600,
        minHeight: 300,
        modal: true,
        buttons: {
            'New': {
                click: function () {
                    voice_provider_form_dialog("");
                },
                id: "button_voice_provider_new",
                text: "New"
            },
            'Edit': {
                click: function () {
                    if (selectedVoiceProvider) {
                        voice_provider_form_dialog(selectedVoiceProvider);
                    }
                },
                id: "button_voice_provider_edit",
                text: "Edit"
            },
            'Delete': {
                click: function () {
                    if (selectedVoiceProvider) {
                        $('#dialog_voice_provider_delete').dialog("open");
                    }
                },
                id: "button_voice_provider_delete",
                text: "Delete"
            },
            'Close': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_voice_providers_close",
                text: "Close"
            }
        },
        open: function (event, ui) {
            $('.ui-dialog :button', this).blur();

            $(this).dialog_icons();
            translate_dialog_voice_providers();
        }
    });

    $dialog_voice_provider_edit = $('#dialog_voice_provider_edit').dialog({
        autoOpen: false,
        title: 'Voice Provider',
        width: 600,
        modal: true,
        buttons: {
            'Cancel': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_voice_provider_cancel",
                text: "Cancel"
            },
            'Save': {
                click: function () {
                    if ($("#form_voiceprovider").valid()) {
                        save_voice_provider_config();
                    }
                },
                id: "button_voice_provider_save",
                text: "Save"
            }
        },
        open: function (event, ui) {
            $(this).dialog_icons();
            translate_dialog_voice_provider_edit();
        },
        close: function (event, ui) {
            load_voice_providers();
        }
    });

    $dialog_voice_provider_delete = $('#dialog_voice_provider_delete').dialog({
        autoOpen: false,
        title: 'Deleting Voice provider',
        width: 600,
        modal: true,
        buttons: {
            'Delete': {
                click: function () {
                    delete_voice_provider(selectedVoiceProvider);
                    $(this).dialog('close');
                },
                id: "button_voice_provider_delete_delete",
                text: "Delete"
            },
            "Cancel": {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_voice_provider_delete_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_dialog_voice_provider_delete();
        },
        close: function (event, ui) {
            load_voice_providers();
        }
    });

    $('#button_voice_provider_set_default').click(function () {
        if (selectedVoiceProvider) {
            set_default_provider('voice', selectedVoiceProvider);
        }
    });

    /* end of voice provider config */

    /*********************************************************************
     * System config
     */

    var $dialog_system_config = $('#dialog_system_settings').dialog({
        autoOpen: false,
        title: 'System config',
        width: 600,
        modal: true,
        buttons: {
            'Save config': {
                click: function () {
                    if ($("#form_sysconfig").valid()) {
                        save_system_config();
                        $(this).dialog('close');
                    } else {
                        alert_box({
                            'title': "",
                            'text': "text_error_saving_system_config",
                            'is_escaped': true
                        });
                    }
                },
                id: "button_system_save",
                text: "Save config"
            },
            Cancel: {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_system_cancel",
                text: "Cancel"
            }
        },
        open: function (event, ui) {
            $(this).dialog_icons();
            translate_system_settings();
        }
    });
    $('#tab_system_settings').tabs();

    $('#menu_system_config').click(function () {
        load_system_config();
        $dialog_system_config.dialog('open');
    });

    $('#menu_sms_provider_config').click(function () {
        load_sms_providers();
        $dialog_sms_provider_config.dialog('open');
    });

    $('#menu_email_provider_config').click(function () {
        load_email_providers();
        $dialog_email_provider_config.dialog('open');
    });

    $('#menu_push_provider_config').click(function () {
        load_push_providers();
        $dialog_push_provider_config.dialog('open');
    });

    $('#menu_voice_provider_config').click(function () {
        load_voice_providers();
        $dialog_voice_provider_config.dialog('open');
    });

    $('#menu_token_config').click(function () {
        try {
            $dialog_token_config.dialog('open');
        } catch (error) {
            alert_box({
                'title': '',
                'text': "text_catching_generic_error",
                'param': escape(error),
                'is_escaped': true
            });
        }
    });


    $('#menu_policies').click(function () {
        $('#tabs').tabs('option', 'active', 2);
    });

    /*********************************************************************
     * license support contact
     */
    $dialog_support_contact = $('#dialog_support_contact').dialog({
        autoOpen: false,
        title: 'Support Contact',
        width: 600,
        modal: true,
        buttons: {
            'Ok': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_support_contact_close",
                text: "Ok"
            }
        },
        open: function (event, ui) {
            translate_support_contact();
        }

    });

    /*********************************************************************
     * license stuff
     */
    var $dialog_view_support = $('#dialog_support_view').dialog({
        autoOpen: false,
        title: 'LinOTP Support Info',
        width: 600,
        modal: true,
        buttons: {
            'Setup Support': {
                click: function () {
                    $(this).dialog('close');
                    $dialog_set_support.dialog('open');
                },
                id: "button_support_setup",
                text: "Setup support subscription"
            },
            'Close': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_support_close",
                text: "Close"
            }
        },
        open: function (event, ui) {
            $(this).dialog_icons();
            translate_support_view();
        }

    });
    $('#menu_view_support').click(function () {
        support_view();
        $dialog_view_support.dialog('open');
    });

    var $dialog_set_support = $('#dialog_set_support').dialog({
        autoOpen: false,
        title: 'Load LinOTP Support Subscription',
        width: 600,
        modal: true,
        buttons: {
            'Set subscription': {
                click: function () {
                    support_set();
                    $(this).dialog('close');
                },
                id: "button_support_set",
                text: "Set subscription"
            },
            Cancel: {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_support_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_support_set();
        }
    });
    $('#menu_set_support').click(function () {
        support_set();
        $dialog_set_support.dialog('open');
    });

    var $dialog_about = $('#dialog_about').dialog({
        autoOpen: false,
        title: 'About LinOTP',
        width: 600,
        modal: true,
        buttons: {
            'Close': {
                click: function () { $(this).dialog('close'); },
                id: "button_about_close",
                text: "Close"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_about();
        }
    });
    $('#menu_about').click(function () {
        $dialog_about.dialog('open');
    });


    /**********************************************************************
     * loading token file
     */

    var $dialog_load_tokens_pskc = create_pskc_dialog();
    var $dialog_load_tokens_feitian = create_feitian_dialog();
    var $dialog_load_tokens_dpw = create_dpw_dialog();
    var $dialog_load_tokens_dat = create_dat_dialog();
    var $dialog_load_tokens_aladdin = create_aladdin_dialog();
    var $dialog_load_tokens_oathcsv = create_oathcsv_dialog();
    var $dialog_load_tokens_yubikeycsv = create_yubikeycsv_dialog();

    $('#menu_load_aladdin_xml_tokenfile').click(function () {
        $dialog_load_tokens_aladdin.dialog('open');
    });
    $('#menu_load_oath_csv_tokenfile').click(function () {
        $dialog_load_tokens_oathcsv.dialog('open');
    });
    $('#menu_load_yubikey_csv_tokenfile').click(function () {
        $dialog_load_tokens_yubikeycsv.dialog('open');
    });
    $('#menu_load_feitian').click(function () {
        $dialog_load_tokens_feitian.dialog('open');
    });
    $('#menu_load_pskc').click(function () {
        $dialog_load_tokens_pskc.dialog('open');
    });
    $('#menu_load_dpw').click(function () {
        $dialog_load_tokens_dpw.dialog('open');
    });
    $('#menu_load_dat').click(function () {
        $dialog_load_tokens_dat.dialog('open');
    });

    /*******************************************************
     * Enrolling tokens
     */
    function button_enroll() {

        init_$tokentypes();
        try {
            tokentype_changed();
        } catch (error) {
            alert_box({
                'title': '',
                'text': "text_catching_generic_error",
                'param': escape(error),
                'is_escaped': true
            });
            return false;
        }
        // ajax call w. callback//
        get_enroll_infotext();
        translate_token_enroll();
        $dialog_enroll_token.dialog('open');

        return false;
    }

    var $dialog_enroll_token = $('#dialog_token_enroll').dialog({
        autoOpen: false,
        title: 'Enroll Token',
        resizeable: false,
        width: 600,
        modal: true,
        buttons: {
            'Enroll': {
                click: function () {
                    try {
                        token_enroll();
                        $(this).dialog('close');
                    }
                    catch (e) {
                        alert_box({
                            'title': i18n.gettext('Failed to enroll token'),
                            'text': i18n.gettext('The entered PINs do not match!'),
                            'type': ERROR,
                            'is_escaped': true
                        });
                    }
                },
                id: "button_enroll_enroll",
                text: "Enroll"
            },
            'Cancel': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_enroll_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            $(this).dialog_icons();
        }
    });

    $('#button_enroll').click(button_enroll);
    //jQuery(document).bind('keydown', 'Alt+e', button_enroll());



    $('#realms').change(function () {
        var new_realm = $('#realm').val();
        $('#user_table').flexOptions({
            params: [{
                name: 'realm',
                value: new_realm
            }],
            newp: 1
        });
        $('#user_table').flexReload();
        // remove the selected user display
        $('#selected_users').html("");
    });

    $dialog_setpin_token = $('#dialog_set_pin').dialog({
        autoOpen: false,
        title: 'Set PIN',
        resizeable: false,
        width: 400,
        modal: true,
        buttons: {
            'Set PIN': {
                click: function () {
                    try {
                        token_setpin();
                        $(this).dialog('close');
                    }
                    catch (e) {
                        alert_box({
                            'title': i18n.gettext('Failed to set PIN'),
                            'text': i18n.gettext('The entered PINs do not match!'),
                            'type': ERROR,
                            'is_escaped': true
                        });
                    }
                },
                id: "button_setpin_setpin",
                text: "Set PIN"
            },
            'Cancel': {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_setpin_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            $(this).dialog_icons();
            translate_set_pin();
        },
        close: function () {
            $('#pin1').val('');
            $('#pin2').val('');
        }
    });

    $('#button_setpin').click(function () {
        tokens = get_selected_tokens();
        view_setpin_dialog(tokens);
        return false;
    });

    var $dialog_unassign_token = $('#dialog_unassign_token').dialog({
        autoOpen: false,
        title: 'Unassign selected tokens?',
        resizable: false,
        width: 400,
        modal: true,
        buttons: {
            'Unassign tokens': {
                click: function () {
                    token_unassign();
                    $(this).dialog('close');
                },
                id: "button_unassign_unassign",
                text: "Unassign tokens"
            },
            Cancel: {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_unassign_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            tokens = get_selected_tokens();
            token_string = tokens.join(", ");
            $('#tokenid_unassign').html(escape(token_string));

            $(this).dialog_icons();
            translate_dialog_unassign();
        }
    });
    $('#button_unassign').click(function () {
        $dialog_unassign_token.dialog('open');
        return false;
    });


    var $dialog_delete_token = $('#dialog_delete_token').dialog({
        autoOpen: false,
        title: 'Delete selected tokens?',
        resizable: false,
        width: 400,
        modal: true,
        buttons: {
            'Delete tokens': {
                click: function () {
                    token_delete();
                    $(this).dialog('close');
                },
                id: "button_delete_delete",
                text: "Delete tokens"
            },
            Cancel: {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_delete_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            tokens = get_selected_tokens();
            $('#delete_info').html(escape(tokens.join(", ")));

            $(this).dialog_icons();
            translate_dialog_delete_token();
        }
    });
    $('#button_delete').click(function () {
        $dialog_delete_token.dialog('open');
        return false;
    });

    $('#text_no_realm').dialog({
        autoOpen: false,
        modal: true,
        show: {
            effect: "fade",
            duration: 1000
        },
        hide: {
            effect: "fade",
            duration: 500
        },
        buttons: {
            Ok: function () {
                $(this).dialog("close");
                $dialog_realms.dialog("open");
            }
        }
    });


    /******************************************************************+
     *
     * Tabs
     */
    $("#tabs").tabs({
        collapsible: false,
        spinner: 'Retrieving data...',
        beforeLoad: function (event, ui) {
            // The purpose of the following is to prevent automatic reloads
            // of the tab. When the tab loads for the first time the 'loaded'
            // option is set.
            // The tab can be reloaded by reloading the whole page, or using
            // the controls provided inside the tab.
            // Tab Option 'cache: true' (used before for this same purpose)
            // was removed in jQuery UI version 1.10
            if (ui.tab.data("loaded")) {
                event.preventDefault();
            }
            else {
                ui.jqXHR.then(function () {
                    ui.tab.data("loaded", true);
                });
                // Following replaces ajaxOptions error function. ajaxOptions was
                // removed in jQuery UI 1.10
                ui.jqXHR.fail(function () {
                    ui.panel.html("Couldn't load this tab. " +
                        "Please contact your administrator.");
                });
            }
            return;
        },
        load: function (event, ui) {
            $(ui.panel).enableUIComponents();
        }
    });

    /**********************************************************************
     * Token info dialog
     */
    $dialog_tokeninfo_set = $('#dialog_tokeninfo_set').dialog({
        autoOpen: false,
        title: "Setting Hashlib",
        resizeable: true,
        width: 400,
        modal: true,
        buttons: {
            OK: {
                click: function () {
                    token_info_save();
                    $(this).dialog('close');
                },
                id: "button_tokeninfo_ok",
                text: "OK"
            },
            Cancel: {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_tokeninfo_cancel",
                text: "Cancel"
            }
        }
    });
    $dialog_tokeninfo_set.html('<select id=hashlib name=hashlib>\
                    <option value=sha1>sha1</option>\
                    <option value=sha256>sha256</option>\
                    </select>');

    $dialog_token_info = $('#dialog_token_info').dialog({
        autoOpen: false,
        title: 'Token info',
        resizeable: true,
        width: 800,
        modal: true,
        open: function () {
            $(this).dialog_icons();
            translate_dialog_token_info();
        }
    });

    fill_realms();

    // Log Div
    $("#logAccordion").accordion({
        fillSpace: true
    });

    $('#login-status-password, #menu_tools_changepassword').click(function () {
        $('#dialog_change_password').dialog({
            title: i18n.gettext("Change password"),
            width: 650,
            modal: true,
            open: function () {
                $("form", this).validate({
                    rules: {
                        password_old: {
                            required: true
                        },
                        password_new: {
                            required: true,
                            minlength: 6,
                            "password-strength": 3
                        },
                        password_confirm: {
                            equalTo: "#password_new",
                            required: true
                        }
                    }
                });
                // resset password inputs on dialog open
                $("input", this).val("");

                // fix table after the browser balances the widths
                $("table tr:first-child td", this).each(function () {
                    $(this).css("width", $(this).width());
                });
            },
            buttons: [
                {
                    text: i18n.gettext("Cancel"),
                    icons: {
                        primary: 'ui-icon-cancel'
                    },
                    click: function () {
                        $(this).dialog("close");
                    }
                },
                {
                    text: i18n.gettext("Save"),
                    icons: {
                        primary: 'ui-icon-disk'
                    },
                    click: function () {
                        if ($("form", this).valid()) {
                            changePassword();
                            $(this).dialog("close");
                        }
                    }
                }
            ]
        });
    });

    // display welcome screen if required
    check_for_welcome_screen();


});
//--------------------------------------------------------------------------------------
// End of document ready

/**
 * openExpirationDialog
 *
 * is the handler to create and or open the dialog to set the expiration
 * on one or many tokens
 */
function openExpirationDialog() {
    var setexpiration_validator;
    $("#dialog_setexpiration").dialog({
        title: i18n.gettext('Set Token Expiration'),
        width: 600,
        modal: true,
        buttons: [
            {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_setexpiration_cancel",
                text: i18n.gettext("Cancel")
            },
            {
                click: function () {
                    var dialog = $(this);

                    if (!setexpiration_validator.valid()) {
                        return;
                    }

                    var validityPeriodStart = $("#setexpiration_period_start").datetimepicker('getValue');
                    validityPeriodStart = $("#setexpiration_period_start").val() ? parseInt(validityPeriodStart.valueOf() / 1000) : "unlimited";

                    var validityPeriodEnd = $("#setexpiration_period_end").datetimepicker('getValue');
                    validityPeriodEnd = $("#setexpiration_period_end").val() ? parseInt(validityPeriodEnd.valueOf() / 1000) : "unlimited";

                    var data = {
                        "tokens": get_selected_tokens(),
                        "countAuthMax": $("#setexpiration_count_requests").val() || "unlimited",
                        "countAuthSuccessMax": $("#setexpiration_count_success").val() || "unlimited",
                        "validityPeriodStart": validityPeriodStart,
                        "validityPeriodEnd": validityPeriodEnd
                    };


                    $.post("/admin/setValidity", data, function (data, textStatus, XMLHttpRequest) {
                        if (data.result && data.result.status == true) {
                            alert_info_text({
                                'text': i18n.gettext("Expiration set successfully"),
                                'is_escaped': true
                            });
                            dialog.dialog('close');
                            tokeninfo_redisplay();
                        }
                        else {
                            var message = i18n.gettext("An error occurred during saving expiration.");
                            message += (isDefinedKey(data, ["result", "error", "message"]) ? "<br><br>" + escape(data.result.error.message) : "");

                            alert_box({
                                'title': i18n.gettext('Error saving expiration'),
                                'text': message,
                                'type': ERROR,
                                'is_escaped': true
                            });
                        }
                    });
                },
                id: "button_setexpiration_save",
                text: i18n.gettext("Save")
            }
        ],
        open: function () {
            var tokens = get_selected_tokens();
            $('#dialog_setexpiration_tokens').text(tokens.join(", "));

            setexpiration_validator = $("form", this).validate();
            setexpiration_validator.resetForm();

            var showWarning = tokens.length > 1;

            if (showWarning) {
                $(".multiple-tokens.warning .tokencount", this).text(tokens.length);
            }
            else if (tokens.length === 1) {
                show_waiting();
                getTokenDetails(tokens[0]).then(function (token) {
                    var countRequests = token["LinOtp.TokenInfo"]["count_auth_max"];
                    var countSuccess = token["LinOtp.TokenInfo"]["count_auth_success_max"];

                    $("#setexpiration_count_requests").val(countRequests);
                    $("#setexpiration_count_success").val(countSuccess);

                    var periodStartISO = token["LinOtp.TokenInfo"]["validity_period_start"];
                    var periodEndISO = token["LinOtp.TokenInfo"]["validity_period_end"];

                    // append timezone to and wrap backend datetime string twice to convert
                    // it to a valid and localized js date time object
                    var timezone = "+0000";
                    if (periodStartISO) {
                        var periodStart = new Date(new Date(periodStartISO + timezone));
                        $('#setexpiration_period_start').datetimepicker({ value: periodStart });
                    }
                    if (periodEndISO) {
                        var periodEnd = new Date(new Date(periodEndISO + timezone));
                        $('#setexpiration_period_end').datetimepicker({ value: periodEnd });
                    }

                    hide_waiting();
                }, function () {
                    var message = i18n.gettext("An error occurred during token processing.");
                    alert_box({
                        'title': i18n.gettext('Error loading token info'),
                        'text': message,
                        'type': ERROR,
                        'is_escaped': true
                    });

                    hide_waiting();
                });
            }

            $(".multiple-tokens.warning").toggleClass("hidden", !showWarning);

        },
        create: function () {
            $(".multiple-tokens.warning", this).html(sprintf($(".multiple-tokens.warning", this).text(), "<span class='tokencount'></span>"));

            $("input", this).change(function () {
                if ($(this).val() === "0") {
                    $(this).val("");
                }
            });

            jQuery.datetimepicker.setLocale(CURRENT_LANGUAGE);

            var dtStart = $('#setexpiration_period_start'),
                dtEnd = $('#setexpiration_period_end'),
                dtConfig = {
                    format: "Y-m-d H:i (T)",
                    dayOfWeekStart: 1,
                    onShow: function (event, $input) {
                        if (!$input.is(":focus")) {
                            setTimeout(function () { $input.datetimepicker("hide"); });
                        }
                    }
                };

            function dtStartOnChange() {
                if (dtStart.datetimepicker('getValue') > dtEnd.datetimepicker('getValue')) {
                    dtEnd.datetimepicker("reset");
                    dtEndOnChange();
                }
                dtEnd.datetimepicker({
                    minDate: dtStart.val()
                });
            }
            function dtEndOnChange() {
                var invalidPeriod = dtStart.val().length !== 0
                    && dtEnd.val().length !== 0
                    && dtStart.datetimepicker('getValue') > dtEnd.datetimepicker('getValue');
                if (invalidPeriod) {
                    var valid_cfg = {};
                    valid_cfg[dtEnd.attr("name")] = i18n.gettext("Invalid time period");
                    setexpiration_validator.showErrors(valid_cfg);
                }
                else {
                    setexpiration_validator.errorList.pop(dtEnd);
                    dtEnd.next().hide(); // hide the error label so that error is not shown anymore.
                    // JQuery-validates data model is updated correct, but the label
                    // is not removed, so we do it manually.
                }
            }

            dtStart.datetimepicker($.extend({ "onChangeDateTime": dtStartOnChange }, dtConfig));
            dtEnd.datetimepicker($.extend({ "onChangeDateTime": dtEndOnChange }, dtConfig));

            $(this).dialog_icons();
        }
    });
}

/**
 * submits the change password form to the linotp backend
 */
function changePassword() {
    var params = {
        'old_password': $('#password_old').val(),
        'new_password': $('#password_new').val(),
    };

    show_waiting();

    $.post('/tools/setPassword', params).always(function (data, textStatus, XMLHttpRequest) {
        if (data.result && data.result.status == true && data.result.value == true) {
            alert_info_text({
                'text': i18n.gettext('Password was successfully changed'),
                'is_escaped': true
            });
        }
        else {
            var message = i18n.gettext("An error occurred during password change.");
            message += (isDefinedKey(data, ["result", "error", "message"]) ? "<br><br>" + escape(data.result.error.message) : "");

            alert_box({
                'title': i18n.gettext('Error changing password'),
                'text': message,
                'type': ERROR,
                'is_escaped': true
            });
        }
        hide_waiting();
    });
}


/************************************************************************
 *
 *  SMS Provider edit
 */

function sms_provider_form_dialog(name) {
    if (name) {
        $("#sms_provider_name").val(name);
        $("#sms_provider_class").val(smsProviders[name].Class);
        $("#sms_provider_config").val(smsProviders[name].Config);
        $("#sms_provider_timeout").val(smsProviders[name].Timeout);
    }
    else {
        $("#sms_provider_name").val($("#sms_provider_name").attr("placeholder"));
        // to be replaced by getProviderDef
        $("#sms_provider_class").val($("#sms_provider_class").attr("placeholder"));
        $("#sms_provider_config").val($("#sms_provider_config").attr("placeholder"));
        $("#sms_provider_timeout").val($("#sms_provider_timeout").attr("placeholder"));
    }

    $("#dialog_sms_provider_edit").dialog("open");

    $("#form_smsprovider").validate({
        rules: {
            sms_provider_config: {
                valid_json: true
            },
            sms_provider_name: {
                required: true,
                minlength: 4,
                number: false,
                providername: true
            }
        }
    });
}

function save_sms_provider_config() {
    // Load Values from still opened form
    var provider = $('#sms_provider_name').val();
    var params = {
        'name': provider,
        'class': $('#sms_provider_class').val(),
        'config': $('#sms_provider_config').val(),
        'timeout': $('#sms_provider_timeout').val(),
        'type': 'sms',
    };

    show_waiting();

    $.post('/system/setProvider', params,
        function (data, textStatus, XMLHttpRequest) {
            load_sms_providers();
            if (data.result.status == true && data.result.value == true) {
                $dialog_sms_provider_edit.dialog('close');
            } else if (data.result.value == false) {
                alert_box({
                    'title': i18n.gettext('Failed to save provider'),
                    'text': escape(data.detail.message),
                    'type': ERROR,
                    'is_escaped': true
                });

                var message = sprintf(i18n.gettext('Failed to save provider %s'),
                    escape(provider));
                alert_info_text({
                    'text': message,
                    'type': ERROR,
                    'is_escaped': true
                });
            } else {
                alert_box({
                    'title': i18n.gettext('Error saving provider'),
                    'text': escape(data.result.error.message),
                    'type': ERROR,
                    'is_escaped': true
                });
            }
            hide_waiting();
        });
}

function delete_sms_provider(provider) {
    show_waiting();
    var params = {
        'name': provider,
        'type': 'sms',
    };
    $.post('/system/delProvider', params,
        function (data, textStatus, XMLHttpRequest) {
            load_sms_providers();
            if (data.result.status == true && data.result.value == true) {
                var message = sprintf(i18n.gettext('Provider %s deleted'),
                    escape(provider));
                alert_info_text({
                    'text': message,
                    'is_escaped': true
                });
            } else if (data.result.value == false) {
                var reason_text = ("detail" in data && "message" in data.detail ? escape(data.detail.message) : i18n.gettext('Unknown server error occurred'));
                alert_box({
                    'title': i18n.gettext('Failed to delete provider'),
                    'text': reason_text,
                    'type': ERROR,
                    'is_escaped': true
                });
                var message = sprintf(i18n.gettext('Failed to delete provider %s'),
                    escape(provider));
                alert_info_text({
                    'text': message,
                    'type': ERROR,
                    'is_escaped': true
                });
            } else {
                alert_box({
                    'title': i18n.gettext('Error deleting provider'),
                    'text': escape(data.result.error.message),
                    'type': ERROR,
                    'is_escaped': true
                });
            }
            hide_waiting();
        }
    );
}

function set_default_provider(type, provider) {
    show_waiting();
    var params = {
        'name': provider,
        'type': type,
    };
    $.post('/system/setDefaultProvider', params,
        function (data, textStatus, XMLHttpRequest) {
            window['load_' + type + '_providers']();
            if (data.result.status == true && data.result.value == true) {
                var message = sprintf(i18n.gettext('Provider %s set as default'),
                    escape(provider));
                alert_info_text({
                    'text': message,
                    'is_escaped': true
                });
            } else if (data.result.value == false) {
                alert_box({
                    'title': i18n.gettext('Failed to set default provider'),
                    'text': escape(data.detail.message),
                    'type': ERROR,
                    'is_escaped': true
                });
                var message = sprintf(i18n.gettext('Failed to set default provider %s'),
                    escape(provider));
                alert_info_text({
                    'text': message,
                    'type': ERROR,
                    'is_escaped': true
                });
            } else {
                alert_box({
                    'title': i18n.gettext('Error setting default provider'),
                    'text': escape(data.result.error.message),
                    'type': ERROR,
                    'is_escaped': true
                });
            }
            hide_waiting();
        }
    );
}

/************************************************************************
 *
 *  Email provider edit
 */

function email_provider_form_dialog(name) {
    if (name) {
        $("#email_provider_name").val(name);
        $("#email_provider_class").val(emailProviders[name].Class);
        $("#email_provider_config").val(emailProviders[name].Config);
        $("#email_provider_timeout").val(emailProviders[name].Timeout);
    }
    else {
        $("#email_provider_name").val($("#email_provider_name").attr("placeholder"));
        // to be replaced by getProviderDef
        $("#email_provider_class").val($("#email_provider_class").attr("placeholder"));
        $("#email_provider_config").val($("#email_provider_config").attr("placeholder"));
        $("#email_provider_timeout").val($("#email_provider_timeout").attr("placeholder"));
    }

    $("#dialog_email_provider_edit").dialog("open");

    $("#form_emailprovider").validate({
        rules: {
            email_provider_config: {
                valid_json: true
            },
            email_provider_name: {
                required: true,
                minlength: 4,
                number: false,
                providername: true
            }
        }
    });
}

function save_email_provider_config() {
    // Load Values from still opened form
    var provider = $('#email_provider_name').val();
    var params = {
        'name': provider,
        'class': $('#email_provider_class').val(),
        'config': $('#email_provider_config').val(),
        'timeout': $('#email_provider_timeout').val(),
        'type': 'email',
    };
    show_waiting();

    $.post('/system/setProvider', params,
        function (data, textStatus, XMLHttpRequest) {
            if (data.result.status == true && data.result.value == true) {
                $dialog_email_provider_edit.dialog('close');
            } else if (data.result.value == false) {
                alert_box({
                    'title': i18n.gettext('Failed to save provider'),
                    'text': escape(data.detail.message),
                    'type': ERROR,
                    'is_escaped': true
                });

                var message = sprintf(i18n.gettext('Failed to save provider %s'),
                    escape(provider));
                alert_info_text({
                    'text': message,
                    'type': ERROR,
                    'is_escaped': true
                });
            } else {
                alert_box({
                    'title': i18n.gettext('Error saving provider'),
                    'text': escape(data.result.error.message),
                    'type': ERROR,
                    'is_escaped': true
                });
            }
            hide_waiting();
        });
}

function delete_email_provider(provider) {
    show_waiting();
    var params = {
        'name': provider,
        'type': 'email',
    };
    $.post('/system/delProvider', params,
        function (data, textStatus, XMLHttpRequest) {
            load_email_providers();
            if (data.result.status == true && data.result.value == true) {
                var message = sprintf(i18n.gettext('Provider %s deleted'),
                    escape(provider));
                alert_info_text({
                    'text': message,
                    'is_escaped': true
                });
            } else if (data.result.value == false) {
                var reason_text = ("detail" in data && "message" in data.detail ? escape(data.detail.message) : i18n.gettext('Unknown server error occurred'));
                alert_box({
                    'title': i18n.gettext('Failed to delete provider'),
                    'text': reason_text,
                    'type': ERROR,
                    'is_escaped': true
                });
                var message = sprintf(i18n.gettext('Failed to delete provider %s'),
                    escape(provider));
                alert_info_text({
                    'text': message,
                    'type': ERROR,
                    'is_escaped': true
                });
            } else {
                alert_box({
                    'title': i18n.gettext('Error deleting provider'),
                    'text': escape(data.result.error.message),
                    'type': ERROR,
                    'is_escaped': true
                });
            }
            hide_waiting();
        }
    );
}

/************************************************************************
*
*  Push provider edit
*/

function push_provider_form_dialog(name) {
    if (name) {
        $("#push_provider_name").val(name);
        $("#push_provider_class").val(pushProviders[name].Class);
        $("#push_provider_config").val(pushProviders[name].Config);
        $("#push_provider_timeout").val(pushProviders[name].Timeout);
    }
    else {
        $("#push_provider_name").val($("#push_provider_name").attr("placeholder"));
        // to be replaced by getProviderDef
        $("#push_provider_class").val($("#push_provider_class").attr("placeholder"));
        $("#push_provider_config").val($("#push_provider_config").attr("placeholder"));
        $("#push_provider_timeout").val($("#push_provider_timeout").attr("placeholder"));
    }

    $("#dialog_push_provider_edit").dialog("open");

    $("#form_pushprovider").validate({
        rules: {
            push_provider_config: {
                valid_json: true
            },
            push_provider_name: {
                required: true,
                minlength: 4,
                number: false,
                providername: true
            }
        }
    });
}

function save_push_provider_config() {
    // Load Values from still opened form
    var provider = $('#push_provider_name').val();
    var params = {
        'name': provider,
        'class': $('#push_provider_class').val(),
        'config': $('#push_provider_config').val(),
        'timeout': $('#push_provider_timeout').val(),
        'type': 'push',
    };
    show_waiting();

    $.post('/system/setProvider', params,
        function (data, textStatus, XMLHttpRequest) {
            if (data.result.status == true && data.result.value == true) {
                $dialog_push_provider_edit.dialog('close');
            } else if (data.result.value == false) {
                alert_box({
                    'title': i18n.gettext('Failed to save provider'),
                    'text': escape(data.detail.message),
                    'type': ERROR,
                    'is_escaped': true
                });

                var message = sprintf(i18n.gettext('Failed to save provider %s'),
                    escape(provider));
                alert_info_text({
                    'text': message,
                    'type': ERROR,
                    'is_escaped': true
                });
            } else {
                alert_box({
                    'title': i18n.gettext('Error saving provider'),
                    'text': escape(data.result.error.message),
                    'type': ERROR,
                    'is_escaped': true
                });
            }
            hide_waiting();
        });
}

function delete_push_provider(provider) {
    show_waiting();
    var params = {
        'name': provider,
        'type': 'push',
    };
    $.post('/system/delProvider', params,
        function (data, textStatus, XMLHttpRequest) {
            load_push_providers();
            if (data.result.status == true && data.result.value == true) {
                var message = sprintf(i18n.gettext('Provider %s deleted'),
                    escape(provider));

                alert_info_text({
                    'text': message,
                    'is_escaped': true
                });

            } else if (data.result.value == false) {
                var reason_text = ("detail" in data && "message" in data.detail ? escape(data.detail.message) : i18n.gettext('Unknown server error occurred'));
                alert_box({
                    'title': i18n.gettext('Failed to delete provider'),
                    'text': reason_text,
                    'type': ERROR,
                    'is_escaped': true
                });

                var message = sprintf(i18n.gettext('Failed to delete provider %s'),
                    escape(provider));
                alert_info_text({
                    'text': message,
                    'type': ERROR,
                    'is_escaped': true
                });
            } else {
                alert_box({
                    'title': i18n.gettext('Error deleting provider'),
                    'text': escape(data.result.error.message),
                    'type': ERROR,
                    'is_escaped': true
                });
            }
            hide_waiting();
        });
}

/************************************************************************
*
*  Voice provider edit
*/

function voice_provider_form_dialog(name) {
    if (name) {
        $("#voice_provider_name").val(name);
        $("#voice_provider_class").val(voiceProviders[name].Class);
        $("#voice_provider_config").val(voiceProviders[name].Config);
        $("#voice_provider_timeout").val(voiceProviders[name].Timeout);
    }
    else {
        $("#voice_provider_name").val($("#voice_provider_name").attr("placeholder"));
        // to be replaced by getProviderDef
        $("#voice_provider_class").val($("#voice_provider_class").attr("placeholder"));
        $("#voice_provider_config").val($("#voice_provider_config").attr("placeholder"));
        $("#voice_provider_timeout").val($("#voice_provider_timeout").attr("placeholder"));
    }

    $("#dialog_voice_provider_edit").dialog("open");

    $("#form_voiceprovider").validate({
        rules: {
            voice_provider_config: {
                valid_json: true
            },
            voice_provider_name: {
                required: true,
                minlength: 4,
                number: false,
                providername: true
            }
        }
    });
}

function save_voice_provider_config() {
    // Load Values from still opened form
    var provider = $('#voice_provider_name').val();
    var params = {
        'name': provider,
        'class': $('#voice_provider_class').val(),
        'config': $('#voice_provider_config').val(),
        'timeout': $('#voice_provider_timeout').val(),
        'type': 'voice',
    };
    show_waiting();

    $.post('/system/setProvider', params,
        function (data, textStatus, XMLHttpRequest) {
            if (data.result.status == true && data.result.value == true) {
                $dialog_voice_provider_edit.dialog('close');
            } else if (data.result.value == false) {
                alert_box({
                    'title': i18n.gettext('Failed to save provider'),
                    'text': escape(data.detail.message),
                    'type': ERROR,
                    'is_escaped': true
                });

                var message = sprintf(i18n.gettext('Failed to save provider %s'),
                    escape(provider));
                alert_info_text({
                    'text': message,
                    'type': ERROR,
                    'is_escaped': true
                });
            } else {
                alert_box({
                    'title': i18n.gettext('Error saving provider'),
                    'text': escape(data.result.error.message),
                    'type': ERROR,
                    'is_escaped': true
                });
            }
            hide_waiting();
        });
}

function delete_voice_provider(provider) {
    show_waiting();
    var params = {
        'name': provider,
        'type': 'voice',
    };
    $.post('/system/delProvider', params,
        function (data, textStatus, XMLHttpRequest) {
            load_voice_providers();
            if (data.result.status == true && data.result.value == true) {
                var message = sprintf(i18n.gettext('Provider %s deleted'),
                    escape(provider));

                alert_info_text({
                    'text': message,
                    'is_escaped': true
                });

            } else if (data.result.value == false) {
                var reason_text = ("detail" in data && "message" in data.detail ? escape(data.detail.message) : i18n.gettext('Unknown server error occurred'));
                alert_box({
                    'title': i18n.gettext('Failed to delete provider'),
                    'text': reason_text,
                    'type': ERROR,
                    'is_escaped': true
                });

                var message = sprintf(i18n.gettext('Failed to delete provider %s'),
                    escape(provider));
                alert_info_text({
                    'text': message,
                    'type': ERROR,
                    'is_escaped': true
                });
            } else {
                alert_box({
                    'title': i18n.gettext('Error deleting provider'),
                    'text': escape(data.result.error.message),
                    'type': ERROR,
                    'is_escaped': true
                });
            }
            hide_waiting();
        });
}


/************************************************************************
 *
 *  Resolver edit funtions
 */

/**
 * fetch current flat file resolver definition and open dialog to create, edit and duplicate flat file resolvers
 * @param  {String}  name      name of resolver to edit/duplicate or empty string for a create dialog
 * @param  {Boolean} duplicate whether a duplicate should be created or not
 */
function resolver_file(name, duplicate) {
    if ($form_validator_file) {
        $form_validator_file.resetForm();
    }

    var obj = {
        'result': {
            'value': {
                'data': {
                    'fileName': '/etc/passwd'
                }
            }
        }
    };

    g.current_resolver_name = (duplicate ? "" : name);
    $('#file_resolvername').val(g.current_resolver_name);

    if (name) {
        // load the config of the resolver "name".
        clientUrlFetch('/system/getResolver', { 'resolver': name }, function (xhdr, textStatus) {
            var resp = xhdr.responseText;
            obj = jQuery.parseJSON(resp);

            $('#file_filename').val(obj.result.value.data.fileName);
        });
    } else {
        $('#file_filename').val(obj.result.value.data.fileName);
    }

    $dialog_file_resolver.dialog('open');

    $form_validator_file = $("#form_fileconfig").validate({
        rules: {
            file_filename: {
                required: true,
                minlength: 2,
                number: false
            },
            file_resolvername: {
                required: true,
                minlength: 4,
                number: false,
                resolvername: true,
                unique_resolver_name: true
            }
        }
    });
}

function realm_modify(name) {
    var resolvers = get_resolvers();
    if (resolvers.length === 0) {
        alert_box({
            'title': "Cannot " + (name.length === 0 ? "create" : "edit") + " a realm",
            'text': "Please create a UserIdResolver first",
            'is_escaped': true
        });
    } else {
        realm_edit(name);
        realms_load();
        fill_realms();
    }
}

function realm_edit(realm) {
    $('#realm_name').val(realm);
    if (realm) {
        $('#realm_edit_realm_name').html(escape(realm));

        $('#realm_intro_new').hide();
        $('#realm_intro_edit').show();
    }
    else {
        $('#realm_intro_edit').hide();
        $('#realm_intro_new').show();
    }

    // get the realm configuration
    var resp = clientUrlFetchSync('/system/getRealms', {});
    var realm = jQuery.parseJSON(resp).result.value[realm];

    var realmResolvers = realm ? realm.useridresolver : [];
    realmResolvers = realmResolvers
        .map(function (r) { return r.split(".").pop(); });

    sortAdminResolversTop = realm && realm.admin ? 1 : -1;

    // get all resolvers
    var resolverListHtml = '';
    $.post('/system/getResolvers', {},
        function (data, textStatus, XMLHttpRequest) {
            var resolvers = Object
                .keys(data.result.value)
                .map(function (resolver_name) { return data.result.value[resolver_name]; })
                .sort(function (r1, r2) {
                    return (r1.admin < r2.admin ? 1 : -1) * sortAdminResolversTop;
                });

            resolverListHtml = '<ol id="resolvers_in_realms_select" class="select_list ui-selectable">';

            for (var resolver of resolvers) {

                isContainedInRealm = realmResolvers.indexOf(resolver.resolvername) != -1;
                isAdmin = resolver.admin;

                var element_classes = "ui-widget-content";
                if (isContainedInRealm) {
                    element_classes += " ui-selected";
                }

                var e_key = escape(resolver.resolvername);
                var element_id = "realm_edit_click_" + e_key;
                var e_resolver_type = escape(resolver.type);
                var e_spec = escape(resolver.spec);

                resolverListHtml += '<li id="' + element_id + '" class="' + element_classes + '"'
                    + 'data-resolver-spec="' + e_spec + '">'
                    + '<span class="name">' + e_key + '</span> '
                    + '[<span class="type">' + e_resolver_type + '</span>]'
                    + (isAdmin ? ' <span class="tag">' + i18n.gettext("admin") + '</span>' : '')
                    + '</li>';
            }

            resolverListHtml += '</ol>';

            $('#realm_edit_resolver_list').html(resolverListHtml);
            $('#resolvers_in_realms_select').selectable({
                stop: check_for_selected_resolvers
            }); // end of selectable
            check_for_selected_resolvers();
        }); // end of $.post
    $dialog_edit_realms.dialog("option", "title", "Edit Realm " + realm);
    $dialog_edit_realms.dialog('open');

    $("#form_realmconfig").validate({
        rules: {
            realm_name: {
                required: true,
                minlength: 4,
                number: false,
                realmname: true
            }
        }
    });
}

function check_for_selected_resolvers() {
    g.resolvers_in_realm_to_edit = $("#resolvers_in_realms_select .ui-selected")
        .map(function () {
            return $(this).attr("data-resolver-spec");
        })
        .get()
        .join(',');
}

var originalLdapFormData = null;
function resolver_set_ldap(obj) {

    var data = obj.result.value.data;

    $('#ldap_uri').val(data.LDAPURI);
    $('#ldap_basedn').val(data.LDAPBASE);
    $('#ldap_binddn').val(data.BINDDN);
    $('#ldap_password').val("");
    $('#ldap_timeout').val(data.TIMEOUT);
    $('#ldap_sizelimit').val(data.SIZELIMIT);
    $('#ldap_loginattr').val(data.LOGINNAMEATTRIBUTE);
    $('#ldap_searchfilter').val(data.LDAPSEARCHFILTER);
    $('#ldap_userfilter').val(data.LDAPFILTER);
    $('#ldap_mapping').val(data.USERINFO);
    $('#ldap_uidtype').val(data.UIDTYPE);

    // get the configuration value of the enforce TLS (if exists) and adjust the checkbox
    $('#ldap_enforce_tls').prop('checked',
        !!data.EnforceTLS && data.EnforceTLS.toLowerCase() == "true"
    );

    // get the configuration value of the only_trusted_certs (if exists) and adjust the checkbox
    $('#ldap_only_trusted_certs').prop('checked',
        !!data.only_trusted_certs && data.only_trusted_certs.toLowerCase() == "true"
    );

    $('#ldap_noreferrals').prop('checked', data.NOREFERRALS == "True");

    handler_ldaps_starttls_show();

    // indicate whether the resolver will be saved during test
    originalLdapFormData = $('#form_ldapconfig').serialize();
    changeListener = $("#form_ldapconfig").on("change", function () {
        $("#button_test_ldap").data("save-resolver", $(this).serialize() != originalLdapFormData);
        if ($("#button_test_ldap").data("save-resolver")) {
            $("#button_test_ldap").button('option', 'label', i18n.gettext("Save & test resolver"));
        } else {
            $("#button_test_ldap").button('option', 'label', i18n.gettext("Test resolver"));
        }

    }).trigger("change");
}


/**
 * fetch current ldap resolver definition and open dialog to create, edit and duplicate ldap resolvers
 * @param  {String}  name      name of resolver to edit/duplicate or empty string for a create dialog
 * @param  {Boolean} duplicate whether a duplicate should be created or not
 */
function resolver_ldap(name, duplicate) {
    if ($form_validator_ldap) {
        $form_validator_ldap.resetForm();
    }

    var obj = {
        'result': {
            'value': {
                'data': {
                    'BINDDN': 'cn=administrator,dc=yourdomain,dc=tld',
                    'LDAPURI': 'ldap://linotpserver1, ldap://linotpserver2',
                    'EnforceTLS': 'True',
                    'only_trusted_certs': 'True',
                    'LDAPBASE': 'dc=yourdomain,dc=tld',
                    'TIMEOUT': '5',
                    'SIZELIMIT': '500',
                    'LOGINNAMEATTRIBUTE': 'sAMAccountName',
                    'LDAPSEARCHFILTER': '(sAMAccountName=*)(objectClass=user)',
                    'LDAPFILTER': '(&(sAMAccountName=%s)(objectClass=user))',
                    'USERINFO': '{ "username": "sAMAccountName", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }',
                    'UIDTYPE': 'objectGUID',
                    'NOREFERRALS': 'True',
                }
            }
        }
    };

    g.current_resolver_name = duplicate ? "" : name;
    $('#ldap_resolvername').val(g.current_resolver_name);

    if (name) {
        // load the config of the resolver "name".
        clientUrlFetch('/system/getResolver', { 'resolver': name }, function (xhdr, textStatus) {
            var resp = xhdr.responseText;
            obj = jQuery.parseJSON(resp);
            if (obj.result.status) {
                resolver_set_ldap(obj);
            } else {
                // error reading resolver
                alert_box({
                    'title': "",
                    'text': "text_ldap_load_error",
                    'param': escape(obj.result.error.message),
                    'is_escaped': true
                });
            }
        });
    } else {
        resolver_set_ldap(obj);
    }

    var critical_inputs = $('#ldap_uri, #ldap_basedn, #ldap_binddn');

    // reset critical input password requirement validation
    critical_inputs.off("change keyup");
    $("#ldap_password").removeClass("input-placeholder-warning");

    // enable critical input password requirement validation for resolver edits
    if (g.current_resolver_name) {
        $('#ldap_password').attr("placeholder", password_placeholder_not_changed);
        critical_inputs.on('change keyup', function (e) {
            var sth_changed = $('#ldap_uri').val() != obj.result.value.data.LDAPURI
                || $('#ldap_basedn').val() != obj.result.value.data.LDAPBASE
                || $('#ldap_binddn').val() != obj.result.value.data.BINDDN;

            $("#ldap_password").rules("add", {
                required: sth_changed
            });

            $('#ldap_password').attr("placeholder", (sth_changed ? password_placeholder_required : password_placeholder_not_changed));

            if (!sth_changed) {
                $("#ldap_password").valid();
                $("#ldap_password").removeClass("input-placeholder-warning");
            }
            else {
                $("#ldap_password").addClass("input-placeholder-warning");
            }
        });
    }
    else {
        $('#ldap_password').attr("placeholder", password_placeholder_required);
    }

    $('#progress_test_ldap').hide();
    $dialog_ldap_resolver.dialog('open');

    $form_validator_ldap = $("#form_ldapconfig").validate({
        rules: {
            ldap_uri: {
                required: true,
                minlength: 8,
                number: false,
                ldap_uri: /^(ldap:\/\/|ldaps:\/\/)/i
            },
            ldap_timeout: {
                required: true,
                minlength: 1,
                ldap_timeout: true
            },
            ldap_resolvername: {
                required: true,
                minlength: 4,
                resolvername: true,
                unique_resolver_name: true
            },
            ldap_searchfilter: {
                required: true,
                minlength: 5,
                ldap_searchfilter: true
            },
            ldap_userfilter: {
                required: true,
                minlength: 5,
                ldap_userfilter: true
            },
            ldap_mapping: {
                required: true,
                valid_json: true,
                minlength: 5,
                ldap_mapping: true
            },
            ldap_uidtype: {
                ldap_uidtype: true
            }
        }
    });

    // make password field required if it is a new resolver and therefor name is empty
    $("#ldap_password").rules("add", {
        required: !g.current_resolver_name
    });
}

/*
 * for all input fields of the form, set the corresponding
 * values from the obj
 *
 * Assumption:
 *   the input form names are the same as the config entries
 */
function set_form_input(form_name, data) {
    var items = {};
    $('#' + form_name).find(':input').each(
        function (id, el) {
            if (el.name != "") {
                name = el.name;
                id = el.id;
                if (data.hasOwnProperty(name)) {
                    var value = data[name];
                    $('#' + id).val(value);
                } else {
                    $('#' + id).val('');
                }
            }
        }
    );

    for (var i = 0; i < items.length; i++) {
        var name = items[i];

    }

}

/*
 * for all input fields of the form, set the corresponding
 * values from the obj
 *
 * Assumption:
 *   the input form names are the same as the config entries
 */
function get_form_input(form_name) {
    var items = {};
    $('#' + form_name).find(':input').each(
        function (id, el) {
            if (el.name != "") {
                items[el.name] = el.value;
            }
        }
    );
    return items;
}

function resolver_set_http(data) {
    set_form_input('form_httpconfig', data);
    http_resolver_https();
}

function resolver_http(name, duplicate) {
    if ($form_validator_http) {
        $form_validator_http.resetForm();
    }

    var obj = {
        'result': {
            'value': {
                'data': {
                    'AUTHUSER': 'administrator',
                    'HTTPURI': 'http://linotpserver1,http://linotpserver2',
                    'TIMEOUT': '5',
                    'LOGINNAMEATTRIBUTE': '{ "path"="getUserId","searchstr"="username=%(username)s@%(realm)s"}',
                    'HTTPSEARCHFILTER': '{ "path"="getUser","searchstr"="userid=%(userid)s"}',
                    'HTTPFILTER': '{ "path"="admin/userlist","searchstr"="username=%(username)s"} "jsonpath"="/result/value"',
                    'USERINFO': '{ "username": "login", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }',
                    'CACERTIFICATE': '',
                }
            }
        }
    };

    g.current_resolver_name = name;

    if (name) {
        // load the config of the resolver "name".
        clientUrlFetch('/system/getResolver', { 'resolver': name }, function (xhdr, textStatus) {
            var resp = xhdr.responseText;
            var obj = jQuery.parseJSON(resp);
            $('#http_resolvername').val(name);
            if (obj.result.status) {
                var data = obj.result.value.data;
                resolver_set_http(data);
            } else {
                // error reading resolver
                alert_box({
                    'title': "",
                    'text': "text_http_load_error",
                    'param': obj.result.error.message,
                    'is_escaped': true
                });
            }
        });

        $('#http_password').attr("placeholder", password_placeholder_not_changed);
    } // end if
    else {
        $('#http_resolvername').val("");
        $('#http_password').attr("placeholder", password_placeholder_required);

        var data = obj.result.value.data;
        resolver_set_http(data);
    }

    $('#progress_test_http').hide();
    $('#http_setting_tabs').tabs();
    $dialog_http_resolver.dialog('open');


    $form_validator_http = $("#form_httpconfig").validate({
        ignore: "",
        rules: {
            http_uri: {
                required: true,
                minlength: 8,
                number: false,
                http_uri: /^(http:\/\/|https:\/\/)/i
            },
            http_timeout: {
                required: true,
                minlength: 1,
                number: true
            },
            http_resolvername: {
                required: true,
                minlength: 4,
                resolvername: true,
                unique_resolver_name: true
            },
            http_searchfilter: {
                required: true,
                minlength: 5,
                http_searchfilter: true
            },
            http_userfilter: {
                required: true,
                minlength: 5,
                http_userfilter: true
            },
            http_mapping: {
                required: true,
                valid_json: true,
                minlength: 5,
                http_mapping: true
            },
            http_uidtype: {
                http_uidtype: true
            }
        }
    });

    // make password field required if it is a new resolver and therefor name is empty
    $("#http_password").rules("add", {
        required: !name
    });
}

var originalSqlFormData = null;

function resolver_set_sql(obj) {
    $('#sql_driver').val(obj.result.value.data.Driver);
    $('#sql_server').val(obj.result.value.data.Server);
    $('#sql_port').val(obj.result.value.data.Port);
    $('#sql_limit').val(obj.result.value.data.Limit);
    $('#sql_database').val(obj.result.value.data.Database);
    $('#sql_table').val(obj.result.value.data.Table);
    $('#sql_user').val(obj.result.value.data.User);
    $('#sql_password').val("");
    $('#sql_mapping').val(obj.result.value.data.Map);
    $('#sql_where').val(obj.result.value.data.Where);
    $('#sql_conparams').val(obj.result.value.data.conParams);
    $('#sql_encoding').val(obj.result.value.data.Encoding);

    // indicate whether the resolver will be saved during test
    originalSqlFormData = $('#form_sqlconfig').serialize();
    changeListener = $("#form_sqlconfig").on("change", function () {
        $("#button_test_sql").data("save-resolver", $(this).serialize() != originalSqlFormData);
        if ($("#button_test_sql").data("save-resolver")) {
            $("#button_test_sql").button('option', 'label', i18n.gettext("Save & test resolver"));
        } else {
            $("#button_test_sql").button('option', 'label', i18n.gettext("Test resolver"));
        }

    }).trigger("change");
}

/**
 * fetch current sql resolver definition and open dialog to create, edit and duplicate sql resolvers
 * @param  {String}  name      name of resolver to edit/duplicate or empty string for a create dialog
 * @param  {Boolean} duplicate whether a duplicate should be created or not
 */
function resolver_sql(name, duplicate) {
    if ($form_validator_sql) {
        $form_validator_sql.resetForm();
    }

    var obj = {
        'result': {
            'value': {
                'data': {
                    'Database': 'yourUserDB',
                    'Driver': 'mysql+mysqldb',
                    'Server': '127.0.0.1',
                    'Port': '3306',
                    'Limit': '500',
                    'User': 'user',
                    'Password': 'secret',
                    'Table': 'usertable',
                    'Map': '{ "userid" : "id", "username": "user", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" ,"password" : "password" }',
                    'Where': '',
                    'conParams': '',
                    'Encoding': ''

                }
            }
        }
    };

    g.current_resolver_name = duplicate ? "" : name;
    $('#sql_resolvername').val(g.current_resolver_name);

    $('#progress_test_sql').hide();

    if (name) {
        // load the config of the resolver "name".
        clientUrlFetch('/system/getResolver', { 'resolver': name }, function (xhdr, textStatus) {
            var resp = xhdr.responseText;
            obj = jQuery.parseJSON(resp);
            if (obj.result.status) {
                resolver_set_sql(obj);
            } else {
                // error reading resolver
                alert_box({
                    'title': "",
                    'text': "text_sql_load_error",
                    'param': escape(obj.result.error.message),
                    'is_escaped': true
                });
            }
        });
    } else {
        resolver_set_sql(obj);
    }

    var critical_inputs = $('#sql_driver, #sql_server, #sql_port, #sql_database, #sql_user');

    // reset critical input password requirement validation
    critical_inputs.off("change keyup");
    $("#sql_password").removeClass("input-placeholder-warning");

    // enable critical input password requirement validation for resolver edits
    if (g.current_resolver_name) {
        $('#sql_password').attr("placeholder", password_placeholder_not_changed);

        critical_inputs.on('change keyup', function (e) {
            var sth_changed = $('#sql_driver').val() != obj.result.value.data.Driver
                || $('#sql_server').val() != obj.result.value.data.Server
                || $('#sql_port').val() != obj.result.value.data.Port
                || $('#sql_database').val() != obj.result.value.data.Database
                || $('#sql_user').val() != obj.result.value.data.User;

            $("#sql_password").rules("add", {
                required: sth_changed
            });

            $('#sql_password').attr("placeholder", (sth_changed ? password_placeholder_required : password_placeholder_not_changed));

            if (!sth_changed) {
                $("#sql_password").valid();
                $("#sql_password").removeClass("input-placeholder-warning");
            }
            else {
                $("#sql_password").addClass("input-placeholder-warning");
            }
        });
    }
    else {
        $('#sql_password').attr("placeholder", password_placeholder_required);
    }

    $dialog_sql_resolver.dialog('open');


    $form_validator_sql = $("#form_sqlconfig").validate({
        rules: {
            sql_resolvername: {
                required: true,
                minlength: 4,
                resolvername: true,
                unique_resolver_name: true
            },
            sql_driver: {
                required: true,
                minlength: 3,
                number: false
                //sql_driver: true
            },
            sql_port: {
                minlength: 1,
                number: true
            },
            sql_limit: {
                minlength: 1,
                number: true
            },
            sql_mapping: {
                valid_json: true,
                required: true,
                minlength: 5,
                sql_mapping: true
            }
        }
    });

    // make password field required if it is a new resolver and therefor name is empty
    $("#sql_password").rules("add", {
        required: !g.current_resolver_name
    });
}

function confirm_cancel_dialog(dialogname) {
    var defer = $.Deferred();
    var text = '<div style="text-align: center"><br/>' +
        sprintf(i18n.gettext("The %s dialog contains unsaved changes."), dialogname) +
        '<br/><br/>' +
        i18n.gettext('Do you really want to close the dialog and discard the changes?') +
        '</div>';

    $(text).dialog({
        title: i18n.gettext("Close Dialog"),
        width: 500,
        modal: true,
        buttons: [

            {
                text: i18n.gettext("Cancel"),
                click: function () {
                    $(this).dialog("close");
                    defer.reject("false");
                }
            },
            {
                text: i18n.gettext("Discard"),
                click: function () {
                    $(this).dialog("close");
                    defer.resolve("true");
                }
            }
        ]
    });
    return defer.promise();
}

function split(val) {
    return val.split(/,\s*/);
}
function extractLast(term) {
    return split(term).pop();
}

/*
 * This function needs to be called, whenever the scope is changed or loaded.
 */
function renew_policy_actions() {
    var scope = $('#policy_scope_combo').val();
    var actions = get_scope_actions(scope);
    define_policy_action_autocomplete(actions);
}

/*
 * This sets the allowed actions in the policy action input
 */
function define_policy_action_autocomplete(availableActions) {
    $("#policy_action")
        .autocomplete({
            minLength: 0,
            source: function (request, response) {
                // delegate back to autocomplete, but extract the last term
                response($.ui.autocomplete.filter(
                    availableActions, extractLast(request.term)));
            },
            focus: function () {
                // prevent value inserted on focus
                return false;
            },
            select: function (event, ui) {
                var terms = split(this.value);
                // remove the current input
                terms.pop();
                // add the selected item
                terms.push(ui.item.value);
                // add placeholder to get the comma-and-space at the end
                terms.push("");
                this.value = terms.join(", ");
                return false;
            }
        });
}

function view_policy() {
    $("#policy_table").flexigrid({
        url: '/system/policies_flexi',
        method: 'POST',
        dataType: 'json',
        colModel: [
            { display: i18n.gettext('Active'), name: 'active', width: 35, sortable: true },
            { display: i18n.gettext('Name'), name: 'name', width: 100, sortable: true },
            { display: i18n.gettext('User'), name: 'user', width: 80, sortable: true },
            { display: i18n.gettext('Scope'), name: 'scope', width: 80, sortable: true },
            { display: i18n.gettext('Action'), name: 'action', width: 200, sortable: true },
            { display: i18n.gettext('Realm'), name: 'realm', width: 100, sortable: true },
            { display: i18n.gettext('Client'), name: 'client', width: 200, sortable: true },
            { display: i18n.gettext('Time'), name: 'time', width: 50, sortable: true }
        ],
        height: 200,
        rpOptions: [10, 15, 20, 50, 100],
        sortname: "name",
        sortorder: "asc",
        useRp: true,
        rp: 50,
        usepager: true,
        singleSelect: true,
        showTableToggleBtn: true,
        preProcess: pre_flexi,
        onError: error_flexi,
        onSubmit: on_submit_flexi,
        dblClickResize: true
    });

    $('#policy_export').attr("href", '/system/getPolicy?export=true&display_inactive=true');

    $('#policy_import').click(function () {
        $dialog_import_policy.dialog("open");
    });

    $('#button_policy_add').click(function (event) {
        event.preventDefault();
        var pol_name = $('#policy_name').val();
        pol_name = $.trim(pol_name);
        if (pol_name.length == 0) {
            alert_box({
                'title': 'Policy Name',
                'text': "text_policy_name_not_empty",
                'is_escaped': true
            });
            return;
        }

        if ($('#policy_active').is(':checked')) {
            pol_active = "True";
        } else {
            pol_active = "False";
        }
        var params = {
            'name': $('#policy_name').val(),
            'user': $('#policy_user').val(),
            'action': $('#policy_action').val(),
            'scope': $('#policy_scope_combo').val(),
            'realm': $('#policy_realm').val(),
            'time': $('#policy_time').val(),
            'client': $('#policy_client').val(),
            'active': pol_active,
        };
        $.post('/system/setPolicy', params,
            function (data, textStatus, XMLHttpRequest) {
                if (data.result.status == true) {
                    alert_info_text({
                        'text': "text_policy_set",
                        'is_escaped': true
                    });
                    $('#policy_table').flexReload();
                } else {
                    alert_info_text({
                        'text': escape(data.result.error.message),
                        'type': ERROR,
                        'is_escaped': true
                    });
                }
            });
    });

    $('#button_policy_delete').click(function (event) {
        event.preventDefault();
        var policy = get_selected_policy().join(',');
        if (policy) {
            var params = { 'name': policy };
            $.post('/system/delPolicy', params,
                function (data, textStatus, XMLHttpRequest) {
                    if (data.result.status == true) {
                        alert_info_text({
                            'text': "text_policy_deleted",
                            'is_escaped': true
                        });
                        $('#policy_table').flexReload();
                    } else {
                        alert_info_text({
                            'text': escape(data.result.error.message),
                            "type": ERROR,
                            'is_escaped': true
                        });
                    }
                });
            $('#policy_form').trigger("reset");
        }
    });

    $('#button_policy_clear').click(function (event) {
        event.preventDefault();
        $('#policy_form').trigger("reset");
    });

    $('#policy_scope_combo').change(function () {
        renew_policy_actions();
    });

    $('#policy_table').click(function (event) {
        get_selected();
    });

    sortChildsOfElement("#policy_scope_combo");
}

function sortChildsOfElement(elem) {
    $(elem).each(function () {
        var items = $(this).children().get();
        items.sort(function (a, b) {
            var keyA = $(a).text();
            keyA = $.trim(keyA).toLowerCase();

            var keyB = $(b).text();
            keyB = $.trim(keyB).toLowerCase();

            if (keyA < keyB) return -1;
            if (keyA > keyB) return 1;
            return 0;
        });
        var parent = $(elem);
        $.each(items, function (i, child) {
            parent.append(child);
        });
    });
}

function view_token() {
    $("#token_table").flexigrid({
        url: '/manage/tokenview_flexi',
        method: 'POST',
        dataType: 'json',
        colModel: [
            { display: i18n.gettext('Serial Number'), name: 'TokenSerialnumber', width: 100, sortable: true, align: 'center' },
            { display: i18n.gettext('Active'), name: 'Isactive', width: 40, sortable: true, align: 'center' },
            { display: i18n.gettext('Username'), name: 'Username', width: 100, sortable: false, align: 'center' },
            { display: i18n.gettext('Realm'), name: 'realm', width: 100, sortable: false, align: 'center' },
            { display: i18n.gettext('Type'), name: 'TokenType', width: 50, sortable: true, align: 'center' },
            { display: i18n.gettext('Login Attempts Failed'), name: 'FailCount', width: 140, sortable: true, align: 'center' },
            { display: i18n.gettext('Description'), name: 'TokenDesc', width: 100, sortable: true, align: 'center' },
            { display: i18n.gettext('Max Login Attempts'), name: 'maxfailcount', width: 110, sortable: false, align: 'center' },
            { display: i18n.gettext('OTP Length'), name: 'otplen', width: 75, sortable: false, align: 'center' },
            { display: i18n.gettext('Count Window'), name: 'countwindow', width: 90, sortable: false, align: 'center' },
            { display: i18n.gettext('Sync Window'), name: 'syncwindow', width: 80, sortable: false, align: 'center' },
            { display: i18n.gettext('User ID'), name: 'Userid', width: 60, sortable: true, align: 'center' },
            { display: i18n.gettext('Resolver'), name: 'IdResolver', width: 200, sortable: true, align: 'center' }
        ],
        height: 400,
        searchitems: [
            { display: i18n.gettext('Login Name'), name: 'loginname', isdefault: true },
            { display: i18n.gettext('All other columns'), name: 'all' },
            { display: i18n.gettext('Realm'), name: 'realm' }
        ],
        rpOptions: [10, 15, 20, 50, 100],
        sortname: "TokenSerialnumber",
        sortorder: "asc",
        useRp: true,
        rp: 15,
        usepager: true,
        showTableToggleBtn: true,
        preProcess: pre_flexi,
        onError: error_flexi,
        onSubmit: on_submit_flexi,
        onSuccess: show_selected_status,
        dblClickResize: true,
        searchbutton: true
    });
    $('#token_table').click(function (event) {
        get_selected();
    });

}

function view_user() {
    $("#user_table").flexigrid({
        url: '/manage/userview_flexi',
        method: 'POST',
        dataType: 'json',
        colModel: [
            { display: i18n.gettext('Username'), name: 'username', width: 90, sortable: true, align: "left" },
            { display: i18n.gettext('UserIdResolver'), name: 'useridresolver', width: 200, sortable: true, align: "left" },
            { display: i18n.gettext('Surname'), name: 'surname', width: 100, sortable: true, align: "left" },
            { display: i18n.gettext('Given Name'), name: 'givenname', width: 100, sortable: true, align: "left" },
            { display: i18n.gettext('Email'), name: 'email', width: 100, sortable: false, align: "left" },
            { display: i18n.gettext('Mobile'), name: 'mobile', width: 50, sortable: true, align: "left" },
            { display: i18n.gettext('Phone'), name: 'phone', width: 50, sortable: false, align: "left" },
            { display: i18n.gettext('User ID'), name: 'userid', width: 200, sortable: true, align: "left" }
        ],
        height: 400,
        searchitems: [
            { display: i18n.gettext('Username'), name: 'username', isdefault: true },
            { display: i18n.gettext('Surname'), name: 'surname' },
            { display: i18n.gettext('Given Name'), name: 'givenname' },
            { display: i18n.gettext('Description'), name: 'description' },
            { display: i18n.gettext('User ID'), name: 'userid' },
            { display: i18n.gettext('Email'), name: 'email' },
            { display: i18n.gettext('Mobile'), name: 'mobile' },
            { display: i18n.gettext('Phone'), name: 'phone' }
        ],
        rpOptions: [15, 20, 50, 100],
        sortname: "username",
        sortorder: "asc",
        useRp: true,
        singleSelect: true,
        rp: 15,
        usepager: true,
        showTableToggleBtn: true,
        preProcess: pre_flexi,
        onError: error_flexi,
        onSubmit: on_submit_flexi,
        onSuccess: show_selected_status,
        dblClickResize: true,
        searchbutton: true
    });

    $('#user_table').click(function (event) {
        get_selected();
    });
}

function view_audit() {
    $("#audit_table").flexigrid({
        url: '/audit/search',
        method: 'POST',
        dataType: 'json',
        colModel: [
            { display: i18n.gettext('Number'), name: 'number', width: 50, sortable: true },
            { display: i18n.gettext('Date (UTC)'), name: 'date', width: 200, sortable: true },
            { display: i18n.gettext('Signature'), name: 'signature', width: 60, sortable: false },
            { display: i18n.gettext('Missing Lines'), name: 'missing_lines', width: 90, sortable: false },
            { display: i18n.gettext('Action'), name: 'action', width: 120, sortable: true },
            { display: i18n.gettext('Success'), name: 'success', width: 50, sortable: true },
            { display: i18n.gettext('Serial'), name: 'serial', width: 100, sortable: true },
            { display: i18n.gettext('Token Type'), name: 'tokentype', width: 80, sortable: true },
            { display: i18n.gettext('User'), name: 'user', width: 100, sortable: true },
            { display: i18n.gettext('Realm'), name: 'realm', width: 100, sortable: true },
            { display: i18n.gettext('Administrator'), name: 'administrator', width: 100, sortable: true },
            { display: i18n.gettext('Action Detail'), name: 'action_detail', width: 200, sortable: true },
            { display: i18n.gettext('Info'), name: 'info', width: 200, sortable: true },
            { display: i18n.gettext('LinOTP Server'), name: 'linotp_server', width: 100, sortable: true },
            { display: i18n.gettext('Client'), name: 'client', width: 100, sortable: true },
            { display: i18n.gettext('Log Level'), name: 'log_level', width: 40, sortable: true },
            { display: i18n.gettext('Clearance Level'), name: 'clearance_level', width: 20, sortable: true }
        ],
        height: 400,
        searchitems: [
            { display: i18n.gettext('Serial'), name: 'serial', isdefault: true },
            { display: i18n.gettext('User'), name: 'user', isdefault: false },
            { display: i18n.gettext('Realm'), name: 'realm', isdefault: false },
            { display: i18n.gettext('Action'), name: 'action' },
            { display: i18n.gettext('Action Detail'), name: 'action_detail' },
            { display: i18n.gettext('Token Type'), name: 'token_type' },
            { display: i18n.gettext('Administrator'), name: 'administrator' },
            { display: i18n.gettext('Successful'), name: 'success' },
            { display: i18n.gettext('Info'), name: 'info' },
            { display: i18n.gettext('LinOTP Server'), name: 'linotp_server' },
            { display: i18n.gettext('Client'), name: 'client' },
            { display: i18n.gettext('Date (UTC)'), name: 'date' },
            { display: i18n.gettext('Extended Search'), name: 'extsearch' }
        ],
        rpOptions: [10, 15, 30, 50],
        sortname: "number",
        sortorder: "desc",
        useRp: true,
        singleSelect: true,
        rp: 15,
        usepager: true,
        showTableToggleBtn: true,
        preProcess: pre_flexi,
        onError: error_flexi,
        onSubmit: on_submit_flexi,
        searchbutton: true
    });
}

loadTranslations();
