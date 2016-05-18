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
window.onerror = error_handling;

/* Use Jed for i18n. The correct JSON file is dynamically loaded later. */
var i18n = new Jed({});
var sprintf = Jed.sprintf;

encodings = [
    "ascii","big5","big5hkscs",
    "cp037","cp424","cp437",
    "cp500","cp720","cp737",
    "cp775","cp850","cp852",
    "cp855","cp856","cp857",
    "cp858","cp860","cp862",
    "cp863","cp864","cp865",
    "cp866","cp869","cp874",
    "cp875","cp932","cp949",
    "cp950","cp1006","cp1026",
    "cp1140","cp1250","cp1251",
    "cp1252","cp1253","cp1254",
    "cp1255","cp1256","cp1257",
    "cp1258","euc_jp","euc_jis_2004",
    "euc_jisx0213","euc_kr",
    "gb2312","gbk","gb18030",
    "hz","iso2022_jp",
    "iso2022_jp_1","iso_2022_jp_2",
    "iso2022_jp_2004",
    "iso2022_jp_3",
    "iso2022_jp_ext",
    "iso2022_kr",
    "latin_1",
    "iso8859_1",
    "iso8859_2",
    "iso8859_3",
    "iso8859_4",
    "iso8859_5",
    "iso8859_6",
    "iso8859_7",
    "iso8859_8",
    "iso8859_9",
    "iso8859_10",
    "iso8859_13",
    "iso8859_14",
    "iso8859_15",
    "iso8859_16",
    "johab",
    "koi8_r","koi8_u",
    "mac_cyrillic",
    "mac_greek",
    "mac_iceland",
    "mac_latin2",
    "mac_roman",
    "mac_turkish",
    "ptcp154",
    "shift_jis",
    "shift_jis_2004",
    "shift_jisx0213",
    "utf_32",
    "utf_32_be",
    "utf_32_le",
    "utf_16",
    "utf_16_be",
    "utf_16_le",
    "utf_7",
    "utf_8",
    "utf_8_sig"
];


function error_handling(message, file, line){
    Fehler = "We are sorry. An internal error occurred:\n" + message + "\nin file:" + file + "\nin line:" + line +
    "\nTo go on, reload this web page.";
    alert(escape(Fehler));
    return true;
}

function Logout(logout_url) {
/* clear the admin cookie and
   * for IE try to clean the ClearAuthenticationCache and reload same page
   * for Firefox/Chrome redirect to a location, with new basic auth in url
*/

    var done = false;
    done = document.execCommand("ClearAuthenticationCache", false);
    $.cookie("admin_session", "invalid", {expires: 0,  path: '/'});

    if (done == true) {
        window.location.href = document.URL;
    } else {
        window.location.href = logout_url;
    }
}

/*
 * add the jquery validation methods
 */
$.validator.addMethod('valid_json', function (value, element, param) {
    var isValid = false;
    try {
        var obj = $.parseJSON(value);
        isValid = true;
    } catch(err) {
        isValid = false;
    }
    return isValid;
    },
    i18n.gettext('Not a valid json string!')
);

jQuery.validator.addMethod("realmname", function(value, element, param){
    return value.match(/^[a-zA-z0-9_\-\.]+$/i);
    },
    i18n.gettext("Please enter a valid realm name. It may contain characters, numbers and '_-.'.")
);

jQuery.validator.addMethod("resolvername", function(value, element, param){
    return value.match(/^[a-zA-z0-9_\-]+$/i);
    },
    i18n.gettext("Please enter a valid resolver name. It may contain characters, numbers and '_-'.")
);

jQuery.validator.addMethod("ldap_uri", function(value, element, param){
    return value.match(param);
    },
    i18n.gettext("Please enter a valid ldap uri. It needs to start with ldap:// or ldaps://")
);
jQuery.validator.addMethod("http_uri", function(value, element, param){
    return value.match(param);
    },
    i18n.gettext("Please enter a valid http uri. It needs to start with http:// or https://")
);

//LDAPTIMEOUT: "(float or number) | (float or number; float or number)"
jQuery.validator.addMethod("ldap_timeout", function(value, element, param){
	var float_tuple = /(^[+]?[0-9]+(\.[0-9]+){0,1}$)|((^[+]?[0-9]+(\.[0-9]+){0,1})\s*;\s*([+]?[0-9]+(\.[0-9]+){0,1}$))/;
    return value.match(float_tuple);
    },
    i18n.gettext("Please enter a timeout like: 5.0; 5.0 ")
);

// LDAPSEARCHFILTER: "(sAMAccountName=*)(objectClass=user)"
jQuery.validator.addMethod("ldap_searchfilter", function(value, element, param){
    return value.match(/(\(\S+=(\S+).*\))+/);
    },
    i18n.gettext("Please enter a valid searchfilter like this: (sAMAccountName=*)(objectClass=user)")
);

// LDAPFILTER: "(&(sAMAccountName=%s)(objectClass=user))"
jQuery.validator.addMethod("ldap_userfilter", function(value, element, param){
    return value.match(/\(\&(\(\S+=(\S+).*\))+\)/);
    },
    i18n.gettext("Please enter a valid user searchfilter like this: (&(sAMAccountName=%s)(objectClass=user))")
);

jQuery.validator.addMethod("ldap_mapping", function(value, element, param){
    return value.match(/{.+}/);
    },
    i18n.gettext('Please enter a valid searchfilter like this: \
    { "username": "sAMAccountName", "phone" : "telephoneNumber", "mobile" \
    : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }')
);

jQuery.validator.addMethod("ldap_uidtype", function(value,element,param){
    return value.match(/.*/);
    },
    i18n.gettext('Please enter the UID of your LDAP server like DN, entryUUID, objectGUID or GUID')
);

jQuery.validator.addMethod("sql_driver", function(value, element, param){
    return value.match(/(mysql)|(postgres)|(mssql)|(oracle)|(ibm_db_sa\+pyodbc)|(ibm_db_sa)/);
    },
    i18n.gettext("Please enter a valid driver specification like: mysql, postgres, mssql, oracle, ibm_db_sa or ibm_db_sa+pyodbc")
);

jQuery.validator.addMethod("sql_mapping", function(value, element, param){
    return value.match(/{.+}/);
    },
    i18n.gettext('Please enter a valid searchfilter like this: \
    { "username": "usercolumn", "password":"pw", "salt": "salt", "phone" : "telephoneNumber", "mobile" \
    : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }')
);


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

// FIXME: global variable should be worked out
var g = {};
    g.display_genkey = false;
    g.running_requests = 0;
    g.resolver_to_edit = "";
    g.realm_to_edit = "";
    g.resolvers_in_realm_to_edit = "";
    g.realms_of_token = new Array();

ERROR = "error";

var support_license_dict = {
    'comment' : i18n.gettext('Description'),
    'issuer' : i18n.gettext('Issuer'),
    'token-num' : i18n.gettext('Number of tokens'),
    'licensee' : i18n.gettext('Licensee'),
    'address' : i18n.gettext('Address'),
    'contact-name' : i18n.gettext('Contact name'),
    'contact-email' : i18n.gettext('Contact EMail'),
    'contact-phone' : i18n.gettext('Contact phone'),
    'date' : i18n.gettext('Date'),
    'expire' : i18n.gettext('Expiration'),
    'subscription' : i18n.gettext('Subscription'),
    'version' : i18n.gettext('Version'),
};

function len(obj) {
  var len = obj.length ? --obj.length : -1;
    for (var k in obj)
      len++;
  return len;
}


function error_flexi(data){
    // we might do some mods here...
    alert_info_text({'text': "text_error_fetching_list",
                     "type": ERROR,
                    'is_escaped': true});
}

function pre_flexi(data){
    // adjust the input for the linotp api version >= 2.0
    if (data.result) {
        if (data.result.status === false) {
            alert_info_text({'text': escape(data.result.error.message),
                            'is_escaped': true});
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

function on_submit_flexi(){
/*
 * callback, to add in parameters to the flexi grid
 */
    var active_realm = $('#realm').val();
    var session = getsession();

    var params = [
        {name: 'realm', value: active_realm},
        {name: 'session', value: session},
        ];

    var policy_params = [
        {name: 'session', value: session},
        ];

    $('#user_table').flexOptions({params: params});
    $('#audit_table').flexOptions({params: params});
    $('#token_table').flexOptions({params: params});
    $('#policy_table').flexOptions({params: policy_params});

    return true;
}

function alert_info_text(params) {
/*
 * write tnto the report line
 * :param params: dicttionary with
 * text - If the parameter is the ID of an element, we pass the text
 *       of this very element
 * param - replace parameter
 * display_type: report or ERROR
 */

    var s = params['text'] || '';
    var text_container = params['param'] || '';
    var display_type = params['type'] || '';
    var is_escaped = params['is_escaped'] || false;

    if (is_escaped == false)
    {
        text_container = escape(text_container);
        s = escape(s);
    }
    /*
     * If the parameter is the ID of an element, we pass the text from this very element
     */
    str = s;
    try {
        if (text_container) {
            $('#'+s+' .text_param1').html(text_container);
        }
        if ( $('#'+s).length > 0 ) { // Element exists!
            s = $('#'+s).html();
        } else {
            s = str;
        }

    }
    catch (e) {
        s = str;
    }

    new_info_bar = $('#info_bar').clone(true,true)
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
    new_info_bar.show()

    toggle_close_all_link();

    $('#info_box').show();
}

function toggle_close_all_link() {
    /*
     * This function counts the number of visible info boxes and error boxes and
     * if more than 1 are displayed it shows the "Close all" link. Otherwise it
     * hides the link.
     */
    visible_boxes = $("#info_box > div").filter(":visible");
    close_all = $("a.close_all");
    if (visible_boxes.length > 1) {
        close_all.click(function( event ) {
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

function alert_box(params) {
/*
 * pop up an alert box
 * :param params: dicttionary
 * s - If the parameter is the ID of an element, we pass the text
 *     of this very element
 */

    var escaped = params['is_escaped'] || false;
    var title = params['title'] || '';
    var s = params['text'] || '';
    var param1 = params['param'] || '';

    if (escaped == false)
    {
        title = escape(title);
        s = escape(s);
        param1 = escape(param1);
    }

    str = s;
    try {
        if (param1) {
            $('#'+s+' .text_param1').html(param1);
        }
        if ( $('#'+s).length > 0 ) { // Element exists!
            s=$('#'+s).html();
        } else {
            s = str;
        }

    }
    catch (e) {
        s = str;
    }
    title_t = title;
    try {
        if ($('#'+title).length > 0 ) {
            title_t=$('#'+title).text();
        } else {
            title_t = title;
        }
    } catch(e) {
        title_t = title;
    }

     $('#alert_box').dialog("option", "title", title_t);
     $('#alert_box_text').html(s);
     $('#alert_box').dialog("open");

}

// ####################################################
//
//  functions for seletected tokens and selected users
//

function get_selected_tokens(){
    var selectedTokenItems = new Array();
    var tt = $("#token_table");
    $('.trSelected', tt).each(function(){
        var id = $(this).attr('id');
        var serial = id.replace(/row/, "");
        //var serial = $(this).attr('cells')[0].textContent;
        selectedTokenItems.push(serial);
    });
    return selectedTokenItems;
}

function get_selected_user(){
    /*
     * This function returns the list of selected users.
     * Each list element is an object with
     *  - login
     *  - resolver
     */
    var selectedUserItems = new Array();
    var tt = $("#user_table");
    var selected = $('.trSelected', tt);
    if (selected.length > 1){
        // unselect all selected users - as the last selected could not be identified easily
        selected.removeClass('trSelected');
        alert_box({'title': i18n.gettext("User selection:"),
                   'text' : i18n.gettext("Selection of more than one user is not supported!")+"<p>"
                            + i18n.gettext("Please select only one user.") + "</p>",
                   'is_escaped': true});
        return selectedUserItems;
    }
    var actual_realm = $('#realm').val();
    selected.each(function(){
        var user = new Object();
        user = { resolver:"" , login:"" , realm:actual_realm };
        column = $('td', $(this));
        column.each(function(){
            var attr = $(this).attr("abbr");
            if (attr == "useridresolver") {
                var loc = $('div', $(this)).html();
                var resolver = escape(loc.split('.'));
                user.resolver = resolver[resolver.length-1];
            }
        });

        var id = $(this).attr('id');
        user.login = id.replace(/row/, "");
        selectedUserItems.push(user);
    });
    return selectedUserItems;
}

function get_selected_policy(){
    var selectedPolicy = new Array();
    var pt = $('#policy_table');
    $('.trSelected', pt).each(function(){
        var id = $(this).attr('id');
        var policy = id.replace(/row/, "");
        selectedPolicy.push(policy);
    });
    return selectedPolicy;
}

function get_scope_actions(scope) {
    /*
     * This function returns the allowed actions within a scope
     */
    var actions = Array();
    var resp = clientUrlFetchSync("/system/getPolicyDef",
                                  {"scope" : scope},
                                  true, "Error fetching policy definitions:");
    var obj = jQuery.parseJSON(resp);
    if (obj.result.status) {
            for (var k in obj.result.value) {
                action = k;
                if ("int"==obj.result.value[k].type) {
                    action = k+"=<int>";
                } else
                if ("str"==obj.result.value[k].type) {
                    action = k+"=<string>";
                };
                actions.push(action);
            }
    }
    return actions.sort();
}

function get_policy(definition) {
    /*
     * This function returns the policies which conform to the
     * set of definitions: scope, action, user, realm
     */
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

function get_selected_mobile(){
    var selectedMobileItems = new Array();
    var tt = $("#user_table");

    var yourAbbr = "mobile";
    var column = tt.parent(".bDiv").siblings(".hDiv").find("table tr th").index($("th[abbr='" + yourAbbr + "']",
                ".flexigrid:has(#user_table)"));

    $('.trSelected', tt).each(function(){
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
    var column = tt.parent(".bDiv").siblings(".hDiv").find("table tr th").index($("th[abbr='"+yourAbbr+"']",
                 ".flexigrid:has(#user_table)"));
    $('.trSelected', tt).each(function(){
        //var value = tt.children("td").eq(column).text();
        var value = $('.trSelected td:eq(4)', tt).text();
        selectedEmailItems.push(value);
    });
    return selectedEmailItems;
}

function get_token_owner(token_serial){

    // sorry: we need to do this synchronously
    var resp = clientUrlFetchSync('/admin/getTokenOwner',
                                    {'serial': token_serial});
    if (resp == undefined) {
        alert('Server is not responding');
        return 0;
    }
    var obj = jQuery.parseJSON(resp);
    return obj.result.value;

}

function show_selected_status(){
    var selectedUserItems = get_selected_user();
    var selectedTokenItems = get_selected_tokens();
    $('#selected_tokens').html(escape(selectedTokenItems.join(", ")));
    // we can only select a single user
    if ( selectedUserItems.length > 0 )
        $('#selected_users').html(escape(selectedUserItems[0].login));
    else
        $('#selected_users').html("");
}

function get_selected(){
    var selectedUserItems = get_selected_user();
    var selectedTokenItems = get_selected_tokens();
    $('#selected_tokens').html(escape(selectedTokenItems.join(", ")));
    // we can only select a single user
    if ( selectedUserItems.length > 0 )
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

        if (selectedTokenItems.length == 0) {
            $("#button_tokenrealm").button("disable");
            $("#button_resync").button("disable");
            $("#button_losttoken").button("disable");
            $('#button_getmulti').button("disable");
            $("#button_tokeninfo").button("disable");
        }
        else if (selectedTokenItems.length == 1) {
            $("#button_tokenrealm").button("enable");
            $("#button_resync").button("enable");
            $('#button_losttoken').button("enable");
            $('#button_getmulti').button("enable");
            $("#button_tokeninfo").button("enable");
          }
        else if (selectedTokenItems.length > 1) {
            $("#button_tokenrealm").button("enable");
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
        	var params = {'name' : policy,
                    'display_inactive': '1',
                    'session':getsession()};
            $.post('/system/getPolicy', params,
             function(data, textStatus, XMLHttpRequest){
                if (data.result.status == true) {
                    policies = policy.split(',');
                    pol = policies[0];
                    var pol_active = data.result.value[pol].active;
                    if (pol_active == undefined) {
                        pol_active = "True";
                    }
                    $('#policy_active').prop('checked', pol_active=="True");
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

function disable_all_buttons(){
    $('#button_assign').button("disable");
    $('#button_unassign').button("disable");
    $('#button_tokenrealm').button("disable");
    $('#button_getmulti').button("disable");
    $('#button_enable').button("disable");
    $('#button_disable').button("disable");
    $('#button_setpin').button("disable");
    $('#button_delete').button("disable");
    $('#button_resetcounter').button("disable");
    $("#button_resync").button("disable");
    $("#button_tokeninfo").button("disable");
    $("#button_losttoken").button("disable");
}

function init_$tokentypes(){
/*
 * initalize the list of all avaliable token types
 * - required to show and hide the dynamic enrollment section
 */
    var options = $('#tokentype > option');
    if ($tokentypes == undefined) {$tokentypes = {};};
    options.each(
      function(i){
        var key = $(this).val();
        var title = $(this).text();
        $tokentypes[key] = title;
      }
    );
}



function get_server_config() {
/*
 * retrieve the linotp server config
 *
 * return the config as dict
 * or raise an exception
 */

    var $systemConfig = {};
    var resp = clientUrlFetchSync('/system/getConfig', {});
    try {
        var data = jQuery.parseJSON(resp);
        if (data.result.status == false) {
            //console_log("Failed to access linotp system config: " + data.result.error.message);
            throw("" + data.result.error.message);
        }else {
            $systemConfig = data.result.value;
            //console_log("Access linotp system config: " + data.result.value);
        }
    }
    catch (e) {
        //console_log("Failed to access linotp system config: " + e);
        throw(e);
    }
    return $systemConfig;
}

var $token_config_changed = [];

function load_token_config() {

    var selectTag = $('#tab_token_settings');
    selectTag.find('div').each(
        function() {
          var attr =$(this).attr('id');
          var n= attr.split("_");
          var tt = n[0];
          $tokenConfigCallbacks[tt] = tt+'_get_config_params';
          $tokenConfigInbacks[tt]   = tt+'_get_config_val';
        }
    );
    $('#tab_token_settings div form :input').change(
        function(){
            var attr = $(this).closest("form").closest("div").attr('id');
            var n= attr.split("_");
            var tt = n[0];
            $token_config_changed.push(tt);
            var nn = "#" +tt + "_token_settings";
            var label = $("#tab_token_settings [href='"+nn+"']").closest('a').text();

            var marker = "* ";

            if (label.substring(0, marker.length) !== marker) {
                $("#tab_token_settings [href='"+nn+"']").closest('a').text(marker + label);
                //$("#tab_token_settings [href='"+nn+"']").closest('a').attr( "class", 'token_config_changed');
            }
        }
    );

    // might raise an error, which must be catched by the caller
    $systemConfig = get_server_config();

    for (tt in $tokenConfigInbacks) {
        try{
            var functionString = ''+$tokenConfigInbacks[tt]+'';
            var funct = window[functionString];
            var exi = typeof funct;
            var l_params = {};
            if (exi == 'function') {
                l_params = window[functionString]();
            }

            for (var key in l_params) {
                if (key in $systemConfig) {
                    try{
                        //alert('Val = >' + $systemConfig[key] + '<');
                        //console_log("  " + key + ": " + l_params[key] + '  ' +  $systemConfig[key] + 'not found!');
                        $('#'+l_params[key]).val( $systemConfig[key] );

                    } catch(err) {
                        //console_log('error ' + err + "  " + key + ": " + l_params[key] + '  ' + 'not found!')
                    }
                }
            }
        }
        catch(err) {
            //console_log('callbacack for ' + tt + ' not found!')
        }
    }
    return;
}
/*
callback save_token_config()
*/
function save_token_config(){
    show_waiting();
    /* for every token call the getParamCallback */
    var params = {'session': getsession()};
    for (tt in $tokenConfigCallbacks) {
        try{
            if ($.inArray(tt, $token_config_changed)!==-1) {
                var functionString = ''+$tokenConfigCallbacks[tt];
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
        catch(err) {
            //console_log('callbacack for ' + tt + ' not found!')
        }

    }
    //console_log(params)
    $.post('/system/setConfig', params,
     function(data, textStatus, XMLHttpRequest){
        hide_waiting();
        if (data.result.status == false) {
            alert_info_text({'text': escape(data.result.error.message),
                             'type': ERROR,
                             'is_escaped': true});
        }
    });
}


/*
 * Retrieve session cookie if it does not exist
 */


function getsession(){
    var session="";
    if (document.cookie) {
        session = getcookie("admin_session");
   }
   if ("" == session) {
        // we need to get the session ID synchronous or we will have unpredictiable
        // behavious
        var resp = $.ajax({
            url: '/admin/getsession',
            async: false,
            type: "POST"
        }).responseText;
        var data = jQuery.parseJSON(resp);

        if (data.result.value == true)
            session=getcookie("admin_session");
    }
    return session;
}


function reset_waiting() {
    g.running_requests = 0;
    hide_waiting();
}

// ####################################################
//
//  URL fetching
// The myURL needs to end with ? if it has no parameters!


function clientUrlFetch(myUrl, params, callback, parameter){
    /*
     * clientUrlFetch - to submit a asyncronous http request
     *
     * @remark: introduced the params (:dict:) so we could switch to
     *          a POST request, which will allow more and secure data
     */
    if (!('session' in params)) {
        params['session'] = getsession();
    }

    show_waiting();

    g.running_requests = g.running_requests +1 ;

    promise = $.ajax({
        url: myUrl,
        data : params,
        async: true,
        type: 'POST',
        complete: function(xhdr, textStatus) {
            g.running_requests = g.running_requests -1;
            if (g.running_requests <= 0) {
                hide_waiting();
                g.running_requests = 0;
            }
            if (callback != null) {
                callback(xhdr, textStatus, parameter);
            }
        }
      });
    return promise
}

function clientUrlFetchSync(myUrl,params){
    /*
     * clientUrlFetchSync - to submit a syncronous  http request
     *
     * @remark: introduced the params (:dict:) so we could switch to
     *          a POST request, which will allow more and secure data
     */

    var session = getsession();
    //myUrl     = myUrl + "&session=" + session;
    params['session'] = session;

    show_waiting();

    var resp = $.ajax({
        url: myUrl,
        data : params,
        async: false,
        type: 'POST',
        }
    ).responseText;
    hide_waiting();
    return resp;
}


// ####################################################
// get overall number of tokens
function get_tokennum(){
    // sorry: we need to do this synchronously
    var resp = clientUrlFetchSync('/admin/show', {'page':1,'pagesize':1,
                                                  'filter' : '/:token is active:/'});
    if (resp == undefined) {
        alert('Server is not responding');
        return 0;
    }
    var obj = jQuery.parseJSON(resp);
    return obj.result.value.resultset.tokens;
}

function check_license(){
    /* call the server license check*/
    var resp = clientUrlFetchSync('/system/isSupportValid',{});
    var obj = jQuery.parseJSON(resp);
    if (obj.result.value === false) {
       message = escape(obj.detail.reason);
       intro = escape($('#text_support_lic_error').html());
       alert_info_text({'text': intro + " " + message,
                        'type': ERROR,
                        'is_escaped': true
                        });
    }
    if (obj['detail'] && obj.detail['download_licence_info']) {
        $('#dialog_support_contact').html(obj.detail['download_licence_info']);
        $dialog_support_contact.dialog('open');
    }
}

function check_serial(serial){
    var resp = clientUrlFetchSync('/admin/check_serial',{'serial':serial});
    var obj = jQuery.parseJSON(resp);
    return obj.result.value.new_serial;
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

function assign_callback(xhdr, textStatus, serial) {
    resp = xhdr.responseText;
    obj = jQuery.parseJSON(resp);
    if (obj.result.status == false) {
        alert_info_text({'title': escape(obj.result.error.message),
                         'type': ERROR,
                         'is_esacped': true});
    } else
        view_setpin_after_assigning([serial]);
    reset_buttons();
}

function token_operations_callback(responses) {
    /*
     * Evaluates a list of responses, displays a list of all the errors found
     * and finally reloads the page.
     */
    var error_messages = [];
    $.each(responses, function(index, responseData){
        // "responseData" will contain an array of response information for each specific request
        if (responseData.length !== 3 || responseData[1] !== 'success') {
            error_messages.push('Request ' + index +  ' unsucessful')
            return true; // skip to next item of each loop
        }
        var obj = responseData[0];
        if (obj.result.status == false) {
            error_messages.push(obj.result.error.message);
        }
        else if (obj.result.value == 0) {
            // No operation performed on token
            error_messages.push(obj.detail.message)
        }
    });

    if (error_messages.length > 0) {
        alert_info_text({'text': escape(error_messages.join(" -- ")),
                         'type': ERROR,
                         'is_escaped': true});
    }
    reset_buttons();
}

function token_operation(tokens, url, params) {
    /*
     * Performs an operation on a list of tokens
     *
     * tokens is a list of tokens (serial numbers)
     * url is the operation to perform. For example "/admin/remove"
     * params are any parameters required for the requests. You DON'T need to
     * pass in the session. Token serial is set inside this function as well.
     */
    if (!('session' in params)) {
        // To make the operation a tiny bit more efficient we fetch the session
        // once instead of in every request (as clientUrlFetch would do).
        params['session'] = getsession();
    }
    var requests = Array();
    for (var i = 0; i < tokens.length; i++) {
        params['serial'] = tokens[i];
        var promise = clientUrlFetch(url, params)
        requests.push(promise);
    }
    // By using the 'when' function (that takes a list of promises/deferreds as
    // input) we make sure 'reset_buttons()' is execute ONCE after ALL the
    // deletion requests have finished.
    var defer = $.when.apply($, requests);
    defer.done(function(){
        var responses = [];
        if (requests.length == 1) {
            // "arguments" will be the array of response information for the request
            responses = [arguments];
        }
        else {
            responses = arguments;
        }
        token_operations_callback(responses);
    });
}

function token_delete(){
    var tokens = get_selected_tokens();
    token_operation(tokens, "/admin/remove", {});
}

function token_unassign(){
    var tokens = get_selected_tokens();
    token_operation(tokens, "/admin/unassign", {});
}

function token_reset(){
    var tokens = get_selected_tokens();
    token_operation(tokens, "/admin/reset", {});
}

function token_disable(){
    var tokens = get_selected_tokens();
    token_operation(tokens, "/admin/disable", {});
}

function token_enable(){
    var tokens = get_selected_tokens();
    check_license();
    token_operation(tokens, "/admin/enable", {});
}

function token_assign(){

    tokentab = 0;
    tokens = get_selected_tokens();
    user = get_selected_user();
    count = tokens.length;
    for (i = 0; i < count; i++) {
        serial = tokens[i];
        clientUrlFetch("/admin/assign", {"serial": serial,
                                        "user": user[0].login,
                                        'resConf':user[0].resolver,
                                        'realm': $('#realm').val()}, assign_callback, serial);
    }
}

function token_resync_callback(xhdr, textStatus) {
    var resp = xhdr.responseText;
    var obj = jQuery.parseJSON(resp);
    if (obj.result.status) {
            if (obj.result.value)
                alert_info_text({'text': "text_resync_success",
                                 'is_escaped': true,
                                 });
            else
                alert_info_text({'text': "text_resync_fail",
                                 'type': ERROR,
                                 'is_escaped': true,
                                 });
    } else {
        message = escape(obj.result.error.message);
        alert_info_text({'text': message, 'type': ERROR, 'is_escaped': true});
    }

    reset_buttons();
}

function token_resync(){
    var tokentab = 0;
    var tokens = get_selected_tokens();
    var count = tokens.length;
    for (i = 0; i < count; i++) {
        var serial = tokens[i];
        clientUrlFetch("/admin/resync", {"serial" : serial, "otp1" : $('#otp1').val(), "otp2":  $('#otp2').val()}, token_resync_callback);
    }
}

function losttoken_callback(xhdr, textStatus){
    var resp = xhdr.responseText;

    obj = jQuery.parseJSON(resp);
    if (obj.result.status) {
        var serial = obj.result.value.serial;
        var end_date = obj.result.value.end_date;
        var password = '';
        if ('password' in obj.result.value){
            password = obj.result.value.password ;
            $('#temp_token_password').text(password);
        }
        $('#temp_token_serial').html(escape(serial));
        $('#temp_token_enddate').html(escape(end_date));
        $dialog_view_temporary_token.dialog("open");
    } else {
        alert_info_text({'text': "text_losttoken_failed",
                         'param': escape(obj.result.error.message),
                         'type': ERROR,
                         'is_escaped': true});
    }
    $("#token_table").flexReload();
    $('#selected_tokens').html('');
    disable_all_buttons();
}

function token_losttoken(token_type) {
    /*
     * token_losttoken - request enrollment of losttoken
     */
    var tokens = get_selected_tokens();
    var count = tokens.length;

    /* this for loop is unused as the gui allows only the losttoken action
     * if only one token is selected (count is 1) */
    for (i = 0; i < count; i++) {
        var params = {"serial" : tokens[i]};

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
                alert_info_text({'text': "text_setpin_success",
                                 'is_escaped': true});
            else
                alert_info_text({'text': "text_setpin_failed",
                                 'param': escape(obj.result.error.message),
                                 'type': ERROR,
                                 'is_escaped': true,
                                 });
        }
}

function token_setpin(){
    var token_string = $('#setpin_tokens').val();
    var tokens = token_string.split(",");
    var count = tokens.length;
    var pin = $('#pin1').val();
    var pintype = $('#pintype').val();

    for ( i = 0; i < count; i++) {
        var serial = tokens[i];
        if (pintype.toLowerCase() == "otp") {
            clientUrlFetch("/admin/set", {"serial" : serial , "pin" : pin}, setpin_callback);
        } else if ((pintype.toLowerCase() == "motp")) {
            clientUrlFetch("/admin/setPin", {"serial" : serial, "userpin" : pin}, setpin_callback);
        } else if ((pintype.toLowerCase() == "ocrapin")) {
            clientUrlFetch("/admin/setPin", {"serial" : serial, "userpin" : pin}, setpin_callback);
        } else
            alert_info_text({'text': "text_unknown_pintype",
                             'param': pintype,
                             'type': ERROR,
                             'is_escaped': true});
    }

}

function view_setpin_dialog(tokens) {
    /*
     * This function encapsulates the set pin dialog and is
     * called by the button "set pin" and can be called
     * after enrolling or assigning tokesn.
     *
     * Parameter: array of serial numbers
     */
    var token_string = tokens.join(", ");
    $('#dialog_set_pin_token_string').html(escape(token_string));
    $('#setpin_tokens').val(tokens);
    $dialog_setpin_token.dialog('open');
}

function view_setpin_after_assigning(tokens) {
    /*
     * depending on the policies
     * - random pin
     * we can display or not display it.
     * TODO: should this be disabled on otppin != 0 as well?
     */
    var display_setPin = true;

    var selected_users = get_selected_user();
    var policy_def = {'scope':'enrollment',
                  'action': 'otp_pin_random'};
        policy_def['realm'] = selected_users[0].realm;
        policy_def['user']  = selected_users[0].login;

    var rand_pin = get_policy(policy_def);
    if (rand_pin.length > 0) {
        display_setPin = false;
    }

    if (display_setPin === true) {
        view_setpin_dialog(tokens);
    }

}

/******************************************************************************
 *  token info
 */
function token_info(){
    var tokentab = 0;
    var tokens = get_selected_tokens();
    var count = tokens.length;
    if (count != 1) {
        alert_info_text({'text': "text_only_one_token_ti",
                         'is_escaped': true});
        return false;
    }
    else {
        var serial = tokens[0];
        var resp = clientUrlFetchSync("/manage/tokeninfo",{"serial" : serial});
        return resp;
    }
}


function get_token_type(){
    var tokentab = 0;
    var tokens = get_selected_tokens();
    var count = tokens.length;
    var ttype = "";
    if (count != 1) {
        alert_info_text({'text': "text_only_one_token_type",
                         'is_escaped': true});
        return false;
    }
    else {
        var serial = tokens[0];
        var resp = clientUrlFetchSync("/admin/show",{"serial" : serial});
        try {
            var obj = jQuery.parseJSON(resp);
            ttype = obj['result']['value']['data'][0]['LinOtp.TokenType'];
        }
        catch (e) {
            alert_info_text({'text': "text_fetching_tokentype_failed",
                             'param': escape(e),
                             'type': ERROR,
                             'is_escape': true});
        }
        return ttype;
    }
}

function tokeninfo_redisplay() {
    var tokeninfo = token_info();
    $dialog_token_info.html($.parseHTML(tokeninfo));
    set_tokeninfo_buttons();
}

function token_info_save(){
    var info_type = $('input[name="info_type"]').val();
    var info_value = $('#info_value').val();

    var tokens = get_selected_tokens();
    var count = tokens.length;
    var serial = tokens[0];
    if (count != 1) {
        alert_info_text({'text': "text_only_one_token_ti",
                         'is_escape': true});
        return false;
    }
    else {
        // see: http://stackoverflow.com/questions/10640159/key-for-javascript-dictionary-is-not-stored-as-value-but-as-variable-name
        var param={"serial" : serial};
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
        alert_info_text({'text': "text_created_token",
                         'param': escape(serial),
                         'is_escaped': true});
        if (true == g.display_genkey) {

            // display the QR-Code of the URL. tab
            var users = get_selected_user();
            var emails = get_selected_email();
            $('#token_enroll_serial').html(escape(serial));
            if (users.length >= 1) {
                var login = escape(users[0].login);
                var user = login;
                var email = escape(jQuery.trim(emails[0]))
                if (email.length > 0) {
                    user = "<a href=mailto:" +email+">"+login+"</a>"
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
                if (theDetail != null && theDetail.hasOwnProperty('description') ){
                    // fallback, if no ordering is defined
                    if (theDetail.hasOwnProperty('order')) {
                        order = theDetail.order;
                    } else {
                        order = k;
                    }
                    var description = escape(theDetail.description);
                    if ( $("#description_" +k ).length !== 0) {
                    	// we only require the text value of the description
                        description = $("#description_" +k ).text();
                    }
                    dia_tabs[order] = '<li><a href="#url_content_'+k+'">'+ description + '</a></li>';
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
            dia_text += '<input type=hidden id=enroll_token_serial value='+serial+'>';
            // end of qr_url_tabs
            dia_text += '</div>';

			// the output fragments of dia_text ae already escaped
            $('#enroll_url').html($.parseHTML(dia_text));
            $('#qr_url_tabs').tabs();
            $dialog_show_enroll_url.dialog("open");
        }
    }
    else {
        alert_info_text({'text': "text_error_creating_token",
                         'param': escape(obj.result.error.message),
                         'type':ERROR,
                         'is_escape': true});
    }
    reset_buttons();
}

function _extract_tab_content(theDetail, k) {
    var value = theDetail.value;
    var img   = theDetail.img;

    var annotation = '';
    if($('#annotation_' + k).length !== 0) {
        annotation = $('#annotation_' + k).html();
    }
	annotation = escape(annotation);

    var dia_text ='';
    dia_text += '<div id="url_content_'+k+'">';
    dia_text += "<p>";
    dia_text += "<div class='enrollment_annotation'>" + annotation + "</div>";
    dia_text += "<a href='"+ value+ "'>"+img+"</a>";
    dia_text += "<br/>";
    dia_text += "<div class='enrollment_value'>" + value + "</div>";
    dia_text += "</p></div>";
    return dia_text;
}

function token_enroll(){
    check_license();
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
    g.display_genkey = false;
    // get the token type and call the geturl_params() method for this token - if exist
    var typ = $('#tokentype').val();
    // dynamic tokens might overwrite this description
    params['description']='webGUI_generated';

    /* switch can be removed by default, if token migration is completed*/

    switch (typ) {
        case 'ocra':
            params['sharedsecret'] = 1;
            // If we got to generate the hmac key, we do it here:
            if  ( $('#ocra_key_cb').is(':checked') ) {
                params['genkey']    = 1;
            } else {
                // OTP Key
                params['otpkey']    = $('#ocra_key').val();
            }
            if ($('#ocra_pin1').val() != '') {
                params['pin'] = $('#ocra_pin1').val();
            }
            break;

        default:
            if (typ in $tokentypes)
            {  /*
                * the dynamic tokens must provide a function to gather all data from the form
                */
                var params = {};
                var functionString = typ + '_get_enroll_params';
                var funct = window[functionString];
                var exi = typeof funct;

                if (exi == 'undefined') {
                    alert('undefined function '+ escape(functionString) +
                          ' for tokentype ' + escape(typ)  );
                }
                if (exi == 'function') {
                    params = window[functionString]();
                }
            } else {
                alert_info_text({'text': "text_enroll_type_error",
                                 'type': ERROR,
                                 'is_escaped': true});
                return false;
            }
    }
    params['type'] = typ;
    if (params['genkey'] == 1){
        g.display_genkey = true;
    }
    clientUrlFetch(url, params, enroll_callback, serial);

}

function get_enroll_infotext(){
    var users = get_selected_user();
    $("#enroll_info_text_user").hide();
    $("#enroll_info_text_nouser").hide();
    $("#enroll_info_text_multiuser").hide();
    if (users.length == 1) {
        $("#enroll_info_text_user").show();
        var login = escape(users[0].login);
        var resolver = escape(users[0].resolver);
        $('#enroll_info_user').html($.parseHTML( login +" ("+resolver+")"));
    }
    else
        if (users.length == 0) {
            $("#enroll_info_text_nouser").show();
        }
        else {
            $("#enroll_info_text_multiuser").show();
        }
}

function tokentype_changed(){
    var $tokentype = $("#tokentype").val();
    var html = "unknown tokentype!";

    // might raise an error, which must be catched by the caller
    $systemConfig = get_server_config();

    // verify that the tokentypes is a defined dict
    if ($tokentypes == undefined) {
        $tokentypes = {};
    }

    if (len($tokentypes) > 0) {
        for (var k in $tokentypes){
            var tt = '#token_enroll_'+k;
            //console_log(tt);
            $(tt).hide();
        }
    }

    $('#token_enroll_ocra').hide();

    switch ($tokentype) {
        case "ocra":
            $('#token_enroll_ocra').show();
            break;
        case undefined:
            break;
        default:
            // call the setup default method for the token enrollment, before shown
            var functionString = ''+$tokentype+'_enroll_setup_defaults';
            var funct = window[functionString];
            var exi = typeof funct;
            try{
                if (exi == 'function') {
                    var rand_pin = 0;
                    var options = {};
                    var selected_users = get_selected_user();
                    if (selected_users.length == 1) {
                        var policy_def = {'scope':'enrollment',
                                      'action': 'otp_pin_random'};
                        policy_def['realm'] = selected_users[0].realm;
                        policy_def['user']  = selected_users[0].login;
                        rand_pin = get_policy(policy_def).length;
                        options = {'otp_pin_random':rand_pin}
                    }
                    var l_params = window[functionString]($systemConfig, options);
                }
            }
            catch(err) {
                //console_log('callbacack for ' + functionString + ' not found!')
            }

            $('#token_enroll_'+$tokentype).show();
            break;
    }
}



// ##################################################
// Icon functions for the dialogs

function do_dialog_icons(){
    $('.ui-dialog-buttonpane').find('button:contains("Cancel")').button({
        icons: {
            primary: 'ui-icon-cancel'
        }
    });
    $('.ui-dialog-buttonpane').find('button:contains("New")').button({
        icons: {
            primary: 'ui-icon-plusthick'
        }
    });
    $('.ui-dialog-buttonpane').find('button:contains("Delete")').button({
        icons: {
            primary: 'ui-icon-trash'
        }
    });
    $('.ui-dialog-buttonpane').find('button:contains("Save")').button({
        icons: {
            primary: 'ui-icon-disk'
        }
    });
    $('.ui-dialog-buttonpane').find('button:contains("Set PIN")').button({
        icons: {
            primary: 'ui-icon-pin-s'
        }
    });
    $('.ui-dialog-buttonpane').find('button:contains("Edit")').button({
        icons: {
            primary: 'ui-icon-pencil'
        }
    });
    $('.ui-dialog-buttonpane').find('button:contains("load tokenfile")').button({
        icons: {
            primary: 'ui-icon-folder-open'
        }
    });
    $('.ui-dialog-buttonpane').find('button:contains("load token file")').button({
        icons: {
            primary: 'ui-icon-folder-open'
        }
    });
    $('.ui-dialog-buttonpane').find('button:contains("Set subscription")').button({
        icons: {
            primary: 'ui-icon-document-b'
        }
    });
    $('.ui-dialog-buttonpane').find('button:contains("Set Default")').button({
        icons: {
            primary: 'ui-icon-flag'
        }
    });
    $('.ui-dialog-buttonpane').find('button:contains("Enroll")').button({
        icons: {
            primary: 'ui-icon-plusthick'
        }
    });
    $('.ui-dialog-buttonpane').find('button:contains("Resync")').button({
        icons: {
            primary: 'ui-icon-refresh'
        }
    });
    $('.ui-dialog-buttonpane').find('button:contains("unassign token")').button({
        icons: {
            primary: 'ui-icon-pin-arrowthick-1-w'
        }
    });
    $('.ui-dialog-buttonpane').find('button:contains("delete token")').button({
        icons: {
            primary: 'ui-icon-pin-trash'
        }
    });
    $('.ui-dialog-buttonpane').find('button:contains("Close")').button({
        icons: {
            primary: 'ui-icon-closethick'
        }
    });
    //$('.ui-dialog-buttonpane').find('button:contains("Clear Default")').button({
    //  icons: {primary: 'ui-icon-pin-s'}});
}

// #################################################
//
// realms and resolver functions
//
function _fill_resolvers(widget){
	var params = {'session':getsession()};
    $.post('/system/getResolvers', params,
     function(data, textStatus, XMLHttpRequest){
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


function _fill_realms(widget, also_none_realm){
    var defaultRealm = "";
    var params = {'session':getsession()};
    $.post('/system/getRealms', params,
     function(data, textStatus, XMLHttpRequest){
        // value._default_.realmname
        // value.XXXX.realmname
        //var realms = "Realms: <select id=realm>"
        var realms = "";
        // we need to calculate the length:
        if (1==also_none_realm) {
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

function get_defaulrealm(){
    var realms = new Array();
    var url = '/system/getDefaultRealm';

    var resp = $.ajax({
            url: url,
            async: false,
            data: { 'session':getsession()},
            type: "GET"
        }).responseText;
    var data = jQuery.parseJSON(resp);
    for (var i in data.result.value) {
        realms.push(i);
    };
    return realms;
}

function get_realms(){
    var realms = new Array();
    var resp = $.ajax({
            url: '/system/getRealms',
            async: false,
            data: { 'session':getsession()},
            type: "GET"
        }).responseText;
    var data = jQuery.parseJSON(resp);
    for (var i in data.result.value) {
        realms.push(i);
    };
    return realms;
}

function get_resolvers(){
    /*
     * return the list of the resolver names
     */
    var resolvers = new Array();
    var resp = $.ajax({
            url: '/system/getResolvers',
            async: false,
            data: { 'session':getsession()},
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
        if (obj.result.value.success==true) {
            if (""!=obj.result.value.serial) {

                var text = i18n.gettext("Found the token: ") +
                           escape(obj.result.value.serial);

                if (obj.result.value.user_login != "") {

                    text += "\n" +
                            i18n.gettext("The token belongs to ") +
                            escape(obj.result.value.user_login) +
                            " ("+ escape(obj.result.value.user_resolver) +")";
                }
                alert_info_text({'text': text,
                                 'is_escaped': true});
            }
            else
                alert_info_text({'text': "text_get_serial_no_otp",
                                 'is_escaped': true});
        }else{
            alert_info_text({"text": "text_get_serial_error",
                             'type': ERROR,
                             'is_escaped': true});
        }
    } else {
        alert_info_text({'text': "text_failed",
                         'param': escape(obj.result.error.message),
                         'type': ERROR,
                         'is_escaped': true});
    }
}
// get Serial by OTP
function getSerialByOtp(otp, type, assigned, realm) {
    var param = {};
    param["otp"] = otp;
    if (""!=type) {
        param["type"]=type;
    }
    if (""!=assigned) {
        param["assigned"] = assigned;
    }
    if (""!=realm) {
        param["realm"] = realm;
    }
    clientUrlFetch('/admin/getSerialByOtp', param, get_serial_by_otp_callback);

}


function ldap_resolver_ldaps() {
    /*
     * This function checks if the LDAP URI is using SSL.
     * If so, it displays the CA certificate entry field.
     */
    var ldap_uri = $('#ldap_uri').val();
    if (ldap_uri.toLowerCase().match(/^ldaps:/)) {
        $('#ldap_resolver_certificate').show();
    } else {
        $('#ldap_resolver_certificate').hide();
    }
    return false;
}

function parseXML(xml, textStatus){
    var version = $(xml).find('version').text();
    var status = $(xml).find('status').text();
    var value = $(xml).find('value').text();
    var message = $(xml).find('message').text();

    if ("error" == textStatus) {
        alert_info_text({'text': "text_linotp_comm_fail",
                         'type': ERROR,
                         'is_escaped': true});
    }
    else {
        if ("False" == status) {
            alert_info_text({'text': "text_token_import_failed",
                             'param': escape(message),
                             'type': ERROR,
                             'is_escaped': true,
                             });
        }
        else {
            // reload the token_table
            $('#token_table').flexReload();
            $('#selected_tokens').html('');
            disable_all_buttons();
            alert_info_text({'text': "text_token_import_result",
                             'param': escape(value),
                             'is_escaped': true,
                             });

        }
    }
    hide_waiting();
};

function parsePolicyImport(xml, textStatus) {
    var version = $(xml).find('version').text();
    var status = $(xml).find('status').text();
    var value = $(xml).find('value').text();
    var message = $(xml).find('message').text();

    if ("error" == textStatus) {
        alert_info_text({'text': "text_linotp_comm_fail",
                         'type': ERROR,
                         'is_escaped': true});
    }
    else {
        if ("False" == status) {
            alert_info_text({'text': "text_policy_import_failed",
                             'param': escape(message),
                             'is_escaped': true});
        }
        else {
            // reload the token_table
            $('#policy_table').flexReload();
            alert_info_text({'text': "text_policy_import_result",
                             'param': escape(value),
                             'is_escaped': true});
        }
    }
    hide_waiting();
};

// calback to handle response when license has been submitted
function parseLicense(xml_response, textStatus, xhr){
    var xml = null;

    if(testXMLObject(xml_response)){
        xml = xml_response;
    }
    else{
        try{ // try for activeX errors
            if( window.DOMParser ){ // good browser
                var parser = new DOMParser();
                xml = parser.parseFromString(xhr.responseText,"text/xml");
            }
            else{ // Internet Explorer
                xml = new ActiveXObject("Microsoft.XMLDOM");
                xml.async = "false";
                if(typeof xhr.responseXML.xml !== 'undefined'){
                    xml.loadXML(xhr.responseXML.xml);
                }
                else{ // IE 9
                    alert(xhr.responseXML.activeElement.innerText);
                    xmlstr = xhr.responseXML.activeElement.innerText.replace(/[\n\r]-?/g, '');
                    xml.loadXML(xmlstr);
                }
            }
            if(!testXMLObject(xml)){
                throw "Error: xml could not be parsed";
            }
        }
        catch(e){ // if nothing helped
            xml = null;
        }
    }

    var status = $(xml).find('status').text();
    var value = $(xml).find('value').text();
    var xml_message = $(xml).find('message').text();
    var reason = $(xml).find('reason').text();

    var error_intro = i18n.gettext('The upload of your support and subscription license failed: ');
    var dialog_title = i18n.gettext('License upload');

    // error occured
    if(xml == null){
        var status_unkown = i18n.gettext('License uploaded');
        alert_info_text({'text': status_unkown,
                     'is_escaped': true
                     });
    }
    else if(status.toLowerCase() == "false") {
        var message = i18n.gettext('Invalid License') + ': <br>' + escape(xml_message);
        alert_info_text({'text': message,
                         'type': ERROR,
                         'is_escaped': true
                         });

        alert_box({'title': dialog_title,
                   'text': error_intro + message,
                   'is_escaped': true});
    } else {
        if (value.toLowerCase() == "false"){
            var message = i18n.gettext('Invalid License') + ': <br>' + escape(reason);
            alert_info_text({'text': message,
                             'type': ERROR,
                             'is_escaped': true});
            alert_box({'title': dialog_title,
                       'text': error_intro + message,
                       'is_escaped': true});
        } else {
            alert_box({'title': dialog_title,
                       'text': "text_support_lic_installed",
                       'is_escaped': true});
        }
    }
    hide_waiting();
};

function testXMLObject(xml){
    try{
        if($(xml).find('version').text() == ""){
            throw "Error: xml needs reparsing";
        }
        else{
            state = "successful"
            return true;
        }
    }catch(e){
        return false;
    }
}

function import_policy() {
    show_waiting();
    $('#load_policies').ajaxSubmit({
        data: { session:getsession() },
        type: "POST",
        error: parsePolicyImport,
        success: parsePolicyImport,
        dataType: 'xml'
    });
    return false;
}

function load_tokenfile(type){
    show_waiting();
    if ("aladdin-xml" == type) {
        $('#load_tokenfile_form_aladdin').ajaxSubmit({
            data: { session:getsession() },
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: 'xml'
        });
    }
    else if ("feitian" == type) {
        $('#load_tokenfile_form_feitian').ajaxSubmit({
            data: { session:getsession() },
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: 'xml'
        });
    }
    else if ("pskc" == type) {
        $('#load_tokenfile_form_pskc').ajaxSubmit({
            data: { session:getsession() },
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: 'xml'
        });
    }
    else if ("dpw" == type) {
        $('#load_tokenfile_form_dpw').ajaxSubmit({
            data: { session:getsession() },
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: "xml"
        });
    }
    else if ("dat" == type) {
        $('#load_tokenfile_form_dat').ajaxSubmit({
            data: { session:getsession() },
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: "dat"
        });
    }
    else if ("vasco" == type) {
        $('#load_tokenfile_form_vasco').ajaxSubmit({
            data: { session:getsession() },
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: "xml"
        });
    }
    else if ("oathcsv" == type) {
        $('#load_tokenfile_form_oathcsv').ajaxSubmit({
            data: { session:getsession() },
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: "xml"
        });
    }
    else if ("yubikeycsv" == type) {
        $('#load_tokenfile_form_yubikeycsv').ajaxSubmit({
            data: { session:getsession() },
            type: "POST",
            error: parseXML,
            success: parseXML,
            dataType: "xml"
        });
    }
    else {
        alert_info_text({'text': "text_import_unknown_type",
                         'type': ERROR,
                         'is_escaped': true});
    };
    return false;
}

function support_set(){
    show_waiting();
    //check for extension .pem:
    var filename = $('#license_file').val();
    var extension = /\.pem$/;
    if (extension.exec(filename) ) {
    $('#set_support_form').ajaxSubmit({
        data: { session:getsession() },
        type: "POST",
        error: parseLicense,
        success: parseLicense,
        dataType: 'xml'
    });
    } else {
        alert_info_text({'text': "text_import_pem",
                         'type': ERROR,
                         'is_escaped': true});
    }
    hide_waiting();
    return false;
}

function support_view(){

    // clean out old data
    $("#dialog_support_view").html("");

    var params = { 'session':getsession()};
    $.post('/system/getSupportInfo', params,
     function(data, textStatus, XMLHttpRequest){
        support_info = data.result.value;

        if ($.isEmptyObject(support_info)) {
            var info = "";
            info += '<h2 class="contact_info">' + i18n.gettext('Professional LinOTP support and enterprise subscription') + '</h2>';
            info += i18n.gettext('For professional LinOTP support and enterprise subscription, feel free to contact <p class="contact_info"><a href="mailto:sales@lsexperts.de">LSE Leading Security Experts GmbH</a></p> for support agreement purchase.');
            $("#dialog_support_view").html($.parseHTML(info));

        } else {
            var info = "";
            info += '<h2 class="contact_info">' + i18n.gettext('Your LinOTP support subscription') + '</h2>';
            info += "<table><tbody>";
            $.map(support_info, function(value,key){
                if ( support_license_dict.hasOwnProperty(key) ) {
                    key = i18n.gettext(support_license_dict[key]);
                }
                if (value && value.length > 0) {
                    info += "<tr><td class='subscription_detail'>" + key + "</td><td class='subscription_detail'>" + value + "</td></tr>";
                }
            });
            info += "</tbody></table>";
            info += "<div class='subscription_info'><br>" +
                i18n.gettext("For support and subscription please contact us at") +
                " <a href='https://www.lsexperts.de/service-support.html' target='noreferrer'>https://www.lsexperts.de</a> <br>" +
                i18n.gettext("by phone") + " +49 6151 86086-115 " + i18n.gettext("or email") + " support@lsexperts.de</div>";
            $("#dialog_support_view").html($.parseHTML(info));
        }
    });
    return false;
}

function load_system_config(){
    show_waiting();
    var params = {'session':getsession()};
    $.post('/system/getConfig', params,
     function(data, textStatus, XMLHttpRequest){
        // checkboxes this way:
        hide_waiting();
        checkBoxes = new Array();
        if (data.result.value.DefaultResetFailCount == "True") {
            checkBoxes.push("sys_resetFailCounter");
        };
        if (data.result.value.splitAtSign == "True") {
            checkBoxes.push("sys_splitAtSign");
        };
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
        $('#sys_maxFailCount').val(data.result.value.DefaultMaxFailCount);
        $('#sys_syncWindow').val(data.result.value.DefaultSyncWindow);
        $('#sys_otpLen').val(data.result.value.DefaultOtpLen);
        $('#sys_countWindow').val(data.result.value.DefaultCountWindow);
        $('#sys_challengeTimeout').val(data.result.value.DefaultChallengeValidityTime);
        $('#sys_autoResyncTimeout').val(data.result.value.AutoResyncTimeout);
        $('#sys_mayOverwriteClient').val(data.result.value.mayOverwriteClient);
        // OCRA stuff
        $('#ocra_default_suite').val(data.result.value.OcraDefaultSuite);
        $('#ocra_default_qr_suite').val(data.result.value.QrOcraDefaultSuite);
        $('#ocra_max_challenge').val(data.result.value.OcraMaxChallenges);
        $('#ocra_challenge_timeout').val(data.result.value.OcraChallengeTimeout);

        /*todo call the 'tok_fill_config.js */
    });
}

function save_system_config(){
    show_waiting();
    var params = {
            'DefaultMaxFailCount': $('#sys_maxFailCount').val(),
            'DefaultSyncWindow': $('#sys_syncWindow').val(),
            'DefaultOtpLen': $('#sys_otpLen').val(),
            'DefaultCountWindow': $('#sys_countWindow').val(),
            'DefaultChallengeValidityTime': $('#sys_challengeTimeout').val(),
            'AutoResyncTimeout': $('#sys_autoResyncTimeout').val(),
            'mayOverwriteClient': $('#sys_mayOverwriteClient').val(),
            'totp.timeShift': $('#totp_timeShift').val(),
            'totp.timeStep': $('#totp_timeStep').val(),
            'totp.timeWindow': $('#totp_timeWindow').val(),
            'OcraDefaultSuite' : $('#ocra_default_suite').val(),
            'QrOcraDefaultSuite' : $('#ocra_default_qr_suite').val(),
            'OcraMaxChallenges' : $('#ocra_max_challenge').val(),
            'OcraChallengeTimeout' : $('#ocra_challenge_timeout').val(),
            'session':getsession()}

    $.post('/system/setConfig', params,
     function(data, textStatus, XMLHttpRequest){
        hide_waiting();
        if (data.result.status == false) {
            alert_info_text({'text': "text_system_save_error",
                             'type': ERROR,
                             'is_escape': true});
        }
    });

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
    var defaultReset = "False";
    if ($("#sys_resetFailCounter").is(':checked')) {
        defaultReset = "True";
    }
    var realmbox = "False";
    if ($("#sys_realmbox").is(':checked')) {
        realmbox = "True";
    }
    var params = { 'session':getsession(),
            'PrependPin' :prepend,
            'FailCounterIncOnFalsePin' : fcounter ,
            'splitAtSign' : splitatsign,
            'DefaultResetFailCount' : defaultReset,
            'AutoResync' :    autoresync,
            'PassOnUserNotFound' : passOUNFound,
            'PassOnUserNoToken' : passOUNToken,
            'selfservice.realmbox' : realmbox,
            'allowSamlAttributes' : allowsaml,
             };
    $.post('/system/setConfig', params,
     function(data, textStatus, XMLHttpRequest){
        if (data.result.status == false) {
            alert_info_text({'text': "text_system_save_error_checkbox",
                             'type': ERROR,
                             'is_escaped': true});
        }
    });
}

function save_ldap_config(){
    // Save all LDAP config
    var resolvername = $('#ldap_resolvername').val();
    var resolvertype = "ldapresolver";
    var ldap_map = {
        '#ldap_uri': 'LDAPURI',
        '#ldap_basedn': 'LDAPBASE',
        '#ldap_binddn': 'BINDDN',
        '#ldap_password': 'BINDPW',
        '#ldap_timeout': 'TIMEOUT',
        '#ldap_sizelimit': 'SIZELIMIT',
        '#ldap_loginattr': 'LOGINNAMEATTRIBUTE',
        '#ldap_searchfilter': 'LDAPSEARCHFILTER',
        '#ldap_userfilter': 'LDAPFILTER',
        '#ldap_mapping': 'USERINFO',
        '#ldap_uidtype': 'UIDTYPE',
        '#ldap_noreferrals' : 'NOREFERRALS',
        '#ldap_certificate': 'CACERTIFICATE',
    };
    var url = '/system/setResolver';
    var params = {}
    params['name']= resolvername;
    params['type'] = resolvertype;
    for (var key in ldap_map) {
        var new_key = ldap_map[key];
        var value = $(key).val();
        params[new_key] = value;
    }
    // checkboxes
    var noreferrals="False";
    if ($("#ldap_noreferrals").is(':checked')) {
        noreferrals = "True";
    }
    params["NOREFERRALS"] = noreferrals;

    params["session"] = getsession();
    show_waiting();

    $.post(url, params,
     function(data, textStatus, XMLHttpRequest){
        hide_waiting();
        if (data.result.status == false) {
            alert_info_text({'text': "text_error_ldap",
                             'param': escape(data.result.error.message),
                             'type': ERROR,
                             'is_escaped': true});
        } else {
            resolvers_load();
            $dialog_ldap_resolver.dialog('close');
        }
    });
    return false;
}

function set_default_realm(realm) {
/*
 * set the default realm
 *
 * @param realm - as string
 */
    var params = {
        'realm' : realm,
        'session':getsession()
        };

    $.post('/system/setDefaultRealm', params,
       function(){
          realms_load();
          fill_realms();
      });
}

function save_realm_config(){
/*
 * save the realm config from the realm edit dialog
 *
 * @param - #realm_name is extracted from form entry
 */
    check_license();
    var realm = $('#realm_name').val();
    show_waiting();
    var params = {
        'realm' :realm,
        'resolvers' : g.resolvers_in_realm_to_edit,
        'session':getsession()
        };

    $.post('/system/setRealm', params,
     function(data, textStatus, XMLHttpRequest){
        hide_waiting();
        if (data.result.status == false) {
            alert_info_text({'text': "text_error_realm",
                             'param': escape(data.result.error.message),
                             'type': ERROR,
                             'is_escaped': true});
        } else {
            fill_realms();
            realms_load();
            alert_info_text({'text': "text_realm_created",
                             'param': escape(realm),
                             'is_escaped': true});
        }
    });
}

function save_tokenrealm_config(){
    var tokens = get_selected_tokens();
    var realms = g.realms_of_token.join(",");
    var params = {
            'serial' :serial,
            'realms' : realms,
            'session':getsession()
            };
    for (var i = 0; i < tokens.length; ++i) {
        serial = tokens[i];
        params['serial'] = serial;

        show_waiting();

        $.post('/admin/tokenrealm', params,
         function(data, textStatus, XMLHttpRequest){
            hide_waiting();
            if (data.result.status == false) {
                alert_info_text({'text': "text_error_set_realm",
                                 'param': escape(data.result.error.message),
                                 'type': ERROR,
                                 'is_escaped': true});
            }
            else {
                $('#token_table').flexReload();
                $('#selected_tokens').html('');
            }
         });
    }
}

function save_file_config(){
   /*
    * save the passwd resolver config
    */
    var resolvername = $('#file_resolvername').val();
    var resolvertype = "passwdresolver";
    var fileName = $('#file_filename').val();
    var params = {};
    params['name'] = resolvername;
    params['type'] = resolvertype;
    params['fileName'] = fileName;
    params['session'] = getsession();
    show_waiting();
    $.post('/system/setResolver', params,
     function(data, textStatus, XMLHttpRequest){
        hide_waiting();
        if (data.result.status == false) {
            alert_info_text({'text': "text_error_save_file",
                             'param': escape(data.result.error.message),
                             'type': ERROR,
                             'is_escaped': true});
        } else {
            resolvers_load();
            $dialog_file_resolver.dialog('close');
        }
    });
}


function save_sql_config(){
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
        '#sql_password': 'Password',
        '#sql_table': 'Table',
        '#sql_mapping': 'Map',
        '#sql_where': 'Where',
        '#sql_conparams': 'conParams',
        '#sql_encoding' : 'Encoding'
    };
    var url = '/system/setResolver';
    var params = {};
    params['name'] = resolvername;
    params['type'] = resolvertype;
    for (var key in map) {
        var value = $(key).val();
        var new_key = map[key];
        params[new_key] = value;
    }
    params['session'] = getsession();
    show_waiting();
    $.post(url, params,
     function(data, textStatus, XMLHttpRequest){
        hide_waiting();
        if (data.result.status == false) {
            alert_info_text({'text': "text_error_save_sql",
                             'param': escape(data.result.error.message),
                             'type': ERROR,
                             'is_escaped': true});
        } else {
            resolvers_load();
            $dialog_sql_resolver.dialog('close');
        }
    });
    return false;
}


// ----------------------------------------------------------------
//   Realms
function realms_load(){

    g.realm_to_edit = "";
    show_waiting();
    var params = { 'session': getsession() };
    $.post('/system/getRealms', params,
     function(data, textStatus, XMLHttpRequest){
        hide_waiting();
        var realms = '<ol id="realms_select" class="select_list" class="ui-selectable">';
        for (var key in data.result.value) {
            var default_realm = "";
            var resolvers = "";
            var resolver_list = data.result.value[key].useridresolver;
            for (var reso in resolver_list) {
                var r = resolver_list[reso].split(".");
                resolvers += r[r.length - 1] + " ";
            }

            if (data.result.value[key]['default']) {
                default_realm = " (Default) ";
            }
			var e_key = escape(key);
			var e_default_realm = escape(default_realm);
			var e_resolvers = escape(resolvers)
            realms += '<li class="ui-widget-content">' + e_key + e_default_realm + ' [' + e_resolvers + ']</li>';
        }
        realms += '</ol>';
        $('#realm_list').html($.parseHTML(realms));
        $('#realms_select').selectable({
            stop: function(){
                $(".ui-selected", this).each(function(){
                    var index = $("#realms_select li").index(this);
                    g.realm_to_edit = escape($(this).html());
                }); // end of each
            } // end of stop function
        }); // end of selectable
    }); // end of $.post
}

function realm_ask_delete(){
    // replace in case of normal realms
    var realm = g.realm_to_edit.replace(/^(\S+)\s+\[(.*)$/, "$1");
    // replace in case of default realm
    realm = realm.replace(/^(\S+)\s+\(Default\)\s+\[(.*)$/, "$1");

    $('#realm_delete_name').html(escape(realm));
    $dialog_realm_ask_delete.dialog('open');
}

// -----------------------------------------------------------------
//   Resolvers


function resolvers_load(){
    show_waiting();
    var params = {'session':getsession()};
    $.post('/system/getResolvers', params,
     function(data, textStatus, XMLHttpRequest){
        hide_waiting();
        var resolvers = '<ol id="resolvers_select" class="select_list" class="ui-selectable">';
        var count = 0;
        for (var key in data.result.value) {
            //resolvers += '<input type="radio" id="resolver" name="resolver" value="'+key+'">';
            //resolvers += key+' ('+data.result.value[key].type+')<br>';
            var e_key = escape(key);
            var e_reolver_type = escape(data.result.value[key].type);
            resolvers += '<li class="ui-widget-content">' + e_key + ' [' + e_reolver_type + ']</li>';
            count = count +1 ;
        }
        resolvers += '</ol>';
        if (count > 0) {
            $('#resolvers_list').html(resolvers);
            $('#resolvers_select').selectable({
                stop: function(){
                    $(".ui-selected", this).each(function(){
                        var index = $("#resolvers_select li").index(this);
                        g.resolver_to_edit = escape($(this).html());
                    }); // end of each
                } // end of stop function
            }); // end of selectable
        } // end of count > 0
        else {
            $('#resolvers_list').html("");
            g.resolver_to_edit = "";
        };
    }); // end of $.post
}


function resolver_delete(){
    var reso = $('#delete_resolver_name').html();
    var params = { 'resolver' : reso, 'session':getsession()};

    show_waiting();
    $.post('/system/delResolver', params,
     function(data, textStatus, XMLHttpRequest){
        hide_waiting();
        if (data.result.status == true) {
            resolvers_load();
            if (data.result.value == true)
                alert_info_text({'text': "text_resolver_delete_success",
                                 'param': escape(reso),
                                 'is_escaped': true});
            else
                alert_info_text({'text': "text_resolver_delete_fail",
                                 'param': escape(reso),
                                 'type': ERROR,
                                 'is_escaped': true});
        }
        else {
            alert_info_text({'text': "text_resolver_delete_fail",
                             'param': escape(data.result.error.message),
                             'type': ERROR,
                             'is_escape': true});
        }
    });
}

function realm_delete(){
    var realm = $('#realm_delete_name').html();
    var params = {'realm' : realm,'session':getsession()};
    $.post('/system/delRealm', params,
     function(data, textStatus, XMLHttpRequest){
        if (data.result.status == true) {
            fill_realms();
            realms_load();
            alert_info_text({'text': "text_realm_delete_success",
                             'param': escape(realm),
                            'is_escaped': true});
        }
        else {
            alert_info_text({'text': "text_realm_delete_fail",
                             'param': escape(data.result.error.message),
                             'type': ERROR,
                            'is_escaped': true});
        }
        hide_waiting();
    });
}

function resolver_ask_delete(){
   if (g.resolver_to_edit.length >0 ) {
    if (g.resolver_to_edit.match(/(\S+)\s(\S+)/)) {
        var reso = g.resolver_to_edit.replace(/(\S+)\s+\S+/, "$1");
        var type = g.resolver_to_edit.replace(/\S+\s+(\S+)/, "$1");

        $('#delete_resolver_type').html(escape(type));
        $('#delete_resolver_name').html(escape(reso));
        $dialog_resolver_ask_delete.dialog('open');
    }
    else {
        alert_info_text({'text': "text_regexp_error",
                         'param': escape(g.resolver_to_edit),
                         'type': ERROR,
                         'is_escaped': true});
    }
   }
}

function resolver_edit_type(){
    var reso = g.resolver_to_edit.replace(/(\S+)\s+\S+/, "$1");
    var type = g.resolver_to_edit.replace(/\S+\s+\[(\S+)\]/, "$1");
    switch (type) {
        case "ldapresolver":
            resolver_ldap(reso);
            break;
        case "sqlresolver":
            resolver_sql(reso);
            break;
        case "passwdresolver":
            resolver_file(reso);
            break;
    }
}


function resolver_new_type(){

    check_license();
    $dialog_ask_new_resolvertype.dialog('open');

}

function add_token_config()
{

    if ($tokentypes == undefined) {
        $tokentypes = {};
    }

    if (len($tokentypes) > 0) {
        for (var k in $tokentypes){
            var tt = '#token_enroll_'+k;
            //console_log(tt);
            $(tt).hide();
        }
    }
}


function set_tokeninfo_buttons(){
/*
 * enables the tokeninfo buttons.
 * As tokeninfo HTML is read from the server via /manage/tokeninfo
 * jqeuery needs to activate the buttons after each call.
 */
    $('#ti_button_desc').button({
        icons: { primary: 'ui-icon-pencil' },
        text: false
    });
    $('#ti_button_desc').click(function(){
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
    $('#ti_button_otplen').click(function(){
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
    $('#ti_button_sync').click(function(){
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
    $('#ti_button_countwindow').click(function(){
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
    $('#ti_button_maxfail').click(function(){
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
    $('#ti_button_failcount').click(function(){
        serial = get_selected_tokens()[0];
        clientUrlFetchSync("/admin/reset", {"serial" : serial});
        tokeninfo_redisplay();
    });

    $('#ti_button_hashlib').button({
        icons: { primary: 'ui-icon-locked'},
        text : false,
        label: "hashlib"
    });
    $('#ti_button_hashlib').click(function(){
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="hashlib">\
            <select id=info_value name=info_value>\
            <option value=sha1>sha1</option>\
            <option value=sha256>sha256</option>\
            </select>');
        translate_dialog_ti_hashlib();
        $dialog_tokeninfo_set.dialog('open');
    });

    $('#ti_button_count_auth_max').button({
        icons: { primary: 'ui-icon-arrowthickstop-1-n'},
        text : false,
        label: "auth max"
    });
    $('#ti_button_count_auth_max').click(function(){
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="countAuthMax">\
            <input id=info_value name=info_value></input>\
            ');
        translate_dialog_ti_countauthmax();
        $dialog_tokeninfo_set.dialog('open');
    });

    $('#ti_button_count_auth_max_success').button({
        icons: { primary: 'ui-icon-arrowthick-1-n'},
        text : false,
        label: "auth max_success"
    });
    $('#ti_button_count_auth_max_success').click(function(){
        $dialog_tokeninfo_set.html($.parseHTML('<input type="hidden" name="info_type" value="countAuthSuccessMax">\
            <input id=info_value name=info_value></input>\
            '));
        translate_dialog_ti_countauthsuccessmax();
        $dialog_tokeninfo_set.dialog('open');
    });

    $('#ti_button_valid_start').button({
        icons: { primary: 'ui-icon-seek-first'},
        text : false,
        label: "valid start"
    });
    $('#ti_button_valid_start').click(function(){
        $dialog_tokeninfo_set.html('Format: %d/%m/%y %H:%M<br><input type="hidden" name="info_type" value="validityPeriodStart">\
            <input id=info_value name=info_value></input>\
            ');
        translate_dialog_ti_validityPeriodStart();
        $dialog_tokeninfo_set.dialog('open');
    });

    $('#ti_button_valid_end').button({
        icons: { primary: 'ui-icon-seek-end'},
        text : false,
        label: "valid end"
    });
    $('#ti_button_valid_end').click(function(){
        $dialog_tokeninfo_set.html('Format: %d/%m/%y %H:%M<br><input type="hidden" name="info_type" value="validityPeriodEnd">\
            <input id=info_value name=info_value></input>\
            ');
        translate_dialog_ti_validityPeriodStart();
        $dialog_tokeninfo_set.dialog('open');
    });
    $('#ti_button_mobile_phone').button({
        icons: { primary: 'ui-icon-signal'},
        text : false,
        label: "mobile phone"
    });
    $('#ti_button_mobile_phone').click(function(){
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
        icons: { primary: 'ui-icon-newwin'},
        text : false,
        label: "time window"
    });
    $('#ti_button_time_window').click(function(){
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="timeWindow">\
            <input id=info_value name=info_value></input>\
            ');
        translate_dialog_ti_timewindow();
        $dialog_tokeninfo_set.dialog('open');
    });

    $('#ti_button_time_shift').button({
        icons: { primary: 'ui-icon-seek-next'},
        text : false,
        label: "time shift"
    });
    $('#ti_button_time_shift').click(function(){
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="timeShift">\
            <input id=info_value name=info_value></input>\
            ');
        translate_dialog_ti_timeshift();
        $dialog_tokeninfo_set.dialog('open');
    });

    $('#ti_button_time_step').button({
        icons: { primary: 'ui-icon-clock'},
        text : false,
        label: "time step"
    });
    $('#ti_button_time_step').click(function(){
        $dialog_tokeninfo_set.html('<input type="hidden" name="info_type" value="timeStep">\
            <select id=info_value name=info_value>\
            <option value=30>30 seconds</option>\
            <option value=60>60 seconds</option>\
            </select>');
        translate_dialog_ti_timestep();
        $dialog_tokeninfo_set.dialog('open');
    });

}

function tokenbuttons(){
    /*
     * This is the function to call handle the buttons, that will only work
     * with tokens and not with users.
     */
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
            'Get Temporary Token': {click: function() {
                var token_type =  $('#dialog_lost_token select').val();
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
            'Cancel': {click: function() {
                $(this).dialog('close');
                },
                id: "button_losttoken_cancel",
                text: i18n.gettext("Cancel")
                }
            },
        open: function() {
            /* get_selected_tokens() returns a list of tokens.
             * We can only handle one selected token (token == 1).
             */
            var tokens = get_selected_tokens();
            if (tokens.length == 1){
                $("#dialog_lost_token select option[value=email_token]").
                    attr('disabled','disabled');
                $("#dialog_lost_token select option[value=sms_token]").
                    attr('disabled','disabled');

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
                    attr('selected',true);
                $('#lost_token_serial').html(escape(token_string));
                translate_dialog_lost_token();
                do_dialog_icons();
            } else {
                $(this).dialog('close');
            }
        }
    });
    $('#button_losttoken').click(function(){
        $('#dialog_lost_token_select').prop('selectedIndex',0);
        $dialog_losttoken.dialog('open');
    });


    var $dialog_resync_token = $('#dialog_resync_token').dialog({
        autoOpen: false,
        title: 'Resync Token',
        resizeable: false,
        width: 400,
        modal: true,
        buttons: {
            'Resync': {click: function(){
                token_resync();
                $(this).dialog('close');
                },
                id: "button_resync_resync",
                text: "Resync"
                },
            Cancel: {click: function(){
                $(this).dialog('close');
                },
                id: "button_resync_cancel",
                text: "Cancel"
                }
        },
        open: function() {
            tokens = get_selected_tokens();
            token_string = tokens.join(", ");
            /* delete otp values in dialog */
            $("#otp1").val("");
            $("#otp2").val("");
            $('#tokenid_resync').html(escape(token_string));
            translate_dialog_resync_token();
            do_dialog_icons();
        }
    });
    $('#button_resync').click(function(){
        $dialog_resync_token.dialog('open');
        return false;
    });


    $('#button_tokeninfo').click(function () {
        var tokeninfo = token_info();
        if (false != tokeninfo) {
            var pHtml = $.parseHTML(tokeninfo);
            $dialog_token_info.html(pHtml);
            set_tokeninfo_buttons();
            buttons = {
                Close: {click: function(){
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
            'Cancel': { click: function(){
                                $(this).dialog('close');
                            },
                        id: "button_tokenrealm_cancel",
                        text: "Cancel"
            },
            'Save': { click: function(){
                            save_tokenrealm_config();
                            $(this).dialog('close');
                            },
                    id: "button_tokenrealm_save",
                    text: "Set Realm"
            }
        },
        open: function() {
            do_dialog_icons();
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
            'Get OTP values': {click: function(){
                var serial = get_selected_tokens()[0];
                var count  = $('#otp_values_count').val();
                var session = getsession();
                window.open('/gettoken/getmultiotp?serial='+serial+'&session='+session+'&count='+count+'&view=1','getotp_window',"status=1,toolbar=1,menubar=1");
                $(this).dialog('close');
                },
                id: "button_getmulti_ok",
                text: "Get OTP values"
                },
            Cancel: {click: function(){
                $(this).dialog('close');
                },
                id: "button_getmulti_cancel",
                text: "Cancel"
                }
        },
        open: function() {
            do_dialog_icons();
            token_string = get_selected_tokens()[0];
            $('#tokenid_getmulti').html(escape(token_string));
            translate_dialog_getmulti();
        }
    });
    $('#button_getmulti').click(function(){
        $dialog_getmulti.dialog('open');
    });

    $('#button_tokenrealm').click(function(event){
        var tokens = get_selected_tokens();
        var token_string = tokens.join(", ");
        g.realms_of_token = Array();

        // get all realms the admin is allowed to view
        var realms = '';
        var params = {'session':getsession()}
        $.post('/system/getRealms', params,
         function(data, textStatus, XMLHttpRequest){
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
                stop: function(){
                    $(".ui-selected", this).each(function(){
                        // fill realms of token
                        var index = $("#tokenrealm_select li").index(this);
                        var realm = escape($(this).html());
                        g.realms_of_token.push(realm);

                    }); // end of stop function
                } // end stop function
            }); // end of selectable
        }); // end of $.post
        if (tokens.length === 0) {
            alert_box({'title': i18n.gettext("Set Token Realm"),
                       'text': i18n.gettext("Please select the token first."),
                       'is_escaped': true});
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

$(document).ready(function(){
    // right after document loading we need to get the session an reload the realm box!
    getsession();
    //fill_realms();

    // hide the javascrip message
    $('#javascript_error').hide();

    $("button").button();
    /*
     $('ul.sf-menu').superfish({
     delay: 0,
     animation: {
     opacity: 'show',
     //    height: 'show'
     },
     speed: 'fast',
     autoArrows: true,
     dropShadows: true
     });
     */
    $('ul.sf-menu').superfish({
        delay: 0,
        speed: 'fast'
    });

    // Button functions
    $('#button_assign').click(function(event){
        token_assign();
        event.preventDefault();
    });

    $('#button_enable').click(function(event){
        token_enable();
        //event.preventDefault();
        return false;
    });

    $('#button_disable').click(function(event){
        token_disable();
        event.preventDefault();
    });

    $('#button_resetcounter').click(function(event){
        token_reset();
        event.preventDefault();
    });

    // Set icons for buttons
    $('#button_enroll').button({
        icons: {
            primary: 'ui-icon-plusthick'
        }
    });
    $('#button_assign').button({
        icons: {
            primary: 'ui-icon-arrowthick-2-e-w'
        }
    });
    $('#button_unassign').button({
        icons: {
            primary: 'ui-icon-arrowthick-1-w'
        }
    });

    $('#button_enable').button({
        icons: {
            primary: 'ui-icon-radio-on'
        }
    });
    $('#button_disable').button({
        icons: {
            primary: 'ui-icon-radio-off'
        }
    });
    $('#button_setpin').button({
        icons: {
            primary: 'ui-icon-pin-s'
        }
    });
    $('#button_delete').button({
        icons: {
            primary: 'ui-icon-trash'
        }
    });

    $('#button_resetcounter').button({
        icons: {
            primary: 'ui-icon-arrowthickstop-1-w'
        }
    });
    $('#button_policy_add').button({
        icons: {
            primary: 'ui-icon-plusthick'
        }
    });
    $('#button_policy_delete').button({
        icons: {
            primary: 'ui-icon-trash'
        }
    });

    // Info box
    $(".button_info_text").button();
    $('.button_info_text').click(function(){
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
        drop: function(ev, ui){
            deleteImage(ui.draggable);
        }
    });

    // let the gallery be droppable as well, accepting items from the trash
    $gallery.droppable({
        accept: '#trash li',
        activeClass: 'custom-state-active',
        drop: function(ev, ui){
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
            'Cancel': { click: function(){
                            $(this).dialog('close');
                        },
                        id: "button_editrealms_cancel",
                        text: "Cancel"
            },
            'Save': { click: function(){
                    if ($("#form_realmconfig").valid()) {
                        /* first check if there is at least one resolver selected */
                        var resolvers = g.resolvers_in_realm_to_edit.split(',');
                        if (resolvers.length == 1 &&
                            resolvers[0].length == 0){
                            alert_box({'title': i18n.gettext("No resolver selected"),
                                       'text': i18n.gettext("Please select at least one resolver from the resolver list."),
                                       'is_escaped': true});

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
        open: function() {
            translate_dialog_realm_edit();
            do_dialog_icons();
        }
    });

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

    /**********************************************************************
    * Temporary token dialog
    */
    $dialog_view_temporary_token = $('#dialog_view_temporary_token').dialog({
        autoOpen: false,
        resizeable: true,
        width: 400,
        modal: false,
        buttons: {
            Close: {click: function(){
                $(this).dialog('close');
                },
                id: "button_view_temporary_token_close",
                text: i18n.gettext("Close")
                },
        },
        open: function() {
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
                'Delete': { click: function(){
                                resolver_delete();
                                $(this).dialog('close');
                            },
                            id: "button_resolver_ask_delete_delete",
                            text: "Delete"
                },
                "Cancel": {
                    click: function(){
                        $(this).dialog('close');
                    },
                    id: "button_resolver_ask_delete_cancel",
                    text: "Cancel"
                }
            },
            open: function() {
                do_dialog_icons();
                translate_dialog_resolver_ask_delete();
            }
        });

    $dialog_ask_new_resolvertype = $('#dialog_resolver_create').dialog({
        autoOpen: false,
        title: 'Creating a new UserIdResolver',
        width: 600,
        height: 500,
        modal: true,
        buttons: {
            'Cancel': { click: function(){
                $(this).dialog('close');
                },
                id: "button_new_resolver_type_cancel",
                text: "Cancel"
            },
            'LDAP': { click: function(){
                        // calling with no parameter, creates a new resolver
                        resolver_ldap("");
                        $(this).dialog('close');
                    },
                    id: "button_new_resolver_type_ldap",
                    text: "LDAP"

            },
            'SQL': { click: function(){
                    // calling with no parameter, creates a new resolver
                    resolver_sql("");
                    $(this).dialog('close');
                },
                id: "button_new_resolver_type_sql",
                text: "SQL"
            },
            'Flatfile': { click: function(){
                // calling with no parameter, creates a new resolver
                resolver_file("");
                $(this).dialog('close');
            },
            id: "button_new_resolver_type_file",
            text: "Flatfile"
            }
        },
        open: function() {
            translate_dialog_resolver_create();
            do_dialog_icons();
        }
    });

    $dialog_import_policy = $('#dialog_import_policy').dialog({
        autoOpen: false,
        title: 'Import policy file',
        width: 600,
        modal: true,
        buttons: {
            'import policy file': { click: function(){
                import_policy('vasco');
                $(this).dialog('close');
                },
                id: "button_policy_load",
                text: "Import policy file"
                },
            Cancel: {click: function(){
                $(this).dialog('close');
                },
                id: "button_policy_cancel",
                text: "Cancel"
                }
        },
        open: function(){
            translate_import_policy();
            do_dialog_icons();
        }
    });


    $dialog_ldap_resolver = $('#dialog_ldap_resolver').dialog({
        autoOpen: false,
        title: 'LDAP Resolver',
        width: 600,
        modal: true,
        buttons: {
            'Cancel': { click: function(){
                $(this).dialog('close');
                },
                id: "button_ldap_resolver_cancel",
                text: "Cancel"
                },
            'Save': { click: function(){
                    // Save the LDAP configuration
                    if ($("#form_ldapconfig").valid()) {
                        save_ldap_config();
                        //$(this).dialog('close');
                    }
                },
                id: "button_ldap_resolver_save",
                text: "Save"
            }
        },
        open: function() {
            do_dialog_icons();
            ldap_resolver_ldaps();
        }
    });

    $('#button_test_ldap').click(function(event){
        $('#progress_test_ldap').show();

        var url = '/admin/testresolver';
        var params = {};
        params['type']              = 'ldap';
        params['ldap_uri']          = $('#ldap_uri').val();
        params['ldap_basedn']       = $('#ldap_basedn').val();
        params['ldap_binddn']       = $('#ldap_binddn').val();
        params['ldap_password']     = $('#ldap_password').val();
        params['ldap_timeout']      = $('#ldap_timeout').val();
        params['ldap_loginattr']    = $('#ldap_loginattr').val();
        params['ldap_searchfilter'] = $('#ldap_searchfilter').val();
        params['ldap_userfilter']   = $('#ldap_userfilter').val();
        params['ldap_mapping']      = $('#ldap_mapping').val();
        params['ldap_sizelimit']    = $('#ldap_sizelimit').val();
        params['ldap_uidtype']      = $('#ldap_uidtype').val();
        params['ldap_certificate']  = $('#ldap_certificate').val();


        if ($('#ldap_noreferrals').is(':checked')) {
            params["NOREFERRALS"] = "True";
        }

        clientUrlFetch(url, params, function(xhdr, textStatus) {
                    var resp = xhdr.responseText;
                    var obj = jQuery.parseJSON(resp);
                    $('#progress_test_ldap').hide();
                    if (obj.result.status == true) {
                        result = obj.result.value.result;
                        if (result.lastIndexOf("success", 0) === 0 ) {
                            var limit = "";
                            if (result === "success SIZELIMIT_EXCEEDED") {
                                limit = i18n.gettext("LDAP Server, especially Active Directory, implement a default serverside maximum size limit of 1000 objects.") +
                                        i18n.gettext("This is independed of the local sizelimit and does not hinder the functionality of LinOTP.");
                            }
                            // show number of found users
                            var userarray = obj.result.value.desc;
                            var usr_msg = sprintf(i18n.gettext("Number of users found: %d"),userarray.length);
                            var msg = i18n.gettext("Connection Test: successful") +
                                      "<p>" + escape(usr_msg) + "</p><p class='hint'>" + escape(limit) + "</p>";

                            alert_box({'title': i18n.gettext("LDAP Connection Test"),
                                       'text': msg,
                                       'is_escaped': true});
                        }
                        else {
                            alert_box({'title': "LDAP Test",
                                       'text': escape(obj.result.value.desc),
                                       'is_escaped': true});
                        }
                    }
                    else {
                        alert_box({'title': "LDAP Test",
                                   'text': escape(obj.result.error.message),
                                   'is_escaped': true});
                    }
                    return false;
                 });
        return false;
    });
    $('#button_preset_ad').click(function(event){
        $('#ldap_loginattr').val('sAMAccountName');
        $('#ldap_searchfilter').val('(sAMAccountName=*)(objectClass=user)');
        $('#ldap_userfilter').val('(&(sAMAccountName=%s)(objectClass=user))');
        $('#ldap_mapping').val('{ "username": "sAMAccountName", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }');
        $('#ldap_uidtype').val('objectGUID');
        return false;
    });
    $('#button_preset_ldap').click(function(event){
        $('#ldap_loginattr').val('uid');
        $('#ldap_searchfilter').val('(uid=*)(objectClass=inetOrgPerson)');
        $('#ldap_userfilter').val('(&(uid=%s)(objectClass=inetOrgPerson))');
        $('#ldap_mapping').val('{ "username": "uid", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }');
        $('#ldap_uidtype').val('entryUUID');
        // CKO: we need to return false, otherwise the page will be reloaded!
        return false;
    });

    $dialog_sql_resolver = $('#dialog_sql_resolver').dialog({
        autoOpen: false,
        title: 'SQL Resolver',
        width: 600,
        modal: true,
        buttons: {
            'Cancel': {click: function(){
                $(this).dialog('close');
                },
                id: "button_resolver_sql_cancel",
                text: "Cancel"
            },
            'Save': {click: function(){
                // Save the SQL configuration
                if ($("#form_sqlconfig").valid()) {
                    save_sql_config();
                    //$(this).dialog('close');
                }
                },
                id: "button_resolver_sql_save",
                text: "Save"
            }
        },
        open: do_dialog_icons
    });

    $('#button_test_sql').click(function(event){
        $('#progress_test_sql').show();
        var url = '/admin/testresolver';
        var params = {};
        params['type'] = 'sql';
        params['sql_driver']    = $('#sql_driver').val();
        params['sql_user']      = $('#sql_user').val();
        params['sql_password']  = $('#sql_password').val();
        params['sql_server']    = $('#sql_server').val();
        params['sql_port']      = $('#sql_port').val();
        params['sql_database']  = $('#sql_database').val();
        params['sql_table']     = $('#sql_table').val();
        params['sql_where']     = $('#sql_where').val();
        params['sql_conparams'] = $('#sql_conparams').val();
        params['sql_encoding']  = $('#sql_encoding').val();

        clientUrlFetch(url, params, function(xhdr, textStatus) {
                    var resp = xhdr.responseText;
                    var obj = jQuery.parseJSON(resp);
                    $('#progress_test_sql').hide();
                    if (obj.result.status == true) {
                        rows = obj.result.value.rows;
                        if (rows > -1) {
                            // show number of found users
                            alert_box({'title': "SQL Test",
                                       'text': "text_sql_config_success",
                                       'param': escape(rows),
                                       'is_escaped': true});
                        } else {
                            err_string = escape(obj.result.value.err_string);
                            alert_box({'title': "SQL Test",
                                       'text': "text_sql_config_fail",
                                       'param': err_string,
                                       'is_escaped': true});
                        }
                    } else {
                        alert_box({'title': "SQL Test",
                                   'text' : escape(obj.result.error.message),
                                   'is_escaped': true,
                                   });
                    }
                    return false;
                 });
        return false;
    });

    $dialog_file_resolver = $('#dialog_file_resolver').dialog({
        autoOpen: false,
        title: 'File Resolver',
        width: 600,
        modal: true,
        maxHeight: 500,
        buttons: {
            'Cancel': {click: function(){
                $(this).dialog('close');
                },
                id: "button_resolver_file_cancel",
                text: "Cancel"
                },
            'Save': {click: function(){
                // Save the File configuration
                if ($("#form_fileconfig").valid()) {
                    save_file_config();
                    //$(this).dialog('close');
                }
                },
                id: "button_resolver_file_save",
                text: "Save"
            }
        },
        open: do_dialog_icons
    });


    $dialog_resolvers = $('#dialog_resolvers').dialog({
        autoOpen: false,
        title: 'Resolvers',
        width: 600,
        height: 500,
        modal: true,
        buttons: {
            'New': { click:  function(){
                        resolver_new_type();
                        resolvers_load();
                        },
                    id: "button_resolver_new",
                    text: "New"
            },
            'Edit': { click: function(){
                            resolver_edit_type();
                            resolvers_load();
                            },
                        id:"button_resolver_edit",
                        text: "Edit"
            },
            'Delete': { click: function(){
                            resolver_ask_delete();
                            resolvers_load();
                            },
                        id: "button_resolver_delete",
                        text:"Delete"
            },
            'Close': { click: function(){
                            $(this).dialog('close');
                            var resolvers = get_resolvers();
                            if (resolvers.length > 0) {
                                var realms = get_realms();
                                if (realms.length == 0) {
                                    $('#text_no_realm').dialog('open');
                            }   }
                        },
                        id: "button_resolver_close",
                        text:"Close"
            }
        },
        open: function(){
            translate_dialog_resolvers();
            do_dialog_icons();
        }
    });
    $('#menu_edit_resolvers').click(function(){
        resolvers_load();
        $dialog_resolvers.dialog('open');
    });


    /**************************************************
     *  Tools
     */
    $dialog_tools_getserial = create_tools_getserial_dialog();
    $('#menu_tools_getserial').click(function(){
        _fill_realms($('#tools_getserial_realm'),1);
        $dialog_tools_getserial.dialog('open');
    });

    $dialog_tools_copytokenpin = create_tools_copytokenpin_dialog();
    $('#menu_tools_copytokenpin').click(function(){
        //_fill_realms($('#tools_getserial_realm'),1)
        $dialog_tools_copytokenpin.dialog('open');
    });

    $dialog_tools_checkpolicy = create_tools_checkpolicy_dialog();
    $('#menu_tools_checkpolicy').click(function(){
        $dialog_tools_checkpolicy.dialog('open');
        $('#cp_allowed').hide();
        $('#cp_forbidden').hide();
        $('#cp_policy').html("");
    });

    $dialog_tools_exporttoken = create_tools_exporttoken_dialog();
    $('#menu_tools_exporttoken').click(function(){
        $dialog_tools_exporttoken.dialog('open');
    });

    $dialog_tools_exportaudit = create_tools_exportaudit_dialog();
    $('#menu_tools_exportaudit').click(function(){
        $dialog_tools_exportaudit.dialog('open');
    });

    $dialog_tools_migrateresolver = create_tools_migrateresolver_dialog();
    $('#menu_tools_migrateresolver').click(function(){
        //_fill_realms($('#tools_getserial_realm'),1)
        _fill_resolvers($('#copy_to_resolver'))
        _fill_resolvers($('#copy_from_resolver'))
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
            'OK': {click:function() {
                    $(this).dialog('close');
                },
                id: "button_show_enroll_ok",
                text: "Ok"
            }
        },
        open: function() {
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
            'Delete': {click: function(){
                $(this).dialog('close');
                show_waiting();
                realm_delete();
                },
                id: "button_realm_ask_delete_delete",
                text: "Delete"
            },
            Cancel: {click:function(){
                $(this).dialog('close');
                },
                id: "button_realm_ask_delete_cancel",
                text: "Cancel"
            }
        },
        open: function() {
            do_dialog_icons();
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
            'New': { click: function(){
                    realm_modify('');
                },
                id: "button_realms_new",
                text: "New"
                },
            'Edit': { click: function(){
                    realm_modify(g.realm_to_edit);
                },
                id: "button_realms_edit",
                text: "Edit"
                },
            'Delete': {click: function(){
                realm_ask_delete();
                realms_load();
                fill_realms();
                },
                id: "button_realms_delete",
                text: "Delete"
                },
            'Close': { click: function(){
                $(this).dialog('close');
                },
                id: "button_realms_close",
                text: "Close"
                },
            'Set Default': {click: function(){
                var realm = "";
                if (g.realm_to_edit.match(/^(\S+)\s\[(.+)\]/)) {
                    realm = g.realm_to_edit.replace(/^(\S+)\s+\[(.+)\]/, "$1");
                    set_default_realm(realm);
                }
                else if (g.realm_to_edit.match(/^\S+\s+\(Default\)\s+\[.+\]/)) {
                    alert_info_text({'text': "text_already_default_realm",
                                     "type": ERROR,
                                    'is_escaped': true});
                }
                else {
                    alert_info_text({'text': "text_realm_regexp_error",
                                     "type": ERROR,
                                     'is_escaped': true});
                }
                },
                id: "button_realms_setdefault",
                text:"Set Default"
                },
            'Clear Default': {click: function(){
                var params = {'session':getsession()};
                $.post('/system/setDefaultRealm', params,
                 function(){
                    realms_load();
                    fill_realms();
                });
                },
                id: "button_realms_cleardefault",
                text: "Clear Default"
                }
        },
        open: function(){
            translate_dialog_realms();
            do_dialog_icons();
        }
    });
    $('#menu_edit_realms').click(function(){
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
                click: function(){
                    var validation_fails = "";
                    $('#dialog_token_settings').find('form').each(
                        function( index ) {
                            var attr = $(this).closest("form").closest("div").attr('id');
                            var tt= attr.split("_")[0];

                            if ($.inArray(tt, $token_config_changed) !== -1) {
                                var valid = $(this).valid();
                                if (valid != true) {
                                    formName = $(this).find('legend').text();
                                    if (formName.length == 0) {
                                        formName = $(this).find('label').first().text();
                                    }
                                    validation_fails = validation_fails +
                                                "<li>" + escape(jQuery.trim(formName)) +"</li>";
                                }
                            }
                        }
                    );
                    if (validation_fails.length > 0) {
                        alert_box({'title': i18n.gettext("Form Validation Error"),
                                   'text': "text_form_validation_error1",
                                   'param':validation_fails,
                                   'is_escaped': true
                                   });
                    }
                    else
                    {
                        save_token_config();
                        $(this).dialog('close');
                    }
                },
                id: "button_token_save",
                text:"Save Token config"
                },
            Cancel: {click: function(){
                $(this).dialog('close');
                },
                id: "button_token_cancel",
                text: "Cancel"
                }
        },
        open: function(event, ui) {
            /**
             * we reset all labels to not contain the leadin star, which shows
             * something has changed before
             */
            var selectTag = $('#tab_token_settings');
            selectTag.find('li').each( function()
            {
                var a_ref = $(this).find("a");
                var label = a_ref.text();
                label = label.replace("* ","");
                a_ref.text(label);
            });
            /* clean up the array, so that it contains no token changed info*/
            $token_config_changed.splice(0,$token_config_changed.length);
            do_dialog_icons();
            translate_token_settings();
        }
    });
    $('#tab_token_settings').tabs();



    /*********************************************************************
     * System config
     */

    var $dialog_system_config = $('#dialog_system_settings').dialog({
        autoOpen: false,
        title: 'System config',
        width: 600,
        modal: true,
        buttons: {
            'Save config': {click: function(){
                if ($("#form_sysconfig").valid()) {
                    save_system_config();
                    $(this).dialog('close');
                } else {
                    alert_box({'title': "",
                               'text': "text_error_saving_system_config",
                               'is_escaped': true});
                }
                },
                id: "button_system_save",
                text:"Save config"
                },
            Cancel: {click: function(){
                $(this).dialog('close');
                },
                id: "button_system_cancel",
                text: "Cancel"
                }
        },
        open: function(event, ui) {
            do_dialog_icons();
            translate_system_settings();
        }
    });
    $('#tab_system_settings').tabs();

    $("#form_sysconfig").validate({
        rules: {
            sys_maxFailCount: {
                required: true,
                minlength: 2,
                number: true
            },
            sys_countWindow: {
                required: true,
                minlength: 2,
                number: true
            },
            sys_syncWindow: {
                required: true,
                minlength: 3,
                number: true
            },
            sys_otpLen: {
                required: true,
                minlength: 1,
                maxlength: 1,
                number: true
            }
        }
    });

    $('#menu_system_config').click(function(){
        load_system_config();
        $dialog_system_config.dialog('open');
    });

    $('#menu_token_config').click(function(){
    try {
          load_token_config();
          $dialog_token_config.dialog('open');
        } catch (error) {
          alert_box({'title': '',
                     'text': "text_catching_generic_error",
                     'param': escape(error),
                     'is_escaped': true});
        }
    });


    $('#menu_policies').click(function(){
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
            'Ok': {click: function(){
                    $(this).dialog('close');
                },
                id: "button_support_contact_close",
                text: "Ok"
            }
        },
        open: function(event, ui) {
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
            'Setup Support': {click: function(){
                $dialog_set_support.dialog('open');
                $(this).dialog('close');
                },
                id: "button_support_set",
                text:"Setup support subscription"
                },
            'Close': {click: function(){
                $(this).dialog('close');
                },
                id: "button_support_close",
                text: "Close"
                }
        },
        open: function(event, ui) {
            do_dialog_icons();
            translate_system_settings();
        }

    });
    $('#menu_view_support').click(function(){
        translate_support_view();
        support_view();
        $dialog_view_support.dialog('open');
    });

    var $dialog_set_support = $('#dialog_set_support').dialog({
        autoOpen: false,
        title: 'Load LinOTP Support Subscription',
        width: 600,
        modal: true,
        buttons: {
            'Set subscription': {click: function(){
                support_set();
                $(this).dialog('close');
                },
                id: "button_support_set",
                text: "Set subscription"
                },
            Cancel: {click: function(){
                $(this).dialog('close');
                },
                id: "button_support_cancel",
                text: "Cancel"
                }
        },
        open: do_dialog_icons
    });
    $('#menu_set_support').click(function(){
        translate_support_set();
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
                click: function(){ $(this).dialog('close');},
                id: "button_about_close",
                text: "Close"
                }
        },
        open: do_dialog_icons
    });
    $('#menu_about').click(function(){
        translate_about();
        //about_view();
        $dialog_about.dialog('open');
    });


    /**********************************************************************
     * loading token file
     */

    var $dialog_load_tokens_pskc  = create_pskc_dialog();
    var $dialog_load_tokens_vasco = create_vasco_dialog();
    var $dialog_load_tokens_feitian = create_feitian_dialog();
    var $dialog_load_tokens_dpw = create_dpw_dialog();
    var $dialog_load_tokens_dat = create_dat_dialog();
    var $dialog_load_tokens_aladdin = create_aladdin_dialog();
    var $dialog_load_tokens_oathcsv = create_oathcsv_dialog();
    var $dialog_load_tokens_yubikeycsv = create_yubikeycsv_dialog();

    $('#menu_load_aladdin_xml_tokenfile').click(function(){
        $dialog_load_tokens_aladdin.dialog('open');
    });
    $('#menu_load_oath_csv_tokenfile').click(function(){
         $dialog_load_tokens_oathcsv.dialog('open');
    });
    $('#menu_load_yubikey_csv_tokenfile').click(function(){
         $dialog_load_tokens_yubikeycsv.dialog('open');
    });
    $('#menu_load_feitian').click(function(){
        $dialog_load_tokens_feitian.dialog('open');
    });
    $('#menu_load_pskc').click(function(){
        $dialog_load_tokens_pskc.dialog('open');
    });
    $('#menu_load_dpw').click(function(){
        $dialog_load_tokens_dpw.dialog('open');
    });
    $('#menu_load_dat').click(function(){
        $dialog_load_tokens_dat.dialog('open');
    });
    $('#menu_load_vasco').click(function(){
        $dialog_load_tokens_vasco.dialog('open');
    });


    /***********************************************************************
     *  Alert dialog
     */
    $('#dialog_alert').dialog({
        autoOpen: false,
        open: function(){

        },
        modal: true,
        buttons: {
            'OK': {click: function(){
                $(this).dialog('close');
                },
                id: "button_alert_ok",
                text: "OK"
                }
        }
    });

    /*******************************************************
     * Enrolling tokens
     */
    function button_enroll(){

        init_$tokentypes();
        try {
            tokentype_changed();
        } catch (error) {
            alert_box({'title': '',
                       'text': "text_catching_generic_error",
                       'param': escape(error),
                       'is_escaped': true,
                       });
            return false;
        }
        // ajax call  w. callback//
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
            'Enroll': {click: function(){
                token_enroll();
                $(this).dialog('close');
                },
                id: "button_enroll_enroll",
                text: "Enroll"
                },
            Cancel: { click: function(){
                $(this).dialog('close');
                },
                id: "button_enroll_cancel",
                text: "Cancel"
                }
        },
        open: do_dialog_icons
    });

    $('#button_enroll').click(button_enroll);
   //jQuery(document).bind('keydown', 'Alt+e', button_enroll());



    $('#realms').change(function(){
        var new_realm = $('#realm').val();
        $('#user_table').flexOptions({
            params: [{
                name: 'realm',
                value: new_realm
            }]
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
            'Set PIN': {click: function(){
                token_setpin();
                $(this).dialog('close');
                },
                id: "button_setpin_setpin",
                text: "Set PIN"
                },
            Cancel: { click: function(){
                $(this).effect('puff');
                $(this).dialog('close');
                },
                id: "button_setpin_cancel",
                text: "Cancel"
                }
        },
        open: function() {
            translate_set_pin();
            do_dialog_icons();
        },
        close: function() {
            $('#pin1').val('');
            $('#pin2').val('');
        }
    });

    $('#button_setpin').click(function(){
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
            'Unassign tokens': {click: function(){
                token_unassign();
                $(this).dialog('close');
                },
                id: "button_unassign_unassign",
                text: "Unassign tokens"
                },
            Cancel: { click: function(){
                $(this).dialog('close');
                },
                id: "button_unassign_cancel",
                text: "Cancel"
                }
        },
        open: function() {
            do_dialog_icons();
            translate_dialog_unassign();
            tokens = get_selected_tokens();
            token_string = tokens.join(", ");
            $('#tokenid_unassign').html(escape(token_string));
        }
    });
    $('#button_unassign').click(function(){
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
            'Delete tokens': {click: function(){
                token_delete();
                $(this).dialog('close');
                },
                id: "button_delete_delete",
                text: "Delete tokens"
                },
            Cancel: {click: function(){
                $(this).dialog('close');
                },
                id: "button_delete_cancel",
                text: "Cancel"
                }
        },
        open: function(){
            tokens = get_selected_tokens();
            $('#delete_info').html(escape(tokens.join(", ")));
            translate_dialog_delete_token();
            do_dialog_icons();
        }
    });
    $('#button_delete').click(function(){
        $dialog_delete_token.dialog('open');
        return false;
    });

    $( "#alert_box" ).dialog({
        autoOpen: false,
        modal: true,
        buttons: {
                Ok: function() {
                    $( this ).dialog( "close" );
                }
            }
     });

     $('#text_no_realm').dialog({
        autoOpen: false,
        modal: true,
        show: {
            effect : "fade",
            duration: 1000
        },
        hide: {
            effect : "fade",
            duration: 500
        },
        buttons: {
            Ok: function() {
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
        beforeLoad: function( event, ui ) {
            // The purpose of the following is to prevent automatic reloads
            // of the tab. When the tab loads for the first time the 'loaded'
            // option is set.
            // The tab can be reloaded by reloading the whole page, or using
            // the controls provided inside the tab.
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
                ui.jqXHR.error(function(){
                    ui.panel.html("Couldn't load this tab. " +
                        "Please contact your administrator.");
                });
            }
            return;
        }
        //load: function(event, ui){
        //    get_selected();
        //}
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
            OK: {click: function(){
                token_info_save();
                $(this).dialog('close');
                },
                id: "button_tokeninfo_ok",
                text: "OK"
                },
            Cancel: {click: function(){
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
        width: 720,
        modal: true,
        open: function(){
            translate_dialog_token_info();
            do_dialog_icons();
        }
    });


    fill_realms();

    //$("#token_table").flexigrid();
    //$("#user_table").flexigrid();
    //$("#audit_table").flexigrid();

    // Log Div
    $("#logAccordion").accordion({
        fillSpace: true
    });
    /*
     $("#logAccordionResizer").resizable({
     resize: function(){
     $("#accordion").accordion("resize");
     },
     minHeight: 60
     });
     */


});
//--------------------------------------------------------------------------------------
// End of document ready


/************************************************************************
 *
 *  Resolver edit funtions
 */
function resolver_file(name){

    var obj = {
        'result': {
            'value': {
                'data': {
                    'fileName': '/etc/passwd'
                }
            }
        }
    };
    if (name) {
        // load the config of the resolver "name".
        clientUrlFetch('/system/getResolver',{'resolver' : name}, function(xhdr, textStatus) {

                var resp = xhdr.responseText;
                obj = jQuery.parseJSON(resp);
                //obj.result.value.data.fileName;

                $('#file_resolvername').val(name);
                $('#file_filename').val(obj.result.value.data.fileName);
        });
    } else {
        $('#file_resolvername').val("");
        $('#file_filename').val(obj.result.value.data.fileName);
    }

    $dialog_file_resolver.dialog('open');

    $("#form_fileconfig").validate({
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
                resolvername: true
            }
        }
    });
}

function realm_modify(name) {
    var resolvers = get_resolvers();
    if (resolvers.length === 0) {
        alert_box({ title: "Cannot " + (name.length === 0 ? "create" : "edit") + " a realm", text: "Please create a UserIdResolver first"});
    } else {
        realm_edit(name);
        realms_load();
        fill_realms();
    }
}

function realm_edit(name){

    var realm = "";
    var html_intro;
    $('#realm_intro_edit').hide();
    $('#realm_intro_new').hide();
    if (name) {
        if (name.match(/^(\S+)\s(\[|\()(.+)\]/)) {
            realm = name.replace(/^(\S+)\s+(\[|\()(.+)\]/, "$1");
        }
        else {
            alert_info_text({'text': "text_realm_name_error",
                             "type": ERROR,
                            'is_escaped': true});
        }
        $('#realm_edit_realm_name').html(escape(realm));
        $('#realm_name').val(realm);
        $('#realm_intro_edit').show();
    }
    else {
        $('#realm_intro_new').show();
    }

    // get the realm configuration
    var resp = clientUrlFetchSync('/system/getRealms',{});
    var realmObj = jQuery.parseJSON(resp);

    var uidresolvers = [];
    var default_realm = "";

    if (realm) {
        uidresolvers = realmObj.result.value[realm].useridresolver;
    }

    // get all resolvers
    var resolvers = '';
    var params = {'session':getsession()};
    $.post('/system/getResolvers', params,
     function(data, textStatus, XMLHttpRequest){
        resolvers = '<ol id="resolvers_in_realms_select" class="select_list" class="ui-selectable">';
        for (var key in data.result.value) {
            var klass = 'class="ui-widget-content"';
            for (var i_reso in uidresolvers) {
                // check if this resolver is contained in the realm
                var reso = uidresolvers[i_reso].split('.');
                if (reso[reso.length - 1] == key) {
                    klass = 'class="ui-selected" class="ui-widget-content" ';
                }
            }
            var e_key = escape(key);
            var id = "id=realm_edit_click_" + e_key;
            var e_resolver_type = escape(data.result.value[key].type);
            resolvers += '<li '+id+' '+ klass + '>' + e_key + ' [' + e_resolver_type + ']</li>';
        }
        resolvers += '</ol>';

        $('#realm_edit_resolver_list').html(resolvers);
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

function check_for_selected_resolvers(){
    var resolvers_in_realm_to_edit = new Array();
    $.when.apply($, $(".ui-selected", this).each(function(){
        var index = $("#resolvers_in_realms_select li").index(this);
        var reso = escape($(this).html());
        if (reso.match(/(\S+)\s\[(\S+)\]/)) {
            var r = reso.replace(/(\S+)\s+\S+/, "$1");
            var t = reso.replace(/\S+\s+\[(\S+)\]/, "$1");
        }
        else {
            alert_info_text({'text': "text_regexp_error",
                             'param': escape(reso),
                             'type': ERROR,
                             'is_escaped': true});
        }
        switch (t) {
            case 'ldapresolver':
                resolvers_in_realm_to_edit.push('useridresolver.LDAPIdResolver.IdResolver.' + r);
                break;
            case 'sqlresolver':
                resolvers_in_realm_to_edit.push('useridresolver.SQLIdResolver.IdResolver.' + r);
                break;
            case 'passwdresolver':
                resolvers_in_realm_to_edit.push('useridresolver.PasswdIdResolver.IdResolver.' + r);
                break;
        }
    })).done(function(){
        g.resolvers_in_realm_to_edit = resolvers_in_realm_to_edit.join(",");
    }); // end of each
}

function resolver_set_ldap(obj) {
    $('#ldap_uri').val(obj.result.value.data.LDAPURI);
    $('#ldap_basedn').val(obj.result.value.data.LDAPBASE);
    $('#ldap_binddn').val(obj.result.value.data.BINDDN);
    $('#ldap_password').val(obj.result.value.data.BINDPW);
    $('#ldap_timeout').val(obj.result.value.data.TIMEOUT);
    $('#ldap_sizelimit').val(obj.result.value.data.SIZELIMIT);
    $('#ldap_loginattr').val(obj.result.value.data.LOGINNAMEATTRIBUTE);
    $('#ldap_searchfilter').val(obj.result.value.data.LDAPSEARCHFILTER);
    $('#ldap_userfilter').val(obj.result.value.data.LDAPFILTER);
    $('#ldap_mapping').val(obj.result.value.data.USERINFO);
    $('#ldap_uidtype').val(obj.result.value.data.UIDTYPE);
    $('#ldap_certificate').val(obj.result.value.data.CACERTIFICATE);
    $('#ldap_noreferrals').val(obj.result.value.data.NOREFERRALS);
    ldap_resolver_ldaps();
}

function resolver_ldap(name){

    var obj = {
        'result': {
            'value': {
                'data': {
                    'BINDDN': 'cn=administrator,dc=yourdomain,dc=tld',
                    'LDAPURI': 'ldap://linotpserver1, ldap://linotpserver2',
                    'LDAPBASE': 'dc=yourdomain,dc=tld',
                    'TIMEOUT': '5',
                    'SIZELIMIT' : '500',
                    'LOGINNAMEATTRIBUTE': 'sAMAccountName',
                    'LDAPSEARCHFILTER': '(sAMAccountName=*)(objectClass=user)',
                    'LDAPFILTER': '(&(sAMAccountName=%s)(objectClass=user))',
                    'USERINFO': '{ "username": "sAMAccountName", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }',
                    'UIDTYPE': 'objectGUID',
                    'CACERTIFICATE' : '',
                    'NOREFERRALS' : 'True',
                }
            }
        }
    };


    if (name) {
        // load the config of the resolver "name".
        clientUrlFetch('/system/getResolver', {'resolver' : name}, function(xhdr, textStatus) {
            var resp = xhdr.responseText;
            var obj = jQuery.parseJSON(resp);
            $('#ldap_resolvername').val(name);
            if (obj.result.status) {
                resolver_set_ldap(obj);
            } else {
                // error reading resolver
                alert_box({'title': "",
                           'text': "text_ldap_load_error",
                           'param': escape(obj.result.error.message),
                           'is_escaped': true});
            }

          });
    } // end if
    else {
        $('#ldap_resolvername').val("");
        resolver_set_ldap(obj);
    }
    $('#ldap_noreferrals').prop('checked', ("True" == obj.result.value.data.NOREFERRALS));

    $('#progress_test_ldap').hide();
    $dialog_ldap_resolver.dialog('open');


    $("#form_ldapconfig").validate({
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
                resolvername: true
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

}

function set_form_input(form_name, data) {
/*
 * for all input fields of the form, set the corresponding
 * values from the obj
 *
 * Assumption:
 *   the input form names are the same as the config entries
 */
    var items = {};
    $('#'+form_name).find(':input').each(
        function (id, el) {
            if (el.name != "") {
                name = el.name;
                id = el.id;
                if (data.hasOwnProperty(name) ){
                    var value = data[name];
                    $('#'+id).val(value);
                } else {
                    $('#'+id).val('');
            } } }
    );

    for (var i = 0; i < items.length; i++) {
        var name = items[i];

    }

}

function get_form_input(form_name) {
/*
 * for all input fields of the form, set the corresponding
 * values from the obj
 *
 * Assumption:
 *   the input form names are the same as the config entries
 */
    var items = {};
    $('#'+form_name).find(':input').each(
        function (id, el) {
            if (el.name != "") {
                items[el.name] = el.value;
            }   }
    );
    return items;
}

function resolver_set_sql(obj) {

    $('#sql_driver').val(obj.result.value.data.Driver);
    $('#sql_server').val(obj.result.value.data.Server);
    $('#sql_port').val(obj.result.value.data.Port);
    $('#sql_limit').val(obj.result.value.data.Limit);
    $('#sql_database').val(obj.result.value.data.Database);
    $('#sql_table').val(obj.result.value.data.Table);
    $('#sql_user').val(obj.result.value.data.User);
    $('#sql_password').val(obj.result.value.data.Password);
    $('#sql_mapping').val(obj.result.value.data.Map);
    $('#sql_where').val(obj.result.value.data.Where);
    $('#sql_conparams').val(obj.result.value.data.conParams);
    $('#sql_encoding').val(obj.result.value.data.Encoding);
}

function resolver_sql(name){

    var obj = {
        'result': {
            'value': {
                'data': {
                    'Database': 'yourUserDB',
                    'Driver': 'mysql',
                    'Server': '127.0.0.1',
                    'Port': '3306',
                    'User': 'user',
                    'Password': 'secret',
                    'Table': 'usertable',
                    'Map': '{ "userid" : "id", "username": "user", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" ,"password" : "password", "salt" : "salt" }',
                    'Where' : '',
                    'conParams' : '',
                    'Encoding' : ''

                }
            }
        }
    };

    $('#progress_test_sql').hide();

    if (name) {
        // load the config of the resolver "name".
        clientUrlFetch('/system/getResolver', {'resolver' : name}, function(xhdr, textStatus) {
                var resp = xhdr.responseText;
                var obj = jQuery.parseJSON(resp);
                //obj.result.value.data.BINDDN;
                $('#sql_resolvername').val(name);
                if (obj.result.status) {
                    resolver_set_sql(obj);
                } else {
                    // error reading resolver
                    alert_box({'title': "",
                               'text': "text_sql_load_error",
                               'param': escape(obj.result.error.message),
                               'is_escaped':true});
                }
            });
        } // end if
    else {
        $('#sql_resolvername').val("");
        resolver_set_sql(obj);
    }

    $dialog_sql_resolver.dialog('open');


    $("#form_sqlconfig").validate({
        rules: {
            sql_resolvername: {
                required: true,
                minlength: 4,
                resolvername: true
            },
            sql_driver: {
                required: true,
                minlength: 3,
                number: false,
                sql_driver: true
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
}

function split( val ) {
        return val.split( /,\s*/ );
}
function extractLast( term ) {
        return split( term ).pop();
}

function renew_policy_actions(){
    /*
     * This function needs to be called, whenever the scope is changed or loaded.
     */
    var scope=$('#policy_scope_combo').val();
    var actions=get_scope_actions(scope);
    define_policy_action_autocomplete( actions );
}

function define_policy_action_autocomplete(availableActions) {
    /*
     * This sets the allowed actions in the policy action input
     */
    $( "#policy_action" )
        .autocomplete({
            minLength: 0,
            source: function( request, response ) {
                // delegate back to autocomplete, but extract the last term
                response( $.ui.autocomplete.filter(
                    availableActions, extractLast( request.term ) ) );
            },
            focus: function() {
                // prevent value inserted on focus
                return false;
            },
            select: function( event, ui ) {
                var terms = split( this.value );
                // remove the current input
                terms.pop();
                // add the selected item
                terms.push( ui.item.value );
                // add placeholder to get the comma-and-space at the end
                terms.push( "" );
                this.value = terms.join( ", " );
                return false;
            }
        });
}

function view_policy() {

    $("#policy_table").flexigrid({
            url : '/system/policies_flexi',
            method: 'POST',
            dataType : 'json',
            colModel : [
                {display: i18n.gettext('Active'), name : 'active', width : 35, sortable : true},
                {display: i18n.gettext('Name'), name : 'name', width : 100, sortable : true},
                {display: i18n.gettext('User'), name : 'user', width : 80, sortable : true},
                {display: i18n.gettext('Scope'), name : 'scope', width : 80, sortable : true},
                {display: i18n.gettext('Action'), name : 'action', width : 200, sortable : true},
                {display: i18n.gettext('Realm'), name : 'realm', width : 100, sortable : true},
                {display: i18n.gettext('Client'), name : 'client', width : 200, sortable : true},
                {display: i18n.gettext('Time'), name : 'time', width : 50, sortable : true}
                ],
            height: 200,
            searchitems : [
                {display: i18n.gettext('All other columns'), name : 'all', isdefault: true}
                ],
            rpOptions: [10,15,20,50,100],
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
            addTitleToCell: true,
            dblClickResize: true,
            searchbutton: true
    });

    $('#policy_export').attr("href", '/system/getPolicy/policy.cfg?session=' + getsession());

    $('#policy_import').click(function(){
        $dialog_import_policy.dialog("open");
    });

    $('#button_policy_add').click(function(event){
        event.preventDefault();
        var pol_name = $('#policy_name').val();
        pol_name = $.trim(pol_name);
        if (pol_name.length == 0) {
        alert_box({'title': 'Policy Name',
                   'text': "text_policy_name_not_empty",
                   'is_escaped': true});
            return;
        }

        if ($('#policy_active').is(':checked')) {
            pol_active = "True";
        } else {
            pol_active = "False";
        }
        var params = { 
                'name' : $('#policy_name').val(),
                'user' : $('#policy_user').val(),
                'action' : $('#policy_action').val(),
                'scope' : $('#policy_scope_combo').val(),
                'realm' : $('#policy_realm').val(),
                'time' : $('#policy_time').val(),
                'client' : $('#policy_client').val(),
                'active' : pol_active,
                'session':getsession() };
        $.post('/system/setPolicy', params,
         function(data, textStatus, XMLHttpRequest){
            if (data.result.status == true) {
                alert_info_text({'text': "text_policy_set",
                                 'is_escaped': true});
                $('#policy_table').flexReload();
            }else {
                alert_info_text({'text': escape(data.result.error.message),
                                 'type': ERROR,
                                 'is_escaped': true});
            }
        });
    });

    $('#button_policy_delete').click(function(event){
        event.preventDefault();
        var policy = get_selected_policy().join(',');
        if (policy) {
            var params = {'name' : policy, 'session':getsession()};
            $.post('/system/delPolicy', params,
             function(data, textStatus, XMLHttpRequest){
                if (data.result.status == true) {
                    alert_info_text({'text': "text_policy_deleted",
                                     'is_escaped': true});
                    $('#policy_table').flexReload();
                } else {
                    alert_info_text({'text': escape(data.result.error.message),
                                     "type": ERROR,
                                     'is_escaped': true});
                }
            });
            $('#policy_form').trigger("reset");
        }
    });

    $('#button_policy_clear').click(function(event){
        event.preventDefault();
        $('#policy_form').trigger("reset");
    });

    $('#policy_scope_combo').change(function(){
        renew_policy_actions();
    });

    $('#policy_table').click(function(event){
        get_selected();
    });

}

function view_token() {
        $("#token_table").flexigrid({
            url : '/manage/tokenview_flexi',
            method: 'POST',
            dataType : 'json',
            colModel : [
                {display: i18n.gettext('Serial Number'), name : 'TokenSerialnumber', width : 100, sortable : true, align: 'center'},
                {display: i18n.gettext('Active'), name : 'Isactive', width : 40, sortable : true, align: 'center'},
                {display: i18n.gettext('Username'), name : 'Username', width : 100, sortable : false, align: 'center'},
                {display: i18n.gettext('Realm'), name : 'realm', width : 100, sortable : false, align: 'center'},
                {display: i18n.gettext('Type'), name : 'TokenType', width : 50, sortable : true, align: 'center'},
                {display: i18n.gettext('Login Attempts Failed'), name : 'FailCount', width : 140, sortable : true, align: 'center'},
                {display: i18n.gettext('Description'), name : 'TokenDesc', width : 100, sortable : true, align: 'center'},
                {display: i18n.gettext('Max Login Attempts'), name : 'maxfailcount', width : 110, sortable : false, align: 'center'},
                {display: i18n.gettext('OTP Length'), name : 'otplen', width : 75, sortable : false, align: 'center'},
                {display: i18n.gettext('Count Window'), name : 'countwindow', width : 90, sortable : false, align: 'center'},
                {display: i18n.gettext('Sync Window'), name : 'syncwindow', width : 80, sortable : false, align: 'center'},
                {display: i18n.gettext('User ID'), name : 'Userid', width : 60, sortable : true, align: 'center'},
                {display: i18n.gettext('Resolver'), name : 'IdResolver', width : 200, sortable : true, align: 'center'}
                ],
            height: 400,
            searchitems : [
                {display: i18n.gettext('Login Name'), name: 'loginname', isdefault: true },
                {display: i18n.gettext('All other columns'), name : 'all'},
                {display: i18n.gettext('Realm'), name: 'realm' }
                ],
            rpOptions: [10,15,20,50,100],
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
            addTitleToCell: true,
            dblClickResize: true,
            searchbutton: true
    });
    $('#token_table').click(function(event){
        get_selected();
    });

}

function view_user() {
        $("#user_table").flexigrid({
            url : '/manage/userview_flexi',
            method: 'POST',
            dataType : 'json',
            colModel : [
                {display: i18n.gettext('Username'), name : 'username', width : 90, sortable : true, align:"left"},
                {display: i18n.gettext('UserIdResolver'), name : 'useridresolver', width : 200, sortable : true, align:"left"},
                {display: i18n.gettext('Surname'), name : 'surname', width : 100, sortable : true, align:"left"},
                {display: i18n.gettext('Given Name'), name : 'givenname', width : 100, sortable : true, align:"left"},
                {display: i18n.gettext('Email'), name : 'email', width : 100, sortable : false, align:"left"},
                {display: i18n.gettext('Mobile'), name : 'mobile', width : 50, sortable : true, align:"left"},
                {display: i18n.gettext('Phone'), name : 'phone', width : 50, sortable : false, align:"left"},
                {display: i18n.gettext('User ID'), name : 'userid', width : 200, sortable : true, align:"left"}
            ],
            height: 400,
            searchitems : [
                {display: i18n.gettext('Username'), name : 'username', isdefault: true},
                {display: i18n.gettext('Surname'), name : 'surname'},
                {display: i18n.gettext('Given Name'), name : 'givenname'},
                {display: i18n.gettext('Description'), name : 'description'},
                {display: i18n.gettext('User ID'), name : 'userid'},
                {display: i18n.gettext('Email'), name : 'email'},
                {display: i18n.gettext('Mobile'), name : 'mobile'},
                {display: i18n.gettext('Phone'), name : 'phone'}
                ],
            rpOptions: [15,20,50,100],
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
            addTitleToCell: true,
            dblClickResize: true,
            searchbutton: true
    });

    $('#user_table').click(function(event){
        get_selected();
    });
}

function view_audit() {
       $("#audit_table").flexigrid({
            url : '/audit/search',
            method: 'POST',
            dataType : 'json',
            colModel : [
                {display: i18n.gettext('Number'), name : 'number', width : 50, sortable : true},
                {display: i18n.gettext('Date'), name : 'date', width : 160, sortable : true},
                {display: i18n.gettext('Signature'), name : 'signature', width : 60, sortable : false},
                {display: i18n.gettext('Missing Lines'), name : 'missing_lines', width : 90, sortable : false},
                {display: i18n.gettext('Action'), name : 'action', width : 120, sortable : true},
                {display: i18n.gettext('Success'), name : 'success', width : 50, sortable : true},
                {display: i18n.gettext('Serial'), name : 'serial', width : 100, sortable : true},
                {display: i18n.gettext('Token Type'), name : 'tokentype', width : 80, sortable : true},
                {display: i18n.gettext('User'), name : 'user', width : 100, sortable : true},
                {display: i18n.gettext('Realm'), name : 'realm', width : 100, sortable : true},
                {display: i18n.gettext('Administrator'), name : 'administrator', width : 100, sortable : true},
                {display: i18n.gettext('Action Detail'), name : 'action_detail', width : 200, sortable : true},
                {display: i18n.gettext('Info'), name : 'info', width : 200, sortable : true},
                {display: i18n.gettext('LinOTP Server'), name : 'linotp_server', width : 100, sortable : true},
                {display: i18n.gettext('Client'), name : 'client', width : 100, sortable : true},
                {display: i18n.gettext('Log Level'), name : 'log_level', width : 40, sortable : true},
                {display: i18n.gettext('Clearance Level'), name : 'clearance_level', width : 20, sortable : true}
                ],
            height: 400,
            searchitems : [
                {display: i18n.gettext('Serial'), name : 'serial', isdefault: true},
                {display: i18n.gettext('User'), name : 'user', isdefault: false},
                {display: i18n.gettext('Realm'), name : 'realm', isdefault: false},
                {display: i18n.gettext('Action'), name: 'action' },
                {display: i18n.gettext('Action Detail'), name: 'action_detail' },
                {display: i18n.gettext('Token Type'), name: 'token_type' },
                {display: i18n.gettext('Administrator'), name: 'administrator' },
                {display: i18n.gettext('Successful'), name: 'success' },
                {display: i18n.gettext('Info'), name: 'info' },
                {display: i18n.gettext('LinOTP Server'), name: 'linotp_server' },
                {display: i18n.gettext('Client'), name: 'client' },
                {display: i18n.gettext('Date'), name: 'date' },
                {display: i18n.gettext('Extended Search'), name: 'extsearch' }
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
            onSubmit: on_submit_flexi,
            addTitleToCell: true,
            searchbutton: true
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
