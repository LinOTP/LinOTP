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

var i18n = new Jed({});
var sprintf = Jed.sprintf;


function create_tools_getserial_dialog() {
     var $dialog = $('#dialog_get_serial').dialog({
        autoOpen: false,
        title: 'Get Serial by OTP value',
        width: 600,
        modal: true,
        buttons: {
            'Get Serial': { click:  function(){
                        getSerialByOtp($('#tools_getserial_otp').val(),
                                $('#tools_getserial_type').val(),
                                $('#tools_getserial_assigned').val(),
                                $('#tools_getserial_realm').val()
                            );
                        },
                    id: "button_tools_getserial_ok",
                    text: "Get Serial"
            },
            'Close': { click: function(){
                            $(this).dialog('close');
                        },
                        id: "button_tools_getserial_close",
                        text:"Close"
            }
        },
        open: function() {
            translate_get_serial();
            do_dialog_icons();
        }
    });
    return $dialog;
  }


function copyTokenPin(from_token, to_token) {
    var param = {};
    param["from"] = from_token;
    param["to"]   = to_token;

    var resp = clientUrlFetchSync('/admin/copyTokenPin', param, true);
    var obj = jQuery.parseJSON(resp);
        if (obj.result.status==true) {
            if (obj.result.value==true) {
                alert("Token PIN copied successfully.");
            }
            else
                alert("Could not copy token PIN.");
    }
}

function create_tools_copytokenpin_dialog() {
     var $dialog = $('#dialog_copy_token').dialog({
        autoOpen: false,
        title: 'Copy Token PIN',
        width: 600,
        modal: true,
        buttons: {
            'Copy PIN': { click:  function(){
                        copyTokenPin($('#copy_from_token').val(),
                                $('#copy_to_token').val()
                            );
                        },
                    id: "button_tools_copytokenpin_ok",
                    text: "Copy PIN"
            },
            'Close': { click: function(){
                            $(this).dialog('close');
                        },
                        id: "button_tools_copytokenpin_close",
                        text:"Close"
            }
        },
        open: function(){
            translate_copy_token();
            do_dialog_icons();
        }
    });
    return $dialog;
  }

function checkPolicy(scope, realm, user, action, client) {
    if ($("#form_check_policy").valid()) {
        var param = {};
        param["scope"]   = scope;
        param["realm"]  = realm;
        param["user"]   = user;
        param["action"] = action;
        param["client"] = client;
        var resp = clientUrlFetchSync('/system/checkPolicy', param, true);
        var obj = jQuery.parseJSON(resp);
        if (obj.result.status==true) {
            if (obj.result.value.allowed) {
                $('#cp_allowed').show();
                $('#cp_forbidden').hide();
                $('#cp_policy').html(  JSON.stringify(obj.result.value.policy).replace(/,/g,",\n").replace(/:\{/g,":\{\n"));
            }else{
                $('#cp_allowed').hide();
                $('#cp_forbidden').show();
                $('#cp_policy').html("" );
            }
        }else{

        }
   }
}

function create_tools_checkpolicy_dialog() {
     var $dialog = $('#dialog_check_policy').dialog({
        autoOpen: false,
        title: 'Check Policy',
        width: 600,
        modal: true,
        buttons: {
            'Check Policy': { click:  function(){
                        checkPolicy($('#cp_scope').val(),
                                    $('#cp_realm').val(),
                                    $('#cp_user').val(),
                                    $('#cp_action').val(),
                                    $('#cp_client').val()
                            );
                        },
                    id: "button_tools_checkpolicy_ok",
                    text: "Copy PIN"
            },
            'Close': { click: function(){
                            $(this).dialog('close');
                        },
                        id: "button_tools_checkpolicy_close",
                        text:"Close"
            }
        },
        open: function(){
            translate_check_policy();
            do_dialog_icons();
        }
    });
    $("#form_check_policy").validate({
        rules: {
            cp_user: {
                required: true
            },
            cp_realm: {
                required: true
            },
            cp_action: {
                required: true
            }
        }
    });

    return $dialog;
  }


function exportToken(attributes) {
    /*
     * We can not do an AJAX call to the /admin/show, since then
     * the result would not be downloadable by the browser.
     * So we add temporarily this form to the body, submit the
     * form and delete it afterwards.
     */
    $("<form action='/admin/show?outform=csv&session="+getsession()+"&user_fields="+attributes+"' method='post'></form>").appendTo("body").submit().remove();
}

function create_tools_exporttoken_dialog() {
     var $dialog = $('#dialog_export_token').dialog({
        autoOpen: false,
        title: 'Export Token Information',
        width: 600,
        modal: true,
        buttons: {
            'Export': { click:  function(){
                        exportToken($('#exporttoken_attributes').val());
                        },
                    id: "button_export_token",
                    text: "Export Token"
            },
            'Close': { click: function(){
                            $(this).dialog('close');
                        },
                        id: "button_export_token_close",
                        text:"Close"
            }
        },
        open: function(){
            translate_export_token();
            do_dialog_icons();
        }
    });

    return $dialog;
}

function exportAudit(audit_num, audit_page) {
    /*
     * We can not do an AJAX call to the /audit/search, since then
     * the result would not be downloadable by the browser.
     * So we add temporarily this form to the body, submit the
     * form and delete it afterwards.
     */
    if ( $.isNumeric(audit_num) == false ) {
        audit_num = 1000;
    }
    if ( $.isNumeric(audit_page) == false) {
        audit_page = 1;
    }

    $("<form action='/audit/search?outform=csv&rp="+audit_num+
        "&page="+audit_page+"&headers=true"+
        "&session="+getsession()+"' method='post'></form>").appendTo("body").submit().remove();
}

function create_tools_exportaudit_dialog() {
     var $dialog = $('#dialog_export_audit').dialog({
        autoOpen: false,
        title: 'Export Audit Information',
        width: 600,
        modal: true,
        buttons: {
            'Export': { click:  function(){
                        exportAudit($('#export_audit_number').val(),
                                    $('#export_audit_page').val());
                        $(this).dialog('close');
                        },
                    id: "button_export_audit",
                    text: "Export audit"
            },
            'Close': { click: function(){
                            $(this).dialog('close');
                        },
                        id: "button_export_audit_close",
                        text:"Close"
            }
        },
        open: function(){
            translate_export_audit();
            do_dialog_icons();
        }
    });

    return $dialog;
}

function add_user_data() {
    /*
     * This function returns an object with the user data as needed by the /admin/init controller
     */
    var param = new Object();
    var users = get_selected_user();
    if (users[0]) {
        param['user'] = users[0].login;
        param['resConf'] = users[0].resolver;
        param['realm'] = $('#realm').val();
    }
    return param;
}

function migrateResolver(from_resolver, to_resolver, serials) {
    var param = {};
    var res = false;
    param["from"] = from_resolver;
    param["to"]   = to_resolver;

    var resp = clientUrlFetchSync('/tools/migrate_resolver', param, true);
    var obj = jQuery.parseJSON(resp);
        if (obj.result.status==true) {
            if (obj.result.value.value==true) {
                msg = escape(obj.result.value.message)
                alert(msg);
                res = true;
            }else {
                var msg = escape(obj.result.error.message);
                var err = i18n.gettext("Could not migrate tokens!\n\n")
                alert(err + msg);
            }
        } else {
            var msg = obj.result.error.message;
            var err = i18n.gettext("Could not migrate tokens!\n\n")
            alert(err + msg)
    }
    return res;
}

function create_tools_migrateresolver_dialog() {
     var $dialog = $('#dialog_migrate_resolver').dialog({
        autoOpen: false,
        title: 'Migrate tokens to new resolver',
        width: 600,
        modal: true,
        buttons: {
            'Migrate Resolver': {
                click: function(){
                    var res = migrateResolver($('#copy_from_resolver').val(),
                                              $('#copy_to_resolver').val());
                    $(this).dialog('close');
                    if (res === true) {
                        $('#token_table').flexReload();
                    }
                },
                id: "button_tools_migrateresolver_ok",
                text: "Migrate tokens"
             },
            'Close': { click: function(){
                            $(this).dialog('close');
                        },
                        id: "button_tools_migrateresolver_close",
                        text:"Close"
            }
        },
        open: function(){
            translate_migrateresolver();
            do_dialog_icons();
        }
    });
    return $dialog;
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
