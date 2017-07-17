/*!
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
 *    E-mail: linotp@keyidentity.com
 *    Contact: www.linotp.org
 *    Support: www.keyidentity.com
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

function create_tools_importusers_dialog() {
    var import_users_dialog = $('#dialog_import_users').dialog({
        autoOpen: false,
        title: i18n.gettext("Import Users"),
        width: 750,
        modal: true,
        buttons: [
            {
                click: function(){
                    $(this).dialog('close');
                },
                id: "button_import_users_close",
                text: i18n.gettext("Cancel")
            },
            {
                click:  function(){
                    if($('#form_import_users').valid()) {
                        show_waiting();

                        $('#import_users_session').val(getsession());

                        $('#form_import_users').ajaxSubmit({
                            success: import_users_dryrun_callback,
                            error: import_users_dryrun_callback
                        });
                    }
                },
                id: "button_import_users",
                text: i18n.gettext("Import")
            }
        ],
        create: function(){
            do_dialog_icons();
            $('#import_users_create_resolver').click(function() {
                $("<div><form action=''><input style='width:100%; box-sizing: border-box;' name='res_name' placeholder='"+i18n.gettext("Resolver name")+"' type='text' autofocus></form></div>").dialog({
                    modal: true,
                    title: i18n.gettext("Create a new resolver"),
                    buttons: [
                        {
                            text: i18n.gettext("Cancel"),
                            click: function() {
                                $( this ).dialog( "close" );
                            }
                        },
                        {
                            text: i18n.gettext("Create"),
                            click: function() {
                                if($("form", this).valid()) {
                                    var name = $("input", this).val();
                                    $("#import_users_resolver").append('<option val="' + name + '">' + name + '</option>');
                                    $("#import_users_resolver").val(name);
                                    $( this ).dialog( "close" );
                                }
                            }
                        }
                    ],
                    create: function() {
                        if($('#import_users_file').val()) {
                            var resolver = $('#import_users_file').val().split('\\').pop().split(".")[0];
                            $("input", this).val(resolver);
                        }
                        g.current_resolver_name = "";
                        $("form", this).validate({
                            debug: true,
                            rules: {
                                "res_name": {
                                    required: true,
                                    minlength: 4,
                                    resolvername: true,
                                    unique_resolver_name: true
                                }
                            }
                        });
                    }
                });
            });
        },
        open: function() {
            show_waiting();

            if(import_users_dialog.data("caller") != "confirm") {
                $('#import_users_dryrun').val("true");
                $('#import_users_file').val("");
                $('#import_users_resolver').val("");
            }

            //prefill resolver select
            $.post('/system/getResolvers', {'session':getsession()}, function(data, status, XMLHttpRequest){
                var resolvers = '<option value="" disabled selected>[' + i18n.gettext("Select resolver") + ']</option>';
                for(var res in data.result.value) {
                    if(data.result.value[res].readonly === true) {
                        resolvers += '<option value="' + res + '">' + res + '</option>';
                    }
                }
                $('#import_users_resolver').html(resolvers);

                hide_waiting();
            });

            import_users_dialog.data("caller", "");
        }
    });
    var import_users_confirm_dialog = $('#dialog_import_users_confirm').dialog({
        autoOpen: false,
        title: i18n.gettext("Confirm changes"),
        width: 750,
        height: $(window).height() * .9,
        modal: true,
        buttons: [
            {
                click: function(){
                    $(this).dialog('close');
                    import_users_dialog.data("caller", "confirm").dialog('open');
                },
                id: "button_import_users_confirm_cancel",
                text: i18n.gettext("Cancel")
            },
            {
                click:  function(){
                    show_waiting();

                    $('#import_users_dryrun').val("false");
                    $('#import_users_session').val(getsession());

                    $('#form_import_users').ajaxSubmit({
                        success: import_users_callback,
                        error: import_users_callback
                    });
                },
                id: "button_import_users_confirm_confirm",
                text: i18n.gettext("Confirm")
            }
        ],
        create: function(){
            do_dialog_icons();
        },
        open: function() {
            $('#import_user_dryrun_results').accordion({
                active:0,
                heightStyle: "fill"
            });
            $( "#import_user_dryrun_result_details .detail-tabs" ).tabs({
              active: 0
            });
        }
    });
    return import_users_dialog;
}

function import_users_callback(response, status) {
    hide_waiting();
    $('#dialog_import_users_confirm').dialog('close');
    if(!response.result) {
        alert_box({'title': i18n.gettext('Connection error'),
            'text': i18n.gettext('Error during import users request.'),
            'is_escaped': true});
        return;
    }

    if(response.result.status !== true) {
        alert_box({'title': i18n.gettext('LinOTP error ' + response.result.error.code),
            'text': i18n.gettext('Error during import users request: ' + response.result.error.message),
            'is_escaped': false});
        return;
    }

    alert_box({'title': i18n.gettext('Import successful'),
        'text': i18n.gettext('The resolver ' + $('#import_users_resolver').val() + ' was successfully updated.'),
        'is_escaped': false});
}

function import_users_dryrun_callback(response, status) {
    hide_waiting();
    if(!response.result) {
        alert_box({'title': i18n.gettext('Connection error'),
            'text': i18n.gettext('Error during import users request.'),
            'is_escaped': true});
        return;
    }

    if(response.result.status !== true) {
        alert_box({'title': i18n.gettext('LinOTP error ' + response.result.error.code),
            'text': i18n.gettext('Error during import users request: ' + response.result.error.message),
            'is_escaped': false});
        return;
    }

    $('#dialog_import_users').dialog('close');

    var result = response.result.value;

    var created = import_users_callback_process_group(
        result.created,
        $('#import_user_dryrun_result_d_new .data-table'),
        i18n.gettext("No users will be created!")
    );

    var modified = import_users_callback_process_group(
        result.modified,
        $('#import_user_dryrun_result_d_mod .data-table'),
        i18n.gettext("No existing users will be modified!")
    );

    var deleted = import_users_callback_process_group(
        result.deleted,
        $('#import_user_dryrun_result_d_del .data-table'),
        i18n.gettext("No users will be deleted!")
    );

    var unchanged = import_users_callback_process_group(
        result.updated,
        $('#import_user_dryrun_result_d_unchanged .data-table'),
        i18n.gettext("No user stays unchanged!")
    );

    $('#import_user_dryrun_results .summary').html(
        "<li>" + sprintf(i18n.gettext('%s new users'), "<b>"+created.length+"</b>") + "</li>"
        + "<li>" + sprintf(i18n.gettext('%s modified users'), "<b>"+modified.length+"</b>") + "</li>"
        + "<li>" + sprintf(i18n.gettext('%s users will be deleted'), "<b>"+deleted.length+"</b>") + "</li>"
        + "<li>" + sprintf(i18n.gettext('%s users are identical and therefor unchanged'), "<b>"+unchanged.length+"</b>") + "</li>"
    );

    $('#dialog_import_users_confirm').dialog('open');
}

/**
 * processes a group of users of the import dialog result to list them for review
 * @param  {Object} group         Object of userid -> username
 * @param  {JQuery} target_table  The JQuery object selecting the table
 * @param  {String} fallback_text Text to display in the table if no users are in the group
 * @return {Array}                containing the user ids of the group
 */
function import_users_callback_process_group(group, target_table, fallback_text) {
    var users = [];
    for (k in group) {
        if (Object.prototype.hasOwnProperty.call(group, k)) {
            users.push(k);
        }
    }

    if(users.length > 0) {
        var tablecontent = "";
        for(i in users) {
            tablecontent += "<tr><td>" + users[i] + "</td><td>" + group[users[i]] + "</td></tr>";
        }
        target_table.html(tablecontent);
    }
    else {
        target_table.html("<td>" + fallback_text + "</td>");
    }
    return users
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
