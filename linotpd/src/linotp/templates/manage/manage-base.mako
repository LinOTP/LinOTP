# -*- coding: utf-8 -*-
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<%doc>
 *
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
</%doc>
<%!
from pylons.i18n.translation import get_lang
%>

<%
lang = get_lang() or "en"
allang = "%r" % lang
if isinstance(lang, list):
    lang = lang[0]
%>

<html>

<head>
<title>${_("LinOTP 2 Management")}</title>

<meta name="copyright" content="KeyIdentity GmbH">
<meta name="keywords" content="LinOTP 2 manage">
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
<meta http-equiv="content-type" content="application/xhtml+xml; charset=UTF-8">
<meta http-equiv="content-style-type" content="text/css">

<meta http-equiv="X-UA-Compatible" content="IE=8,chrome=1">

%if c.debug:
    <link type="text/css" rel="stylesheet" href="/css/jquery-ui/jquery-ui.structure.css">
    <link type="text/css" rel="stylesheet" href="/css/jquery-ui/jquery-ui.theme.css">
%else:
    <link type="text/css" rel="stylesheet" href="/css/jquery-ui/jquery-ui.structure.min.css">
    <link type="text/css" rel="stylesheet" href="/css/jquery-ui/jquery-ui.theme.min.css">
%endif
<link type="text/css" rel="stylesheet" href="/css/flexigrid/flexigrid.css">
<link type='text/css' rel='stylesheet' media='screen' href='/css/superfish.css'>
<link type="text/css" rel="stylesheet" href="/css/linotp.css?ref=${c.version_ref}">
<link type="text/css" rel="stylesheet" href="/manage/style.css?ref=${c.version_ref}">
<link type="text/css" rel="stylesheet" href="/manage/custom-style.css">

%if c.debug:
    <script type="text/javascript" src="/js/jquery-1.12.4.js"></script>
    <script type="text/javascript" src="/js/jquery-ui.js"></script>
    <script type="text/javascript" src="/js/jquery.validate.js"></script>
    <script type="text/javascript" src="/js/jquery.form.js"></script>
    <script type="text/javascript" src="/js/jquery.cookie.js"></script>
    <script type='text/javascript' src='/js/hoverIntent.js'></script>
    <script type='text/javascript' src='/js/superfish.js'></script>
%else:
    <script type="text/javascript" src="/js/jquery-1.12.4.min.js"></script>
    <script type="text/javascript" src="/js/jquery-ui.min.js"></script>
    <script type="text/javascript" src="/js/jquery.validate.min.js"></script>
    <script type="text/javascript" src="/js/jquery.form.min.js"></script>
    <script type="text/javascript" src="/js/jquery.cookie.min.js"></script>
    <script type='text/javascript' src='/js/hoverIntent.js'></script>
    <script type='text/javascript' src='/js/superfish.min.js'></script>
%endif
<script type="text/javascript" src="/js/jed.js"></script>
<script type="text/javascript" src="/js/flexigrid.js"></script>

<script type="text/javascript" src="/js/qrcode.js"></script>
<script type="text/javascript" src="/js/qrcode-helper.js?ref=${c.version_ref}"></script>
<script type="text/javascript" src="/js/linotp_utils.js?ref=${c.version_ref}"></script>

<script type="text/javascript" src="/js/aladdin.js?ref=${c.version_ref}"></script>
<script type="text/javascript" src="/js/oathcsv.js?ref=${c.version_ref}"></script>
<script type="text/javascript" src="/js/yubikeycsv.js?ref=${c.version_ref}"></script>
<script type="text/javascript" src="/js/feitian.js?ref=${c.version_ref}"></script>
<script type="text/javascript" src="/js/dpw.js?ref=${c.version_ref}"></script>
<script type="text/javascript" src="/js/dat.js?ref=${c.version_ref}"></script>
<script type="text/javascript" src="/js/vasco.js?ref=${c.version_ref}"></script>
<script type="text/javascript" src="/js/pskc.js?ref=${c.version_ref}"></script>
<script type="text/javascript" src="/js/tools.js?ref=${c.version_ref}"></script>

<!-- load language settings befor manage.js -->
<script type="text/javascript">
    window.CURRENT_LANGUAGE = "${lang}";
    window.ALL_CURRENT_LANGUAGE = "${allang}";
</script>

<script type="text/javascript" src="/js/manage.js?ref=${c.version_ref}"></script>

</head>
<body>

<noscript>
    <div class="javascript_error">${_("You need to enable Javascript to use the LinOTP Management Web UI.")}</div>
    <style type="text/css">#wrap{display:none;}</style>
</noscript>

<div id="wrap">
<div id="header" class="ui-widget-header ui-corner-all">
    <ul id='menu' class='sf-menu sf-vertical'>
        <li><a href='#'>${_("LinOTP Config")}</a>
            <ul>
                <li><a href='#' id='menu_edit_resolvers'>${_("UserIdResolvers")}</a></li>
                <li><a href='#' id='menu_edit_realms'>${_("Realms")}</a></li>
                <li><a href='#' id='menu_system_config'>${_("System Config")}</a></li>

                %if c.display_provider:
                <li><a href='#'>${_("Provider Config")}</a>
                    <ul>
                        <li><a href='#' id='menu_sms_provider_config'>${_("SMS Provider Config")}</a>
                        <li><a href='#' id='menu_email_provider_config'>${_("Email Provider Config")}</a>
                        <li><a href='#' id='menu_push_provider_config'>${_("Push Provider Config")}</a>
                    </ul>
                 </li>
                % endif

                <li><a href='#' id='menu_token_config'>${_("Token Config")}</a></li>
                <li><a href='#' id='menu_policies'>${_("Policies")}</a></li>
            </ul>
        </li>
        <li><a href='#'>${_("Tools")}</a>
            <ul>
                <li><a href='#' id='menu_tools_getserial'>${_("Get Serial by OTP")}</a></li>
                <li><a href='#' id='menu_tools_copytokenpin'>${_("Copy Token PIN")}</a></li>
                <li><a href='#' id='menu_tools_checkpolicy'>${_("Check Policy")}</a></li>
                <li><a href='#' id='menu_tools_exporttoken'>${_("Export Token Info")}</a></li>
                <li><a href='#' id='menu_tools_exportaudit'>${_("Export Audit Trail")}</a></li>
                <li><a href='#' id='menu_tools_importusers'>${_("Import Users")}</a></li>
                <li><a href='#' id='menu_tools_migrateresolver'>${_("Migrate Resolver")}</a></li>
                % if c.admin_can_change_password:
                <li><a href='#' id='menu_tools_changepassword'>${_("Change password")}</a></li>
                % endif
            </ul>
        </li>
        <li><a href='#'>${_("Import Token File")}</a>
            <ul>
                <li><a href='#' id='menu_load_aladdin_xml_tokenfile'>${_("SafeNet/ Aladdin XML")}</a></li>
                <li><a href='#' id='menu_load_oath_csv_tokenfile'>${_("OATH CSV")}</a></li>
                <li><a href='#' id='menu_load_yubikey_csv_tokenfile'>${_("YubiKey CSV")}</a></li>

            % for id in c.importers:
            <li><a href='#' id='menu_load_${id}'>${c.importers[id]}</a></li>
            % endfor
            </ul>
        </li>
        <li>
            <li><a href='#'>${_("Help")}</a>
            <ul>
                <li><a href='${c.help_url}' rel="noreferrer" target="_blank" id="menu_help">${_("Documentation")}</a></li>
                <li><a href='#' id='menu_view_support'>${_("Support and Subscription")}</a></li>
                <li><a href='#' id='menu_about'>${_("About LinOTP")}</a></li>
            </ul>
        </li>
    </ul>
    <div id="logo"></div>
</div> <!-- header -->
<div class="clearfix">
        % if c.admin:
        <div id="login-status" class="dropdown-container">
        <div class="dropdown-label">
            ${c.admin}<span class="dropdown-icon">&#x25BC;</span>
        </div>
        <div class="dropdown">
            % if c.admin_can_change_password:
            <a href="#" id="login-status-password">${_("Change password")}</a>
            % endif
            <a href="#" id="login-status-logout" data-logout-url="${c.logout_url}">${_("Logout")}</a>
        </div>
        % else:
        <div id="login-status">
        &nbsp;
        % endif
    </div>
</div>
<div class="clearfix">
<div id="sidebar">
    <div class="sel_box">
        <fieldset class="ui-corner-all ui-widget-content">
        <legend id="selected_users_header" class="legend">${_("Selected User")}</legend>
        <div id="selected_users" class="sel_user_box"> </div>
        </fieldset>
        <fieldset class="ui-corner-all ui-widget-content">
        <legend id="selected_tokens_header" class="legend">${_("Selected Token")}</legend>
        <div id="selected_tokens" class='sel_tok_box'> </div>
        </fieldset>
    </div>
    <div id="realms">
    ${_("Realms")}: <select id="realm"> </select>
    </div>
    <button class='action-button' id='button_enroll'>${_("Enroll")}</button>
    <button class='action-button' id='button_assign'>${_("Assign")}</button>
    <button class='action-button' id='button_unassign'>${_("Unassign")}</button>
    <button class='action-button' id='button_enable'>${_("Enable")}</button>
    <button class='action-button' id='button_disable'>${_("Disable")}</button>
    <button class='action-button' id='button_setpin'>${_("Set PIN")}</button>
    <button class='action-button' id='button_resetcounter'>${_("Reset Failcounter")}</button>
    <button class='action-button' id='button_delete'>${_("Delete")}</button>
</div> <!-- sidebar -->

<div id="main">
    <div id="info_box">
        <div id='info_bar'>
          <span id="info_text"></span>
          <button class="button_info_text">OK</button>
       </div>
    </div>
    <a href="#" class="close_all">${_("Close all")}</a>
    <div id="tabs">
        <ul>
            <li><a href="/manage/tokenview"><span>${_("Token View")}</span></a></li>
            <li><a href="/manage/userview"><span>${_("User View")}</span></a></li>
            <li><a href="/manage/policies"><span>${_("Policies")}</span></a></li>
            <li><a href="/manage/audittrail"><span>${_("Audit Trail")}</span></a></li>
        </ul>
    </div>
    <div id='errorDiv'></div>
    <div id='successDiv'></div>
</div>  <!-- end of main-->

</div>
<div id="footer">
    <span id="linotp_version">${c.version}</span> --- &copy; ${c.licenseinfo}
</div>

<span id="include_footer"> </span>
</div>  <!-- end of wrap -->

<div id="all_dialogs" style="display:none; height:0px;">
<!-- ############ DIALOGS ######################### -->
<!-- ############ system settings ################# -->
<div id=dialog_system_settings>
<form class="cmxform" id="form_sysconfig" action="">
    <div id='tab_system_settings'>
        <ul id='config_tab_index'>
            <li><a href='#tab_content_system_settings'>${_("Settings")}</a></li>
            <li><a href='#tab_content_system_caching'>${_("Caching")}</a></li>
            <li><a href='#tab_content_system_gui'>${_("GUI settings")}</a></li>
            <li><a href='#tab_content_system_client'>${_("Client Identification")}</a></li>
            <!-- <li><a href='#tab_content_system_cert'>${_("Certificates")}</a></li> -->
        </ul>
        <div id="tab_content_system_settings">
            <fieldset>
                <table>
                    <tr><td><label for="sys_splitAtSign">${_("Split at @ sign (splitAtSign)")}</label>: </td>
                        <td><input type="checkbox" name="sys_splitAtSign" id="sys_splitAtSign" value="sys_splitAtSign"
                            title="${_('This will use the part right of an @-sign as realm')}"></td></tr>\
                    <tr><td><label for="sys_allowSamlAttributes">${_("Return SAML attributes")}</label>: </td>
                        <td><input type="checkbox" name="sys_allowSamlAttributes" id="sys_allowSamlAttributes" value="sys_allowSamlAttributes"
                            title="${_('The /validate/samlcheck controller will also return user attributes')}"></td></tr>\
                    <tr><td><label for="sys_failCounterInc">${_("FailCounterIncOnFalsePin")}</label>: </td>
                        <td><input type="checkbox" name="sys_failCounterInc" id="sys_failCounterInc" value="sys_failCounterInc"
                            title="${_('This will increase the failcounter, if the user provided a wrong PIN.')}"></td></tr>
                    <tr><td><label for="sys_prependPin">${_("PrependPin")}: </label></td>
                        <td><input type="checkbox" name="sys_prependPin" id="sys_prependPin" value="sys_prependPin"
                            title="${_('This will prepend the PIN to the OTP value. Otherwise the PIN will be appended.')}"></td></tr>
                    <tr><td><label for="sys_autoResync"> ${_("Auto resync")}: </label></td>
                        <td><input type="checkbox" name="sys_autoResync" id="sys_autoResync" value="sys_autoResync"
                            title="${_('This will automatically resync OTP counter of HMAC based tokens.')}"></td></tr>
                    <tr><td><label for="sys_autoResyncTimeout"> ${_("Auto resync timeout")}: </label></td>
                        <td><input type="text" name="sys_autoResyncTimeout" class="required"  id="sys_autoResyncTimeout"
                            title="${_('The time in which the two successive OTP values need to be entered (in seconds)')}"
                             size="4" maxlength="3"></td></tr>
                </table>
            </fieldset>
            <fieldset>
                <legend>${_("Authentication")}</legend>
                <table>
                    <tr><td><label for=sys_passOnUserNotFound>${_("Pass on user not found")}: </label></td>
                        <td><input type="checkbox" name="sys_passOnUserNotFound" id="sys_passOnUserNotFound" value="sys_passOnUserNotFound"
                            title="${_('If checked, users who are not found in the useridresolvers are authenticated successfully. USE WITH CAUTION!')}"></td></tr>\
                    <tr><td><label for=sys_passOnUserNoToken>${_("Pass on user no token")}: </label></td>
                        <td><input type="checkbox" name="sys_passOnUserNoToken" id="sys_passOnUserNoToken" value="sys_passOnUserNoToken"
                            title="${_('If checked, users who have no token get authenticated automatically successful. USE WITH CAUTION!')}"></td></tr>
                </table>
            </fieldset>
            <fieldset>
                <legend>${_("Authorization")}</legend>
                    <label for=sys_mayOverwriteClient>${_("Override authentication client")}:</label>
                    <input type='text' name='sys_mayOverwriteClient' id='sys_mayOverwriteClient' size='40'
                    title="${_('This is a comma separated list of clients, that may send another client IP for authorization policies.')}">
            </fieldset>
        </div>
        <div id="tab_content_system_caching">
            <fieldset>
                <legend>${_("Resolver Lookup Caching")}</legend>
                <table>
                <tr><td><label for=sys_resolver_cache_enable>${_("Enable")}</label></td>
                    <td><input type="checkbox" name="sys_resolver_cache_enable" id="sys_resolver_cache_enable" value="sys.resolver_lookup_cache.enabled"
                        title="${_('Enable caching of the realm to user id resolver lookup')}"></td></tr>
                <tr><td><label for=sys_resolver_cache_enable>${_("Expiration")} </label></td>
                    <td><input type="text" name="sys_resolver_cache_expiration" id="sys_resolver_cache_expiration" size="35"
                        title='${_("The expiration of the resolver lookup caching in seconds or as duration format for days, hours and minutes: >1d 3h 4m<")}'></td></tr>
                </table>
            </fieldset><fieldset>
                <legend>${_("User Lookup Caching")}</legend>
                <table>
                <tr><td><label for=sys_user_cache_enable>${_("Enable")}</label></td>
                    <td><input type="checkbox" name="sys_user_cache_enable" id="sys_user_cache_enable" value="sys_user_lookup_cache_enabled"
                        title="${_('Enable the caching of user lookup in a resolver')}"></td></tr>
                <tr><td><label for=sys_user_cache_enable>${_("Expiration")} </label></td>
                    <td><input type="text" name="sys_user_cache_expiration" id="sys_user_cache_expiration" size="35"
                        title='${_("The expiration of the user lookup caching in seconds or as duration format for days, hours and minutes: >1d 3h 4m<")}'></td></tr>
                </table>
            </fieldset>
        </div> <!-- tab with settings -->
        <div id='tab_content_system_gui'>
            <fieldset>
                    <legend>${_("Selfservice portal")}</legend>
                    <table>
                        <tr><td><label for=sys_realmbox>${_("Display realm select box")}</label></td>
                        <td><input type='checkbox' name='sys_realmbox' id='sys_realmbox' value='sys_realmbox'
                            title='${_("If checked a realm dropdown box will be displayed on the selfservice portal logon page.")}'></td></tr>
                    </table>
            </fieldset>
        </div>  <!-- tab system settings gui -->
        <div id='tab_content_system_client'>
            <fieldset>
                    <legend>${_("Client Identification with Proxy")}</legend>
                    <table>
                        <tr><td><label for="sys_x_forwarded_for">${_("Support for HTTP_X_FORWARDED_FOR")}</label></td>
                        <td><input type='checkbox' name='sys_x_forwarded_for' id='sys_x_forwarded_for' value='sys_x_forwarded_for'
                            title='${_("If checked a realm dropdown box will be displayed on the selfservice portal logon page.")}'></td></tr>

                        <tr><td><label for="sys_forwarded">${_("Support for HTTP_FORWARDED")}</label></td>
                        <td><input type='checkbox' name='sys_forwarded' id='sys_forwarded' value='sys_forwarded'
                            title='${_("If checked a realm dropdown box will be displayed on the selfservice portal logon page.")}'></td></tr>

                        <tr><td><label for=sys_forwarded_proxy> ${_("Trusted Forwarding Proxy")}: </label></td><td></td></tr>
                        <tr><td colspan=2><input type="text" name="sys_forwarded_proxy" class="required"  id="sys_forwarded_proxy" size="35"
                                title='${_("The ip address of the trusted forwarding proxy, which provides the REMOTE_ADDR.")}'></td></tr>

                    </table>
            </fieldset>
        </div>
        <!-- tab system settings client -->
<!--
        <div id='tab_content_system_cert'>
            <fieldset>
                <legend>${_("Certificates")}</legend>
                    <table>
                        <tr>
                            <td>
                                <label for=sys_cert>${_("Use system certificate")}</label>
                            </td>
                            <td>
                                <input type='checkbox' name='sys_cert' id='sys_cert' value='sys_cert'
                                       title='${_("If checked the linotp server will use system certificates")}'>
                            </td>
                        </tr>
                        <!- - todo: button to display all used certificates, for migration - ->
                    </table>
            </fieldset>
        </div>
-->
        <!-- tab system certificate settings -->


    </div> <!-- tab container system settings -->
    </form>
</div>

<script type="text/javascript">
    function translate_system_settings() {
        $("#dialog_system_settings" ).dialog( "option", "title", '${_("System Config")}' );
        $('#button_system_save').button("option", "label", '${_("Save Config")}');
        $('#button_system_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ############ sms provider settings ################# -->
<div id='dialog_sms_providers'>
    <div class="list-wrapper"><div id='sms_providers_list'> </div></div>
    <div class="ui-dialog-buttonpane flat"><button id='button_sms_provider_set_default'>${_("Set as default")}</button></div>
</div>
<script type="text/javascript">
    function translate_dialog_sms_providers() {
        $("#dialog_sms_providers" ).dialog( "option", "title", '${_("SMS Provider: create and edit")}');
        $('#button_sms_provider_new').button("option", "label", '${_("New")}');
        $('#button_sms_provider_edit ').button("option", "label", '${_("Edit")}');
        $('#button_sms_provider_delete ').button("option", "label", '${_("Delete")}');
        $('#button_sms_providers_close ').button("option", "label", '${_("Close")}');
    }
</script>

<!-- ############ sms provider edit ################# -->
<div id="dialog_sms_provider_edit">
    <form class="cmxform" id="form_smsprovider" action="">
        <table>
            <tr>
                <td><label for="sms_provider_name">${_("Name")}</label>: </td>
                <td><input type="text" name="sms_provider_name" class="required"
                                       id="sms_provider_name" size="37" maxlength="80"
                                       placeholder=""></td>
            </tr>
            <tr>
                <td><label for="sms_provider_class">${_("Class")}</label>: </td>
                <td><input type="text" name="sms_provider_class" class="required"
                                       id="sms_provider_class" size="37" maxlength="80"
                                       placeholder="smsprovider.HttpSMSProvider.HttpSMSProvider"></td>
            </tr>
            <tr>
                <td><label for='sms_provider_config'>${_("Config")}</label>: </td>
                <td><textarea name="sms_provider_config" class="required"
                              id="sms_provider_config" cols='35' rows='6'
                              placeholder='{ "URL":"http://smsproviderurl:5001/http2sms", "PARAMETER": {"your url parameter": "as json"}, "SMS_TEXT_KEY":"text", "SMS_PHONENUMBER_KEY":"to", "RETURN_SUCCESS":"ID"}'></textarea></td>
            </tr>
            <tr>
                <td><label for='sms_provider_timeout'>${_("Timeout")}</label>: </td>
                <td><input type="text" name="sms_provider_timeout" class="required"
                              placeholder="120" id="sms_provider_timeout" size="5" maxlength="5"></td>
            </tr>
        </table>
    </form>
</div>
<script type="text/javascript">
    function translate_dialog_sms_provider_edit() {
        $("#dialog_sms_provider_edit" ).dialog( "option", "title", '${_("SMS Provider")}' );
        $('#button_sms_provider_cancel').button("option", "label", '${_("Cancel")}');
        $('#button_sms_provider_save').button("option", "label", '${_("Save")}');
    }
</script>

<!-- ################## sms provider delete ###################### -->
<div id='dialog_sms_provider_delete'>
    <p>${_("Do you want to delete the provider?")}</p>
</div>
<script type="text/javascript">
    function translate_dialog_sms_provider_delete() {
        $("#dialog_sms_provider_delete" ).dialog( "option", "title", '${_("Deleting provider")} ' + selectedSMSProvider );
        $('#button_sms_provider_delete_delete').button("option", "label", '${_("Delete")}');
        $('#button_sms_provider_delete_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ############ email provider settings ################# -->
<div id='dialog_email_providers'>
    <div class="list-wrapper"><div id='email_providers_list'> </div></div>
    <div class="ui-dialog-buttonpane flat"><button id='button_email_provider_set_default'>${_("Set as default")}</button></div>
</div>
<script type="text/javascript">
    function translate_dialog_email_providers() {
        $("#dialog_email_providers" ).dialog( "option", "title", '${_("Email Provider: create and edit")}');
        $('#button_email_provider_new').button("option", "label", '${_("New")}');
        $('#button_email_provider_edit').button("option", "label", '${_("Edit")}');
        $('#button_email_provider_delete').button("option", "label", '${_("Delete")}');
        $('#button_email_providers_close').button("option", "label", '${_("Close")}');
        $('#button_email_provider_set_default').button("option", "label", '${_("Set as default")}');
    }
</script>

<!-- ############ email provider edit ################# -->
<div id="dialog_email_provider_edit">
    <form class="cmxform" id="form_emailprovider" action="">
        <table>
            <tr>
                <td><label for="email_provider_name">${_("Name")}</label>: </td>
                <td><input type="text" name="email_provider_name" class="required"
                                       id="email_provider_name" size="37" maxlength="80"
                                       placeholder=""></td>
            </tr>
            <tr>
                <td><label for="email_provider_class">${_("Class")}</label>: </td>
                <td><input type="text" name="email_provider_class" class="required"
                           id="email_provider_class" size="37" maxlength="80"
                           placeholder="linotp.provider.emailprovider.SMTPEmailProvider"></td>
            </tr>
            <tr>
                <td><label for='email_provider_config'>${_("Config")}</label>: </td>
                <td><textarea name="email_provider_config" class="required"
                              id="email_provider_config" cols='35' rows='6'
                              placeholder='{ "SMTP_SERVER":"mail.example.com", "SMTP_USER":"secret_user", "SMTP_PASSWORD":"secret_pasword", "EMAIL_FROM":"linotp@example.com", "EMAIL_SUBJECT":"Your OTP"}'></textarea></td>
            </tr>
            <tr>
                <td><label for="email_provider_timeout">${_("Timeout (sec)")}</label>: </td>
                <td><input type="number" name="email_provider_timeout" class="required"
                              placeholder="120" id="email_provider_timeout" size="5" maxlength="5"></td>
            </tr>
        </table>
    </form>
</div>
<script type="text/javascript">
    function translate_dialog_email_provider_edit() {
        $("#dialog_email_provider_edit" ).dialog( "option", "title", '${_("Email Provider")}' );
        $('#button_email_provider_cancel').button("option", "label", '${_("Cancel")}');
        $('#button_email_provider_save').button("option", "label", '${_("Save")}');
    }
</script>

<!-- ################## email provider delete ###################### -->
<div id='dialog_email_provider_delete'>
    <p>${_("Do you want to delete the Provider?")}</p>
</div>
<script type="text/javascript">
    function translate_dialog_email_provider_delete() {
        $("#dialog_email_provider_delete" ).dialog( "option", "title", '${_("Deleting provider")} ' + selectedEmailProvider );
        $('#button_email_provider_delete_delete').button("option", "label", '${_("Delete")}');
        $('#button_email_provider_delete_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ############ email provider settings ################# -->
<div id='dialog_email_provider_settings'>

</div>

<script type="text/javascript">
    function translate_email_provider_settings() {
        $("#dialog_email_provider_settings" ).dialog( "option", "title", '${_("Email Provider Configuration")}' );
        $('#button_email_provider_save').button("option", "label", '${_("Save Config")}');
        $('#button_email_provider_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ############ push provider settings ################# -->
<div id='dialog_push_providers'>
    <div class="list-wrapper"><div id='push_providers_list'> </div></div>
    <div class="ui-dialog-buttonpane flat"><button id='button_push_provider_set_default'>${_("Set as default")}</button></div>
</div>
<script type="text/javascript">
    function translate_dialog_push_providers() {
        $("#dialog_push_providers" ).dialog( "option", "title", '${_("Push Provider: create and edit")}');
        $('#button_push_provider_new').button("option", "label", '${_("New")}');
        $('#button_push_provider_edit').button("option", "label", '${_("Edit")}');
        $('#button_push_provider_delete').button("option", "label", '${_("Delete")}');
        $('#button_push_providers_close').button("option", "label", '${_("Close")}');
    }
</script>

<!-- ############ push provider edit ################# -->
<div id="dialog_push_provider_edit">
    <form class="cmxform" id="form_pushprovider" action="">
        <table>
            <tr>
                <td><label for="push_provider_name">${_("Name")}</label>: </td>
                <td><input type="text" name="push_provider_name" class="required"
                                       id="push_provider_name" size="37" maxlength="80"
                                       placeholder=""></td>
            </tr>
            <tr>
                <td><label for="push_provider_class">${_("Class")}</label>: </td>
                <td><input type="text" name="push_provider_class" class="required"
                           id="push_provider_class" size="37" maxlength="80"
                           placeholder="DefaultPushProvider"></td>
            </tr>
            <tr>
                <td><label for='push_provider_config'>${_("Config")}</label>: </td>
                <td><textarea name="push_provider_config" class="required"
                              id="push_provider_config" cols='35' rows='6'
                              placeholder=
'{
"push_url": "https://push.keyidentity.com/send",
"access_certificate": "/etc/linotp2/push-license.pem",
"server_certificate": "/etc/linotp2/keyidentity-push-ca-bundle.crt"
}'

syst></textarea></td>
            </tr>
            <tr>
                <td><label for="push_provider_timeout">${_("Timeout (sec)")}</label>: </td>
                <td><input type="number" name="push_provider_timeout" class="required"
                              placeholder="120" id="push_provider_timeout" size="5" maxlength="5"></td>
            </tr>
        </table>
    </form>
</div>
<script type="text/javascript">
    function translate_dialog_push_provider_edit() {
        $("#dialog_push_provider_edit" ).dialog( "option", "title", '${_("Push Provider")}' );
        $('#button_push_provider_cancel').button("option", "label", '${_("Cancel")}');
        $('#button_push_provider_save').button("option", "label", '${_("Save")}');
    }
</script>

<!-- ################## push provider delete ###################### -->
<div id='dialog_push_provider_delete'>
    <p>${_("Do you want to delete the Provider?")}</p>
</div>
<script type="text/javascript">
    function translate_dialog_push_provider_delete() {
        $("#dialog_push_provider_delete" ).dialog( "option", "title", '${_("Deleting provider")} ' + selectedPushProvider );
        $('#button_push_provider_delete_delete').button("option", "label", '${_("Delete")}');
        $('#button_push_provider_delete_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ############ push provider settings ################# -->
<div id='dialog_push_provider_settings'>

</div>

<script type="text/javascript">
    function translate_push_provider_settings() {
        $("#dialog_push_provider_settings" ).dialog( "option", "title", '${_("Push Provider Configuration")}' );
        $('#button_push_provider_save').button("option", "label", '${_("Save Config")}');
        $('#button_push_provider_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>




<!-- ############ dialog settings ################# -->
<div id='dialog_token_settings'>
    <div id='tab_token_settings'><!-- tab container token settings -->
        <ul id='token_tab_index'>
        % for entry in c.token_config_tab:
            <li> <a href="#${entry}_token_settings">${c.token_config_tab[entry] |n}</a></li>
        % endfor
            <li> <a href="#ocra_token_settings">${_("OCRA Token")}</a></li>
            <li> <a href="#tokendefault_token_settings">${_("Default Settings")}</a></li>
        </ul> <!-- tab with token settings -->
        % for entry in c.token_config_div:
            <div id="${entry}_token_settings">
                ${c.token_config_div[entry] |n}
            </div>
        % endfor

        <%doc>
            Ocra token config tab _static_
        </%doc>
        <script type="text/javascript">
            /*
             * 'typ'_get_config_val()
             *
             * this method is called, when the token config dialog is opened
             * - it contains the mapping of config entries to the form id
             * - according to the Config entries, the form entries will be filled
             *
             */

            function ocra_get_config_val(){
                var id_map = {};

                id_map['OcraMaxChallenges'] = 'ocra_max_challenge';
                id_map['OcraChallengeTimeout'] = 'ocra_challenge_timeout';
                id_map['OcraDefaultSuite'] = 'ocra_default_suite';
                id_map['QrOcraDefaultSuite'] = 'ocra_default_qr_suite';

                return id_map;
            }

            /*
             * 'typ'_get_config_params()
             *
             * this method is called, when the token config is submitted
             * - it will return a hash of parameters for system/setConfig call
             *
             */
            function ocra_get_config_params(){
                var url_params ={};

                url_params['OcraMaxChallenges'] = $('#ocra_max_challenge').val();
                url_params['OcraChallengeTimeout'] = $('#ocra_challenge_timeout').val();
                url_params['OcraDefaultSuite'] = $('#ocra_default_suite').val();
                url_params['QrOcraDefaultSuite'] = $('#ocra_default_qr_suite').val();

                return url_params;
            }
        </script>
        <div id="ocra_token_settings">
            <form class="cmxform" id="form_ocra_config" action="">
                <fieldset id='ocra_config'>
                    <legend>${_("OCRA token settings")}</legend>
                    <table>
                        <tr><td><label for=ocra_max_challenge>${_("Maximum concurrent OCRA challenges")}</label></td>
                            <td><input type="text" id="ocra_max_challenge" maxlength="4" class=integer
                                title='${_("This is the maximum concurrent challenges per OCRA Token.")}'></td></tr>
                        <tr><td><label for=ocra_challenge_timeout>${_("OCRA challenge timeout")}</label></td>
                            <td><input type="text" id="ocra_challenge_timeout" maxlength="6"
                                title='${_("After this time a challenge can not be used anymore. Valid entries are like 1D, 2H or 5M where D=day, H=hour, M=minute.")}'></td></tr>
                        <tr><td><label for=ocra_default_suite>${_("Default OCRA suite")}</label></td>
                            <td><input type="text" name="ocra_default_suite" id="ocra_default_suite" size='30' maxlength="40"
                                title="${_('This is the suite for newly enrolled OCRA tokens. Default is OCRA-1:HOTP-SHA256-8:C-QA08')}"></td></tr>
                        <tr><td><label for=ocra_default_qr_suite>${_("Default QR suite")}</label></td>
                            <td><input type="text" name="ocra_default_qr_suite" id="ocra_default_qr_suite" maxlength=40 size=30
                                title='${_("This is the suite for newly enrolled OCRA tokens. Default is OCRA-1:HOTP-SHA256-6:C-QA64")}'></td></tr>
                    </table>
                </fieldset>
            </form>
        </div>

        <%doc>
            Default token config tab _static_
        </%doc>
        <script type="text/javascript">
            /*
             * 'typ'_get_config_val()
             *
             * this method is called, when the token config dialog is opened
             * - it contains the mapping of config entries to the form id
             * - according to the Config entries, the form entries will be filled
             *
             */

            function tokendefault_get_config_val(){
                var id_map = {};

                id_map['DefaultResetFailCount'] = 'default_token_resetFailCounter';
                id_map['DefaultMaxFailCount'] = 'default_token_maxFailCount';
                id_map['DefaultSyncWindow'] = 'default_token_syncWindow';
                id_map['DefaultOtpLen'] = 'default_token_otpLen';
                id_map['DefaultCountWindow'] = 'default_token_countWindow';
                id_map['DefaultChallengeValidityTime'] = 'default_token_challengeTimeout';

                return id_map;
            }

            /*
             * 'typ'_get_config_params()
             *
             * this method is called, when the token config is submitted
             * - it will return a hash of parameters for system/setConfig call
             *
             */
            function tokendefault_get_config_params(){
                var url_params ={};

                url_params['DefaultResetFailCount'] =
                    ($("#default_token_resetFailCounter").is(':checked') ? "True" : "False");

                url_params['DefaultMaxFailCount'] = $('#default_token_maxFailCount').val();
                url_params['DefaultSyncWindow'] = $('#default_token_syncWindow').val();
                url_params['DefaultOtpLen'] = $('#default_token_otpLen').val();
                url_params['DefaultCountWindow'] = $('#default_token_countWindow').val();
                url_params['DefaultChallengeValidityTime'] = $('#default_token_challengeTimeout').val();

                return url_params;
            }
        </script>
        <div id="tokendefault_token_settings">
            <form class="cmxform" id="form_default_token_config" action="">
                <fieldset>
                    <legend>${_("Default token settings")}</legend>
                    <table>
                        <tr>
                            <td>
                                <label for=default_token_resetFailCounter>${_("DefaultResetFailCount")}:</label>
                            </td>
                            <td>
                                <input type="checkbox" name="default_token_resetFailCounter" id="default_token_resetFailCounter" value="default_token_resetFailCounter"
                                    title='${_("Will reset the fail counter when the user authenticated successfully")}'>
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <label for=default_token_maxFailCount> ${_("DefaultMaxFailCount")}: </label>
                            </td>
                            <td>
                                <input type="number" name="default_token_maxFailCount" id="default_token_maxFailCount"
                                    title='${_("This is the maximum allowed failed logins for a new enrolled token.")}'>
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <label for=default_token_countWindow> ${_("DefaultCountWindow")}: </label>
                            </td>
                            <td>
                                <input type="number" name="default_token_countWindow" id="default_token_countWindow"
                                    title='${_("This is the default look ahead window for counter based tokens.")}'>
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <label for=default_token_syncWindow> ${_("DefaultSyncWindow")}: </label>
                            </td>
                            <td>
                                <input type="number" name="default_token_syncWindow" id="default_token_syncWindow"
                                    title='${_("A new token will have this window to do the manual or automatic OTP sync.")}'>
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <label for=default_token_otpLen> ${_("DefaultOtpLen")}: </label>
                            </td>
                            <td>
                                <select name="default_token_otpLen" title='${_("A new token will be set to this OTP length.")}' id="default_token_otpLen">
                                    <option value=6>${_("6 digits")}</option>
                                    <option value=8>${_("8 digits")}</option>
                                    <option value=10>${_("10 digits")}</option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <label for='default_token_challengeTimeout'> ${_("DefaultChallengeValidityTime")}: </label>
                            </td>
                            <td>
                                <input type="number" name="default_token_challengeTimeout" id="default_token_challengeTimeout"
                                    title='${_("Default validity timeframe of a challenge.")}' placeholder="120">
                            </td>
                        </tr>
                    </table>
                </fieldset>
            </form>
        </div>
    </div> <!-- tab container system settings -->
</div>

<script type="text/javascript">
    function translate_token_settings() {
        $("#dialog_token_settings" ).dialog( "option", "title", '${_("Tokentype Configuration")}' );
        $('#button_token_save').button("option", "label", '${_("Save Config")}');
        $('#button_token_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ################ Support Contact ################ -->
<div id='dialog_support_contact'></div>

<script type="text/javascript">
    function translate_support_contact() {
        $("#dialog_support_view" ).dialog( "option", "title", '${_("Support Contact")}' );
        $('#button_support_contact_close').button("option", "label", '${_("Ok")}');
    }
</script>

<!-- ################ Support view ################ -->
<div id='dialog_support_view'>
</div>

<script type="text/javascript">
    function translate_support_view() {
        $("#dialog_support_view" ).dialog( "option", "title", '${_("KeyIdentity LinOTP Support and Subscription")}' );
        $('#button_support_set').button("option", "label", '${_("Set Support and Subscription")}');
        $('#button_support_close').button("option", "label", '${_("Close")}');
    }
</script>

<!-- ################# set Support Subscription ################ -->


<div id='dialog_set_support'>
    <form id="set_support_form" action="/system/setSupport" method="post"
                enctype="multipart/form-data" onsubmit="return false;">
        <p>${_("Please choose your support and subscription file")}:</p>
        <p><input name="license" id="license_file" type="file" size="30" accept="text/*">
        </p>
    </form>
</div>

<script type="text/javascript">
    function translate_support_set() {
        $("#dialog_set_support" ).dialog( "option", "title", '${_("KeyIdentity LinOTP Support and Subscription")}' );
        $('#button_support_set').button("option", "label", '${_("Set Support and Subscription")}');
        $('#button_support_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ################# change password ################ -->

<div id='dialog_change_password'>
    <p id='about_id'>${_("If LinOTP is setup to manage its administration users, you can change your LinOTP management password now.")}</p>
    <p>${_("User:")}&nbsp;${c.admin}
    <form class="cmxform" action="">
        <table>
            <tr>
                <td>
                    <label for="password_old">${_("Old password")}</label>
                </td>
                <td>
                    <input type="password" name="password_old" id="password_old">
                </td>
            </tr>
            <tr><td colspan="2"></td></tr>
            <tr>
                <td>
                    <label for="password_new">${_("New password")}</label>
                </td>
                <td>
                    <input type="password" name="password_new" id="password_new">
                </td>
            </tr>
            <tr>
                <td>
                    <label for="password_confirm">${_("Confirm new password")}</label>
                </td>
                <td>
                    <input type="password" name="password_confirm" id="password_confirm">
                </td>
            </tr>
        </table>
    </form>
</div>

<!-- ################# about LinOTP ################ -->

<div id='dialog_about'>
    <p id='about_id'>${_("LinOTP - the open source solution for two factor authentication.")}</p>
    <p id='about_copyright'>${_("Copyright (C) 2010 - 2017 KeyIdentity GmbH")}</p>
    <p id='about_licens'>${_("Licensed under AGPLv3")}</p>
    <p id='about_lse_id'>${_("For more information please visit:")}</p>
    <p><a href="https://www.linotp.org" rel="noreferrer" target="_blank">https://www.linotp.org</a>
    <br>${_("or")}<br>
    <a href="https://www.keyidentity.com" rel="noreferrer" target="_blank">https://www.keyidentity.com</a></p>
    <p><a href="https://www.linotp.org/resources/changelogs.html" target="_blank">${_("View latest changelog")}</a></p>
    <p>${_("Authors:")}
        <br>Cornelius Kölbel, Kay Winkler, Omar Kohl, Friedrich Weber,
        <br>Christian Pommranz, Reinhard Stampp, Rainer Endres,
        <br>Stefan Pietsch, Eric Sesterhenn, Marian Pascalau,
        <br>Fabian Vallon, Veronika Schindler, Lukas Engelter,
        <br>Mirko Ahnert, Chris Halls
    </p>

</div>
<script type="text/javascript">
    function translate_about() {
        $("#dialog_about").dialog( "option", "title", '${_("About KeyIdentity LinOTP")}' );
        $('#button_about_close').button("option", "label", '${_("Close")}');
    }
</script>


<!-- ##################### Set PIN ######################### -->
<div id='dialog_set_pin'>
    <p>${_("You may reset the PINs for the tokens")}
        <span id='dialog_set_pin_token_string'> </span>
        </p>

    <form action="">
        <div><input id='setpin_tokens' type='hidden'></div>
        <fieldset>
            <table>
                <tr>
                    <td>
                        <label for="pintype">${_("PIN type")}</label>
                    </td>
                    <td>
                        <select name="pintype" id="pintype">
                            <option value="motp">mOTP PIN</option>
                            <option value="ocra">OCRA PIN</option>
                            <option selected value="otp">OTP PIN</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td>
                        <label for="pin1">PIN</label>
                    </td>
                    <td>
                        <input type="password" autocomplete="off" onkeyup="checkpins('#pin1,#pin2');" name="pin1" id="pin1"
                            class="text ui-widget-content ui-corner-all">
                    </td>
                </tr>
                <tr>
                    <td>
                        <label for="pin2">${_("PIN (again)")}</label>
                    </td>
                    <td>
                        <input type="password" autocomplete="off" onkeyup="checkpins('#pin1,#pin2');" name="pin2" id="pin2"
                            class="text ui-widget-content ui-corner-all">
                    </td>
                </tr>
            </table>
        </fieldset>
    </form>
</div>

<script type="text/javascript">
    function translate_set_pin() {
        $("#dialog_set_pin" ).dialog( "option", "title", '${_("Set PIN")}' );
        $('#button_setpin_setpin').button("option", "label", '${_("Set PIN")}');
        $('#button_setpin_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>


<!-- ############## Token enroll ################################ -->
<div id='dialog_token_enroll'>
    <div id='enroll_info_text_user'>
        <p>
        ${_("The token will be enrolled for user")}
        <b><span id='enroll_info_user'> </span></b>.
        </p>
    </div>
    <div id='enroll_info_text_nouser'>
        <table width="100%"><tr>
        <td><label for='enroll_info_text_nouser_cb'>${_("Currently this token will not be assigned to any users.")}</label></td>
        <td align="right"><label for='enroll_info_text_nouser_cb'>${_("[?]")}</label></td>
        </tr></table>
        <input type='checkbox' id='enroll_info_text_nouser_cb' checked="checked"  style="display:none;"
            onclick="cb_changed('enroll_info_text_nouser_cb',['enroll_info_text_nouser_cb_more'])">
        <blockquote>
            <label id='enroll_info_text_nouser_cb_more' class='italic_label' style="display:none;">${_("If you select one user, this token will be "+
                "automatically assigned to this user. Anyhow, you can assign this token to any user later on.")}</label>
        </blockquote>
    </div>
    <div id='enroll_info_text_multiuser'>
        <p>${_("You selected more than one user. If you want to assign the token to a user during enrollment, "+
                "you need to select only one user.  Anyhow, you can assign this token to any user later on.")}
        </p>
    </div>
    <form id="form_enroll_token" action="">
        <fieldset>
            <table>
                <tr><td><label for="tokentype">${_("Token type")}</label></td><td>
                    <select name="tokentype" id="tokentype" onchange="tokentype_changed();">
                        <option value="ocra">${_("OCRA - challenge/response Token")}</option>
                        <!-- we do not sort by the key/conf but for the value -->
                        %for tok in sorted(c.token_enroll_tab, key=lambda t: c.token_enroll_tab[t]):
                        %if tok == 'hmac':
                          <option selected value="${tok}">${c.token_enroll_tab[tok] |n}</option>
                        %else:
                          <option value="${tok}">${c.token_enroll_tab[tok] |n}</option>
                        %endif
                        %endfor
                    </select>
                </td></tr>
            </table>
            <div class="token_enroll_frame" id="token_enroll_ocra">
                <hr>
                <p><span id='ocra_key_intro'>
                    ${_("Please enter or copy the OCRA key.")}</span></p>
                <table><tr>
                <td><label for="ocra_key" id='ocra_key_label'>${_("OCRA key")}</label></td>
                <td><input type="text" name="ocra_key" id="ocra_key" value="" class="text ui-widget-content ui-corner-all"></td>
                </tr>
                <tr><td> </td><td><input type='checkbox' id='ocra_key_cb' onclick="cb_changed('ocra_key_cb',['ocra_key','ocra_key_label','ocra_key_intro']);">
                    <label for=ocra_key_cb>${_("Generate OCRA key.")}</label></td></tr>
                <tr name="set_pin_rows" class="space" title='${_("Protect your token with a static PIN")}'><th colspan="2">${_("Token PIN:")}</th></tr>
                <tr name="set_pin_rows">
                    <td class="description"><label for="ocra_pin1" id="ocra_pin1_label">${_("enter PIN")}:</label></td>
                    <td><input type="password" autocomplete="off" name="pin1" id="ocra_pin1"
                            class="text ui-widget-content ui-corner-all"></td>
                </tr>
                <tr name="set_pin_rows" >
                    <td class="description"><label for="ocra_pin2" id="ocra_pin2_label">${_("confirm PIN")}:</label></td>
                    <td><input type="password" autocomplete="off" name="pin2" id="ocra_pin2"
                            class="text ui-widget-content ui-corner-all"></td>
                </tr>
                </table>
            </div>

            %for tok in c.token_enroll_div:
             <div class="token_enroll_frame" id="token_enroll_${tok}">${c.token_enroll_div[tok] |n}</div>
            %endfor

        </fieldset>
    </form>
</div>

<script type="text/javascript">
    function translate_token_enroll() {
        $("#dialog_token_enroll" ).dialog( "option", "title", '${_("Enroll Token")}');
        $('#button_enroll_enroll').button("option", "label", '${_("Enroll")}');
        $('#button_enroll_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>


<!-- ####################################### get serial ############# -->
<div id='dialog_get_serial'>
    <p>${_("Here you can search for the serial of a token."+
        "You need to enter the current OTP value, and choose where you want to search for this token.")}</p>
        <p>${_("Beware: This can be time consuming!")}</p>
        <p><label for="tools_getserial_type">${_("Type")}</label> <input id='tools_getserial_type'></p>
        <p><label for="tools_getserial_assigned">${_("Assigned token")}</label>
            <select id='tools_getserial_assigned'><option> </option>
                <option value="1">${_("assigned")}</option>
                <option value="0">${_("not assigned")}</option>
            </select></p>
        <p><label for="tools_getserial_realm">${_("Realm")}</label>
            <select id='tools_getserial_realm'> </select></p>
        <p><label for="tools_getserial_otp">${_("OTP value")}</label>
            <input id='tools_getserial_otp'></p>
</div>

<script type="text/javascript">
    function translate_get_serial() {
        $("#dialog_get_serial" ).dialog( "option", "title", '${_("Get Serial by OTP value")}' );
        $('#button_tools_getserial_ok').button("option", "label", '${_("Get Serial")}');
        $('#button_tools_getserial_close').button("option", "label", '${_("Close")}');
    }
</script>


<!-- ###################### check policy ####################### -->
<div id="dialog_check_policy">
    <p>${_("Here you can check your policies.")}</p>
    <p>${_("You can enter the corresponding values and the system will check, if there is any matching policy for this scenario.")}</p>
    <form class="cmxform" id="form_check_policy" action="">
    <table>
        <tr><td><label for=cp_scope>${_("Scope")}</label></td>
            <td>
                <select id='cp_scope'>
                    %for scope in c.polDefs.keys():
                    <option value="${scope}">${scope}</option>
                    %endfor
                </select>
            </td></tr>
        <tr><td><label for="cp_realm">${_("Realm")}</label></td>
            <td><input id="cp_realm" class="required"></td></tr>
        <tr><td><label for="cp_action">${_("Action")}</label></td>
            <td><input id="cp_action" class="required"></td></tr>
        <tr><td><label for="cp_user">${_("User")}</label></td>
            <td><input id="cp_user" class="required"></td></tr>
        <tr><td><label for="cp_client">${_("Client")}</label></td>
            <td><input id="cp_client"></td></tr>
    </table>
    <hr>
    <div id="cp_allowed">${_("This action is allowed by the following policy:")}</div>
    <div id="cp_forbidden">${_("This action is not allowed by any policy!")}</div>
    <div><pre id="cp_policy"> </pre></div>
    </form>
</div>

<script type="text/javascript">
    function translate_check_policy() {
        $("#dialog_check_policy" ).dialog( "option", "title", '${_("Check Policy")}' );
        $('#button_tools_checkpolicy_ok').button("option", "label", '${_("Check Policy")}');
        $('#button_tools_checkpolicy_close').button("option", "label", '${_("Close")}');
    }
</script>

<!-- ###################### export token ####################### -->


<div id="dialog_export_token">
    <p>${_("Here you can export token information of the tokens you are allowed to view to a CSV file.")}</p>
    <p>${_("You can enter additional attributes, you defined in the user mapping in the UserIdResolver. These attributes will be added to the CSV file.")}</p>
    <form class="cmxform" id="form_export_token" action="">
        <div><input type="text" id="exporttoken_attributes"></div>
    </form>
</div>

<script type="text/javascript">
    function translate_export_token() {
        $("#dialog_export_token" ).dialog( "option", "title", '${_("Export Token Info")}' );
        $('#button_export_token').button("option", "label", '${_("Export")}');
        $('#button_export_token_close').button("option", "label", '${_("Close")}');
    }
</script>

<!-- ###################### export audit ####################### -->

<div id="dialog_export_audit">
    <p>${_("Here you can export the audit information to a CSV file.")}</p>
    <p><label for="export_audit_number">${_("Number of audit entries to export")}:</label>
        <input id="export_audit_number" size=7 maxlength=6
        title='${_("Enter the number of audit entries you want to export.")}'>
        </p>
    <p><label for="export_audit_page">${_("Page to export")}:</label>
        <input id="export_audit_page"  size=7 maxlength=6
        title='${_("Enter the page of the audit entries you want to export.")}'>
        </p>
</div>

<script type="text/javascript">
    function translate_export_audit() {
        $("#dialog_export_audit" ).dialog( "option", "title", '${_("Export Audit Trail")}' );
        $('#button_export_audit').button("option", "label", '${_("Export")}');
        $('#button_export_audit_close').button("option", "label", '${_("Close")}');
    }
</script>

<!-- ###################### import users ####################### -->

<div id="dialog_import_users">
    <form class="cmxform" id="form_import_users" action="/tools/import_users" method="post" enctype="multipart/form-data">
        <p>${_("With this dialog you can import users to create an internally managed user resolver.")}</p>
        <br>
        <p>${_("You can upload csv files with the following column order:")}</p>
        <table class="data-table">
            <tr>
                <td>username</td>
                <td>userid</td>
                <td>surname</td>
                <td>givenname</td>
                <td>email</td>
                <td>phone</td>
                <td>mobile</td>
                <td>password</td>
            </tr>
        </table>
        <br>
        <p>
            <input name="file" id="import_users_file" type="file" size="30" accept="text/*"
                    title='${_("Please choose the csv file containing the users to import")}' required>
        </p>
        <br>
        <fieldset>
            <legend class='resolver_dialog_label'>${_("CSV Configuration")}</legend>
            <table>
                <tr>
                    <td>${_("Field delimiter:")}</td>
                    <td>
                        <select name="delimiter" required>
                            <option value="," selected>,</option>
                            <option value=";">;</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td>${_("Text delimiter:")}</td>
                    <td>
                        <select name="quotechar" required>
                            <option value="&#34;" selected>"</option>
                            <option value="&#39;">'</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td>${_("Password format:")}</td>
                    <td>
                        <label>
                            <input type="radio" name="passwords_in_plaintext" value="True" checked>
                            ${_("plaintext (will be hashed during import)")}
                        </label>
                        <br>
                        <label title='${_("Permitted formats are bcrypt, SHA256crypt and SHA512crypt")}'>
                            <input type="radio" name="passwords_in_plaintext" value="False">
                            ${_("secure hash")}
                        </label>
                    </td>
                </tr>
                <tr>
                    <td colspan="2">
                        <label title="Check this if the first row contains header information an should get skipped">
                            <input type="checkbox" name="skip_header" value="True">
                            ${_("Skip first line (header information)")}
                        </label>
                    </td>
                </tr>
            </table>
        </fieldset>
        <br>
        <p>${_("The users of the csv file will update an existing or populate a new managed resolver. The target resolver has to be added to a realm after the import.")}</p>
        <table>
            <tr>
                <td>${_("Resolver:")}</td>
                <td>
                    <table>
                        <tr>
                            <td style="width: 100%">
                                <select name="resolver" id="import_users_resolver" required></select>
                            </td>
                            <td style="white-space: nowrap">
                                &nbsp;or <a href="#" id="import_users_create_resolver">${_("create new...")}</a>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
        <input type="hidden" id="import_users_dryrun" name="dryrun" value="true">
        <input type="hidden" id="import_users_session" name="session" value="">
    </form>
</div>

<div id="dialog_import_users_confirm">
    <p>${_("The user import from the selected file would result in the \
    following changes. If results are as expected, you have to complete \
    the import by confirming the changes.")}</p>
    <div id="import_user_dryrun_results">
        <h3>${_("Summary")}</h3>
        <div>
            <ul class="summary"></ul>
        </div>
        <h3>${_("Details")}</h3>
        <div id="import_user_dryrun_result_details">
            <div class="detail-tabs">
                <ul>
                    <li><a href="#import_user_dryrun_result_d_new">New</a></li>
                    <li><a href="#import_user_dryrun_result_d_mod">Modified</a></li>
                    <li><a href="#import_user_dryrun_result_d_del">Deleted</a></li>
                    <li><a href="#import_user_dryrun_result_d_unchanged">Unchanged</a></li>
                </ul>
                <div id="import_user_dryrun_result_d_new">
                    <table class="data-table"></table>
                </div>
                <div id="import_user_dryrun_result_d_mod">
                    <table class="data-table"></table>
                </div>
                <div id="import_user_dryrun_result_d_del">
                    <table class="data-table"></table>
                </div>
                <div id="import_user_dryrun_result_d_unchanged">
                    <table class="data-table"></table>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- ###################### copy token ####################### -->
<div id='dialog_copy_token'>
    <p>${_("Here you can copy the OTP PIN from one token to the other.")}</p>
    <p>${_("Please enter the serial number of the token with the existing PIN and the serial number of the token, that should get the same PIN.")}</p>
    <p><label for=copy_from_token>${_("From token")}</label> <input id='copy_from_token'></p>
    <p><label for=copy_to_token>${_("To token")}</label> <input id='copy_to_token'></p>
</div>

<script type="text/javascript">
    function translate_copy_token() {
        $("#dialog_copy_token").dialog( "option", "title", '${_("Copy Token PIN")}' );
        $('#button_tools_copytokenpin_ok').button("option", "label", '${_("Copy PIN")}');
        $('#button_tools_copytokenpin_close').button("option", "label", '${_("Close")}');
    }
</script>

<!-- ###################### copy token ####################### -->
<div id='dialog_migrate_resolver'>
    <p>${_("Migrate assigned tokens to a new resolver")}</p>
    <table>
    <tr>
        <td><label for='copy_from_resolver'>${_("From resolver")}</label></td>
        <td><select id='copy_from_resolver'> </select></td>
    </tr>
    <tr>
        <td><label for='copy_to_resolver'>${_("To resolver")}</label></td>
        <td><select id='copy_to_resolver'> </select></td>
    </tr>
    </table>
</div>

<script type="text/javascript">
    function translate_migrateresolver() {
        $("#dialog_migrate_resolver" ).dialog( "option", "title", '${_("Migrate Resolver")}' );
        $('#button_tools_migrateresolver_ok').button("option", "label", '${_("Migrate tokens")}');
        $('#button_tools_migrateresolver_close').button("option", "label", '${_("Close")}');
    }
</script>



<!-- ############# import Safenet ######################### -->
<div id='dialog_import_safenet'>
    <form id="load_tokenfile_form_aladdin" action="/admin/loadtokens" method="post"
                enctype="multipart/form-data" onsubmit="return false;">
        <p>${_("Here you can upload the XML file that came with your SafeNet eToken PASS.")}</p>
        <p>${_("Please choose the token file")}:<br>
        <input name="file" type="file" size="30" accept="text/*">
        <div>
            <label for=aladdin_hashlib>${_("Hash algorithm")}:</label>
             <select id='aladdin_hashlib' name=aladdin_hashlib >
                <option value="auto">${_("automatic detection")}</option>
                <option value="sha1">sha1</option>
                <option value="sha256">sha256</option>
            </select>
        </div>
        <div>
            <input name="type" type="hidden" value="aladdin-xml">
            <input name="session" id="loadtokens_session_aladdin" type="hidden" value="">
            <div id="safenet_realms" name="targetrealm">
              <label for="safenet_realm">${_("Target realm")}:</label>
              <select id="safenet_realm" name="realm"> </select>
            </div>
        </div>
    </form>
</div>

<script type="text/javascript">
    function translate_import_safenet() {
        $("#dialog_import_safenet" ).dialog( "option", "title", '${_("Aladdin XML Token File")}' );
        $('#button_aladdin_load').button("option", "label", '${_("Load Token File")}');
        $('#button_aladdin_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ################ import PSKC ########################### -->
<div id='dialog_import_pskc'>
    <script type="text/javascript">pskc_type_changed();</script>
    <form id="load_tokenfile_form_pskc" action="/admin/loadtokens" method="post"
            enctype="multipart/form-data" onsubmit="return false;">
        <p>${_("Here you may upload the XML file of any OATH compliant OTP Token."+
            "The LinOTP server will automatically recognize "+
            "if the token is an HOTP (event based) or a TOTP (time based) token. "+
            "If the HMAC secrets are encrypted you either "+
            "need - depending on the encryption - the password or the encryption key.")}</p>
        <p>${_("Please choose the token file")}: </p>
        <p>
            <input name="file" type="file" size="30" accept="text/*">
            <input name="type" type="hidden" value="pskc">
        </p>
        <p>
        <input type="checkbox" name="pskc_checkserial" value="True" id='pskc_checkserial'>
            <label for='pskc_checkserial'>
                ${_("Check the serial numbers for OATH compliance (non-compliant serial numbers will be ignored)")}
                </label>
        </p>
        <p>
            <select id='pskc_type' name='pskc_type' onchange="pskc_type_changed();">
                <option value='plain' selected='selected'>${_("plain value")}</option>
                <option value='key'>${_("preshared key")}</option>
                <option value='password'>${_("password protected")}</option>
            </select>
            <input id='pskc_password' name='pskc_password' type='password' size='32'>
            <input id='pskc_preshared' name='pskc_preshared' size='32'>
        </p>
        <p>
            <input name="session" id="loadtokens_session_pskc" type="hidden" value="">
        </p>
        <div id="pskc_realms" name="targetrealm">
          <label for="pskc_realm">${_("Target realm")}:</label>
          <select id="pskc_realm" name="realm"> </select>
        </div>
    </form>
</div>

<script type="text/javascript">
    function translate_import_pskc() {
        $("#dialog_import_pskc" ).dialog( "option", "title", '${_("PSKC Key File")}' );
        $('#button_pskc_load').button("option", "label", '${_("Load Token File")}');
        $('#button_pskc_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ###################### import OATH CSV ####################### -->
<div id='dialog_import_oath'>
    <form id="load_tokenfile_form_oathcsv" action="/admin/loadtokens" method="post"
            enctype="multipart/form-data" onsubmit="return false;">
        <p>${_("Here you can upload a CSV file for your OATH token. The file is supposed to contain one token per line")}:</p>
        <p>${_("For HOTP and TOTP tokens:")}</p>
        <p>${_("Serial number, Seed, Type, OTP length, Time step")}</p>
        <p>${_("For OCRA tokens:")}</p>
        <p>${_("Serial Number, Seed, Type, Ocra Suite")}</p>
        <fieldset>
            <legend>${_("Default Values:")}</legend>
            <table>
                <tr><td>${_("Type")}</td><td>-></td><td>${_("HOTP")}</td></tr>
                <tr><td>${_("OTP length")}</td><td>-></td><td>6</td></tr>
                <tr><td>${_("Time step")}</td><td>-></td><td>30</td></tr>
                <tr><td>${_("OCRA suite")}</td><td>-></td><td>${_("optional")}</td></tr>
            </table>
        </fieldset>
        <p>${_("Please choose the token file")}:
            <input name="file" type="file" size="30" accept="text/*">
            <input name="type" type="hidden" value="oathcsv">\
            <input name="session" id="loadtokens_session_oathcsv" type="hidden" value="">\
        </p>
            <div id="oath_realms" name="targetrealm">
              <label for="oath_realm">${_("Target realm")}:</label>
              <select id="oath_realm" name="realm"> </select>
            </div>

    </form>
</div>

<script type="text/javascript">
    function translate_import_oath() {
        $("#dialog_import_oath" ).dialog( "option", "title", '${_("OATH CSV Token File")}' );
        $('#button_oathcsv_load').button("option", "label", '${_("Load Token File")}');
        $('#button_oathcsv_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ###################### import YubiKey CSV ####################### -->
<div id='dialog_import_yubikey'>
    <form id="load_tokenfile_form_yubikeycsv" action="/admin/loadtokens" method="post"
             enctype="multipart/form-data" onsubmit="return false;">
        <p>${_("Here you can upload a CSV file for your YubiKey token. The file is supposed to contain one token per line")}:</p>
        <p>${_("Please choose the token file")}:
             <input name="file" type="file" size="30" accept="text/*">
             <input name="type" type="hidden" value="yubikeycsv">\
             <input name="session" id="loadtokens_session_yubikeycsv" type="hidden" value="">
        </p>
        <div id="yubi_realms" name="targetrealm">
          <label for="yubi_realm">${_("Target realm")}:</label>
          <select id="yubi_realm" name="realm"> </select>
        </div>
    </form>
</div>

<script type="text/javascript">
    function translate_import_yubikey() {
        $("#dialog_import_yubikey" ).dialog( "option", "title", '${_("YubiKey CSV Token File")}' );
        $('#button_yubikeycsv_load').button("option", "label", '${_("Load Token File")}');
        $('#button_yubikeycsv_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ##################### import Tagespasswort ######################## -->
<div id='dialog_import_dpw'>
    <form id="load_tokenfile_form_dpw" action="/admin/loadtokens" method="post"
            enctype="multipart/form-data" onsubmit="return false;">
        <p>${_("Here you can upload the data file that came with your Tagespasswort tokens.")}</p>
        <p>${_("Please choose the token file")}: </p>
        <p>
            <input name="file" type="file" size="30" accept="text/*">
            <input name="type" type="hidden" value="dpw">
            <input name="session" id="loadtokens_session_dpw" type="hidden" value="">
        </p>
        <div id="dpw_realms" name="targetrealm">
          <label for="dpw_realm">${_("Target realm")}:</label>
          <select id="dpw_realm" name="realm"> </select>
        </div>
    </form>
</div>

<script type="text/javascript">
    function translate_import_dpw() {
        $("#dialog_import_dpw" ).dialog( "option", "title", '${_("Tagespasswort Token File")}' );
        $('#button_dpw_load').button("option", "label", '${_("Load Token File")}');
        $('#button_dpw_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ##################### import eToken DAT file ######################## -->
<div id='dialog_import_dat'>
    <form id="load_tokenfile_form_dat" action="/admin/loadtokens" method="post"
            enctype="multipart/form-data" onsubmit="return false;">
        <label for="upload_etoken_dat"> ${_("Upload the eToken data file:")}</label>
        <input id='upload_etoken_dat' name="file" type="file"
                size="30" accept="text/* data/*">
        <p>
            <label for='startdate'>${_("Timebased eToken can use a different start date")}:</label>
            <input id='startdate' name="startdate" type="datetime" value="1.1.2000 00:00:00">
        </p>
        <input name="type" type="hidden" value="dat">
        <input name="session" id="loadtokens_session_dat" type="hidden" value="">
        <div id="dat_realms" name="targetrealm">
          <label for="dat_realm">${_("Target realm")}:</label>
          <select id="dat_realm" name="realm"> </select>
        </div>

    </form>
</div>

<script type="text/javascript">
    function translate_import_dat() {
        $("#dialog_import_dat" ).dialog( "option", "title", '${_("eToken DAT File")}' );
        $('#button_dat_load').button("option", "label", '${_("Load Token File")}');
        $('#button_dat_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ######################## import Feitian ############################# -->

<div id='dialog_import_feitian'>
    <form id="load_tokenfile_form_feitian" action="/admin/loadtokens" method="post"\
                enctype="multipart/form-data" onsubmit="return false;">
                <p>${_("Here you can upload the XML file that came with your Feitian tokens.")}</p>
                <p>${_("Please choose the token file")}:<br>
                <input name="file" type="file" size="30" accept="text/*">
                <input name="type" type="hidden" value="feitian">
                <input name="session" id="loadtokens_session_feit" type="hidden" value="">
                <div id="feitian_realms" name="targetrealm">
                  <label for="feitian_realm">${_("Target realm")}:</label>
                  <select id="feitian_realm" name="realm"> </select>
                </div>
                </p></form>
</div>
<script type="text/javascript">
    function translate_import_feitian() {
        $("#dialog_import_feitian" ).dialog( "option", "title", '${_("Feitian XML Token file")}' );
        $('#button_feitian_load').button("option", "label", '${_("Load Token File")}');
        $('#button_feitian_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ################ import VASCO ################################## -->
<div id='dialog_import_vasco'>
    <form id="load_tokenfile_form_vasco" action="/admin/loadtokens" method="post"\
        enctype="multipart/form-data" onsubmit="return false;">
        <p><b>${_("Import tokens from Vasco DPX file")}</b></p>
        <div>
            <table>
            <tr><td><label for="vasco_file">${_("Please choose the token file")}:</label></td>
                <td><input id="vasco_file" name="file" type="file" size="30" accept="text/*"></td>
            </tr>
            <tr><td><label for=vasco_otplen>${_("OTP length")}:</label></td>
                <td><select name='vasco_otplen' id='vasco_otplen'>
                <option selected>6</option>
                <option>8</option></select>
                </td>
            </tr>
            <tr><td><label for="vasco_transportkey">${_("Transport key:")}</label></td>
                <td><input id="vasco_transportkey" name="transportkey" value="" size="32"></td>
            </tr>
            <tr><td><label for="vasco_target_realm">${_("Target realm")}</label></td>
                <td><input id="vasco_target_realm" name="realm" type="text" value="" size="32"></td>
            </tr>
            </table>
            <input name="type" type="hidden" value="vasco">
            <input name="session" id="loadtokens_session_vasco" type="hidden" value="">
        </div>
    </form>
</div>
<script type="text/javascript">
    function translate_import_vasco() {
        $("#dialog_import_vasco" ).dialog( "option", "title", '${_("Vasco DPX File")}' );
        $('#button_vasco_load').button("option", "label", '${_("Load Token File")}');
        $('#button_vasco_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ################### dialog import policies ################# -->
<div id='dialog_import_policy'>
    <form id="load_policies" action="/system/importPolicy" method="post"\
                enctype="multipart/form-data" onsubmit="return false;">
                <p>${_("Here you can import your policy file.")}</p>
                <p>${_("Please choose the policy file")}:<br>
                <input name="file" type="file" size="30" accept="text/*"></p>
                <input name="type" type="hidden" value="policy">
                </form>
</div>
<script type="text/javascript">
    function translate_import_policy() {
        $("#dialog_import_policies" ).dialog( "option", "title", '${_("Import policies")}' );
        $('#button_policy_load').button("option", "label", '${_("Import policy file")}');
        $('#button_policy_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>



<!-- ##################### realms ##################################### -->
<div id='dialog_realms'>
    <p>${_("Create a new realm or select one available realm")}:</p>
    <div id='realm_list'> </div>
</div>
<script type="text/javascript">
    function translate_dialog_realms() {
        $("#dialog_realms" ).dialog( "option", "title", '${_("Realms")}' );
        $('#button_realms_new').button("option", "label", '${_("New")}');
        $('#button_realms_edit').button("option", "label", '${_("Edit")}');
        $('#button_realms_delete').button("option", "label", '${_("Delete")}');
        $('#button_realms_close').button("option", "label", '${_("Close")}');
        $('#button_realms_setdefault').button("option", "label", '${_("Set Default")}');
        $('#button_realms_cleardefault').button("option", "label", '${_("Clear Default")}');
    }
</script>
<!-- ######################### resolvers ############################## -->
<div id='dialog_resolvers'>
    <p>${_("Create a new or select one available UserIdResolver")}:</p>
    <div id='resolvers_list'> </div>
</div>
<script type="text/javascript">
    function translate_dialog_resolvers() {
        $("#dialog_resolvers" ).dialog( "option", "title", '${_("Resolver")}');
        $('#button_resolver_new').button("option", "label", '${_("New")}');
        $('#button_resolver_edit').button("option", "label", '${_("Edit")}');
        $('#button_resolver_duplicate').button("option", "label", '${_("Duplicate")}');
        $('#button_resolver_delete').button("option", "label", '${_("Delete")}');
        $('#button_resolver_close').button("option", "label", '${_("Close")}');
    }
</script>

<!-- ###################### create resolver ########################### -->
<div id='dialog_resolver_create'>
    ${_("Which type of resolver do you want to create?")}
</div>
<script type="text/javascript">
    function translate_dialog_resolver_create() {
        $("#dialog_resolver_create" ).dialog( "option", "title", '${_("Creating a new UserIdResolver")}' );
        $('#button_new_resolver_type_ldap').button("option", "label", '${_("LDAP")}');
        $('#button_new_resolver_type_sql').button("option", "label", '${_("SQL")}');
        $('#button_new_resolver_type_http .ui-button-text').html('HTTP');
        $('#button_new_resolver_type_flatfile').button("option", "label", '${_("Flatfile")}');
        $('#button_new_resolver_type_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ################### edit realm ####################################### -->
<div id='dialog_edit_realms'>
    <!--${_("Here you can add or remove existing resolvers to the realm")}:-->
    <form class="cmxform" id="form_realmconfig" action="">
        <div id='realm_intro_new'>
            <p>${_("You are creating a new realm.")}
            ${_("You may add resolvers by holding down Ctrl-Key and left-clicking.")}</p>\
            <p><label for=realm_name>${_("Realm name")}:</label>
                <input type='text' class="required" id='realm_name' size='20' maxlength='60' value="">
                </p>
        </div>
        <div id='realm_intro_edit'>
            <p>${_("Here you may define the resolvers belonging to the realm")}:</p>
            <p><b><span id='realm_edit_realm_name'> </span></b></p>
            <p>${_("You may add resolvers by holding down Ctrl-Key and left-clicking.")}</p>
            <input type='hidden' id='realm_name' size='20' maxlength='60'>
        </div>

        <div id='realm_edit_resolver_list'> </div>
    </form>
</div>
<script type="text/javascript">
    function translate_dialog_realm_edit() {
        $("#dialog_edit_realms" ).dialog( "option", "title", '${_("Edit Realm")}' );
        $('#button_editrealms_cancel').button("option", "label", '${_("Cancel")}');
        $('#button_editrealms_save').button("option", "label", '${_("Save")}');
    }
</script>

<!-- ################# delete token ######################### -->
<div id='dialog_delete_token'>
    <p>${_("The following tokens will be permanently deleted and can not be recovered.")}
    </p>
    <span id='delete_info'> </span>
</div>
<script type="text/javascript">
    function translate_dialog_delete_token() {
        $("#dialog_delete_token" ).dialog( "option", "title", '${_("Delete selected tokens?")}' );
        $('#button_delete_delete').button("option", "label", '${_("Delete tokens")}');
        $('#button_delete_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ########################### token enrollment ############ -->
<div id='dialog_show_enroll_url'>
    <p>
    ${_("Enrolled the token")} <b><span id='token_enroll_serial'> </span></b>
    ${_("for user")} <span id='token_enroll_user'> </span>.
    </p>

    <div id='enroll_url'> </div>
</div>
<script type="text/javascript">
    function translate_dialog_show_enroll_url() {
        $("#dialog_show_enroll_url" ).dialog( "option", "title", '${_("token enrollment")}' );
        $('#button_show_enroll_ok').button("option", "label", '${_("OK")}');
    }
</script>
<!--
<div id='dialog_enroll'>
    <p>
    ${_("Enrolled the token")} <b><span id='token_enroll_serial_0'> </span></b>
    ${_("for user")} <span id='token_enroll_user_0'> </span>.
    </p>
    <div id='enroll_dialog'> </div>
</div>
<script type="text/javascript">
    function translate_dialog_show_enroll_url() {
        $("#dialog_show_enroll_url" ).dialog( "option", "title", '${_("token enrollment")}' );
        $('#button_show_enroll_ok').button("option", "label", '${_("OK")}');
    }
</script>
-->
<!-- #################### dialog lost token######################### -->
<div id='dialog_lost_token'>
    <p>${_("Token serial: ")} <span id='lost_token_serial'> </span> </p>
    <p>${_("The token was lost? You may enroll a temporary token and automatically disable the lost token.")}</p>

    <select id="dialog_lost_token_select">
        <option value="select_token">
            ${_("- Select Temporary Token Type -")}
        </option>
        <option value="password_token">
            ${_("Simple Password Token")}
        </option>
        <option value="email_token">
            ${_("Email Token")}
        </option>
        <option value="sms_token">
            ${_("SMS Token")}
        </option>
    </select>

</div>
<script type="text/javascript">
    function translate_dialog_lost_token() {
        $("#dialog_lost_token" ).dialog( "option", "title", '${_("Lost Token")}' );
        $('#button_losttoken_ok').button("option", "label", '${_("Get Temporary Token")}');
        $('#button_losttoken_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ##################### dialog token info######################### -->
<div id='dialog_token_info'>
</div>
<script type="text/javascript">
    function translate_dialog_token_info() {
        $("#dialog_token_info" ).dialog( "option", "title", '${_("Token Info")}' );
        $('#button_ti_hashlib').button("option", "label", '${_("Hashlib")}');
        $('#button_ti_close').button("option", "label", '${_("Close")}');
        $('#button_ti_otplength').button("option", "label", '${_("OTP Length")}');
        $('#button_ti_counterwindow').button("option", "label", '${_("Counter Window")}');
        $('#button_ti_failcount').button("option", "label", '${_("Max Fail Counter")}');
        $('#button_ti_countauthmax').button("option", "label", '${_("Max Auth Count")}');
        $('#button_ti_countauthsuccessmax').button("option", "label", '${_("Max Successful Auth Count")}');
        $('#button_ti_validityPeriodStart').button("option", "label", '${_("Validity start")}');
        $('#button_ti_validityPeriodEnd').button("option", "label", '${_("Validity end")}');
        $('#button_ti_syncwindow').button("option", "label", '${_("Sync Window")}');
        $('#button_ti_timewindow').button("option", "label", '${_("Time Window")}');
        $('#button_ti_timeshift').button("option", "label", '${_("Time Shift")}');
        $('#button_ti_timestep').button("option", "label", '${_("Time Step")}');
    }
</script>

<!-- ############### dialog token info details ######################### -->
<div id='dialog_tokeninfo_set'>

</div>
<script type="text/javascript">
    function translate_dialog_ti_hashlib() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Hashlib")}');
        $('#button_tokeninfo_ok').button("option", "label", '${_("OK")}');
        $('#button_tokeninfo_cancel').button("option", "label", '${_("Cancel")}');
    }
    function translate_dialog_ti_otplength() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set OTP length")}');
        $('#button_tokeninfo_ok').button("option", "label", '${_("OK")}');
        $('#button_tokeninfo_cancel').button("option", "label", '${_("Cancel")}');
    }
    function translate_dialog_ti_counterwindow() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Counter Window")}' );
        $('#button_tokeninfo_ok').button("option", "label", '${_("OK")}');
        $('#button_tokeninfo_cancel').button("option", "label", '${_("Cancel")}');
    }
    function translate_dialog_ti_maxfailcount() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Max Failcount")}' );
        $('#button_tokeninfo_ok').button("option", "label", '${_("OK")}');
        $('#button_tokeninfo_cancel').button("option", "label", '${_("Cancel")}');
    }
    function translate_dialog_ti_countauthmax() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Max Auth Count")}' );
        $('#button_tokeninfo_ok').button("option", "label", '${_("OK")}');
        $('#button_tokeninfo_cancel').button("option", "label", '${_("Cancel")}');
    }
    function translate_dialog_ti_countauthsuccessmax() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Max Successful Auth Count")}' );
        $('#button_tokeninfo_ok').button("option", "label", '${_("OK")}');
        $('#button_tokeninfo_cancel').button("option", "label", '${_("Cancel")}');
    }
    function translate_dialog_ti_validityPeriodStart() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("Validity start")}' );
        $('#button_tokeninfo_ok').button("option", "label", '${_("OK")}');
        $('#button_tokeninfo_cancel').button("option", "label", '${_("Cancel")}');
    }
    function translate_dialog_ti_validityPeriodEnd() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("Validity end")}' );
        $('#button_tokeninfo_ok').button("option", "label", '${_("OK")}');
        $('#button_tokeninfo_cancel').button("option", "label", '${_("Cancel")}');
    }
    function translate_dialog_ti_phone() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("Mobile phone number")}' );
        $('#button_tokeninfo_ok').button("option", "label", '${_("OK")}');
        $('#button_tokeninfo_cancel').button("option", "label", '${_("Cancel")}');
    }
    function translate_dialog_ti_syncwindow(){
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Sync Window")}' );
        $('#button_tokeninfo_ok').button("option", "label", '${_("OK")}');
        $('#button_tokeninfo_cancel').button("option", "label", '${_("Cancel")}');
    }
    function translate_dialog_ti_timewindow(){
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Time Window")}' );
        $('#button_tokeninfo_ok').button("option", "label", '${_("OK")}');
        $('#button_tokeninfo_cancel').button("option", "label", '${_("Cancel")}');
    }
    function translate_dialog_ti_timeshift(){
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Time Shift")}' );
        $('#button_tokeninfo_ok').button("option", "label", '${_("OK")}');
        $('#button_tokeninfo_cancel').button("option", "label", '${_("Cancel")}');
    }
    function translate_dialog_ti_timestep(){
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Time Step")}');
        $('#button_tokeninfo_ok').button("option", "label", '${_("OK")}');
        $('#button_tokeninfo_cancel').button("option", "label", '${_("Cancel")}');
    }
    function translate_dialog_ti_description(){
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Description")}');
        $('#button_tokeninfo_ok').button("option", "label", '${_("OK")}');
        $('#button_tokeninfo_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>



<!-- ##################### resync token ############################# -->
<div id='dialog_resync_token'>
    <p>${_("You may resync the token:")} <span id='tokenid_resync'> </span>.</p>
    <p>${_("Therefor please enter two OTP values.")}</p>
    <form action=""><fieldset><table>
            <tr><td>
            <label for="otp1">OTP 1</label>
            </td><td>
            <input type="text" name="otp1" id="otp1" class="text ui-widget-content ui-corner-all">
            </td></tr><tr><td>
            <label for="otp2">OTP 2</label>
            </td><td>
            <input type="text" name="otp2" id="otp2" class="text ui-widget-content ui-corner-all">
            </td></tr></table>
            </fieldset>
        </form>
</div>

<script type="text/javascript">
    function translate_dialog_resync_token() {
        $("#dialog_resync_token" ).dialog( "option", "title", '${_("Resync Token")}' );
        $('#button_resync_resync').button("option", "label", '${_("Resync")}');
        $('#button_resync_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ######################## dialog edit token realm ############# -->
<div id='dialog_edit_tokenrealm'>
    <form class="cmxform" id="form_tokenrealm" action="">
    <p>${_("Define to which realms the token(s) shall belong to:")}*</p>
    <p><span id='tokenid_realm'> </span></p>
    <p><input type='hidden' id='realm_name' size='20' maxlength='60'></p>
    <div id='token_realm_list'> </div>
    <p><i>*${_("You may add realms by holding down Ctrl-Key and left-clicking.")}</i></p>
    </form>
</div>
<script type="text/javascript">
    function translate_dialog_token_realm() {
        $("#dialog_edit_tokenrealm" ).dialog( "option", "title", '${_("Edit Realms of Token")}' );
        $('#button_tokenrealm_save').button("option", "label", '${_("Set Realm")}');
        $('#button_tokenrealm_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ############### get list of OTP valus ############################ -->
<div id='dialog_getmulti'>
    <p>${_("You may get OTP values for token:")} <span id='tokenid_getmulti'> </span></p>
    <p><label for=otp_values_count>${_("Enter the number, how many OTP values you want to retrieve:")}</label></p>
    <input id='otp_values_count' maxlength='6' class='required'>
</div>

<script type="text/javascript">
    function translate_dialog_getmulti() {
        $("#dialog_getmulti" ).dialog( "option", "title", '${_("Get OTP values")}' );
        $('#button_getmulti_ok').button("option", "label", '${_("OK")}');
        $('#button_getmulti_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ########### unassign token############################# -->
<div id='dialog_unassign_token'>
    <p>${_("The following Tokens will be unassigned from the their users:")}
        <span id='tokenid_unassign'> </span></p>
    <p>${_("The users will not be able to authenticate with this token anymore. Are you sure?")}
    </p>
</div>
<script type="text/javascript">
    function translate_dialog_unassign() {
        $("#dialog_unassign_token" ).dialog( "option", "title", '${_("Unassign selected tokens?")}' );
        $('#button_unassign_unassign').button("option", "label", '${_("Unassign")}');
        $('#button_unassign_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>
<!-- #################### realm ask delete ###################### -->
<div id='dialog_realm_ask_delete'>
    ${_("Do you want to delete the realm")} <b><span id='realm_delete_name'> </span></b>?
</div>
<script type="text/javascript">
    function translate_dialog_realm_ask_delete() {
        $("#dialog_realm_ask_delete" ).dialog( "option", "title", '${_("Deleting realm")}' );
        $('#button_realm_ask_delete_delete').button("option", "label", '${_("Delete")}');
        $('#button_realm_ask_delete_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>
<!-- ################## resolver ask delete ###################### -->
<div id='dialog_resolver_ask_delete'>
    <p>${_("Do you want to delete the resolver?")}</p>
    <p>
        ${_("Name")}: <span id='delete_resolver_name'> </span><br>
        ${_("Type")}: <span id='delete_resolver_type'> </span>
    </p>
</div>
<script type="text/javascript">
    function translate_dialog_resolver_ask_delete() {
        $("#dialog_resolver_ask_delete" ).dialog( "option", "title", '${_("Deleting resolver")}' );
        $('#button_resolver_ask_delete_delete').button("option", "label", '${_("Delete")}');
        $('#button_resolver_ask_delete_cancel').button("option", "label", '${_("Cancel")}');
    }
</script>

<!-- ############# temp token dialog ############################ -->
<div id='dialog_view_temporary_token'>
    <p>
        ${_("Token enrolled. Use the old PIN with the new password.")}
        ${_("The temporary token can be used till the end date.")}
    </p>
    <p>
        ${_("Serial")}: <span id='temp_token_serial'> </span><br>
        ${_("Password")}: <span id='temp_token_password'> </span><br>
        ${_("End date")}: <span id='temp_token_enddate'> </span>
</div>
<script type="text/javascript">
    function translate_dialog_view_temptoken() {
        $("#dialog_view_temporary_token" ).dialog( "option", "title", '${_("New Temporary Token")}' );
        $('#button_view_temporary_token_close').button("option", "label", '${_("Close")}');
    }
</script>

<!-- ################## dialog LDAP resolver ######################### -->

<div id='dialog_ldap_resolver'>
    <form class="cmxform" id="form_ldapconfig" action="">
        <fieldset>
            <legend class='resolver_dialog_label'>${_("Server Configuration")}</legend>
            <table>
                <colgroup>
                    <col span="1" class="label-column">
                    <col span="1">
                </colgroup>
                <tr><td><label for=ldap_resolvername>${_("Resolver name")}:</label></td>
                    <td><input type="text" name="ldap_resolvername" class="required"  id="ldap_resolvername" size="35" maxlength="20"></td></tr>
                <tr><td><label for=ldap_uri>${_("Server-URI")}:</label></td>
                    <td><input type="text" name="ldap_uri" class="required"  id="ldap_uri" size="35" maxlength="200"
                        onkeyup="handler_ldap_certificate_show();"></td></tr>
                <tr><td> </td>
                    <td><input type="checkbox" name="ldap_enforce_tls" id="ldap_enforce_tls" onchange="handler_ldap_certificate_show();">
                        <label id="ldap_enforce_tls_label" for="ldap_enforce_tls">${_("Enforce STARTTLS")}</label></td></tr>
                <tr id="ldap_resolver_certificate"><td>
                    <label for="ldap_certificate">${_("CA Certificate")}:</label></td>
                    <td><textarea name="ldap_certificate" id="ldap_certificate" cols="34" rows="5"
                        title='${_("If you are using STARTTLS or LDAPS you can enter the CA certificate in PEM format here.")}'> </textarea></td>
                    </tr>
                <tr><td><label for=ldap_basedn>${_("BaseDN")}:</label></td>
                    <td><input type="text" name="ldap_basedn" class="required"  id="ldap_basedn" size="35" maxlength="200"></td></tr>
                <tr><td><label for=ldap_binddn>${_("BindDN")}:</label></td>
                    <td><input type="text" name="ldap_binddn" id="ldap_binddn" size="35" maxlength="200"></td></tr>
                <tr>
                    <td>
                        <label for=ldap_password>${_("Bind Password")}</label>:
                    </td>
                    <td>
                        <input type="password" autocomplete="off" name="ldap_password" id="ldap_password" size="35" maxlength="60">
                        <div class="input_hint">${_("If security relevant information is changed, for example the URL, the password has to be provided to avoid unprivileged exposure of the password.")}</div>
                    </td>
                </tr>
                <tr><td><label for=ldap_timeout>${_("Timeout")}</label>:</td>
                    <td><input type="text" name="ldap_timeout" class="required"  id="ldap_timeout" size="35" maxlength="10"></td></tr>
                <tr><td><label for=ldap_sizelimit>${_("Sizelimit")}:</label></td>
                    <td><input type="text" name="ldap_sizelimit" class="required"  id="ldap_sizelimit" size="35" maxlength="10"></td></tr>
                <tr><td> </td>
                    <td><input type="checkbox" name="noreferrals" value="noreferralss" id="ldap_noreferrals">
                        <label for=ldap_noreferrals>${_("No anonymous referral chasing")}</label></td></tr>
            </table>

            <button class="action-button" id="button_test_ldap">${_("Test LDAP Server connection")}</button>
            <div id="progress_test_ldap"><img src="/images/ajax-loader.gif" border="0" alt=""> ${_("Testing connection ...")} </div>
        </fieldset>

        <fieldset>
            <legend class='resolver_dialog_label'>${_("Mapping Attributes")}</legend>
            <table>
                <colgroup>
                    <col span="1" class="label-column">
                    <col span="1">
                </colgroup>
                <tr><td><label for="ldap_loginattr">${_("LoginName Attribute")}:</label></td>
                    <td><input type="text" name="ldap_loginattr" class="required"  id="ldap_loginattr" size="35" maxlength="60"></td></tr>
                <tr><td><label for="ldap_searchfilter">${_("Searchfilter")}:</label></td>
                    <td><input type="text" name="ldap_searchfilter" class="required"  id="ldap_searchfilter" size="35" maxlength="200"></td></tr>
                <tr><td><label for="ldap_userfilter">${_("Userfilter")}:</label></td>
                    <td><input type="text" name="ldap_userfilter" class="required"  id="ldap_userfilter" size="35" maxlength="200"></td></tr>
                <tr><td><label for="ldap_mapping">${_("Attribute mapping")}:</label></td>
                    <td><input type="text" name="ldap_mapping" class="required"  id="ldap_mapping" size="35" maxlength="200"></td></tr>
                <tr><td><label for="ldap_uidtype" title="${_('The UID (unique identifier) for your LDAP objects - could be DN, GUID or entryUUID (LDAP) or objectGUID (Active Directory)')}">${_("UID Type")}:</label></td>
                    <td><input type="text" name="ldap_uidtype" id="ldap_uidtype" size="20" maxlength="20"></td></tr>
                </table>
                <table width="100%"><tr>
                <td><button class="action-button" id="button_preset_ad">${_("Preset Active Directory")}</button></td>
                <td><button class="action-button" id="button_preset_ldap">${_("Preset LDAP")}</button></td>
                </tr>
            </table>
        </fieldset>
    </form>
</div>
<script type="text/javascript">
    function translate_dialog_ldap_resolver() {
        $("#dialog_ldap_resolver" ).dialog( "option", "title", '${_("LDAP Resolver")}' );
        $('#button_test_ldap').button("option", "label", '${_("Test LDAP connection")}');
        $('#button_preset_ad').button("option", "label", '${_("Preset AD")}');
        $('#button_preset_ldap').button("option", "label", '${_("Preset LDAP")}');
        $('#button_resolver_ldap_cancel').button("option", "label", '${_("Cancel")}');
        $('#button_resolver_ldap_save').button("option", "label", '${_("Save")}');
    }
</script>


<!-- ### -->
<!-- ################## dialog HTTP resolver ######################### -->

<div id='dialog_http_resolver'>
    <form class="cmxform" id="form_httpconfig" action="">
        <fieldset>
            <legend class='resolver_dialog_label'>${_("Server Configuration")}</legend>
            <table>
                <colgroup>
                    <col span="1" class="label-column">
                    <col span="1">
                </colgroup>
                <tr><td><label for=http_resolvername>${_("Resolver name:")}</label></td>
                    <td><input type="text" name="Resolvername" class="required"
                        id="http_resolvername" size="35" maxlength="20"></td></tr>
                <tr><td><label for=http_uri>${_("Server-URI:")}</label></td>
                    <td><input type="text" name="Uri" class="required"
                        id="http_uri" size="35" maxlength="200"></td></tr>
                <tr id="http_resolver_certificate"><td>
                    <label for="http_certificate">${_("CA Certificate:")}</label></td>
                    <td><textarea name="Certificate" id="http_certificate" cols="34" rows="5"
                        title='If you are using HTTP you can enter the CA certificate in PEM format here.'> </textarea></td>
                    </tr>
                <tr><td><label for=http_authuser>${_("Auth User:")}</label></td>
                    <td><input type="text" name="Authuser" id="http_authuser" size="35" maxlength="200"></td></tr>
                <tr><td><label for=http_password>${_("Password")}</label>:</td>
                    <td><input type="password" autocomplete="off" name="Password" id="http_password" size="35" maxlength="60"></td></tr>
                <tr><td><label for=http_timeout>${_("Timeout")}</label>:</td>
                    <td><input type="text" name="Timeout" class="required"  id="http_timeout" size="35" maxlength="5"></td></tr>
                <tr><td> </td>
                    <td>
                    <button class="action-button" id="button_test_http">${_("Test HTTP Server connection")}</button>
                    <div id="progress_test_http"><img src="/images/ajax-loader.gif" border="0" alt="">${_("Testing connection ... ")}</div>
                    </td>
                </tr>
            </table>

        </fieldset>
        <fieldset>
        <legend class='resolver_dialog_label'>${_("JSON Configuration")}</legend>
        <div id='http_setting_tabs'>
            <ul id='http_settings_index'>
                <li><a href='#http_userid_setting'>${_("UserId")}</a></li>
                <li><a href='#http_username_setting'>${_("Username")}</a></li>
                <li><a href='#http_userlist_setting'>${_("Userlist")}</a></li>
            </ul>
            <div id="http_userid_setting">
                <table>
                <tr><td><label for="http_userid_request_path">${_("URL path:")}</label></td>
                    <td><input type="text" name="userid_request_path" class="required"
                                           id="http_userid_request_path" size="25"></td></tr>
                <tr><td><label for="http_userid_request_mapping">${_("Parameters:")}</label></td>
                    <td><input type="text" name="userid_request_mapping" class="required"
                                           id="http_userid_request_mapping" size="25"></td></tr>
                <tr><td><label for="http_userid_result_path">${_("Result path:")}</label></td>
                    <td><input type="text" name="userid_result_path" class="required"
                                           id="http_userid_result_path" size="25"></td></tr>
                <tr><td><label for="http_userid_result_mapping">${_("Attribute mapping:")}</label></td>
                    <td><input type="text" name="userid_result_mapping" class="required"
                                           id="http_userid_result_mapping" size="25"></td></tr>
                </table>
            </div>
            <div id="http_username_setting">
                <table>
                <tr><td><label for="http_username_request_path">${_("URL path:")}</label></td>
                    <td><input type="text" name="username_request_path" class="required"
                                           id="http_username_request_path" size="25"></td></tr>
                <tr><td><label for="http_username_request_mapping">${_("Parameters:")}</label></td>
                    <td><input type="text" name="username_request_mapping" class="required"
                                           id="http_username_request_mapping" size="25"></td></tr>
                <tr><td><label for="http_username_result_path">${_("Result path:")}</label></td>
                    <td><input type="text" name="username_result_path" class="required"
                                           id="http_username_result_path" size="25"></td></tr>
                <tr><td><label for="http_username_result_mapping">${_("Attribute mapping:")}</label></td>
                    <td><input type="text" name="username_result_mapping" class="required"
                                           id="http_username_result_mapping" size="25"></td></tr>
                </table>
            </div>
            <div id="http_userlist_setting">
                <table>
                <tr><td><label for="http_userlist_request_path">${_("URL path:")}</label></td>
                    <td><input type="text" name="userlist_request_path" class="required"
                                           id="http_userlist_request_path" size="25"></td></tr>
                <tr><td><label for="http_userlist_request_mapping">${_("Parameters:")}</label></td>
                    <td><input type="text" name="userlist_request_mapping" class="required"
                                           id="http_userlist_request_mapping" size="25"></td></tr>
                <tr><td><label for="http_userlist_result_path">${_("Result path:")}</label></td>
                    <td><input type="text" name="userlist_result_path" class="required"
                                           id="http_userlist_result_path" size="25"></td></tr>
                <tr><td><label for="http_userlist_result_mapping">${_("Attribute mapping:")}</label></td>
                    <td><input type="text" name="userlist_result_mapping" class="required"
                                           id="http_userlist_result_mapping" size="25"></td></tr>
                </table>
            </div>
        </div>
        </fieldset>
    </form>
</div>
<script type="text/javascript">
    function translate_dialog_http_resolver() {
        $("#dialog_http_resolver" ).dialog( "option", "title", 'HTTP Resolver');
        $('#button_test_http .ui-button-text').html('Test HTTP connection');
        $('#button_resolver_http_cancel').button("option", "label", '${_("Cancel")}');
        $('#button_resolver_http_save').button("option", "label", '${_("Save")}');
    }
</script>



<!-- #################### dialog SQL resolver #################################### -->

<div id='dialog_sql_resolver'>
<form class="cmxform" id="form_sqlconfig" action="">
  <fieldset>
    <legend class='resolver_dialog_label'>${_("Server Configuration")}</legend>
        <table>
            <colgroup>
                <col span="1" class="label-column">
                <col span="1">
            </colgroup>
            <tr><td><label for=sql_resolvername>${_("Resolver name")}:</label></td>
                <td><input type="text" name="sql_resolvername" class="required"  id="sql_resolvername" size="30" maxlength="20"></td></tr>
            <tr><td><label for=sql_driver>${_("Driver")}:</label></td>
                <td><input type="text" name="sql_driver" class="required"  id="sql_driver" size="30" maxlength="40"></td></tr>
            <tr><td><label for=sql_server>${_("Server")}:</label></td>
                <td><input type="text" name="sql_server"  id="sql_server" size="30" maxlength="80"></td></tr>
            <tr><td><label for=sql_port>${_("Port")}:</label></td>
                <td><input type="text" name="sql_port"  id="sql_port" size="30" maxlength="5"></td></tr>
            <tr><td><label for=sql_database>${_("Database")}:</label></td>
                <td><input type="text" name="sql_database"  id="sql_database" size="30" maxlength="60"></td></tr>
            <tr><td><label for=sql_user>${_("User")}:</label></td>
                <td><input type="text" name="sql_user"   id="sql_user" size="30" maxlength="60"></td></tr>
            <tr>
                <td>
                    <label for=sql_password>${_("Password")}</label>:
                </td>
                <td>
                    <input type="password" autocomplete="off" name="sql_password" id="sql_password" size="30" maxlength="60">
                    <div class="input_hint">${_("If security relevant information is changed, for example the URL, the password has to be provided to avoid unprivileged exposure of the password.")}</div>
                </td>
            </tr>
            <tr><td><label for=sql_table>${_("Database table")}:</label></td>
                <td><input type="text" name="sql_table" class="required"  id="sql_table" size="30" maxlength="60"></td></tr>
            <tr><td><label for=sql_limit>${_("Limit")}:</label></td>
                <td><input type="text" name="sql_limit" class="required"  id="sql_limit" size="30" maxlength="5"></td></tr>
            <tr><td><label for=sql_encoding>${_("Database encoding")}:</label></td>
                <td><input type="text" name="sql_encoding" class="optional"  id="sql_encoding" size="30" maxlength="200"></td></tr>
            <tr><td><label for=sql_conparams>${_("Additional connection parameters")}:</label></td>
                <td><input type="text" name="sql_conparams" class="optional"  id="sql_conparams" size="30"></td></tr>
        </table>
        <button class="action-button" id="button_test_sql">${_("Test SQL connection")}</button>
        <div id="progress_test_sql"><img src="/images/ajax-loader.gif" border="0" alt=""> ${_("Testing connections...")} </div>
    </fieldset>

    <fieldset>
      <legend class='resolver_dialog_label'>${_("Mapping Attributes")}</legend>
        <table>
            <colgroup>
                <col span="1" class="label-column">
                <col span="1">
            </colgroup>
            <tr><td><label for=sql_mapping>${_("Attribute mapping")}:</label></td>
                <td><input type="text" name="sql_mapping" class="required"  id="sql_mapping" size="35" maxlength="200"></td></tr>
            <tr><td><label for=sql_where>${_("Where statement")}:</label></td>
                <td><input type="text" name="sql_where" class="optional"  id="sql_where" size="35" maxlength="200"></td></tr>
        </table>
    </fieldset></form>
</div>
<script type="text/javascript">
    function translate_dialog_sql_resolver() {
        $("#dialog_sql_resolver" ).dialog( "option", "title", '${_("SQL Resolver")}' );
        $('#button_test_sql').button("option", "label", '${_("Test SQL connection")}');
        $('#button_resolver_sql_cancel').button("option", "label", '${_("Cancel")}');
        $('#button_resolver_sql_save').button("option", "label", '${_("Save")}');
    }
</script>

<!-- ################ dialog file resolver #################### -->


<div id="dialog_file_resolver">
    <form class="cmxform" id="form_fileconfig" action="">
        <fieldset>
            <table>
                <colgroup>
                    <col span="1" class="label-column">
                    <col span="1">
                </colgroup>
                <tr><td><label for=file_resolvername>${_("Resolver name")}:</label></td>
                    <td><input type="text" name="file_resolvername" class="required"  id="file_resolvername" size="35" maxlength="20"></td></tr>
                <tr><td><label for=file_filename>${_("filename")}:</label></td>
                    <td><input type="text" name="file_filename" class="required"  id="file_filename" size="35" maxlength="200"></td></tr>
            </table>
        </fieldset>
    </form>
</div>
<script type="text/javascript">
    function translate_dialog_sql_resolver() {
        $("#dialog_file_resolver" ).dialog( "option", "title", '${_("File Resolver")}' );
        $('#button_resolver_file_cancel').button("option", "label", '${_("Cancel")}');
        $('#button_resolver_file_save').button("option", "label", '${_("Save")}');
    }
</script>

</div> <!-- end of all dialogs -->


<!-- ################ Alert ################################### -->
<div id="all_alerts" style="display:none; height:0px;">
<div id="text_resync_fail">${_("Resyncing of token failed")}</div>
<div id="text_resync_success">${_("Resynced token successfully")}</div>
<div id="text_setpin_success">${_("set PIN successfully")}</div>
<div id="text_only_one_token_ti">${_("When displaying Token information you may only select one single Token.")}</div>
<div id="text_only_one_token_type">${_("When retrieving the token type you may only select one single Token.")}</div>
<div id="text_enroll_type_error">${_("Error: unknown tokentype in function token_enroll()")}</div>
<div id="text_get_serial_no_otp">${_("Could not find a token for this OTP value.")}</div>
<div id="text_get_serial_error">${_("Error finding a token to this OTP value.")}</div>
<div id="text_linotp_comm_fail">${_("Failed to communicate to LinOTP server")}</div>
<div id="text_import_unknown_type">${_("unknown token type to load!")}</div>
<div id="text_import_pem">${_("You may only upload support subscription files ending with .pem")}</div>
<div id="text_sms_save_error">${_("Error saving SMS configuration. Please check your configuration and your server")}</div>
<div id="text_system_save_error">${_("Error saving system configuration. Please check your configuration and your server")}</div>
<div id="text_system_save_error_checkbox">${_("Error saving system checkboxes configuration. Please check your configuration and your server")}</div>
<div id="text_realm_regexp_error">${_("Regexp error in realm. You need to select ONE realm to set it as default.")}</div>
<div id="text_realm_name_error">${_("There is an error in the realm name!")}</div>
<div id="text_policy_set">${_("Policy set.")}</div>
<div id="text_policy_name_not_empty">${_("Policy name is not defined!")}</div>
<div id="text_policy_deleted">${_("Policy deleted.")}</div>
<div id="text_error_fetching_list">${_("Error fetching list!")}</div>
<div id="text_created_token">${_("created token with serial")} <span class="text_param1"> </span></div>
<div id="text_losttoken_failed">${_("losttoken failed")}: <span class="text_param1"> </span></div>
<div id="text_setpin_failed">${_("set token PIN failed")}: <span class="text_param1"> </span></div>
<div id="text_fetching_tokentype_failed">${_("Error while fetching the tokentype")}: <span class="text_param1"> </span></div>
<div id="text_error_creating_token">${_("Error creating token")}: <span class="text_param1"> </span></div>
<div id="text_failed">${_("Failed")}: <span class="text_param1"> </span></div>
<div id="text_token_import_failed">${_("Failed to import token")}: <span class="text_param1"> </span></div>
<div id="text_token_import_result">${_("Token import result")}: <span class="text_param1"> </span></div>
<div id="text_policy_import_failed">${_("Failed to import policies")}: <span class="text_param1"> </span></div>
<div id="text_policy_import_result">${_("Policy import result")}: <span class="text_param1"> </span></div>
<div id="text_subscription_import_failed">${_("Failed to load support subscription")}: <span class="text_param1"> </span></div>
<div id="text_subscription_import_result">${_("Support subscription import result")}: <span class="text_param1"> </span></div>
<div id="text_error_ldap">${_("Error saving ldap configuration.")}: <span class="text_param1"> </span></div>
<div id="text_error_realm">${_("Error saving realm configuration.")}: <span class="text_param1"> </span></div>
<div id="text_realm_created">${_("Realm created")}: <span class="text_param1"> </span></div>
<div id="text_error_set_realm">${_("Error setting Token realms")}: <span class="text_param1"> </span></div>
<div id="text_error_save_file">${_("Error saving file configuration")}: <span class="text_param1"> </span></div>
<div id="text_error_save_sql">${_("Error saving sql configuration")}: <span class="text_param1"> </span></div>
<div id="text_resolver_delete_success">${_("Resolver deleted successfully")}: <span class="text_param1"> </span></div>
<div id="text_resolver_delete_fail">${_("Failed deleting resolver")}: <span class="text_param1"> </span></div>
<div id="text_realm_delete_success">${_("Realm deleted")}: <span class="text_param1"> </span></div>
<div id="text_realm_delete_fail">${_("Failed deleting Realm")}: <span class="text_param1"> </span></div>
<div id="text_regexp_error">${_("Error in regular expression for")}: <span class="text_param1"> </span></div>
<div id="text_ldap_config_success">${_("LDAP Server configuration seems to be OK! Number of users found")}: <span class="text_param1"> </span></div>
<div id="text_ldap_load_error">${_("Error loading LDAP resolver")}: <span class="text_param1"> </span></div>
<div id="text_http_config_success">${_("HTTP Server configuration seems to be OK! Number of users found")}: <span class="text_param1"> </span></div>
<div id="text_http_load_error">${_("Error loading HTTP resolver")}: <span class="text_param1"> </span></div>
<div id="text_sql_load_error">${_("Error loading SQL resolver")}: <span class="text_param1"> </span></div>
<div id="text_sql_config_success">${_("SQL config seems to be OK! Number of users found")}: <span class="text_param1"> </span></div>
<div id="text_sql_config_fail">${_("SQL config contains errors")}: <span class="text_param1"> </span></div>
<div id="text_unknown_pintype">${_("Unknown PIN type")}: <span class="text_param1"> </span></div>
<div id="text_error_saving_system_config">${_("You entered invalid data. Please check all the Tabs!")}</div>
<div id="text_catching_generic_error">${_("Error occurred during processing")}: <span class="text_param1"> </span></div>
<div id="text_no_realm">${_("You have defined UserIdResolvers. But you need to create at least one realm that contains some of your UserIdResolvers. The realm Dialog will now open to do this.")}</div>
<div id="text_already_default_realm">${_("This realm is already the default realm.")}</div>
<div id="text_form_validation_error1">${_("Incorrect or missing input at")}:<ul><span class="text_param1"> </span></ul>
    <div>${_("Please have a look at each of the forms for more details.")}</div></div>
<div id="text_form_validation_error_title">${_("Form Validation Error")}</div>
<div id="text_support_lic_error">${_("License reminder:")}</div>
<div id="text_support_lic_installed">${_("Support license installed successfully.")}</div>


<div id="description_googleurl">${_("OATH Soft Token")}</div>
<div id="annotation_googleurl">${_("QR-Code for installing the token in OATH compatible Soft Tokens (FreeOTP, Google Authenticator and other tokens using the 'otpauth:/' syntax).")}</div>

<div id="description_oathurl">${_("'OATH token' app")}</div>
<div id="annotation_oathurl">${_("QR-Code for installing the token in the 'OATH Token' app for iOS.")}</div>

<div id="description_otpkey">${_("OTP seed")}</div>
<div id="annotation_otpkey">${_("The OATH token seed for installing the token using manual input.")}</div>


</div> <!--end of hidden-->

<div id="alert_box">
    <span id="alert_box_text"> </span>
</div>

<div id="do_waiting">
    <img src="/images/ajax-loader.gif" alt="loading"><span>${_("Communicating with LinOTP server...")}</span>
</div>


</body>
</html>

