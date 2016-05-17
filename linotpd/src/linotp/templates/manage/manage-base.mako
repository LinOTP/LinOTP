# -*- coding: utf-8 -*-
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
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

<meta name="copyright" content="LSE Leading Security Experts GmbH">
<meta name="keywords" content="LinOTP 2 manage">
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
<meta http-equiv="content-type" content="application/xhtml+xml; charset=UTF-8">
<meta http-equiv="content-style-type" content="text/css">

<meta http-equiv="X-UA-Compatible" content="IE=8,chrome=1" />

%if c.debug:
    <link type="text/css" rel="stylesheet" href="/css/jquery-ui/jquery-ui.structure.css" />
    <link type="text/css" rel="stylesheet" href="/css/jquery-ui/jquery-ui.theme.css" />
%else:
    <link type="text/css" rel="stylesheet" href="/css/jquery-ui/jquery-ui.structure.min.css" />
    <link type="text/css" rel="stylesheet" href="/css/jquery-ui/jquery-ui.theme.min.css" />
%endif
<link type="text/css" rel="stylesheet" href="/css/flexigrid/flexigrid.css">
<link type='text/css' rel='stylesheet' media='screen' href='/css/superfish.css' />
<link type="text/css" rel="stylesheet" href="/css/linotp.css"/>
<link type="text/css" rel="stylesheet" href="/manage/style.css"/>
<link type="text/css" rel="stylesheet" href="/manage/custom-style.css"/>

%if c.debug:
    <script type="text/javascript" src="/js/jquery-1.12.0.js"></script>
    <script type="text/javascript" src="/js/jquery-ui.js"></script>
    <script type="text/javascript" src="/js/jquery.validate.js"></script>
    <script type="text/javascript" src="/js/jquery.form.js"></script>
    <script type="text/javascript" src="/js/jquery.cookie.js"></script>
    <script type='text/javascript' src='/js/hoverIntent.js'></script>
    <script type='text/javascript' src='/js/superfish.js'></script>
%else:
    <script type="text/javascript" src="/js/jquery-1.12.0.min.js"></script>
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
<script type="text/javascript" src="/js/qrcode-helper.js"></script>
<script type="text/javascript" src="/js/linotp_utils.js"></script>

<script type="text/javascript" src="/js/aladdin.js"></script>
<script type="text/javascript" src="/js/oathcsv.js"></script>
<script type="text/javascript" src="/js/yubikeycsv.js"></script>
<script type="text/javascript" src="/js/feitian.js"></script>
<script type="text/javascript" src="/js/dpw.js"></script>
<script type="text/javascript" src="/js/dat.js"></script>
<script type="text/javascript" src="/js/vasco.js"></script>
<script type="text/javascript" src="/js/pskc.js"></script>
<script type="text/javascript" src="/js/tools.js"></script>

<!-- load language settings befor manage.js -->
<script type="text/javascript">
    window.CURRENT_LANGUAGE = "${lang}";
    window.ALL_CURRENT_LANGUAGE = "${allang}";
</script>

<script type="text/javascript" src="/js/manage.js"></script>

</head>
<body>

<div id="wrap">
<div id="header" class="ui-widget-header ui-corner-all">
    <ul id='menu' class='sf-menu sf-vertical'>
        <li><a href='#'>${_("LinOTP Config")}</a>
            <ul>
                <li><a href='#' id='menu_edit_resolvers'>${_("UserIdResolvers")}</a></li>
                <li><a href='#' id='menu_edit_realms'>${_("Realms")}</a></li>
                <li><a href='#' id='menu_system_config'>${_("System Config")}</a></li>
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
                <li><a href='#' id='menu_tools_migrateresolver'>${_("Migrate Resolver")}</a></li>
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
                <li><a href='${c.help_url}' target="noreferrer" id="menu_help">${_("Documentation")}</a></li>
                <li><a href='#' id='menu_view_support'>${_("Support and Subscription")}</a></li>
                <li><a href='#' id='menu_about'>${_("About LinOTP")}</a></li>
            </ul>
        </li>
    </ul>
    <div id="logo"></div>
</div> <!-- header -->
<div id="login-status" align="right" style="font-size: 70%">
    <p>${_("Logged in as")}: ${c.admin} | <a href=# onclick='Logout("${c.logout_url}");return false;' >${_("Logout")}</a>
    </p>
</div>
<div class="javascript_error" id="javascript_error">
    ${_("You need to enable Javascript to use the LinOTP Management Web UI.")}
</div>

<div id="do_waiting">
    <img src="/images/ajax-loader.gif" border="0" alt="" /><span>${_("Communicating with LinOTP server...")}</span>
</div>

<div id="left_and_right">
<div id="sidebar">
    <div class="sel_box">
        <fieldset name="${_('Selected User')}" class="ui-corner-all ui-widget-content">
        <legend id="selected_users_header" class="legend">${_("Selected User")}</legend>
        <div id="selected_users" class="sel_user_box"> </div>
        </fieldset>
        <fieldset name="${_('Selected Token')}" class="ui-corner-all ui-widget-content">
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
${c.version} --- &copy; ${c.licenseinfo}
</div>

<span id="include_footer"> </span>
</div>  <!-- end of wrap -->

<div id="all_dialogs" style="display:none; height:0px;">
<!-- ############ DIALOGS ######################### -->
<!-- ############ system settings ################# -->
<div id=dialog_system_settings>
<form class="cmxform" id="form_sysconfig">
    <div id='tab_system_settings'>
        <ul id='config_tab_index'>
            <li><a href='#tab_content_system_settings'>${_("Settings")}</a></li>
            <li><a href='#tab_content_system_defaults'>${_("Token defaults")}</a></li>
            <li><a href='#tab_content_system_gui'>${_("GUI settings")}</a></li>
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
                        <td><input type="checkbox" name="sys_prependPin" id="sys_prependPin" value="sys_prependPin" id="sys_prependPin"
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
            <fieldset id='ocra_config'>
                <legend>${_("OCRA settings")}</legend>
                <table>
                    <tr><td><label for=ocra_max_challenge>${_("Maximum concurrent OCRA challenges")}</label></td>
                        <td><input type="text" id="ocra_max_challenge" maxlength="4" class=integer
                            title='${_("This is the maximum concurrent challenges per OCRA Token.")}'/></td></tr>
                    <tr><td><label for=ocra_challenge_timeout>${_("OCRA challenge timeout")}</label></td>
                        <td><input type="text" id="ocra_challenge_timeout" maxlength="6"
                            title='${_("After this time a challenge can not be used anymore. Valid entries are like 1D, 2H or 5M where D=day, H=hour, M=minute.")}'></td></tr>
                </table>
            </fieldset>
    </div> <!-- tab with settings -->
        <div id='tab_content_system_defaults'>
            <fieldset>
                <legend>${_("Misc settings")}</legend>
                <table>
                    <tr><td><label for=sys_resetFailCounter>${_("DefaultResetFailCount")}:</label></td>
                        <td><input type="checkbox" name="sys_resetFailCounter" id="sys_resetFailCounter" value="sys_resetFailCounter"
                            title='${_("Will reset the fail counter when the user authenticated successfully")}'></td></tr>
                    <tr><td><label for=sys_maxFailCount> ${_("DefaultMaxFailCount")}: </label></td>
                        <td><input type="text" name="sys_maxFailCount" class="required"  id="sys_maxFailCount" size="4" maxlength="3"
                            title='${_("This is the maximum allowed failed logins for a new enrolled token.")}'></td></tr>
                    <tr><td><label for=sys_syncWindow> ${_("DefaultSyncWindow")}: </label></td>
                        <td><input type="text" name="sys_syncWindow" class="required"  id="sys_syncWindow" size="4" maxlength="6"
                            title='${_("A new token will have this windows to do the manual or automatic OTP sync.")}'></td></tr>
                    <tr><td><label for=sys_otpLen> ${_("DefaultOtpLen")}: </label></td>
                        <td><input type="text" name="sys_otpLen" class="required"  id="sys_otpLen" size="4" maxlength="1"
                            title='${_("A new token will be set to this OTP length.")}'></td></tr>
                    <tr><td><label for=sys_countWindow> ${_("DefaultCountWindow")}: </label></td>
                        <td><input type="text" name="sys_countWindow" class="required"  id="sys_countWindow" size="4" maxlength="3"
                            title='${_("This is the default look ahead window for counter based tokens.")}'></td></tr>
                <tr><td><label for='sys_challengeTimeout'> ${_("DefaultChallengeValidityTime")}: </label></td>
                    <td><input type="text" name="sys_challengeTimeout" class="required"  id="sys_challengeTimeout" size="4" maxlength="3"
                        title='${_("Default validity timeframe of a challenge.")}' value=120></td></tr>

                </table>
            </fieldset>
            <fieldset>
                <legend>${_("OCRA settings")}</legend>
                <table>
                    <tr><td><label for=ocra_default_suite>${_("Default OCRA suite")}</label></td>
                        <td><input type="text" name="ocra_default_suite" id="ocra_default_suite" size='30' maxlength="40"
                            title="${_('This is the suite for newly enrolled OCRA tokens. Default is OCRA-1:HOTP-SHA256-8:C-QA08')}"></td></tr>
                    <tr><td><label for=ocra_default_qr_suite>${_("Default QR suite")}</label></td>
                        <td><input type="text" name="ocra_default_qr_suite" id="ocra_default_qr_suite" maxlength=40 size=30
                            title='${_("This is the suite for newly enrolled QR tokens. Default is OCRA-1:HOTP-SHA256-6:C-QA64")}'></td></tr>
                </table>
            </fieldset>
        </div> <!-- tab with defaults -->
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
    </div> <!-- tab container system settings -->
    </form>
</div>

<script>
    function translate_system_settings() {
        $("#dialog_system_settings" ).dialog( "option", "title", '${_("System Config")}' );
        $('#button_system_save .ui-button-text').html(escape('${_("Save Config")}'));
        $('#button_system_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>

<!-- ############ system settings ################# -->
<div id='dialog_token_settings'>
    <div id='tab_token_settings'><!-- tab container token settings -->
        <ul id='token_tab_index'>
        % for entry in c.token_config_tab:
            <li> <a href="#${entry}_token_settings">${c.token_config_tab[entry] |n}</a></li>
        % endfor
        </ul> <!-- tab with token settings -->
        % for entry in c.token_config_div:
            <div id="${entry}_token_settings">
                ${c.token_config_div[entry] |n}
            </div>
        % endfor

    </div> <!-- tab container system settings -->
</div>

<script>
    function translate_token_settings() {
        $("#dialog_token_settings" ).dialog( "option", "title", '${_("Tokentype Configuration")}' );
        $('#button_token_save .ui-button-text').html(escape('${_("Save Config")}'));
        $('#button_token_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>

<!-- ################ Support Contact ################ -->
<div id='dialog_support_contact'></div>

<script>
    function translate_support_contact() {
        $("#dialog_support_view" ).dialog( "option", "title", '${_("Support Contact")}' );
        $('#button_support_contact_close .ui-button-text').html(escape('${_("Ok")}'));
    }
</script>

<!-- ################ Support view ################ -->
<div id='dialog_support_view'>
</div>

<script>
    function translate_support_view() {
        $("#dialog_support_view" ).dialog( "option", "title", '${_("LSE LinOTP Support and Subscription")}' );
        $('#button_support_set .ui-button-text').html(escape('${_("Set Support and Subscription")}'));
        $('#button_support_close .ui-button-text').html(escape('${_("Close")}'));
    }
</script>

<!-- ################# set Support Subscription ################ -->


<div id='dialog_set_support'>
    <form id="set_support_form" action="/system/setSupport" method="post"
                enctype="multipart/form-data" onsubmit="return false;">
        <p>${_("Please choose your support and subscription file")}:</p>
        <p><input name="license" id="license_file" type="file" size="30" maxlength="100000" accept="text/*">
        <input type="hidden" name="format" value="xml">
        </p>
    </form>
</div>

<script>
    function translate_support_set() {
        $("#dialog_set_support" ).dialog( "option", "title", '${_("LSE LinOTP Support and Subscription")}' );
        $('#button_support_set .ui-button-text').html(escape('${_("Set Support and Subscription")}'));
        $('#button_support_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>

<!-- ################# about LinOTP ################ -->

<div id='dialog_about' align="center">
    <p id='about_id'>${_("LinOTP - the open source solution for two factor authentication.")}</p>
    <p id='about_copyright'>${_("Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH")}</p>
    <p id='about_licens'>${_("Licensed under AGPLv3")}</p>
    <p id='about_lse_id'>${_("For more information please visit:")}</p>
    <p><a href="https://www.linotp.org/" target="noreferrer">https://www.linotp.org</a>
    <br/>${_("or")}<br/>
    <a href="https://www.lsexperts.de/" target="noreferrer">https://www.lsexperts.de</a></p>
    <p>${_("Authors:")}
        <br>Cornelius Kölbel, Kay Winkler, Omar Kohl, Friedrich Weber,
        <br>Christian Pommranz, Reinhard Stampp, Rainer Endres,
        <br>Stefan Pietsch, Eric Sesterhenn, Marian Pascalau,
        <br>Fabian Vallon, Veronika Schindler, Philipp Lay
    </p>

</div>
<script>
    function translate_about() {
        $("#dialog_about").dialog( "option", "title", '${_("About LSE LinOTP")}' );
        $('#button_about_close .ui-button-text').html(escape('${_("Close")}'));
    }
</script>


<!-- ##################### Set PIN ######################### -->
<div id='dialog_set_pin'>
    <p>${_("You may reset the PINs for the tokens")}
        <span id='dialog_set_pin_token_string'> </span>
        </p>

    <form>
        <input id='setpin_tokens' type='hidden'>
        <fieldset>
            <table>
                <tr><td>
                <label for="pintype">${_("PIN type")}</label>
                </td><td>
                <select name="pintype" id="pintype">
                <option value="motp">mOTP PIN</option>
                <option value="ocra">OCRA PIN</option>
                <option selected value="otp">OTP PIN</option>
                </select>
                </td></tr><tr><td>
                <label for="pin1">PIN</label>
                </td><td>
                <input type="password" autocomplete="off" onkeyup="checkpins('pin1','pin2');" name="pin1" id="pin1"
                    class="text ui-widget-content ui-corner-all" />
                </td></tr><tr><td>
                <label for="pin2">${_("PIN (again)")}</label>
                </td><td>
                <input type="password" autocomplete="off" onkeyup="checkpins('pin1','pin2');" name="pin2" id="pin2" class="text ui-widget-content ui-corner-all" />
                </td></tr>
            </table>
        </fieldset>
    </form>
</div>

<script>
    function translate_set_pin() {
        $("#dialog_set_pin" ).dialog( "option", "title", '${_("Set PIN")}' );
        $('#button_setpin_setpin .ui-button-text').html(escape('${_("Set PIN")}'));
        $('#button_setpin_cancel .ui-button-text').html(escape('${_("Cancel")}'));
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
        <blockquote>
        <input type='checkbox' id='enroll_info_text_nouser_cb' checked="checked"  style="display:none;"
            onclick="cb_changed('enroll_info_text_nouser_cb',['enroll_info_text_nouser_cb_more'])">
        <label id='enroll_info_text_nouser_cb_more' class='italic_label' style="display:none;">${_("If you select one user, this token will be "+
                "automatically assigned to this user. Anyhow, you can assign this token to any user later on.")}</label>
        </blockquote>
    </div>
    <div id='enroll_info_text_multiuser'>
        <p>${_("You selected more than one user. If you want to assign the token to a user during enrollment, "+
                "you need to select only one user.  Anyhow, you can assign this token to any user later on.")}
        </p>
    </div>
    <script type="text/javascript">tokentype_changed();</script>
    <form id="form_enroll_token">
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

            <div id="token_enroll_ocra">
                <hr>
                <p><span id='ocra_key_intro'>
                    ${_("Please enter or copy the OCRA key.")}</span></p>
                <table><tr>
                <td><label for="ocra_key" id='ocra_key_label'>${_("OCRA key")}</label></td>
                <td><input type="text" name="ocra_key" id="ocra_key" value="" class="text ui-widget-content ui-corner-all" /></td>
                </tr>
                <tr><td> </td><td><input type='checkbox' id='ocra_key_cb' onclick="cb_changed('ocra_key_cb',['ocra_key','ocra_key_label','ocra_key_intro']);">
                    <label for=ocra_key_cb>${_("Generate OCRA key.")}</label></td></tr>
                <tr name="set_pin_rows" class="space" title='${_("Protect your token with a static PIN")}'><th colspan="2">${_("Token PIN:")}</th></tr>
                <tr name="set_pin_rows" >
                    <td class="description"><label for="ocra_pin1" id="ocra_pin1_label">${_("enter PIN")}:</label></td>
                    <td><input type="password" autocomplete="off" onkeyup="checkpins('ocra_pin1','ocra_pin2');" name="pin1" id="ocra_pin1"
                            class="text ui-widget-content ui-corner-all" /></td>
                </tr>
                <tr name="set_pin_rows" >
                    <td class="description"><label for="ocra_pin2" id="ocra_pin2_label">${_("confirm PIN")}:</label></td>
                    <td><input type="password" autocomplete="off" onkeyup="checkpins('ocra_pin1','ocra_pin2');" name="pin2" id="ocra_pin2"
                            class="text ui-widget-content ui-corner-all" /></td
                </tr>
                </table>
            </div>

            %for tok in c.token_enroll_div:
             <div id="token_enroll_${tok}">${c.token_enroll_div[tok] |n}</div>
            %endfor

        </fieldset>
    </form>
</div>

<script>
    function translate_token_enroll() {
        $("#dialog_token_enroll" ).dialog( "option", "title", '${_("Enroll Token")}' );
        $('#button_enroll_enroll .ui-button-text').html(escape('${_("Enroll")}'));
        $('#button_enroll_cancel .ui-button-text').html(escape('${_("Cancel")}'));
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

<script>
    function translate_get_serial() {
        $("#dialog_get_serial" ).dialog( "option", "title", '${_("Get Serial by OTP value")}' );
        $('#button_tools_getserial_ok .ui-button-text').html(escape('${_("Get Serial")}'));
        $('#button_tools_getserial_close .ui-button-text').html(escape('${_("Close")}'));
    }
</script>


<!------------------------ check policy ------------------------->
<div id="dialog_check_policy">
    <p>${_("Here you can check your policies.")}</p>
    <p>${_("You can enter the corresponding values and the system will check, if there is any matching policy for this scenario.")}</p>
    <form class="cmxform" id="form_check_policy">
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

<script>
    function translate_check_policy() {
        $("#dialog_check_policy" ).dialog( "option", "title", '${_("Check Policy")}' );
        $('#button_tools_checkpolicy_ok .ui-button-text').html(escape('${_("Check Policy")}'));
        $('#button_tools_checkpolicy_close .ui-button-text').html(escape('${_("Close")}'));
    }
</script>

<!------------------------ export token ------------------------------->

<div id="dialog_export_token">
    <p>${_("Here you can export token information of the tokens you are allowed to view to a CSV file.")}</p>
    <p>${_("You can enter additional attributes, you defined in the user mapping in the UserIdResolver. These attributes will be added to the CSV file.")}</p>
    <form class="cmxform" id="form_export_token">
        <input id="exporttoken_attributes">
    </form>
</div>

<script>
    function translate_export_token() {
        $("#dialog_export_token" ).dialog( "option", "title", '${_("Export Token Info")}' );
        $('#button_export_token .ui-button-text').html(escape('${_("Export")}'));
    }
</script>

<!------------------------ export audit ------------------------------->

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

<script>
    function translate_export_audit() {
        $("#dialog_export_audit" ).dialog( "option", "title", '${_("Export Audit Trail")}' );
        $('#button_export_audit .ui-button-text').html(escape('${_("Export")}'));
    }
</script>


<!-- ###################### copy token ####################### -->
<div id='dialog_copy_token'>
    <p>${_("Here you can copy the OTP PIN from one token to the other.")}</p>
    <p>${_("Please enter the serial number of the token with the existing PIN and the serial number of the token, that should get the same PIN.")}</p>
    <p><label for=copy_from_token>${_("From token")}</label> <input id='copy_from_token'></p>
    <p><label for=copy_to_token>${_("To token")}</label> <input id='copy_to_token'></p>
</div>

<script>
    function translate_copy_token() {
        $("#dialog_copy_token").dialog( "option", "title", '${_("Copy Token PIN")}' );
        $('#button_tools_copytokenpin_ok .ui-button-text').html(escape('${_("Copy PIN")}'));
        $('#button_tools_copytokenpin_close .ui-button-text').html(escape('${_("Close")}'));
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

<script>
    function translate_migrateresolver() {
        $("#dialog_migrate_resolver" ).dialog( "option", "title", '${_("Migrate Resolver")}' );
        $('#button_tools_migrateresolver_ok .ui-button-text').html(escape('${_("Migrate tokens")}'));
        $('#button_tools_migrateresolver_close .ui-button-text').html(escape('${_("Close")}'));
    }
</script>



<!-- ############# import Safenet ######################### -->
<div id='dialog_import_safenet'>
    <form id="load_tokenfile_form_aladdin" action="/admin/loadtokens" method="post"
                enctype="multipart/form-data" onsubmit="return false;">
        <p>${_("Here you can upload the XML file that came with your SafeNet eToken PASS.")}</p>
        <p>${_("Please choose the token file")}:<br>
        <input name="file" type="file" size="30" maxlength="1000000" accept="text/*">
        <p>
            <label for=aladdin_hashlib>${_("Hash algorithm")}:</label>
             <select id='aladdin_hashlib' name=aladdin_hashlib >
                <option value="auto">${_("automatic detection")}</option>
                <option value="sha1">sha1</option>
                <option value="sha256">sha256</option>
            </select>
        </p>
        <p>
        <input name="type" type="hidden" value="aladdin-xml">
        <input name="session" id="loadtokens_session_aladdin" type="hidden" value="">
        <div id="safenet_realms" name="targetrealm">
          <label for="safenet_realm">${_("Target realm")}:</label>
          <select id="safenet_realm" name="realm"> </select>
        </div>

        </p>
    </form>
</div>

<script>
    function translate_import_safenet() {
        $("#dialog_import_safenet" ).dialog( "option", "title", '${_("Aladdin XML Token File")}' );
        $('#button_aladdin_load .ui-button-text').html(escape('${_("Load Token File")}'));
        $('#button_aladdin_cancel .ui-button-text').html(escape('${_("Cancel")}'));
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
            <p>${_("Please choose the token file")}:<br>
            <input name="file" type="file" size="30" maxlength="1000000" accept="text/*">
            <input name="type" type="hidden" value="pskc">
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
            <input name="session" id="loadtokens_session_pskc" type="hidden" value="">
            <div id="pskc_realms" name="targetrealm">
              <label for="pskc_realm">${_("Target realm")}:</label>
              <select id="pskc_realm" name="realm"> </select>
            </div>

        </p>

    </form>
</div>

<script>
    function translate_import_pskc() {
        $("#dialog_import_pskc" ).dialog( "option", "title", '${_("PSKC Key File")}' );
        $('#button_pskc_load .ui-button-text').html(escape('${_("Load Token File")}'));
        $('#button_pskc_cancel .ui-button-text').html(escape('${_("Cancel")}'));
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
            <input name="file" type="file" size="30" maxlength="1000000" accept="text/*">
            <input name="type" type="hidden" value="oathcsv">\
            <input name="session" id="loadtokens_session_oathcsv" type="hidden" value="">\
        </p>
            <div id="oath_realms" name="targetrealm">
              <label for="oath_realm">${_("Target realm")}:</label>
              <select id="oath_realm" name="realm"> </select>
            </div>

    </form>
</div>

<script>
    function translate_import_oath() {
        $("#dialog_import_oath" ).dialog( "option", "title", '${_("OATH CSV Token File")}' );
        $('#button_oathcsv_load .ui-button-text').html(escape('${_("Load Token File")}'));
        $('#button_oathcsv_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>

<!-- ###################### import YubiKey CSV ####################### -->
<div id='dialog_import_yubikey'>
    <form id="load_tokenfile_form_yubikeycsv" action="/admin/loadtokens" method="post"
             enctype="multipart/form-data" onsubmit="return false;">
        <p>${_("Here you can upload a CSV file for your YubiKey token. The file is supposed to contain one token per line")}:</p>
        <p>${_("Please choose the token file")}:
             <input name="file" type="file" size="30" maxlength="1000000" accept="text/*">
             <input name="type" type="hidden" value="yubikeycsv">\
             <input name="session" id="loadtokens_session_yubikeycsv" type="hidden" value="">
        </p>
        <p>
            <div id="yubi_realms" name="targetrealm">
              <label for="yubi_realm">${_("Target realm")}:</label>
              <select id="yubi_realm" name="realm"> </select>
            </div>
        </p>
    </form>
</div>

<script>
    function translate_import_yubikey() {
        $("#dialog_import_yubikey" ).dialog( "option", "title", '${_("YubiKey CSV Token File")}' );
        $('#button_yubikeycsv_load .ui-button-text').html(escape('${_("Load Token File")}'));
        $('#button_yubikeycsv_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>

<!-- ##################### import Tagespasswort ######################## -->
<div id='dialog_import_dpw'>
    <form id="load_tokenfile_form_dpw" action="/admin/loadtokens" method="post"
            enctype="multipart/form-data" onsubmit="return false;">
        <p>${_("Here you can upload the data file that came with your Tagespasswort tokens.")}</p>
        <p>${_("Please choose the token file")}:
            <input name="file" type="file" size="30" maxlength="1000000" accept="text/*">
            <input name="type" type="hidden" value="dpw">
            <input name="session" id="loadtokens_session_dpw" type="hidden" value="">
            <div id="dpw_realms" name="targetrealm">
              <label for="dpw_realm">${_("Target realm")}:</label>
              <select id="dpw_realm" name="realm"> </select>
            </div>

        </p>
    </form>
</div>

<script>
    function translate_import_dpw() {
        $("#dialog_import_dpw" ).dialog( "option", "title", '${_("Tagespasswort Token File")}' );
        $('#button_dpw_load .ui-button-text').html(escape('${_("Load Token File")}'));
        $('#button_dpw_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>

<!-- ##################### import eToken DAT file ######################## -->
<div id='dialog_import_dat'>
    <form id="load_tokenfile_form_dat" action="/admin/loadtokens" method="post"
            enctype="multipart/form-data" onsubmit="return false;">
        <label for="upload_etoken_dat"> ${_("Upload the eToken data file:")}</label>
            <input id='upload_etoken_dat' name="file" type="file"
                    size="30" maxlength="1000000" accept="text/* data/*">
        </p>
        <p>
            <label for='startdate'>Timebased eToken can use a different start date:</label>
            <input id='startdate' name="startdate" type="datetime" value="1.1.2000 00:00:00"/>
        </p>
        <input name="type" type="hidden" value="dat">
        <input name="session" id="loadtokens_session_dat" type="hidden" value="">
        <div id="dat_realms" name="targetrealm">
          <label for="dat_realm">${_("Target realm")}:</label>
          <select id="dat_realm" name="realm"> </select>
        </div>

    </form>
</div>

<script>
    function translate_import_dat() {
        $("#dialog_import_dat" ).dialog( "option", "title", '${_("eToken DAT File")}' );
        $('#button_dat_load .ui-button-text').html(escape('${_("Load Token File")}'));
        $('#button_dat_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>

<!-- ######################## import Feitian ############################# -->

<div id='dialog_import_feitian'>
    <form id="load_tokenfile_form_feitian" action="/admin/loadtokens" method="post"\
                enctype="multipart/form-data" onsubmit="return false;">
                <p>${_("Here you can upload the XML file that came with your Feitian tokens.")}</p>
                <p>${_("Please choose the token file")}:<br>
                <input name="file" type="file" size="30" maxlength="1000000" accept="text/*">
                <input name="type" type="hidden" value="feitian">
                <input name="session" id="loadtokens_session_feit" type="hidden" value="">
                <div id="feitian_realms" name="targetrealm">
                  <label for="feitian_realm">${_("Target realm")}:</label>
                  <select id="feitian_realm" name="realm"> </select>
                </div>
                </p></form>
</div>
<script>
    function translate_import_feitian() {
        $("#dialog_import_feitian" ).dialog( "option", "title", '${_("Feitian XML Token file")}' );
        $('#button_feitian_load .ui-button-text').html(escape('${_("Load Token File")}'));
        $('#button_feitian_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>

<!-- ################ import VASCO ################################## -->
<div id='dialog_import_vasco'>
    <form id="load_tokenfile_form_vasco" action="/admin/loadtokens" method="post"\
                enctype="multipart/form-data" onsubmit="return false;">
                <p>${_("Here you can upload your Vasco DPX file.")}</p>
                <p>${_("Please choose the token file")}:<br>
                <input name="file" type="file" size="30" maxlength="1000000" accept="text/*"></p>
                <input name="type" type="hidden" value="vasco">
                <p><label for=vasco_otplen>${_("OTP length")}:</label>
                     <select name='vasco_otplen' id='vasco_otplen'><option selected>6</option>
                <option>8</option></select>
                <input name="session" id="loadtokens_session_vasco" type="hidden" value="">
                </p>
                <div id="vasco_realms" name="targetrealm">
                <label for="vasco_realm">${_("Target realm")}:</label>
                <select id="vasco_realm" name="realm"> </select>
                </div>
            </form>

</div>
<script>
    function translate_import_vasco() {
        $("#dialog_import_vasco" ).dialog( "option", "title", '${_("Vasco DPX File")}' );
        $('#button_vasco_load .ui-button-text').html(escape('${_("Load Token File")}'));
        $('#button_vasco_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>

<!-- ################### dialog import policies ################# -->
<div id='dialog_import_policy'>
    <form id="load_policies" action="/system/importPolicy" method="post"\
                enctype="multipart/form-data" onsubmit="return false;">
                <p>${_("Here you can import your policy file.")}</p>
                <p>${_("Please choose the policy file")}:<br>
                <input name="file" type="file" size="30" maxlength="1000000" accept="text/*"></p>
                <input name="type" type="hidden" value="policy">
                </form>
</div>
<script>
    function translate_import_policy() {
        $("#dialog_import_policies" ).dialog( "option", "title", '${_("Import policies")}' );
        $('#button_policy_load .ui-button-text').html(escape('${_("Import policy file")}'));
        $('#button_policy_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>



<!-- ##################### realms ##################################### -->
<div id='dialog_realms'>
    <p>${_("Create a new realm or select one available realm")}:</p>
    <div id='realm_list'> </div>
</div>
<script>
    function translate_dialog_realms() {
        $("#dialog_realms" ).dialog( "option", "title", '${_("Realms")}' );
        $('#button_realms_new .ui-button-text').html(escape('${_("New")}'));
        $('#button_realms_edit .ui-button-text').html(escape('${_("Edit")}'));
        $('#button_realms_delete .ui-button-text').html(escape('${_("Delete")}'));
        $('#button_realms_close .ui-button-text').html(escape('${_("Close")}'));
        $('#button_realms_setdefault .ui-button-text').html(escape('${_("Set Default")}'));
        $('#button_realms_cleardefault .ui-button-text').html(escape('${_("Clear Default")}'));
    }
</script>
<!-- ######################### resolvers ############################## -->
<div id='dialog_resolvers'>
    <p>${_("Create a new or select one available UserIdResolver")}:</p>
    <div id='resolvers_list'> </div>
</div>
<script>
    function translate_dialog_resolvers() {
        $("#dialog_resolvers" ).dialog( "option", "title", '${_("Resolver")}');
        $('#button_resolver_new .ui-button-text').html(escape('${_("New")}'));
        $('#button_resolver_edit .ui-button-text').html(escape('${_("Edit")}'));
        $('#button_resolver_delete .ui-button-text').html(escape('${_("Delete")}'));
        $('#button_resolver_close .ui-button-text').html(escape('${_("Close")}'));
    }
</script>

<!-- ###################### create resolver ########################### -->
<div id='dialog_resolver_create'>
    ${_("Which type of resolver do you want to create?")}
</div>
<script>
    function translate_dialog_resolver_create() {
        $("#dialog_resolver_create" ).dialog( "option", "title", '${_("Creating a new UserIdResolver")}' );
        $('#button_new_resolver_type_ldap .ui-button-text').html(escape('${_("LDAP")}'));
        $('#button_new_resolver_type_sql .ui-button-text').html(escape('${_("SQL")}'));
        $('#button_new_resolver_type_flatfile .ui-button-text').html(escape('${_("Flatfile")}'));
        $('#button_new_resolver_type_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>

<!-- ################### edit realm ####################################### -->
<div id='dialog_edit_realms'>
    <!--${_("Here you can add or remove existing resolvers to the realm")}:-->
    <form class="cmxform" id="form_realmconfig">
        <div id='realm_intro_new'>
            <p>${_("You are creating a new realm.")}
            ${_("You may add resolvers by holding down Ctrl-Key and left-clicking.")}</p>\
            <p><label for=realm_name>${_("Realm name")}:</label>
                <input type='text' class="required" id='realm_name' size='20' maxlength='60' value="" />
                </p>
        </div>
        <div id='realm_intro_edit'>
            <p>${_("Here you may define the resolvers belonging to the realm")}:</p>
                <p><b><span id='realm_edit_realm_name'> </span></b></p>
                <p>${_("You may add resolvers by holding down Ctrl-Key and left-clicking.")}</p>
                <input type='hidden' id='realm_name' size='20' maxlength='60'/>
        </div>

        <div id='realm_edit_resolver_list'> </div>
    </form>
</div>
<script>
    function translate_dialog_realm_edit() {
        $("#dialog_edit_realms" ).dialog( "option", "title", '${_("Edit Realm")}' );
        $('#button_editrealms_cancel .ui-button-text').html(escape('${_("Cancel")}'));
        $('#button_editrealms_save .ui-button-text').html(escape('${_("Save")}'));
    }
</script>

<!-- ################# delete token ######################### -->
<div id='dialog_delete_token'>
    <p>${_("The following tokens will be permanently deleted and can not be recovered.")}
    </p>
    <span id='delete_info'>	</span>
</div>
<script>
    function translate_dialog_delete_token() {
        $("#dialog_delete_token" ).dialog( "option", "title", '${_("Delete selected tokens?")}' );
        $('#button_delete_delete .ui-button-text').html(escape('${_("Delete tokens")}'));
        $('#button_delete_cancel .ui-button-text').html(escape('${_("Cancel")}'));
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
<script>
    function translate_dialog_show_enroll_url() {
        $("#dialog_show_enroll_url" ).dialog( "option", "title", '${_("token enrollment")}' );
        $('#button_show_enroll_ok .ui-button-text').html(escape('${_("OK")}'));
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
<script>
    function translate_dialog_show_enroll_url() {
        $("#dialog_show_enroll_url" ).dialog( "option", "title", '${_("token enrollment")}' );
        $('#button_show_enroll_ok .ui-button-text').html(escape('${_("OK")}'));
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
<script>
    function translate_dialog_lost_token() {
        $("#dialog_lost_token" ).dialog( "option", "title", '${_("Lost Token")}' );
        $('#button_losttoken_ok .ui-button-text').html(escape('${_("Get Temporary Token")}'));
        $('#button_losttoken_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>

<!-- ##################### dialog token info######################### -->
<div id='dialog_token_info'>
</div>
<script>
    function translate_dialog_token_info() {
        $("#dialog_token_info" ).dialog( "option", "title", '${_("Token Info")}' );
        $('#button_ti_hashlib .ui-button-text').html(escape('${_("Hashlib")}'));
        $('#button_ti_close .ui-button-text').html(escape('${_("Close")}'));
        $('#button_ti_otplength .ui-button-text').html(escape('${_("OTP Length")}'));
        $('#button_ti_counterwindow .ui-button-text').html(escape('${_("Counter Window")}'));
        $('#button_ti_failcount .ui-button-text').html(escape('${_("Max Fail Counter")}'));
        $('#button_ti_countauthmax .ui-button-text').html(escape('${_("Max Auth Count")}'));
        $('#button_ti_countauthsuccessmax .ui-button-text').html(escape('${_("Max Successful Auth Count")}'));
        $('#button_ti_validityPeriodStart .ui-button-text').html(escape('${_("Validity start")}'));
        $('#button_ti_validityPeriodEnd .ui-button-text').html(escape('${_("Validity end")}'));
        $('#button_ti_syncwindow .ui-button-text').html(escape('${_("Sync Window")}'));
        $('#button_ti_timewindow .ui-button-text').html(escape('${_("Time Window")}'));
        $('#button_ti_timeshift .ui-button-text').html(escape('${_("Time Shift")}'));
        $('#button_ti_timestep .ui-button-text').html(escape('${_("Time Step")}'));
    }
</script>

<!-- ############### dialog token info details ######################### -->
<div id='dialog_tokeninfo_set'>

</div>
<script>
    function translate_dialog_ti_hashlib() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Hashlib")}');
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_otplength() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set OTP length")}');
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_counterwindow() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Counter Window")}' );
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_maxfailcount() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Max Failcount")}' );
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_countauthmax() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Max Auth Count")}' );
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_countauthsuccessmax() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Max Successful Auth Count")}' );
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_validityPeriodStart() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("Validity start")}' );
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_validityPeriodEnd() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("Validity end")}' );
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_countauthmax() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Max Auth Count")}' );
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_countauthsuccessmax() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Max Successful Auth Count")}' );
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_validityPeriodStart() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("Validity start")}' );
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_validityPeriodEnd() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("Validity end")}' );
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_phone() {
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("Mobile phone number")}' );
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_syncwindow(){
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Sync Window")}' );
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_timewindow(){
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Time Window")}' );
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_timeshift(){
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Time Shift")}' );
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_timestep(){
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Time Step")}');
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
    function translate_dialog_ti_description(){
        $("#dialog_tokeninfo_set" ).dialog( "option", "title", '${_("set Description")}');
        $('#button_tokeninfo_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_tokeninfo_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>



<!-- ##################### resync token ############################# -->
<div id='dialog_resync_token'>
    <p>${_("You may resync the token:")} <span id='tokenid_resync'> </span>.</p>
    <p>${_("Therefor please enter two OTP values.")}</p>
    <form><fieldset><table>
            <tr><td>
            <label for="otp1">OTP 1</label>
            </td><td>
            <input type="text" name="otp1" id="otp1" class="text ui-widget-content ui-corner-all" />
            </td></tr><tr><td>
            <label for="otp2">OTP 2</label>
            </td><td>
            <input type="text" name="otp2" id="otp2" class="text ui-widget-content ui-corner-all" />
            </td></tr></table>
            </fieldset>
        </form>
</div>

<script>
    function translate_dialog_resync_token() {
        $("#dialog_resync_token" ).dialog( "option", "title", '${_("Resync Token")}' );
        $('#button_resync_resync .ui-button-text').html(escape('${_("Resync")}'));
        $('#button_resync_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>

<!-- ######################## dialog edit token realm ############# -->
<div id='dialog_edit_tokenrealm'>
    <form class="cmxform" id="form_tokenrealm">
    <p>${_("Define to which realms the token(s) shall belong to:")}*</p>
    <p><span id='tokenid_realm'> </span></p>
    <input type='hidden' id='realm_name' size='20' maxlength='60'>
    <div id='token_realm_list'> </div>
    <i>*${_("You may add realms by holding down Ctrl-Key and left-clicking.")}</i>
    </form>
</div>
<script>
    function translate_dialog_token_realm() {
        $("#dialog_edit_tokenrealm" ).dialog( "option", "title", '${_("Edit Realms of Token")}' );
        $('#button_tokenrealm_save .ui-button-text').html(escape('${_("Set Realm")}'));
        $('#button_tokenrealm_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>

<!-- ############### get list of OTP valus ############################ -->
<div id='dialog_getmulti'>
    <p>${_("You may get OTP values for token:")} <span id='tokenid_getmulti'> </span></p>
    <p><label for=otp_values_count>${_("Enter the number, how many OTP values you want to retrieve:")}</label></p>
    <input id='otp_values_count' maxlength='6' class='required'></input>
</div>

<script>
    function translate_dialog_getmulti() {
        $("#dialog_getmulti" ).dialog( "option", "title", '${_("Get OTP values")}' );
        $('#button_getmulti_ok .ui-button-text').html(escape('${_("OK")}'));
        $('#button_getmulti_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>

<!-- ########### unassign token############################# -->
<div id='dialog_unassign_token'>
    <p>${_("The following Tokens will be unassigned from the their users:")}
        <span id='tokenid_unassign'> </span></p>
    <p>${_("The users will not be able to authenticate with this token anymore. Are you sure?")}
    </p>
</div>
<script>
    function translate_dialog_unassign() {
        $("#dialog_unassign_token" ).dialog( "option", "title", '${_("Unassign selected tokens?")}' );
        $('#button_unassign_unassign .ui-button-text').html(escape('${_("Unassign")}'));
        $('#button_unassign_cancel .ui-button-text').html(escape('${_("Cancel")}'));
    }
</script>
<!-- #################### realm ask delete ###################### -->
<div id='dialog_realm_ask_delete'>
    ${_("Do you want to delete the realm")} <b><span id='realm_delete_name'> </span></b>?
</div>
<script>
    function translate_dialog_realm_ask_delete() {
        $("#dialog_realm_ask_delete" ).dialog( "option", "title", '${_("Deleting realm")}' );
        $('#button_realm_ask_delete_delete .ui-button-text').html(escape('${_("Delete")}'));
        $('#button_realm_ask_delete_cancel .ui-button-text').html(escape('${_("Cancel")}'));
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
<script>
    function translate_dialog_resolver_ask_delete() {
        $("#dialog_resolver_ask_delete" ).dialog( "option", "title", '${_("Deleting resolver")}' );
        $('#button_resolver_ask_delete_delete .ui-button-text').html(escape('${_("Delete")}'));
        $('#button_resolver_ask_delete_cancel .ui-button-text').html(escape('${_("Cancel")}'));
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
<script>
    function translate_dialog_view_temptoken() {
        $("#dialog_view_temporary_token" ).dialog( "option", "title", '${_("New Temporary Token")}' );
        $('#button_view_temporary_token_close .ui-button-text').html(escape('${_("Close")}'));
    }
</script>

<!-- ################## dialog LDAP resolver ######################### -->

<div id='dialog_ldap_resolver'>
    <form class="cmxform" id="form_ldapconfig">
        <fieldset name="Server config">
            <legend class='resolver_dialog_label'>${_("Server Configuration")}</legend>
            <table>
            <tr><td><label for=ldap_resolvername>${_("Resolver name")}:</label></td>
                <td><input type="text" name="ldap_resolvername" class="required"  id="ldap_resolvername" size="35" maxlength="20"></td></tr>
            <tr><td><label for=ldap_uri>${_("Server-URI")}:</label></td>
                <td><input type="text" name="ldap_uri" class="required"  id="ldap_uri" size="35" maxlength="200"
                    onkeyup="ldap_resolver_ldaps();"></td></tr>
            <tr id="ldap_resolver_certificate"><td>
                <label for="ldap_certificate">${_("CA Certificate")}:</label></td>
                <td><textarea name="ldap_certificate" id="ldap_certificate" cols="34" rows="5"
                    title='${_("If you are using LDAPS you can enter the CA certificate in PEM format here.")}'> </textarea></td>
                </tr>
            <tr><td><label for=ldap_basedn>${_("BaseDN")}:</label></td>
                <td><input type="text" name="ldap_basedn" class="required"  id="ldap_basedn" size="35" maxlength="200"></td></tr>
            <tr><td><label for=ldap_binddn>${_("BindDN")}:</label></td>
                <td><input type="text" name="ldap_binddn" id="ldap_binddn" size="35" maxlength="200"></td></tr>
            <tr><td><label for=ldap_password>${_("Bind Password")}</label>:</td>
                <td><input type="password" autocomplete="off" name="ldap_password" id="ldap_password" size="35" maxlength="60"></td></tr>
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

        <fieldset name='${_("LDAP attributes")}'>
            <legend class='resolver_dialog_label'>${_("Mapping Attributes")}</legend>
            <table>
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
            </tr></table>
        </fieldset>
    </form>
</div>
<script>
    function translate_dialog_ldap_resolver() {
        $("#dialog_ldap_resolver" ).dialog( "option", "title", '${_("LDAP Resolver")}' );
        $('#button_test_ldap .ui-button-text').html(escape('${_("Test LDAP connection")}'));
        $('#button_preset_ad .ui-button-text').html(escape('${_("Preset AD")}'));
        $('#button_preset_ldap .ui-button-text').html(escape('${_("Preset LDAP")}'));
    }
</script>

<!-- #################### dialog SQL resolver #################################### -->

<div id='dialog_sql_resolver'>
<form class="cmxform" id="form_sqlconfig">
  <fieldset name='${_("Server config")}'>
    <legend class='resolver_dialog_label'>${_("Server Configuration")}</legend>
    <table>
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
        <tr><td><label for=sql_password>${_("Password")}:</label></td>
            <td><input type="password" autocomplete="off" name="sql_password"  id="sql_password" size="30" maxlength="60"></td></tr>
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

    <fieldset name='${_("SQL attributes")}'>
      <legend class='resolver_dialog_label'>${_("Mapping Attributes")}</legend>
        <table>
        <tr><td><label for=sql_mapping>${_("Attribute mapping")}:</label></td>
            <td><input type="text" name="sql_mapping" class="required"  id="sql_mapping" size="35" maxlength="200"></td></tr>
        <tr><td><label for=sql_where>${_("Where statement")}:</label></td>
            <td><input type="text" name="sql_where" class="optional"  id="sql_where" size="35" maxlength="200"></td></tr>
        </table>
    </fieldset></form>
</div>
<script>
    function translate_dialog_sql_resolver() {
        $("#dialog_sql_resolver" ).dialog( "option", "title", '${_("SQL Resolver")}' );
        $('#button_test_sql .ui-button-text').html(escape('${_("Test SQL connection")}'));
    }
</script>

<!-- ################ dialog file resolver #################### -->


<div id="dialog_file_resolver">
<form class="cmxform" id="form_fileconfig"><fieldset name='${_("File configuration")}'><table>
        <tr><td><label for=file_resolvername>${_("Resolver name")}:</label></td>
            <td><input type="text" name="file_resolvername" class="required"  id="file_resolvername" size="35" maxlength="20"></td></tr>
        <tr><td><label for=file_filename>${_("filename")}:</label></td>
            <td><input type="text" name="file_filename" class="required"  id="file_filename" size="35" maxlength="200"></td></tr>
        </table></fieldset></form>
</div>
<script>
    function translate_dialog_sql_resolver() {
        $("#dialog_file_resolver" ).dialog( "option", "title", '${_("File Resolver")}' );
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

</body>
</html>

