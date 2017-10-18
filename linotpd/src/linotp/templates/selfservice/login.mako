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
 * contains the template login web interface
</%doc>

<%!
from pylons.i18n.translation import get_lang
%>

<%
lang = get_lang() or "en"
if isinstance(lang, list):
    lang = lang[0]
%>
<html>

<head>
  <title>LinOTP 2 User self service</title>
  <meta name="copyright" content="KeyIdentity GmbH">
  <meta name="keywords" content="LinOTP 2, self service">
  <meta http-equiv="content-type" content="text/html; charset=UTF-8">
  <meta http-equiv="content-type" content="application/xhtml+xml; charset=UTF-8">
  <meta http-equiv="content-style-type" content="text/css">

  <link type="text/css" rel="stylesheet" href="/selfservice/style.css">
  <link type="text/css" rel="stylesheet" href="/selfservice/custom-style.css">
  <link type="text/css" rel="stylesheet" href="/css/jquery-ui/jquery-ui.min.css">
</head>

<body>
  <div id="wrap">

    <div id="header" class="clearfix">
        <span class="portalname float_left">${_("Selfservice Portal")}</span>
        <div id="logo" class="float_right"> </div>
    </div>

    <div id="content">
      <div id="sidebar">
        <p>${_("This is the LinOTP self service portal. You may login here with your username and realm.")}</p>
        <p>${_("Within the self service portal you may reset the PINs of your tokens, assign new tokens or resync your tokens.")}</p>
        <p>${_("If you lost a token, you may also disable this token.")}</p>
      </div> <!-- sidebar -->

      <div id="main">
        <div id="login-box">
          <h1>${_("Login to LinOTP self service")}</h1>
          <form id="loginForm" action="" method="post">
            <table>
              <tr>
                <td><label for=login>${_("Username")}:</label></td>
                <td><input type="text" id="login" name="login" value="" autofocus></td>
              </tr>
              %if c.realmbox:
              <tr>
                <td>${_("Realm")}:</td>
                <td>
                  <select name="realm">
                    %for realm in c.realmArray:
                    <option value="${realm}"
                        %if c.defaultRealm == realm:
                        selected
                        %endif
                        >
                      ${realm}
                    </option>
                    %endfor
                  </select>
                </td>
              </tr>
              %endif
              <tr>
                <td><label for=password>${_("Password")}:</label></td>
                <td><input type="password" id="password" name="password"></td>
              </tr>
              %if c.mfa_3_fields:
              <tr>
                <td><label for=otp>${_("OTP")}:</label></td>
                <td><input type="text" id="otp" name="otp" spellcheck="false" autocomplete="off"></td>
              </tr>
              %endif
              <tr>
                <td></td>
                <td><input type="submit" value="Login"></td>
              </tr>
            </table>
          </form>
        </div>  <!-- template-area-->
      </div>  <!-- main-->
    </div>
    <div id="footer">
      ${c.version} --- &copy; ${c.licenseinfo}
    </div> <!-- footer -->

  </div> <!-- wrap -->
  <div id="templates" style="display:none;">

    <div id="template-no-token-warning" class="widget">
      <h1>${_("No active token found")}</h1>
      <p>${_("If there is a problem with your current token please contact the help desk.")}</p>
      <p><a href="/selfservice/login" class="ui-button">${_("Cancel")}</a></p>
      <div class="list"></div>
    </div>

    <div id="template-tokenlist" class="widget">
      <h1>${_("Authentication")}</h1>
      <p>${_("Choose your preferred method to authenticate")}</p>
      <div class="list"></div>
    </div>

    <a id="template-tokenlist-entry" href="#" class="tokenlist-entry"><span class="action"></span><br><span class="description"></span></a>

    <a id="template-cancel-entry" href="/selfservice/login" class="tokenlist-entry cancel-auth">${_("Cancel")}</a>

    <div id="template-otp">
      <a href="/selfservice/login" class="ui-button ui-widget ui-corner-all ui-button-icon-only cancel-otp" title='${_("Cancel")}'>
        <span class="ui-icon ui-icon-closethick"></span>
        &nbsp;
      </a>
      <h1>${_("Authentication")}</h1>
      <div class="method"></div>
    </div>

    <div id="template-otp-input" class="otp-login">
      <form action="" method="post">
        <label for="otp">${_("Enter the otp value")}:</label>
        <input type="text" name="otp" spellcheck="false" autocomplete="off">
        <input type="submit" class="ui-button" value="Submit">
      </form>
    </div>

    <div id="template-otp-push" class="push">
      <p>${_("Check your mobile and confirm the login")}</p>
    </div>

    <div id="template-otp-qr" class="qr">
      <p>${_("Scan the QR code and comfirm on your mobile or submit below")}</p>
      <img class="qr" width="300"></img>
    </div>

    <div id="template-otp-polling" class="polling">
      <br>
      <p>${_("Transaction-ID")}: <b class="transactionid"></b></p>
      <p><small>${_("Compare this value to the transaction id shown on your mobile.")}</small></p>
      <br>
      <p><img src="/images/ajax-loader.gif" alt="loading">&nbsp;${_("Waiting for confirmation...")}</p>
      <br>
    </div>

    <div id="template-timeout" class="timeout">
      <p>${_("Login timed out. Please try again.")}</p>
      <a href="/selfservice/login" class="ui-button ui-widget ui-corner-all">${_("Login")}</a>
    </div>

  </div>


  <!-- load language settings -->
  <script type="text/javascript">
    window.CURRENT_LANGUAGE = "${lang}";
  </script>

  <script type="text/javascript" src="/js/jquery-1.12.4.min.js"></script>
  <script type="text/javascript" src="/js/jquery-ui.min.js"></script>
  <script type="text/javascript" src="/js/jquery.form.js"></script>
  <script type="text/javascript" src="/js/jed.js"></script>
  <script type="text/javascript" src="/js/linotp_utils.js"></script>
  <script type="text/javascript" src="/js/selfservice/login.js"></script>
</body>

</html>





