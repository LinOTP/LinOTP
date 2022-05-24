# -*- coding: utf-8 -*-
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2019 KeyIdentity GmbH
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

<html>

<head>

  <title>${_("Management Login - LinOTP")}</title>
  <meta name="copyright" content="netgo GmbH">
  <meta name="keywords" content="LinOTP, manage, Manage-UI, login">
  <meta http-equiv="content-type" content="text/html; charset=UTF-8">
  <meta http-equiv="content-type" content="application/xhtml+xml; charset=UTF-8">
  <meta http-equiv="content-style-type" content="text/css">

  <link rel="icon" type="image/x-icon" href="/static/favicon.ico">
  
  %if c.debug:
    <link type="text/css" rel="stylesheet" href="/static/css/jquery-ui/jquery-ui.structure.css">
    <link type="text/css" rel="stylesheet" href="/static/css/jquery-ui/jquery-ui.theme.css">
  %else:
    <link type="text/css" rel="stylesheet" href="/static/css/jquery-ui/jquery-ui.structure.min.css">
    <link type="text/css" rel="stylesheet" href="/static/css/jquery-ui/jquery-ui.theme.min.css">
  %endif

  <link type="text/css" rel="stylesheet" href="/static/css/linotp.css?ref=${c.version_ref}">
  <link type="text/css" rel="stylesheet" href="/static/manage/style.css?ref=${c.version_ref}">
  <link type="text/css" rel="stylesheet" href="/static/manage/login.css?ref=${c.version_ref}">
  <link type="text/css" rel="stylesheet" href="/custom/manage-style.css?ref=${c.version_ref}">

</head>

<body>

  <div id="wrap">
    <div id="main">
      <div id="login-box">
        <h1>${_("Login to LinOTP Manage-UI")}</h1>
        <form id="loginForm" action="" method="post">
          <table>
            <tr>
              <td><label for=username>${_("Username")}:</label></td>
              <td><input type="text" id="username" name="username" value="" autofocus></td>
            </tr>
            <tr>
              <td><label for=password>${_("Password")}:</label></td>
              <td><input type="password" id="password" name="password"></td>
            </tr>
            <tr>
              <td></td>
              <td><input type="submit" value="Login"></td>
            </tr>
          </table>
        </form>
      </div>
    </div>
    <div id="footer">
      ${c.version} – ${c.licenseinfo}
    </div>
  </div>

  <!-- load language settings -->
  <script type="text/javascript">
    window.CURRENT_LANGUAGE = "${lang}";
  </script>

  %if c.debug:
    <script type="text/javascript" src="/static/js/jquery-3.6.0.js"></script>
    <script>jQuery.migrateMute = true;</script>
    <script type="text/javascript" src="/static/js/jquery-migrate-3.3.2.js"></script>
    <script type="text/javascript" src="/static/js/jquery.form.js?ref=${c.version_ref}"></script>
    <script type="text/javascript" src="/static/js/jquery-ui.js"></script>
  %else:
    <script type="text/javascript" src="/static/js/jquery-3.6.0.min.js"></script>
    <script type="text/javascript" src="/static/js/jquery-migrate-3.3.2.min.js"></script>
    <script type="text/javascript" src="/static/js/jquery.form.min.js?ref=${c.version_ref}"></script>
    <script type="text/javascript" src="/static/js/jquery-ui.min.js"></script>
  %endif
  <script type="text/javascript" src="/static/js/jed.js?ref=${c.version_ref}"></script>

  <script type="text/javascript" src="/static/js/linotp_utils.js?ref=${c.version_ref}"></script>
  <script type="text/javascript" src="/static/js/manage/login.js?ref=${c.version_ref}"></script>

</body>

</html>
