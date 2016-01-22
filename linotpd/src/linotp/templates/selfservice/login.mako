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
 * contains the template login web interface
</%doc>
<html>
<head>
<title>LinOTP 2 User self service</title>
<meta name="copyright" content="LSE Leading Security Experts GmbH">
<meta name="keywords" content="LinOTP 2, self service">
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
<meta http-equiv="content-type" content="application/xhtml+xml; charset=UTF-8">
<meta http-equiv="content-style-type" content="text/css">

<meta http-equiv="X-UA-Compatible" content="IE=8,chrome=1" />

<link type="text/css" rel="stylesheet" href="/selfservice/style.css" />
<link type="text/css" rel="stylesheet" href="/selfservice/custom-style.css" />
<script type="text/javascript" src="/js/jquery-1.12.0.min.js"></script>

</head>

<body>

<script>
$(document).ready(function() {
    $('form:first *:input[type!=hidden]:first').focus();
});
</script>

<div id="wrap">

    <div id="header">
        <div class="header">
            <span class="portalname float_left">${_("Selfservice Portal")}</span>
        </div>
        <div id="logo" class="float_right"> </div>
    </div>


<div id="sidebar">

<P>
${_("This is the LinOTP self service portal. You may login here with your username and realm.")}
</P>
<P>
${_("Within the self service portal you may reset the PINs of your tokens, assign new tokens or resync your tokens.")}
</p>
${_("If you lost a token, you may also disable this token.")}

</div> <!-- sidebar -->

<div id="main">
<h1>${_("Login to LinOTP self service")}</h1>

  <p>
    <form action="/account/dologin" method="POST">
      <table>
        <tr><td><label for=login>${_("Username")}:</label></td>
        <td><input type="text" id="login" name="login" value="" /></td></tr>
        %if c.realmbox:
            <tr>
              <td>${_("Realm")}:</td>
              <td>
                <select name="realm">
                    % for realm in c.realmArray:
                    %if c.defaultRealm == realm:
                    <option value="${realm}" selected>${realm}</option>
                    %else:
                    <option value="${realm}">${realm}</option>
                    %endif
                    %endfor
                </select>
             </td>
          </tr>
        %else:
            <tr style="display:none;">
              <td>${_("Realm")}:</td>
              <td><input type="text" id="realm" name="realm"
                  value='' /></td>
            </tr>
        %endif
        <tr style="display:none;">
            <td><input type="hidden" name="realmbox" value="${c.realmbox}"/></td>
            <td><input type="hidden" name="defaultRealm" value="${c.defaultRealm}"/></td></tr>
        <tr><td><label for=password>${_("Password")}:</label></td>
        <td><input autocomplete="off" type="password" id="password" name="password" value ="" /></td></tr>
        <tr><td> </td>
        <td>   <input type="submit" value="Login" /></td></tr>
      </table>
    </form>
  </p>

<div id='errorDiv'></div>
<div id='successDiv'></div>


</div>  <!-- end of main-->

<div id="footer">
    ${c.version} --- &copy; ${c.licenseinfo}
</div>
</div>  <!-- end of wrap -->
</body>
</html>





