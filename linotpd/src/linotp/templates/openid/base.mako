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
<html>
<head>
<title>LinOTP 2 OpenID Service</title>
<meta name="author" content="Cornelius Kölbel">
<meta name="date" content="2011-06-09T23:23:25+0200">
<meta name="copyright" content="LSE Leading Security Experts GmbH">
<meta name="keywords" content="LinOTP 2, self service">
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
<meta http-equiv="content-type" content="application/xhtml+xml; charset=UTF-8">
<meta http-equiv="content-style-type" content="text/css">

<meta http-equiv="X-UA-Compatible" content="IE=8,chrome=1" />

<link type="text/css" rel="stylesheet" href="/openid/style.css" />
<link type="text/css" rel="stylesheet" href="/openid/custom-style.css" />

</head>

<body>

<div id="wrap">

<div id="header">
    <div id="logo"></div>
    <div class="float_right">
    <span class=portalname>OpenID Service</span>
    </div>
</div>


<div id="sidebar">


%if hasattr(c,"message"):
    <p>${c.message}</p>
%endif
<P>
%if c.logged_in:
    You are logged in as: <tt>${c.login}</tt><br>
    <form action="/openid/logout" method="GET">
    % if hasattr(c,'p'):
    %for k in c.p:
      <input type="hidden" name="${k}" value="${c.p[k]}" />
    %endfor
    <p>If you log out, you have to restart your openid access request!</p>
    %endif
    <input type="submit" value="Logout" />
    </form>
%else:
    You are not logged in. You may <a href=/openid/login>login</a>
%endif
</P>


</div> <!-- sidebar -->

<div id="main">

${self.body()}


</div>  <!-- end of main-->

<div id="footer">
${c.version} --- ${c.licenseinfo}
</div>
</div>  <!-- end of wrap -->
</body>
</html>





