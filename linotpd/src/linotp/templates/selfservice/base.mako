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
<title>${_("LinOTP 2 User self service")}</title>
<meta name="copyright" content="LSE Leading Security Experts GmbH">
<meta name="keywords" content="LinOTP 2, self service">
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
<meta http-equiv="content-type" content="application/xhtml+xml; charset=UTF-8">
<meta http-equiv="content-style-type" content="text/css">

<meta http-equiv="X-UA-Compatible" content="IE=8,chrome=1" />

<link type="text/css" rel="stylesheet" href="/css/linotp.css"/>
<link type="text/css" rel="stylesheet" href="/selfservice/style.css" />
<link type="text/css" rel="stylesheet" href="/selfservice/custom-style.css" />
<link type="text/css" rel="stylesheet" href="/css/flexigrid/flexigrid.css">

<link type="text/css" href="/css/jquery-ui/jquery-ui.min.css" rel="stylesheet" />


<script type="text/javascript" src="/js/jquery-1.12.0.min.js"></script>
<script type="text/javascript" src="/js/jquery-ui.min.js"></script>
<script type="text/javascript" src="/js/jquery.validate.min.js"></script>
<script type="text/javascript" src="/js/jquery.cookie.js"></script>

<script type="text/javascript" src="/js/jed.js"></script>

<script type="text/javascript" src="/js/qrcode.js"></script>
<script type="text/javascript" src="/js/qrcode-helper.js"></script>
<script type="text/javascript" src="/js/linotp_utils.js"></script>
<script type="text/javascript" src="/js/flexigrid.js"></script>

% if "enrollU2F" in c.actions:
<script type="text/javascript" src="/js/u2f-api.js"></script>
% endif

<!-- load language settings befor selfservice.js -->
<script type="text/javascript">
    window.CURRENT_LANGUAGE = "${lang}";
    window.ALL_CURRENT_LANGUAGE = "${allang}";
</script>

<script type="text/javascript" src="/js/selfservice.js"></script>


</head>
<body>

<div id="wrap">

<div id="header">
    <div class="header"> <span class="portalname float_left">${_("Selfservice Portal")}</span></div>
    <div id="logo" class="float_right"> </div>
</div>
<div class="logout">
    <p>${_("Logged in as")}:${c.user}@${c.realm} | <a href=# onclick='SelfLogout("/account/logout");return false;'>${_("Logout")}</a> </p>
</div>

<div id="do_waiting">
    <img src="/images/ajax-loader.gif" border="0" alt="" /><span>${_("Communicating with LinOTP server...")}</span>
</div>

<div id="sidebar">

    <div>${_("Tokens for user:")} ${c.user} ${_("in realm")} ${c.realm}</div>

    <div id='tokenDiv'>

    </div>

    <div id='imprint'>
    ${c.imprint|n}
    </div>

</div> <!-- sidebar -->

<div id="main">

<div id="tabs">
    <ul>
        % for entry in c.dynamic_actions:
            <li><a href='/selfservice/load_form?type=${entry}'>
                <span>${c.dynamic_actions[entry] |n}</span></a></li>
        % endfor

        % if 'activateQR' in c.actions:
            <li><a href="/selfservice/activateqrtoken"><span>${_("Activate your QR token")}</span></a></li>
        %endif
        % if 'webprovisionOCRAToken' in c.actions:
            <li><a href="/selfservice/webprovisionocratoken"><span>${_("Activate your OCRA token")}</span></a></li>
        %endif
        % if 'webprovisionOATH' in c.actions:
            <li><a href="/selfservice/webprovisionoathtoken"><span>${_("Enroll OATH token")}</span></a></li>
        %endif
        % if 'webprovisionGOOGLE' in c.actions or 'webprovisionGOOGLEtime' in c.actions:
            <li><a href="/selfservice/webprovisiongoogletoken"><span>${_("Enroll OATH soft token")}</span></a></li>
        %endif

        % if 'assign' in c.actions:
            <li><a href="/selfservice/assign"><span>${_("Assign Token")}</span></a></li>
        %endif
        %if 'disable' in c.actions:
        <li><a href="/selfservice/disable"><span>${_("Disable Token")}</span></a></li>
        %endif
        %if 'enable' in c.actions:
        <li><a href="/selfservice/enable"><span>${_("Enable Token")}</span></a></li>
        %endif
        %if 'resync' in c.actions:
        <li><a href="/selfservice/resync"><span>${_("Resync Token")}</span></a></li>
        %endif
        %if 'reset' in c.actions:
        <li><a href="/selfservice/reset"><span>${_("Reset Failcounter")}</span></a></li>
        %endif
        %if 'setOTPPIN' in c.actions:
        <li><a href="/selfservice/setpin"><span>${_("set PIN")}</span></a></li>
        %endif
        %if 'setMOTPPIN' in c.actions:
        <li><a href="/selfservice/setmpin"><span>${_("set mOTP PIN")}</span></a></li>
        %endif
        %if 'getotp' in c.actions:
        <li><a href="/selfservice/getotp"><span>${_("get OTP values")}</span></a></li>
        %endif
        %if 'unassign' in c.actions:
        <li><a href="/selfservice/unassign"><span>${_("unassign Token")}</span></a></li>
        %endif
        %if 'delete' in c.actions:
        <li><a href="/selfservice/delete"><span>${_("delete Token")}</span></a></li>
        %endif
        %if 'history' in c.actions:
        <li><a href="/selfservice/history"><span>${_("History")}</span></a></li>
        %endif
    </ul>
</div>

<div id='errorDiv'> </div>
<div id='successDiv'> </div>

</div>  <!-- end of main-->

<div id="footer">
${c.version} --- &copy; ${c.licenseinfo}
</div>


</div>  <!-- end of wrap -->
<input type='hidden' id='token_enroll_fail' value='${_("Error enrolling token:\n %s")}'/>
<input type='hidden' id='token_enroll_ok'   value='${_("Token enrolled successfully:\n %s")}'/>

<div id="alert_box">
    <span id="alert_box_text"> </span>
</div>

</body>
</html>
