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
</%doc>

<html>
<head>
<title>${_("Token Self Service - LinOTP")}</title>
<meta name="copyright" content="arxes-tolina GmbH">
<meta name="keywords" content="LinOTP 2, self service">
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
<meta http-equiv="content-type" content="application/xhtml+xml; charset=UTF-8">
<meta http-equiv="content-style-type" content="text/css">

<link rel="icon" type="image/x-icon" href="/static/favicon.ico">

<link type="text/css" rel="stylesheet" href="/static/css/linotp.css">
<link type="text/css" rel="stylesheet" href="/static/selfservice/style.css">
<link type="text/css" rel="stylesheet" href="/custom/selfservice-style.css">
<link type="text/css" rel="stylesheet" href="/static/css/flexigrid/flexigrid.css">

<link type="text/css" href="/static/css/jquery-ui/jquery-ui.min.css" rel="stylesheet">

<script type="text/javascript" src="/static/js/jquery-3.4.1.min.js"></script>
<script type="text/javascript" src="/static/js/jquery-migrate-3.1.0.min.js"></script>
<script type="text/javascript" src="/static/js/jquery-ui.min.js"></script>
<script type="text/javascript" src="/static/js/jquery.validate.min.js"></script>
<script type="text/javascript" src="/static/js/jquery.cookie.js"></script>

<script type="text/javascript" src="/static/js/jed.js"></script>

<script type="text/javascript" src="/static/js/linotp_utils.js"></script>
<script type="text/javascript" src="/static/js/flexigrid.js"></script>

% if "enrollU2F" in c.actions:
<script type="text/javascript" src="/static/js/u2f-api.js"></script>
% endif

<!-- load language settings befor selfservice.js -->
<script type="text/javascript">
    window.CURRENT_LANGUAGE = "${lang}";
</script>

<script type="text/javascript" src="/static/js/selfservice.js"></script>


</head>
<body>

<div id="wrap">

<div id="header" class="clearfix">
    <span class="portalname float_left">${_("Selfservice Portal")}</span>
    <div id="logo" class="float_right"> </div>
</div>
<div id="content">
<div id="sidebar">

    <div>${_("Tokens for user:")} ${c.user} ${_("in realm")} ${c.realm}</div>

    <div id='tokenDiv'>

    </div>

    <div id='imprint'>
    ${c.imprint|n}
    </div>

</div> <!-- sidebar -->

<div id="main">

<div class="logout">
    <p>${_("Logged in as")}: ${c.user}@${c.realm} | <a href=# onclick='SelfLogout("logout");return false;'>${_("Logout")}</a> </p>
</div>

<div id="do_waiting">
    <img src="/static/images/ajax-loader.gif" border="0" alt=""><span>${_("Communicating with LinOTP server...")}</span>
</div>

<div id="tabs">
    <ul>
        % if 'show_landing_page' in c.actions:
        <li><a href="landing"><span class="ui-icon ui-icon-home" title='${_("Selfservice Home")}'></span></a></li>
        % endif

        % for entry in c.dynamic_actions:
            <li><a href='load_form?type=${entry}'>
                <span>${c.dynamic_actions[entry] |n}</span></a></li>
        % endfor

        % if 'webprovisionOATH' in c.actions:
            <li><a href="webprovisionoathtoken"><span>${_("Enroll OATH token")}</span></a></li>
        %endif
        % if 'webprovisionGOOGLE' in c.actions or 'webprovisionGOOGLEtime' in c.actions:
            <li><a href="webprovisiongoogletoken"><span>${_("Enroll OATH soft token")}</span></a></li>
        %endif

        % if 'assign' in c.actions:
            <li><a href="assign"><span>${_("Assign Token")}</span></a></li>
        %endif
        %if 'disable' in c.actions:
        <li><a href="disable"><span>${_("Disable Token")}</span></a></li>
        %endif
        %if 'enable' in c.actions:
        <li><a href="enable"><span>${_("Enable Token")}</span></a></li>
        %endif
        %if 'resync' in c.actions:
        <li><a href="resync"><span>${_("Resync Token")}</span></a></li>
        %endif
        %if 'reset' in c.actions:
        <li><a href="reset"><span>${_("Reset Failcounter")}</span></a></li>
        %endif
        %if 'setOTPPIN' in c.actions:
        <li><a href="setpin"><span>${_("set PIN")}</span></a></li>
        %endif
        %if 'setMOTPPIN' in c.actions:
        <li><a href="setmpin"><span>${_("set mOTP PIN")}</span></a></li>
        %endif
        %if 'getotp' in c.actions:
        <li><a href="getotp"><span>${_("get OTP values")}</span></a></li>
        %endif
        %if 'unassign' in c.actions:
        <li><a href="unassign"><span>${_("unassign Token")}</span></a></li>
        %endif
        %if 'delete' in c.actions:
        <li><a href="delete"><span>${_("delete Token")}</span></a></li>
        %endif
        %if 'history' in c.actions:
        <li><a href="history"><span>${_("History")}</span></a></li>
        %endif
    </ul>
</div>

<div id='errorDiv'> </div>
<div id='successDiv'> </div>

</div>  <!-- end of main-->
</div>  <!-- end of content-->
<div id="footer">
${c.version} – ${c.licenseinfo}
</div>


</div>  <!-- end of wrap -->
<input type='hidden' id='token_enroll_fail' value='${_("Error enrolling token:\n %s")}'>
<input type='hidden' id='token_enroll_ok'   value='${_("Token enrolled successfully:\n %s")}'>

<div id="alert_box">
    <span id="alert_box_text"> </span>
</div>

</body>
</html>
