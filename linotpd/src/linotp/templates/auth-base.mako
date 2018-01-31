<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2018 KeyIdentity GmbH
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

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
	<meta name="copyright" content="KeyIdentity GmbH">
	<meta name="ROBOTS" content="NOINDEX, NOFOLLOW">
	<meta http-equiv="content-type" content="text/html; charset=UTF-8">
	<meta http-equiv="content-type" content="application/xhtml+xml; charset=UTF-8">
	<meta http-equiv="content-style-type" content="text/css">
	<meta http-equiv="expires" content="0">

	<link type="text/css" rel="stylesheet" href="/selfservice/style.css">
	<link type="text/css" rel="stylesheet" href="/selfservice/auth.css">
	<link type="text/css" rel="stylesheet" href="/selfservice/custom-style.css">

	<script type="text/javascript" src="/js/jquery-1.12.4.min.js"></script>

	<!-- jQuery UI -->
	<link type="text/css" href="/css/jquery-ui/jquery-ui.min.css" rel="stylesheet">
	<script type="text/javascript" src="/js/jquery-ui.min.js"></script>

	<!-- form validation -->
	<script type="text/javascript" src="/js/jquery.validate.min.js"></script>

	<!-- Our own functions -->
	<script type="text/javascript" src="/js/auth.js"></script>

	<%block name="title"/>
</head>
<body>

	<noscript>
		<div class="javascript_error">${_("You need to enable Javascript to use the authentication forms.")}</div>
		<style type="text/css">#wrap{display:none;}</style>
	</noscript>

	<div id="wrap">
	<div id="header">
        <span class="portalname float_left">${_("Authentication")}</span>
	    <div id="logo" class="float_right"> </div>
	</div>

	<div id="content">
		${self.body()}
	</div>

	<div id="footer">${c.version} --- &copy; ${c.licenseinfo}</div>
	</div>
</body>
</html>
