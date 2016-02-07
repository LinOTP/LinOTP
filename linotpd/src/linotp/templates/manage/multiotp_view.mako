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
<title>${_("OTP values")}</title>

<link type="text/css" rel="stylesheet" href="/selfservice/style.css" />
<link type="text/css" rel="stylesheet" href="/selfservice/custom-style.css" />

<%
type=c.ret.get('type',"")
otps=c.ret.get('otp',{})
serial=c.ret.get('serial',"")
%>

</head>

<body>
<p>
${_("Your token")} ${serial} ${_("is of type")} ${type}.
</p> 
<table class=getotp>
%for k in sorted(otps.iterkeys()):
<tr class=getotp>
%if type.lower()=="totp":
<td class="getotp key">${otps[k]["time"]}</td>
<td class="getotp key">${otps[k]["otpval"]}</td>
%else:
<td class="getotp key">${k}</td>
<td class="getotp value">${otps[k]}</td>
%endif
</tr>
%endfor
</table>

<button onclick="window.print();">Print Page</button>
</body>
</html>
