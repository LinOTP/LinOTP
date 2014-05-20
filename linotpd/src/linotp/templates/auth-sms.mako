# -*- coding: utf-8 -*-
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<!--
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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
-->
<html>
<head>
<title>LinOTP SMS Requester Form</title>

<%inherit file="auth-base.mako"/>

<div id="sidebar">
<p>
${_("Here you authenticate with your username and your OTP PIN to retrieve an SMS containing your current OTP value.")}
</p>
<p>
${_("Enter your username and the OTP PIN.")}
</p>
</div> <!-- sidebar -->


<div id="main">
<h1>${_("Login")}</h1>
<div id='register'>
    <p>${_("This form is deprecated since the same functionality was implemented in the regular /auth/index and /auth/index3 forms.")}</p>
    <a href="/auth/index">/auth/index</a>
</div>
<div id='errorDiv'></div>
<div id='successDiv'></div>


</div>  <!-- end of main-->
