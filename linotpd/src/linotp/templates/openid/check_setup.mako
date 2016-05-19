# -*- coding: utf-8 -*-
<%inherit file="base.mako"/>
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

<p>The site <tt>${c.rely_party}</tt> has requested verification of your OpenID as <tt> ${c.identity}</tt>.
</p>
<p>
Verify your identity to the relying party?
</p>

<form action="checkid_submit" method="GET">
     <input type="hidden" name="redirect_token" value="${c.redirect_token}"></input>
     <p> <input type="checkbox" name="verify_always" value="always"> 
     Verify to this relying party always automatically. So, do not ask me again.</p>
     <button type="submit">Verify</button>
</form>
