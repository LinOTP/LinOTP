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

<h1>Login to LinOTP OpenID</h1>

  <p>
    <form action="/openid/check" method="GET">
      <table>
        <tr><td>Username:</td>
        %if "" != c.user:
            <td><input type="hidden" name="user" value="${c.user}" />
            ${c.p["openid.claimed_id"]}
            </td></tr>
        %else:
            <td><input type="text" name="user" value="" /></td></tr>
        %endif
        <tr><td>One Time Password:</td>
        <td><input autocomplete="off" type="password" name="pass" value ="" /></td></tr>
        <tr><td></td>
        <td>   <input type="submit" value="Login" /></td></tr>

      %for k in c.p:
      <input type="hidden" name="${k}" value="${c.p[k]}" />
      %endfor
      </table>
    </form>
  </p>

<div id='errorDiv'></div>
<div id='successDiv'></div>

