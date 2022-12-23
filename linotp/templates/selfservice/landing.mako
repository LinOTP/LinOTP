# -*- coding: utf-8 -*-
<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010-2019 KeyIdentity GmbH
 *   Copyright (C) 2019-     netgo software GmbH
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
 *    E-mail: info@linotp.de
 *    Contact: www.linotp.org
 *    Support: www.linotp.de
 *
</%doc>
<h1 class="center-text">${_("Welcome to the LinOTP Selfservice Portal")}</h1>
<br>
<p>This portal enables you to manage your tokens according to the options available for your account.</p>
<p>Functions are available through their own separate tab.</p>
<p>When your selected action modifies an existing token, please select the intended token in the list on the left.</p>
<br>
% if c.tokenArray:

% else:
<p class="info-box">
  <span class="info-box-icon">➔</span>
  To get started, you need to enroll your first token.
</p>
% endif
