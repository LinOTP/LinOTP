# -*- coding: utf-8 -*-
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
 *    E-mail: info@linotp.de
 *    Contact: www.linotp.org
 *    Support: www.linotp.de
 *
</%doc>
<ul>
% if c.tokenArray:
% for tok in c.tokenArray:
    <li>
        <button
                data-serial="${tok['LinOtp.TokenSerialnumber']}"
                data-tokentype="${tok['LinOtp.TokenType']}"
                class="token ${'active' if tok['LinOtp.Isactive'] else 'disabled'}">
            <span class="serial">
                ${tok['LinOtp.TokenSerialnumber']}
            </span>
            <br>
            <span class="description">
                ${tok['LinOtp.TokenDesc']}
            </span>
        </button>
    </li>
% endfor
% else:
<div class="empty-token-list">You currently have no tokens enrolled</div>
% endif
</ul>
