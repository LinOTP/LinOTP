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
<button class='ui-button' id='button_losttoken'>${_("Lost Token")}</button>
<button class='ui-button' id='button_tokeninfo'>${_("Token Info")}</button>
<button class='ui-button' id='button_resync'>${_("Resync Token")}</button>
<button class='ui-button' id='button_tokenrealm'>${_("Set Token Realm")}</button>
% if c.getotp_active:
<button class='ui-button' id='button_getmulti'>${_("Get OTP")}</button>
% endif

<table id="token_table" class="flexme2" style="display:none"></table>

<script type="text/javascript">
view_token();
tokenbuttons();
</script>


