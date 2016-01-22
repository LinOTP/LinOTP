# -*- coding: utf-8 -*-    
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
<a id=policy_export>${_("Export policies")}</a>

<button id=policy_import>${_("Import policies")}</button>

<table id="policy_table" class="flexme2" style="display:none"></table>
   
<form id="policy_form" action="#" method="post">   
    <table>
    <tr>
        <td><label for=policy_active>${_("Active")}</label></td>
        <td><input type="checkbox" name="policy_active" id="policy_active" checked="checked"></td>
    </tr>
    <tr>
        <td><label for=policy_name>${_("Policy name")}</label></td>
        <td><input type="text" class="required"  id="policy_name" size="40" maxlength="80" 
            title='${_("The name of the policy")}'></td>
    </tr>
    <tr>
        <td><label for=policy_scope_combo>${_("Scope")}</label></td>
        <td>
        <select id='policy_scope_combo'>
        <option value="_">${_("- Select scope -")}</option>
        %for scope in c.polDefs.keys():
        <option value="${scope}">${scope}</option>
        %endfor
        </select>
        </td>
    </tr>
        <tr>
        <td><label for="policy_action">${_("Action")}</label></td>
        <td><input type="text" class="required"  id="policy_action" size="40" maxlength="2000" 
            title='${_("The action that should be allowed. These are actions like: enrollSMS, enrollMOTP...The actions may be comma separated.")}'></td>
    </tr>
    <tr>
        <td><label for="policy_user">${_("User")}</label></td>
        <td><input type="text"  id="policy_user" size="40" maxlength="80" 
            title='${_("The user or usergroup the policy should apply to")}'></td>
    </tr>
        <tr>
        <td><label for="policy_realm">${_("Realm")}</label></td>
        <td><input type="text" class="required"  id="policy_realm" size="40" maxlength="80" 
            title='${_("The realm the policy applies to")}'></td>
    </tr>
    <tr>
        <td><label for="policy_client">${_("Client")}</label></td>
        <td><input type="text"  id="policy_client" size="40" maxlength="120" 
            title='${_("Comma separated list of client IPs and Subnets.")}'></td>
    </tr>
    <tr>
        <td><label for=policy_time>${_("Time")}</label></td>
        <td><input type="text"  id="policy_time" size="40" maxlength="80" 
            title='${_("The time on which the policy should be applied")}'></td>
    </tr>
    <tr>
        <td></td>
        <td>
            <button id="button_policy_add">${_("Set Policy")}</button>
            <button id="button_policy_delete">${_("Delete Selected Policy")}</button>
            <button id="button_policy_clear">${_("Clear Fields")}</button>
        </td>
    </tr>
    </table>
</form>
<script type="text/javascript"> 
    view_policy();
</script>


