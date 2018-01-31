/*!
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
 */

function create_vasco_dialog() {
     var $dialog = $('#dialog_import_vasco').dialog({
        autoOpen: false,
        title: 'Vasco DPX File',
        width: 600,
        modal: true,
        buttons: {
            'Load DPX File': { click: function(){
                $('#loadtokens_session_vasco').val(getsession());
                load_tokenfile('vasco');
                $(this).dialog('close');
                },
                id: "button_vasco_load",
                text: "Load DPX File",
                icons: {
                    primary: 'ui-icon-folder-open'
                }
                },
            Cancel: {click: function(){
                $(this).dialog('close');
                },
                id: "button_vasco_cancel",
                text: "Cancel",
                icons: {
                    primary: 'ui-icon-cancel'
                }
                }
        },
        open: function(){
            _fill_realms($('#vasco_realm'),1);

            translate_import_vasco();
        }
       });
       return $dialog;
};
