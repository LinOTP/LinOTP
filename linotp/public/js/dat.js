/*!
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
 */
function create_dat_dialog() {
    var $dialog_load_tokens_dat = $('#dialog_import_dat').dialog({
        autoOpen: false,
        title: 'eToken dat file',
        width: 600,
        modal: true,
        buttons: {
            'load token file': {
                click: function () {
                    load_tokenfile('dat');
                    $(this).dialog('close');
                },
                id: "button_dat_load",
                text: "load token file"
            },
            Cancel: {
                click: function () {
                    $(this).dialog('close');
                },
                id: "button_dat_cancel",
                text: "Cancel"
            }
        },
        open: function () {
            _fill_realms($('#dat_realm'), 1);

            $(this).dialog_icons();
            translate_import_dat();
        }
    });
    return $dialog_load_tokens_dat;
}
