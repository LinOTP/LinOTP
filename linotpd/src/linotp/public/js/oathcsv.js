/*!
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
 */

 /* Use Jed for i18n. The correct JSON file is dynamically loaded later. */
var i18n = new Jed({});
var sprintf = Jed.sprintf;

function create_oathcsv_dialog() {
 var $dialog_load_tokens_oathcsv = $('#dialog_import_oath').dialog({
        autoOpen: false,
        title: 'OATH CSV Token File',
        width: 600,
        modal: true,
        buttons: {
            'Load Token File': {click: function(){
                $('#loadtokens_session_oathcsv').val(getsession());
                load_tokenfile('oathcsv');
                $(this).dialog('close');
                },
                id: "button_oathcsv_load",
                text: i18n.gettext("Load Token File")
                },
            Cancel: {click: function(){
                $(this).dialog('close');
                },
                id: "button_oathcsv_cancel",
                text: i18n.gettext("Cancel")
                }
        },
        open: function() {
            _fill_realms($('#oath_realm'),1);
            do_dialog_icons();
        }
    });
    return $dialog_load_tokens_oathcsv ;
}
