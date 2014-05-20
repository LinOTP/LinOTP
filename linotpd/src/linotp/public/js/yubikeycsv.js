/*!
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
 */
function create_yubikeycsv_dialog() {
 var $dialog_load_tokens_yubikeycsv = $('#dialog_import_yubikey').dialog({
        autoOpen: false,
        title: 'Yubikey csv Token file',
        width: 600,
        modal: true,
        buttons: {
            'load token file': {click: function(){
            	$('#loadtokens_session_yubikeycsv').val(getsession());
                load_tokenfile('yubikeycsv');
                $(this).dialog('close');
            	},
				id: "button_yubikeycsv_load",
				text: "load token file"
				},
            Cancel: {click: function(){
                $(this).dialog('close');
            	},
				id: "button_yubikeycsv_cancel",
				text: "Cancel"
				}
        },
        open: do_dialog_icons
    });
	return $dialog_load_tokens_yubikeycsv ;
}
