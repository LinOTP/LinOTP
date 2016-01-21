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
function generate_qrcode(typenumber, text) {

    var qr = new QRCode(typenumber, QRErrorCorrectLevel.H);

    qr.addData(text);

    qr.make();

    var output =  "";
    output += "<table style='border-width: 0px; border-style: none; border-color: #0000ff; border-collapse: collapse;'>";

    for (var r = 0; r < qr.getModuleCount(); r++) {

        output += "<tr>";

        for (var c = 0; c < qr.getModuleCount(); c++) {

            output += "<td style='border-width: 0px; border-style: none; border-color: #0000ff; border-collapse: collapse; padding: 0; margin: 0;";
            output += "width: 4px; height: 4px;"
            if (qr.isDark(r, c) ) {
                output += "background-color: #000000;'/>";
            } else {
                output += "background-color: #ffffff;'/>";
            }

        }

        output += "</tr>";

    }

    output += "</table>";

    return output;
}
