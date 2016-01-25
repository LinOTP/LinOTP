#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP admin clients.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

translate:
	intltool-extract --type=gettext/glade ../glinotpadm.glade
	xgettext -k_ -kN_ -kC_:2 -o messages.pot ../bin/glinotpadm.py ../glinotpadm.glade.h ../linotpadminclientgui/etokenng.py ../linotpadminclientgui/license.py --from-code=UTF-8
	msgmerge -U de.po messages.pot
	gtranslator de.po
	msgfmt de.po -o de/LC_MESSAGES/LinOTP2.mo
install:
	install de/LC_MESSAGES/LinOTP2.mo /usr/share/locale/de/LC_MESSAGES/
