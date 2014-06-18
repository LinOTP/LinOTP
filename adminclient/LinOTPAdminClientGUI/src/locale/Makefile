translate:
	intltool-extract --type=gettext/glade ../glinotpadm.glade
	xgettext -k_ -kN_ -kC_:2 -o messages.pot ../glinotpadm.py ../glinotpadm.glade.h ../linotputilsee/etokenng.py ../linotputilsee/license.py --from-code=UTF-8
	msgmerge -U de.po messages.pot
	gtranslator de.po
	msgfmt de.po -o de/LC_MESSAGES/LinOTP2.mo
install:
	install de/LC_MESSAGES/LinOTP2.mo /usr/share/locale/de/LC_MESSAGES/
