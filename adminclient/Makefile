
all:
	(cd src/LinOTPAdminClientCLI/ ; wine c:\\python26\\python setup.py bdist --format=wininst)
	cp src/LinOTPAdminClientCLI/dist/*.win32.exe ../OUTPUT
	
	(cd src/LinOTPAdminClientGUI/ ; wine c:\\python26\\python setup.py bdist --format=wininst)
	cp src/LinOTPAdminClientGUI/dist/*.win32.exe ../OUTPUT

	(cd src/python-yubico/ ; wine c:\\python26\\python setup.py bdist --format=wininst)
	cp src/python-yubico/dist/*.win32.exe ../OUTPUT


#cd src\LinOTPAdminClientGUI\
#python setup.py py2exe
#copy dist\*.win32.exe ..\..\..\
#cd ..\..\

