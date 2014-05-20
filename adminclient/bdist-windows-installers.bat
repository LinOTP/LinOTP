cd src\LinOTPAdminClientCLI\
python setup.py bdist --format=wininst
copy dist\*.win32.exe ..\..\..\
cd ..\..\
cd src\LinOTPAdminClientGUI\
python setup.py bdist --format=wininst
copy dist\*.win32.exe ..\..\..\
cd ..\..\


cd src\LinOTPAdminClientGUI\
python setup.py py2exe
copy dist\*.win32.exe ..\..\..\
cd ..\..\

