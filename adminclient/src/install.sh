INSTANCE="."
cd $INSTANCE/LinOTPAdminClientCLI
python setup.py build
sudo python setup.py install
cd -

cd $INSTANCE/LinOTPAdminClientGUI
python setup.py build
sudo python setup.py install
cd -


