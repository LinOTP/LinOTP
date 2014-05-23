SUB_DIRS	= LinOTPAdminClientCLI LinOTPAdminClientGUI

clean:
	rm -f linotp-adminclient-*
	rm -f LinOTPAdminClientCLI_*
	rm -f python-yubico_*
	rm -f LinOTPAdminClientCLI-*.tar.gz
	for d in $(SUB_DIRS); do (cd $$d; $(MAKE) clean ); done
	rm -rf ../build

create:
	mkdir ../build
	for d in $(SUB_DIRS); do (cd $$d; $(MAKE) create; cp dist/*.tar* ../../build/); done

builddeb: create
	for d in $(SUB_DIRS); do (cd $$d; $(MAKE) builddeb ); done

ppa-preprocess:
	for d in $(SUB_DIRS); do (cd $$d; $(MAKE) ppa-preprocess ); done


ppa-dev:
	for d in $(SUB_DIRS); do (cd $$d; $(MAKE) ppa-dev ); done

all: create builddeb ppa-preprocess
