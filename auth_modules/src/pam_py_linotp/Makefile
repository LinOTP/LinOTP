PYTHON=`which python`

source:
	$(PYTHON) setup.py sdist

create:
	mkdir -p ../build
	make source
	mv dist/pam_py_linotp*.tar.gz ../build/

clean:
	rm -rf dist/
	rm -rf pam_py_linotp.egg-info/
	rm -f ../build/pam_py_linotp*.tar.gz
