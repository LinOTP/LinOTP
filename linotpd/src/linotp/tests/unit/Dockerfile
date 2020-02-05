FROM linotp

#
# Docker-Image >> linotp_unit_tester <<
#


#Unit test specific packages
RUN apt-get update && apt-get install --no-install-recommends --yes \
  		make \
  		python-pip \
  		python-dev \
        python-pytest \
  		pylint \
  		build-essential \
  		autoconf \
  		libtool \
		lsb-release \
  		pkg-config \
  		parallel \
  		mysql-client \
  		sudo \
  	    virtualenv


VOLUME /linotpsrc

WORKDIR /linotpsrc/linotpd/src/linotp/tests/unit

# Pytest in Jessie is too old to support recursive enumeration,
# but version >5.0.0 is not currently properly compatible with
# Python 2.7 due to type annotation syntax
RUN pip install --upgrade setuptools \
	&& pip install "pytest>3,<5.0.0"

#Add dedicated test and NON-root user for
# a) security reasons
# b) Jenkins can't delete  files created by root

RUN useradd -ms /bin/bash tester
USER tester

#set Env Variable so pip install puts required files into venv folder
ENV PYTHONUSERBASE=/tmp/venv

RUN pip install --user --upgrade \
	setuptools \
    flask_testing \
	pytest-freezegun \
	pytest-cov

CMD [ "/usr/bin/make", "test" ]
