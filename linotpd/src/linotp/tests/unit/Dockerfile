FROM linotp

#
# Docker-Image >> linotp_unit_tester <<
#


#Unit test specific packages
RUN apt-get update && apt-get install --no-install-recommends --yes \
  		make \
  		python-pip \
  		python-dev \
  		python-setuptools\
  		pylint \
  		build-essential \
  		autoconf \
  		libtool \
  		pkg-config \
  		parallel \
  		mysql-client \
  		sudo \
  	    virtualenv


VOLUME /linotpsrc

WORKDIR /linotpsrc/linotpd/src/linotp/tests/unit


#Add dedicated test and NON-root user for
# a) security reasons
# b) Jenkins can't delete  files created by root

RUN useradd -ms /bin/bash tester
USER tester


#set Env Variable so pip install puts required files into venv folder
ENV PYTHONUSERBASE=/tmp/venv

RUN pip install --user --upgrade \
        coverage \
        diff-cover \
        unittest2 \
        freezegun \
        Babel \
        argparse \
        cov_core \
        mock \
        nose \
        nose-cov \
        nose-testconfig \
        pytz \
        PySocks


CMD [ "/usr/bin/make", "test" ]
