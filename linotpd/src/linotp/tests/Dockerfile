FROM linotp

ENV LINOTP_CONFIG_FILE=

#
# Docker-Image >> linotp_test_env <<
#


#Unit test specific packages
RUN apt-get update && apt-get install --no-install-recommends --yes \
    make \
    python3-coverage \
    python3-dev \
    python3-flask-testing \
    python3-freezegun \
    python3-mock \
    python3-pytest \
    python3-pytest-flask \
    python3-wheel \
    pylint3 \
    build-essential \
    autoconf \
    libtool \
    lsb-release \
    pkg-config \
    parallel \
    mariadb-client \
    sudo \
    virtualenv


VOLUME /linotpsrc

WORKDIR /linotpsrc/linotpd/src/linotp/tests/unit

RUN useradd -ms /bin/bash tester
USER tester

#set Env Variable so pip install puts required files into venv folder
ENV PYTHONUSERBASE=/tmp/venv

RUN pip3 install --user --upgrade \
    mockldap \
    pytest-test-groups

ENTRYPOINT []

CMD [ "/usr/bin/make", "test" ]
