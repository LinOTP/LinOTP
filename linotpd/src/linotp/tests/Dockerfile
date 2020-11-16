FROM linotp

ENV LINOTP_CFG=

#
# Docker-Image >> linotp-testenv <<
#
# This container is based on the linotp image and includes additional
# dependencies for testing targets.
# It needs an existing linotp image available
# which can be built by make docker-build-linotp
#
# The container can be built by running the toplevel target:
#   make docker-build-testenv

#Unit test specific packages - Debian packages
RUN apt-get update && apt-get install --no-install-recommends --yes \
    make \
    python3-autopep8 \
    python3-coverage \
    python3-dev \
    python3-flask-testing \
    python3-freezegun \
    python3-mock \
    python3-psycopg2 \
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

# Install python modules which do not have equivalent Debian packages
RUN pip3 install --upgrade \
    flaky \
    mockldap \
    "pytest>=5.0" \
    "pytest-cov>=2.10" \
    pytest-freezegun \
    pytest-pudb \
    pytest-testconfig \
    pytest-test-groups \
    pytest-selenium \
    PyMySQL

USER tester

ENTRYPOINT []

CMD [ "/usr/bin/make", "test" ]
