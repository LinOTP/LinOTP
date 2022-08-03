# -*- coding: utf-8 -*-
#
# LinOTP - the Open Source solution for multi-factor authentication
#
# Coypright © 2020- arxes-tolina GmbH
#
# LinOTP packaging tests docker image script

ARG BASE_IMAGE=debian:buster
FROM $BASE_IMAGE

ARG DEBIAN_MIRROR=deb.debian.org

ENV TZ="Europe/Berlin" \
    PYTESTARGS=

RUN echo 'APT::Install-Recommends "0"; \n\
            APT::Get::Assume-Yes "true"; \n\
            APT::Install-Suggests "0";' \
            > /etc/apt/apt.conf.d/01buildconfig \
    && sed -i "s#http://deb\.debian\.org/#http://${DEBIAN_MIRROR}/#" \
        /etc/apt/sources.list \
    # Use eatmydata to speed up apt-get and pip operations \
    && echo "deb [trusted=yes] http://debs-devel.corp.linotp.de/linotp3 buster linotp" > /etc/apt/sources.list.d/linotp-org.list \
    && apt-get update \
    && apt-get install eatmydata \
    && for F in apt-get apache2 mariadb-server; do ln -s /usr/bin/eatmydata /usr/local/bin/$F; done

# Install services that should be available on the machine before upgades are attempted
RUN apt-get install \
        apache2 \
        dbconfig-common \
        mariadb-server \
        postgresql \
        python3-pycryptodome \
        python3-flask \
        python3-flask-babel \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        wget \
    && a2enmod -q auth_digest \
    && a2dismod -q unique_id \
    && a2dismod -q autoindex -f \
    && a2dismod -q cgid \
    && a2dismod -q deflate -f \
    && a2dismod -q status \
    && a2dismod -q negotiation -f \
    && a2dismod -q dir -f \
    && a2dismod -q auth_basic -f \
    && a2disconf -q serve-cgi-bin \
    # Enable restart of services during apt operations \
    && echo 'exit 0' > /usr/sbin/policy-rc.d

RUN pip3 install --upgrade \
    "pytest>=5.0" \
    pytest-pudb \
    pytest-testconfig \
    pytest-test-groups \
    pytest-selenium \
    PyMySQL

COPY run.sh /usr/local/bin

WORKDIR /linotpsrc/linotp/tests/packaging

ENTRYPOINT [ "/usr/local/bin/run.sh" ]

CMD ["pytest -v"]

