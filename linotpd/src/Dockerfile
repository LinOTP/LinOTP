# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2016 - 2019 KeyIdentity GmbH
#
#    This file is part of LinOTP server.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
#
# LinOTP Docker build script

ARG BASE_IMAGE=debian:buster
FROM $BASE_IMAGE

ARG DEBIAN_MIRROR=deb.debian.org
ARG DEBIAN_RELEASE_NAME=buster
ARG DEPENDENCY_SOURCE
ARG DEPENDENCY_GPG_KEYID
ARG DEPENDENCY_COMPONENT
ARG DEPENDENCY_GPG_KEY_URL

# The following environment variables can be set to
# configure the runtime behaviour of the container.
# Most of these should be self explanitory.
#
# To disable HTTP authentication for the manage UI,
# set LINOTP_APACHE_AUTH=false.
#
# To use a database server:
#  LINOTP_DATABASE_URI=<sqlalchemy url>
#
# In order to wait for a database service to start,
# set LINOTP_DB_HOST and LINOTP_DB_PORT to point
# to the port that should be waited for. The default
# wait time is 30s, and can be overriden using
# LINOTP_DB_WAITTIME.
#
# Unencrypted healthchecks can be performed by
# checking http://HOSTNAME:81/validate/ok
#
# To send LinOTP logs directly to
# Logstash, set LOGSTASH_HOST and
# LOGSTASH_PORT to point to your
# Logstash collector. You can optionally
# add additional tags with the
# LOGSTASH_TAGS setting. This is a Python
# list. For example:
#   LOGSTASH_HOST=logstash1
#   LOGSTASH_PORT=5000
#   LOGSTASH_TAGS=('instance1', 'server1')
#
# To change the location of the database
# encryption key file, set
#   SECRET_FILE_LOCATION=/path/to/encKey

ENV TZ="Europe/Berlin" \
    LINOTP_USER=linotp \
    LINOTP_DATABASE_URI=sqlite:////var/lib/linotp/linotp.db \
    LINOTP_DB_HOST= \
    LINOTP_DB_PORT=3306 \
    LINOTP_DB_WAITTIME=30s \
    LINOTP_ADMIN_USER=admin \
    LINOTP_ADMIN_PASSWORD=admin \
    LINOTP_APACHE_AUTH=true \
    LINOTP_APACHE_SSL=true \
    LINOTP_APACHE_HSTS=true \
    LINOTP_LOGLEVEL=INFO \
    LINOTP_CONSOLE_LOGLEVEL=INFO \
    SQLALCHEMY_LOGLEVEL=ERROR \
    APACHE_LOGLEVEL=info \
    LOGSTASH_HOST= \
    LOGSTASH_PORT= \
    LOGSTASH_TAGS=() \
    SECRET_FILE_LOCATION=

# Internal environment variables used by the docker images
ENV LINOTP_CFG_TEMPLATE=/etc/linotp/linotp-docker.cfg.tmpl \
    LINOTP_CFG=/usr/share/linotp/linotp.cfg:/etc/linotp/linotp.cfg \
    LINOTP_HOME=/opt/linotp \
    DEBIAN_FRONTEND=noninteractive \
    FLASK_APP=linotp.app \
    FLASK_ENV=production

RUN echo 'APT::Install-Recommends "0"; \n\
            APT::Get::Assume-Yes "true"; \n\
            APT::Install-Suggests "0";' \
            > /etc/apt/apt.conf.d/01buildconfig \
    && sed -i "s#http://deb\.debian\.org/#http://${DEBIAN_MIRROR}/#" \
        /etc/apt/sources.list

# Add LinOTP packaging key to keyring in order to install
# dependencies
RUN apt-get update && apt-get install curl gnupg
RUN test -z "$DEPENDENCY_SOURCE" \
        || echo "deb $DEPENDENCY_SOURCE $DEBIAN_RELEASE_NAME $DEPENDENCY_COMPONENT" > /etc/apt/sources.list.d/kideps.list
RUN test -z "$DEPENDENCY_GPG_KEYID" \
        || apt-key adv --keyserver hkp://hkps.pool.sks-keyservers.net --recv-keys $DEPENDENCY_GPG_KEYID
RUN test -z "$DEPENDENCY_GPG_KEY_URL" \
        || curl $DEPENDENCY_GPG_KEY_URL | apt-key adv --import

# Install some dependencies which will be cached. This does not
# need to be an exhaustive list because apt will install any
# missing packages.
RUN apt-get update \
    && apt-get install \
        make \
        adduser debconf openssl pwgen python3-configobj \
        python3-beaker python3-passlib python3-cryptography python3-bcrypt python3-pygments \
        python3-decorator python3-docutils python3-formencode python3-httplib2 \
        python3-ldap python3-mako python3-mysqldb python3-netaddr \
        python3-pyrad python3-qrcode python3-routes \
        python3-sqlalchemy \
        apache2 libapache2-mod-wsgi-py3 \
        python3-pysodium python3-requests \
        python3-setuptools \
        distro-info-data \
        libjs-jquery \
        lsb-release \
        locales \
        dh-python \
        python3-flask \
        python3-psycopg2 python3-pymysql

# flask-mako is not yet packaged, so install using pip
RUN apt-get install python3-pip python3-dev python3-wheel swig gcc libssl-dev \
    && pip3 install flask-mako \
    && apt-get remove python3-dev swig gcc libssl-dev python3-wheel \
    && apt-get autoremove

# Install linotp packages from local files.
COPY apt /opt/linotp/apt

RUN echo "linotp linotp/apache/activate boolean true" > /opt/linotp/apt/debconf-selections \
    && echo "linotp linotp/apache/ssl_create boolean true" >> /opt/linotp/apt/debconf-selections \
    && debconf-set-selections /opt/linotp/apt/debconf-selections \
    && echo "deb [trusted=yes] file:/opt/linotp/apt ./" > /etc/apt/sources.list.d/linotp-local.list \
    && (echo "Package: *"; echo "Pin: origin \"\""; echo "Pin-Priority: 900") > /etc/apt/preferences.d/linotp \
    && apt-get update \
    && apt-get install linotp linotp-adminclient-cli \
    && rm /etc/apt/sources.list.d/linotp-local.list \
    && rm -r /opt/linotp/apt /etc/apache2/sites-enabled/000-default.conf \
    && rm /etc/linotp/encKey /etc/linotp/*.pem \
    && mkdir -p /etc/ssl/private /etc/ssl/certs \
    && chown linotp /var/log/linotp

WORKDIR $LINOTP_HOME

# Get dockerfy and configuration template files from build context
COPY *.tmpl /etc/linotp/
COPY dockerfy /usr/local/bin/
COPY linotp-create-htdigest /usr/local/bin/
RUN chmod 755 /usr/local/bin/linotp-create-htdigest

ENTRYPOINT [ "/usr/local/bin/dockerfy", \
    "--template", "/etc/linotp/linotp-docker.cfg.tmpl:/etc/linotp/linotp.cfg", \
    "--template", "/etc/linotp/apache-docker.conf.tmpl:/etc/apache2/sites-enabled/linotp.conf", \
    "--run", "/bin/sh", "-c", \
        "if [ -n \"{{ .Env.LINOTP_DB_HOST }}\" ]; then /usr/local/bin/dockerfy --wait tcp://{{ .Env.LINOTP_DB_HOST }}:{{ .Env.LINOTP_DB_PORT }} --timeout {{ .Env.LINOTP_DB_WAITTIME }}; fi", \
    "--", \
    "--run", "/var/lib/dpkg/info/linotp.postinst", "configure", "--", \
    "--run", "/bin/sh", "-c", \
    "openssl req -new -x509 -newkey rsa:2048 -subj /CN=`hostname`.`dnsdomainname` -days 768 -out /etc/ssl/certs/linotpserver.pem  -keyout /etc/ssl/private/linotpserver.key -nodes", \
    "--", \
    "--run", "/usr/local/bin/linotp-create-htdigest", "{{ .Env.LINOTP_ADMIN_USER }}", "{{ .Env.LINOTP_ADMIN_PASSWORD }}", "--", \
    "--run", "/bin/su", "linotp", "-s", "/bin/sh", "-w", "LINOTP_CONFIG_FILE,FLASK_APP,FLASK_ENV", "-c", "flask init-db", "--" \
]

CMD [ \
    "/usr/sbin/apache2ctl", "-DFOREGROUND" \
]

COPY ./se_mypasswd /etc/se_mypasswd

# Listen on apache port (https 443 by default - see LINOTP_APACHE_SSL and APACHE_PORT)
EXPOSE 80 81 443
