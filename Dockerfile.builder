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
# This container contains build dependencies for building linotp packages

ARG BASE_IMAGE=debian:buster
FROM $BASE_IMAGE

ARG DEBIAN_MIRROR=deb.debian.org

RUN sed -i "s#http://deb\.debian\.org/#http://${DEBIAN_MIRROR}/#" /etc/apt/sources.list \
    && apt-get update \
    && apt-get --no-install-recommends --yes install \
        build-essential devscripts equivs libfile-fcntllock-perl rename

# Use the control files from the packages to install a list of packages needed for builds.
# We copy in just the control files at this point in order to make maximum use of
# docker's caching
COPY debian/control /deps/linotp/debian/

RUN cd /deps/linotp \
    && mk-build-deps --install --remove --tool "apt-get --yes --no-install-recommends" \
    && mkdir /build

WORKDIR /build
