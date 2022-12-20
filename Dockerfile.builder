# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2016 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
#
# This container contains build dependencies for building linotp packages

FROM debian:jessie

ARG DEBIAN_MIRROR=deb.debian.org

RUN sed "s#http://deb\.debian\.org/#http://${DEBIAN_MIRROR}/#" \
	< /etc/apt/sources.list > /etc/apt/sources.list.new && mv -f /etc/apt/sources.list.new /etc/apt/sources.list

RUN apt-get update && apt-get \
		--no-install-recommends --yes install \
		build-essential devscripts equivs libfile-fcntllock-perl

# Use the control files from the packages to install a list of packages needed for builds.
# We copy in just the control files at this point in order to make maximum use of
# docker's caching
COPY linotpd/src/debian/control packaging/deps/linotp/debian/

RUN for D in linotp ;\
	  do \
		echo $D ;\
		cd /packaging/deps/$D ;\
		mk-build-deps --install --remove --tool "apt-get --yes --no-install-recommends" ;\
	done

# The sources will be mounted at runtime into the volume /pkg/linotp
VOLUME /pkg/linotpsrc

WORKDIR /pkg/linotp
