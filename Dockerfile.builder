# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2016 KeyIdentity GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
#
# This container contains build dependencies for building linotp packages

FROM debian:jessie

RUN apt-get update && apt-get \
		--no-install-recommends --yes install \
		build-essential devscripts equivs libfile-fcntllock-perl

# Use the control files from the packages to install a list of packages needed for builds.
# We copy in just the control files at this point in order to make maximum use of
# docker's caching
RUN for D in linotp useridresolver smsprovider ;\
	  do \
	    mkdir -v -p /packaging/deps/$D/debian ;\
	done

COPY linotpd/src/debian/control packaging/deps/linotp/debian
COPY useridresolver/src/debian/control packaging/deps/useridresolver/debian
COPY smsprovider/src/debian/control packaging/deps/smsprovider/debian

RUN for D in linotp useridresolver smsprovider ;\
	  do \
		echo $D ;\
		cd /packaging/deps/$D ;\
		mk-build-deps --install --remove --tool "apt-get --yes --no-install-recommends" ;\
	done

# Finally, copy all the sources into the container
RUN mkdir -v -p /pkg/linotp
COPY . /pkg/linotp

WORKDIR /pkg/linotp
