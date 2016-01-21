# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
""" logic for the selfservice processing """


from pylons import config

import logging
log = logging.getLogger(__name__)

def get_imprint(realm):
    '''
    This function returns the imprint for a certai realm.
    This is just the contents of the file <realm>.imprint in the directory
    <imprint_directory>
    '''
    res = ""
    realm = realm.lower()
    directory = config.get("linotp.imprint_directory", "/etc/linotp2/imprint")
    filename = "%s/%s.imprint" % (directory, realm)
    try:
        pass
        f = open(filename)
        res = f.read()
        f.close()
    except Exception as e:
        log.info("[get_imprint] can not read imprint file: %s. (%r)"
                 % (filename, e))

    return res
