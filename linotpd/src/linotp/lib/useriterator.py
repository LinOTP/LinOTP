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

"""
methodes to iterate through users
"""

import json
import logging


log = logging.getLogger(__name__)

def iterate_users(user_iterators):
    """
    build a userlist iterator / generator that returns the user data on demand

    :param user_iterators: list of tuple (userlist iterators, resolver descr)
    :return: generator of user data dicts (yield)
    """

    for itera in user_iterators:
        user_iterator = itera[0]
        reso = itera[1]
        log.debug("iterating: %r" % reso)

        try:
            while True:
                user_data = user_iterator.next()
                if type(user_data) in [list]:
                    for data in user_data:
                        data['resolver'] = reso
                        resp = "%s" % json.dumps(data)
                        yield resp
                else:
                    user_data['resolver'] = reso
                    resp = "%s" % json.dumps(user_data)
                    yield resp
        except StopIteration as exx:
            # pass on to next iterator
            pass
        except Exception as exx:
            log.exception("Problem during iteration of userlist iterators: %r"
                       % exx)

    raise StopIteration()
