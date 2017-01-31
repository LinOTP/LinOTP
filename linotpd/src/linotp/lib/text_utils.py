# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
"""
 module contains some helper function around the
 text processing of unicode and utf8 strings
"""

UTF8_MAX_BYTES = 6


def simple_slice(text, chunk_size):
    """
    create slices from long text

    :param text: the input text
    :param chunk_size:

    :return: iterator which returns a slice of chunk length
    """
    if text == '':
        yield text

    for pos in xrange(0, len(text), chunk_size):
        yield text[pos:pos + chunk_size]


def utf8_slice(text, chunk_size):
    """
    create slices utf-8 test without breaking utf-8 characters

    :param text: the input text
    :param chunk_size:

    :return: iterator which returns a slice which fits
             in utf-8 buffer of chunk len
    """

    t_len = 0
    start = 0

    for pos in xrange(0, len(text)):

        ll = len(text[pos].encode('utf-8'))
        t_len = t_len + ll

        # we require a space of a least 6 bytes which is the max utf8 bytes
        if t_len + UTF8_MAX_BYTES > chunk_size:

            yield text[start:pos]

            # adjust for next round
            t_len = 0
            start = pos

    # return the rest
    yield text[start:]


