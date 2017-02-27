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
""" contains utility functions for type checking """


import re
import json
from datetime import timedelta

duration_regex = re.compile(r'((?P<weeks>\d+?)(w|week|weeks))?'
                            '((?P<days>\d+?)(d|day|days))?'
                            '((?P<hours>\d+?)(h|hour|hours))?'
                            '((?P<minutes>\d+?)(m|minute|minutes))?'
                            '((?P<seconds>\d+?)(s|second|seconds))?$')


def parse_duration(duration_str):
    """
    transform a duration string into a time delta object

    from:
        http://stackoverflow.com/questions/35626812/how-to-parse-timedelta-from-strings

    :param duration_str:  duration string like '1h' '3h 20m 10s' '10s'
    :return: timedelta
    """

    # remove all white spaces for easier parsing
    duration_str = ''.join(duration_str.split())

    parts = duration_regex.match(duration_str.lower())
    if not parts:
        return
    parts = parts.groupdict()
    time_params = {}
    for (name, param) in parts.iteritems():
        if param:
            time_params[name] = int(param)

    return timedelta(**time_params)


def is_duration(value):

    try:

        get_duration(value)

    except ValueError:
        return False

    return True


def get_duration(value):
    """
    return duration in seconds
    """
    try:

        return(int(value))

    except ValueError:

        res = parse_duration(value)
        if res:
            return int(res.total_seconds())

    raise ValueError("not of type 'duration': %s" % value)


def is_integer(value):
    """
    type checking function for integers

    :param value: the to be checked value
    :return: return boolean
    """

    try:
        int(value)
    except ValueError:
        return False

    return True


def text(value):
    """
    type converter for text config entries

    if the value is unicode or str, leave it as is
    otherwise take the string representation
    """
    if isinstance(value, unicode) or isinstance(value, str):
        return value
    return "%r" % value


def password(value):
    """
    type converter for password config entries

    currently only a dummy, useful for extended password lookup in the config
    """

    # TODO: use the new password class

    return value


def boolean(value):
    """
        type converter for boolean config entries
    """
    true_def = ("yes", "true")
    false_def = ("no", "false")

    if value in (True, False):
        return value

    if value.lower() not in true_def and value.lower() not in false_def:
        raise Exception("unable to convert %r" % value)

    return value.lower() in true_def
