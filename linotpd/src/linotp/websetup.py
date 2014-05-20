# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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

""" Setup the LinOTP application -
                the websetup.py is called for the creating the initial
                data and configuration
"""



from linotp.config.environment import load_environment
import linotp.lib.base

import logging
LOG = logging.getLogger(__name__)



def setup_app(command, conf, param):
    '''
    setup_app is the hook, which is called, when the application is created

    :param command: - not used -
    :param conf: the application configuration
    :param vars: - not used -

    :return: - nothing -
    '''

    load_environment(conf.global_conf, conf.local_conf)
    unitTest = conf.has_key('unitTest')
    linotp.lib.base.setup_app(conf.local_conf, conf.global_conf, unitTest)

###eof#########################################################################

