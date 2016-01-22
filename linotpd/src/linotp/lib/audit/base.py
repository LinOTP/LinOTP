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
"""This is the BaseClass for logging Audit Trails"""

import logging
log = logging.getLogger(__name__)
from pylons import config
from pylons import tmpl_context as c
from pylons import request
import socket


from linotp.lib.token import getTokenNumResolver

def getAuditClass(packageName, className):
    """
        helper method to load the Audit class from a given
        package in literal:

        example:

            getAuditClass("SQLAudit", "Audit")

        check:
            checks, if the log method exists
            if not an error is thrown

"""
    log.debug("[getAuditClass] package: %s, class: %s" % (packageName, className))

    if packageName is None:
        log.error("No suitable Audit Class found. Working with dummy AuditBase class. "
                  "Probably you didn't configure 'linotpAudit' in the linotp.ini file.")
        packageName = "linotp.lib.audit.base"
        className = "AuditBase"
    elif packageName == "linotpee.lib.Audit.SQLAudit":
        log.error("The linotpee package has been removed. Please modify your linotp.ini "
                  "file: linotpAudit.type = linotp.lib.audit.SQLAudit")
        packageName = "linotp.lib.audit.SQLAudit"

    mod = __import__(packageName, globals(), locals(), [className])
    klass = getattr(mod, className)
    log.debug("[getAuditClass] klass: %s" % klass)
    if not hasattr(klass, "log"):
        raise NameError("Audit AttributeError: " + packageName + "." + \
              className + " instance has no attribute 'log'")
        return ""
    else:
        return klass


def getAudit():
    audit_type = config.get("linotpAudit.type")
    audit = getAuditClass(audit_type, "Audit")()
    return audit


def logTokenNum():
    # log the number of the tokens
    c.audit['action_detail'] = "tokennum = %s" % str(getTokenNumResolver())

class AuditBase(object):

    def __init__(self):
        self.name = "AuditBase"

    def initialize(self):
        # defaults
        c.audit = {'action_detail' : '',
                   'info' : '',
                   'log_level' : 'INFO',
                   'administrator' : '',
                   'value' : '',
                   'key' : '',
                   'serial' : '',
                   'token_type' : '',
                   'clearance_level' : 0,
                   'linotp_server' : socket.gethostname(),
                   'realm' : '',
                   'user' : '',
                   'client' : ''
                   }
        c.audit['action'] = "%s/%s" % (
                        request.environ['pylons.routes_dict']['controller'],
                        request.environ['pylons.routes_dict']['action'])
        return c.audit


    def readKeys(self):
        priv = config.get("linotpAudit.key.private")
        pub = config.get("linotpAudit.key.public")
        try:
            f = open(priv, "r")
            self.private = f.read()
            f.close()
        except Exception as e:
            log.exception("[readKeys] Error reading private key %s: (%r)" % (priv, e))

        try:
            f = open(pub, "r")
            self.public = f.read()
            f.close()
        except Exception as e:
            log.exception("[readKeys] Error reading public key %s: (%r)" % (pub, e))

        return

    def getAuditId(self):
        return self.name

    def getTotal(self, param, AND=True, display_error=True):
        '''
        This method returns the total number of audit entries in the audit store
        '''
        return 0

    def log(self, param):
        '''
        This method is used to log the data.
        It should hash the data and do a hash chain and sign the data
        '''
        pass

    def initialize_log(self, param):
        '''
        This method initialized the log state.
        The fact, that the log state was initialized, also needs to be logged.
        Therefor the same params are passed as i the log method.
        '''
        pass

    def set(self):
        '''
        This function could be used to set certain things like the signing key.
        But maybe it should only be read from linotp.ini?
        '''
        pass

    def search(self, param, AND=True, display_error=True, rp_dict=None):
        '''
        This function is used to search audit events.

        param:
            Search parameters can be passed.

        return:
            A list of dictionaries is return.
            Each list element denotes an audit event.
        '''
        result = [ {} ]
        return result

    def searchQuery(self, param, AND=True, display_error=True, rp_dict=None):
        '''
        This function is used to search audit events.

        param:
            Search parameters can be passed.

        return:
            An iterator is returned.
        '''
        return iter([])


def search(param, user=None, columns=None):

    audit = config.get('audit')
    search_dict = {}

    if param.has_key("query"):
        if "extsearch" == param['qtype']:
            # search patterns are delimitered with ;
            search_list = param['query'].split(";")
            for s in search_list:
                log.debug(s)
                key, e, value = s.partition("=")
                key = key.strip()
                value = value.strip()
                search_dict[key] = value
            log.debug(search_dict)

        else:
            search_dict[param['qtype']] = param["query"]
    else:
        for k, v in param.items():
            search_dict[k] = v

    log.debug("[search] search_dict: %s" % search_dict)

    rp_dict = {}
    page = 1
    if 'page' in param:
        rp_dict['page'] = param.get('page')
        page = param.get('page')

    if 'rp' in param:
        rp_dict['rp'] = param.get('rp')
    if 'sortname' in param:
        rp_dict['sortname'] = param.get('sortname')
    if 'sortorder' in param:
        rp_dict['sortorder'] = param.get('sortorder')
    log.debug("[search] rp_dict: %s" % rp_dict)
    if user:
        search_dict['user'] = user.login
        search_dict['realm'] = user.realm

    result = audit.searchQuery(search_dict, rp_dict=rp_dict)

    lines = []

    if not columns:
        columns = ['number', 'date', 'sig_check', 'missing_line',
               'action', 'success', 'serial', 'token_type',
               'user', 'realm', 'administrator', 'action_detail',
               'info', 'linotp_server', 'client', 'log_level',
               'clearance_level']

    # In this case we have only a limited list of columns, like in
    # the selfservice portal
    for row in result:
        a = dict(row.items())
        if 'number' not in a and 'id' in a:
            a['number'] = a['id']
        if 'date' not in a and 'timestamp' in a:
            a['date'] = a['timestamp']
        if 'token_type' not in a and 'tokentype' in a:
            a['token_type'] = a['tokentype']

        cell = []
        for colname in columns:
            if len(a['serial']) > 0:
                pass
            cell.append(a.get(colname))
        lines.append({'id': a['id'], 'cell' : cell })

    # get the complete number of audit logs
    total = audit.getTotal(search_dict)

    return lines, total, page



###eof#########################################################################
