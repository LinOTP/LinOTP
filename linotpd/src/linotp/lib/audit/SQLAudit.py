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
"""
This is the Audit Class, that writes Audits to SQL DB

uses a public/private key for signing the log entries

    # create keypair:
    # openssl genrsa -out private.pem 2048
    # extract the public key:
    # openssl rsa -in private.pem -pubout -out public.pem

"""

import datetime
from sqlalchemy import schema, types, orm, and_, or_, asc, desc

## TODO: the wildcard import is bad!!
from migrate import *

from M2Crypto import EVP, RSA
from binascii import hexlify
from binascii import unhexlify
from sqlalchemy import create_engine
from linotp.lib.audit.base import AuditBase
from pylons import config
import logging
import logging.config
import logging.handlers
import traceback

# Create the logging object from the linotp.ini config file
ini_file = config.get("__file__")
logging.config.fileConfig(ini_file, disable_existing_loggers=False)
log = logging.getLogger(__name__)

metadata = schema.MetaData()

def now():
    u_now = u"%s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    return u_now

table_prefix = config.get("linotpAudit.sql.table_prefix", "")

######################## MODEL ##########################################################

audit_table = schema.Table('%saudit' % table_prefix, metadata,
    schema.Column('id', types.Integer, schema.Sequence('audit_seq_id',
                                                       optional=True),
                  primary_key=True),
    schema.Column('timestamp', types.Unicode(30), default=now, index=True),
    schema.Column('signature', types.Unicode(512), default=u''),
    schema.Column('action', types.Unicode(30), index=True),
    schema.Column('success', types.Unicode(30), default=u"False"),
    schema.Column('serial', types.Unicode(30), index=True),
    schema.Column('tokentype', types.Unicode(40)),
    schema.Column('user', types.Unicode(255), index=True),
    schema.Column('realm', types.Unicode(255), index=True),
    schema.Column('administrator', types.Unicode(255)),
    schema.Column('action_detail', types.Unicode(512), default=u''),
    schema.Column('info', types.Unicode(512), default=u''),
    schema.Column('linotp_server', types.Unicode(80)),
    schema.Column('client', types.Unicode(80)),
    schema.Column('log_level', types.Unicode(20), default=u"INFO", index=True),
    schema.Column('clearance_level', types.Integer, default=0)
)

class AuditTable(object):

    def __init__(self, serial=u"", action=u"", success=u"False",
                tokentype=u"", user=u"",
                realm=u"", administrator=u"",
                action_detail=u"", info=u"",
                linotp_server=u"",
                client=u"",
                log_level=u"INFO",
                clearance_level=0):
        """
        build an audit db entry

        *parmeters require to be compliant to the table defintion, which
         implies that type unicode is recomended where appropriate

        :param serial: token serial number
        :type serial: unicode
        :param action: the scope of the audit entry, eg. admin/show
        :type action: unicode
        :param success: the result of the action
        :type success: unicode
        :param tokentype: which token type was involved
        :type tokentype: unicode
        :param user: user login
        :type user: unicode
        :param realm: the involved realm
        :type realm: unicode
        :param administrator: the admin involved
        :type administrator: unicode
        :param action_detail: the additional action details
        :type action_detail: unicode
        :param info: additional info for failures
        :type info: unicode
        :param linotp_server: the server name
        :type linotp_server: unicode
        :param client: info about the requesting client
        :type client: unicode
        :param loglevel: the loglevel of the action
        :type loglevel: unicode
        :param clearance_level: *??*
        :type clearance_level: integer

        """

        log.debug("[__init__] creating AuditTable object, action = %s"
                  % action)

        self.serial = unicode(serial)
        self.action = unicode(action)
        self.success = unicode(success)
        self.tokentype = unicode(tokentype)
        self.user = unicode(user)
        self.realm = unicode(realm)
        self.administrator = unicode(administrator)
        self.action_detail = unicode(action_detail)
        self.info = unicode(info)
        self.linotp_server = unicode(linotp_server)
        self.client = unicode(client)
        self.log_level = unicode(log_level)
        self.clearance_level = clearance_level


    def getAsString(self):
        '''
        We need to distinguish, if this is an entry after the adding the
        client entry or before. Otherwise the old signatures will break!
        '''
        s = "number=%s, date=%s, action=%s, %s, serial=%s, %s, user=%s, %s, admin=%s, %s, %s, server=%s, %s, %s" % (
                    str(self.id), str(self.timestamp), self.action, str(self.success),
                    self.serial, self.tokentype, self.user, self.realm,
                    self.administrator, self.action_detail, self.info,
                    self.linotp_server, self.log_level, str(self.clearance_level))

        if self.client:
            s += ", client=%s" % self.client
        return s



orm.mapper(AuditTable, audit_table)

########################################################################################

class Audit(AuditBase):

    def __init__(self):
        self.name = "SQlAudit"

        connect_string = config.get("linotpAudit.sql.url")
        pool_recycle = config.get("linotpAudit.sql.pool_recyle", 3600)
        implicit_returning = config.get("linotpSQL.implicit_returning", True)
        self.engine = None
        ########################## SESSION ##################################

        # Create an engine and create all the tables we need
        if implicit_returning:
            # If implicit_returning is explicitly set to True, we
            # get lots of mysql errors
            # AttributeError: 'MySQLCompiler_mysqldb' object has no attribute 'returning_clause'
            # So we do not mention explicit_returning at all
            self.engine = create_engine(connect_string, pool_recycle=pool_recycle)
        else:
            self.engine = create_engine(connect_string, pool_recycle=pool_recycle, implicit_returning=False)

        metadata.bind = self.engine
        metadata.create_all()

        # Set up the session
        self.sm = orm.sessionmaker(bind=self.engine, autoflush=True, autocommit=True,
            expire_on_commit=True)
        self.session = orm.scoped_session(self.sm)

        # initialize signing keys
        self.readKeys()

        self.PublicKey = RSA.load_pub_key(config.get("linotpAudit.key.public"))
        self.VerifyEVP = EVP.PKey()
        self.VerifyEVP.reset_context(md='sha256')
        self.VerifyEVP.assign_rsa(self.PublicKey)

        try:
            # create the column "client"
            column = schema.Column("client", types.Unicode(80))
            column.create(audit_table)
        except Exception, e:
            # Obviously we already migrated the database.
            log.info("[__init__] Error during database migration: %r" % e)


    def _sign(self, audit_line):
        s_audit = audit_line.getAsString()
        log.debug("[_sign] signing %s" % s_audit)

        key = EVP.load_key_string(self.private)
        key.reset_context(md='sha256')
        key.sign_init()
        key.sign_update(s_audit)
        signature = key.sign_final()
        log.debug("[_sign] signature : %s" % hexlify(signature))
        return hexlify(signature)

    def _verify(self, auditline, signature):
        '''
        Verify the signature of the audit line
        '''
        s_audit = auditline.getAsString()
        log.debug("[_verify] verifying %s" % s_audit)
        self.VerifyEVP.verify_init()
        self.VerifyEVP.verify_update(s_audit)
        res = self.VerifyEVP.verify_final(unhexlify(signature))
        return res


    def log(self, param):
        '''
        This method is used to log the data.
        It should hash the data and do a hash chain and sign the data
        '''
        log.debug("[log] writing audit log message")
        try:
            at = AuditTable(
                        serial=param.get('serial'),
                        action=param.get('action'),
                        success=1 if param.get('success') else 0,
                        tokentype=param.get('token_type'),
                        user=param.get('user'),
                        realm=param.get('realm'),
                        administrator=param.get('administrator'),
                        action_detail=param.get('action_detail'),
                        info=param.get('info'),
                        linotp_server=param.get('linotp_server'),
                        client=param.get('client'),
                        log_level=param.get('log_level'),
                        clearance_level=param.get('clearance_level')
            )

            self.session.add(at)
            self.session.flush()
            # At this point "at" contains the primary key id
            at.signature = self._sign(at)
            self.session.merge(at)
            self.session.flush()

            #self.session.commit()
        except Exception as  e:
            log.error("[log] error writing log message: %s" % str(e))
            log.error("[log] %s" % traceback.format_exc())
            self.session.rollback()



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


    def _buildCondition(self, param, AND):
        '''
        create the sqlalchemy condition from the params
        '''
        condition = None

        boolCheck = and_
        if not AND:
            boolCheck = or_

        log.debug("[_buildCondition] building condition for params %s with %s" % (param, AND))

        for k, v in param.items():
            if "" != v:
                if "serial" == k:
                    condition = boolCheck(condition,
                                      AuditTable.serial.like(v))
                elif "user" == k:
                    condition = boolCheck(condition,
                                      AuditTable.user.like(v))
                elif "realm" == k:
                    condition = boolCheck(condition,
                                      AuditTable.realm.like(v))
                elif "action" == k:
                    condition = boolCheck(condition,
                                      AuditTable.action.like(v))
                elif "action_detail" == k:
                    condition = boolCheck(condition,
                                      AuditTable.action_detail.like(v))
                elif "date" == k:
                    condition = boolCheck(condition,
                                      AuditTable.timestamp.like(v))
                elif "number" == k:
                    condition = boolCheck(condition,
                                      AuditTable.id.like(v))
                elif "success" == k:
                    condition = boolCheck(condition,
                                      AuditTable.success.like(v))
                elif "tokentype" == k:
                    condition = boolCheck(condition,
                                      AuditTable.tokentype.like(v))
                elif "administrator" == k:
                    condition = boolCheck(condition,
                                      AuditTable.administrator.like(v))
                elif "info" == k:
                    condition = boolCheck(condition,
                                      AuditTable.info.like(v))
                elif "linotp_server" == k:
                    condition = boolCheck(condition,
                                      AuditTable.linotp_server.like(v))
                elif "client" == k:
                    condition = boolCheck(condition,
                                      AuditTable.client.like(v))

        log.debug("[_buildCondition] return %s" % condition)
        return condition

    def row2dict(self, audit_line):
        """
        convert an SQL audit db to a audit dict

        :param audit_line: audit db row
        :return: audit entry dict
        """

        line = {}
        line['number'] = audit_line.id
        line['date'] = str(audit_line.timestamp)
        line['serial'] = audit_line.serial
        line['action'] = audit_line.action
        line['action_detail'] = audit_line.action_detail
        line['success'] = audit_line.success
        line['token_type'] = audit_line.tokentype
        line['user'] = audit_line.user
        line['realm'] = audit_line.realm
        line['administrator'] = audit_line.administrator
        line['action_detail'] = audit_line.action_detail
        line['info'] = audit_line.info
        line['linotp_server'] = audit_line.linotp_server
        line["client"] = audit_line.client
        line['log_level'] = audit_line.log_level
        line['clearance_level'] = audit_line.clearance_level

        # Signature check
        # TODO: use instead the verify_init
        log.debug("[search] old sig = %s" % audit_line.signature)
        res = self._verify(audit_line, audit_line.signature)
        if res == 1:
            line['sig_check'] = "OK"
        else:
            line['sig_check'] = "FAIL"

        return line

    def searchQuery(self, param, AND=True, display_error=True, rp_dict=None):
        '''
        This function is used to search audit events.

        param:
            Search parameters can be passed.

        return:
            An iterator is returned.
        '''

        if rp_dict is None:
            rp_dict = {}

        if 'or' in param:
            if "true" == param['or'].lower():
                AND = False

        log.debug("[search] got the params %s" % param)
        log.debug("[search] got the rp_dict %s" % rp_dict)

        # build the condition / WHERE clause
        condition = self._buildCondition(param, AND)
        log.debug("[search] the following condition was built from the "
                  "parameters %s (%s): %s" % (param, AND, condition))

        order = AuditTable.id
        if rp_dict.get("sortname"):
            sortn = rp_dict.get('sortname').lower()
            if "serial" == sortn:
                order = AuditTable.serial
            elif "number" == sortn:
                order = AuditTable.id
            elif "user" == sortn:
                order = AuditTable.user
            elif "action" == sortn:
                order = AuditTable.action
            elif "action_detail" == sortn:
                order = AuditTable.action_detail
            elif "realm" == sortn:
                order = AuditTable.realm
            elif "date" == sortn:
                order = AuditTable.timestamp
            elif "administrator" == sortn:
                order = AuditTable.administrator
            elif "success" == sortn:
                order = AuditTable.success
            elif "tokentype" == sortn:
                order = AuditTable.tokentype
            elif "info" == sortn:
                order = AuditTable.info
            elif "linotp_server" == sortn:
                order = AuditTable.linotp_server
            elif "client" == sortn:
                order = AuditTable.client
            elif "log_level" == sortn:
                order = AuditTable.log_level
            elif "clearance_level" == sortn:
                order = AuditTable.clearance_level

        # build the ordering
        order_dir = asc(order)

        if rp_dict.get("sortorder"):
            sorto = rp_dict.get('sortorder').lower()
            if "desc" == sorto:
                order_dir = desc(order)

        if type(condition).__name__ == 'NoneType':
            audit_q = self.session.query(AuditTable)\
                .order_by(order_dir)
        else:
            audit_q = self.session.query(AuditTable)\
                .filter(condition)\
                .order_by(order_dir)

        # FIXME? BUT THIS IS SO MUCH SLOWER!
        # FIXME: Here desc() ordering also does not work! :/

        if 'rp' in rp_dict or 'page' in rp_dict:
            # build the LIMIT and OFFSET
            limit = int(rp_dict.get('rp'))

            if rp_dict.get('rp'):
                limit = int(rp_dict.get('rp'))
            offset = 0
            if rp_dict.get('page'):
                page = int(rp_dict.get('page'))
                offset = limit * (page - 1)

                start = offset
                stop = offset + limit
                audit_q = audit_q.slice(start, stop)

        return iter(audit_q)

    def search(self, param, AND=True, display_error=True, rp_dict={}):
        '''
        This function is used to search audit events.

        param:
            Search parameters can be passed.

        return:
            A list of dictionaries is return.
            Each list element denotes an audit event.
        '''
        if 'or' in param:
            if "true" == param['or'].lower():
                AND = False

        result = [{}]

        log.debug("[search] got the params %s" % param)
        log.debug("[search] got the rp_dict %s" % rp_dict)

        # build the condition / WHERE clause
        condition = self._buildCondition(param, AND)
        log.debug("[search] the following condition was build from "
                  "the parameters %s (%s): %s" % (param, AND, condition))

        # build the LIMIT and OFFSET
        limit = 100
        if rp_dict.get('rp'):
            limit = int(rp_dict.get('rp'))
        offset = 0
        if rp_dict.get('page'):
            page = int(rp_dict.get('page'))
            offset = limit * (page - 1)

        order = AuditTable.id
        if rp_dict.get("sortname"):
            sortn = rp_dict.get('sortname').lower()
            if "serial" == sortn:
                order = AuditTable.serial
            elif "number" == sortn:
                order = AuditTable.id
            elif "user" == sortn:
                order = AuditTable.user
            elif "action" == sortn:
                order = AuditTable.action
            elif "action_detail" == sortn:
                order = AuditTable.action_detail
            elif "realm" == sortn:
                order = AuditTable.realm
            elif "date" == sortn:
                order = AuditTable.timestamp
            elif "administrator" == sortn:
                order = AuditTable.administrator
            elif "success" == sortn:
                order = AuditTable.success
            elif "tokentype" == sortn:
                order = AuditTable.tokentype
            elif "info" == sortn:
                order = AuditTable.info
            elif "linotp_server" == sortn:
                order = AuditTable.linotp_server
            elif "client" == sortn:
                order = AuditTable.client
            elif "log_level" == sortn:
                order = AuditTable.log_level
            elif "clearance_level" == sortn:
                order = AuditTable.clearance_level

        # build the ordering
        order_dir = asc(order)

        if rp_dict.get("sortorder"):
            sorto = rp_dict.get('sortorder').lower()
            if "desc" == sorto:
                order_dir = desc(order)

        if type(condition).__name__ == 'NoneType':
            audit_q = self.session.query(AuditTable)\
                .order_by(order_dir)
        else:
            audit_q = self.session.query(AuditTable)\
                .filter(condition)\
                .order_by(order_dir)

        # FIXME? BUT THIS IS SO MUCH SLOWER!
        # FIXME: Here desc() ordering also does not work! :/
        start = offset
        stop = offset + limit
        audit_q = audit_q.slice(start, stop)

        for audit_line in audit_q:
            line = {}
            line['number'] = audit_line.id
            line['date'] = str(audit_line.timestamp)
            line['serial'] = audit_line.serial
            line['action'] = audit_line.action
            line['action_detail'] = audit_line.action_detail
            line['success'] = audit_line.success
            line['token_type'] = audit_line.tokentype
            line['user'] = audit_line.user
            line['realm'] = audit_line.realm
            line['administrator'] = audit_line.administrator
            line['action_detail'] = audit_line.action_detail
            line['info'] = audit_line.info
            line['linotp_server'] = audit_line.linotp_server
            line['client'] = audit_line.client
            line['log_level'] = audit_line.log_level
            line['clearance_level'] = audit_line.clearance_level

            # Signature check
            # TODO: use instead the verify_init
            log.debug("[search] old sig = %s" % audit_line.signature)
            res = self._verify(audit_line, audit_line.signature)
            if res == 1:
                line['sig_check'] = "OK"
            else:
                line['sig_check'] = "FAIL"
            # TODO: missing line check


            result.append(line)

        log.debug("[search] %s" % result)
        return result

    def getTotal(self, param, AND=True, display_error=True):
        '''
        This method returns the total number of audit entries in
        the audit store
        '''
        condition = self._buildCondition(param, AND)
        log.debug("[getTotal] condition: %s" % condition)
        if type(condition).__name__ == 'NoneType':
            c = self.session.query(AuditTable).count()
        else:
            c = self.session.query(AuditTable).filter(condition).count()

        log.debug("[getTotal] count=%s " % str(c))
        return c

###eof#########################################################################
