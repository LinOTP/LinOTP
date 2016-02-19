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
This is the Audit Class, that writes Audits to SQL DB

uses a public/private key for signing the log entries

    # create keypair:
    # openssl genrsa -out private.pem 2048
    # extract the public key:
    # openssl rsa -in private.pem -pubout -out public.pem

"""

import datetime
from sqlalchemy import schema, types, orm, and_, or_, asc, desc

from M2Crypto import EVP, RSA
from binascii import hexlify
from binascii import unhexlify
from sqlalchemy import create_engine
from linotp.lib.audit.base import AuditBase
from pylons import config

import logging.config


import linotp

# Create the logging object from the linotp.ini config file
ini_file = config.get("__file__")
if ini_file is not None:
    # When importing the module with Sphinx to generate documentation
    # 'ini_file' is None. In other cases this should not be the case.
    logging.config.fileConfig(ini_file, disable_existing_loggers=False)
log = logging.getLogger(__name__)

metadata = schema.MetaData()


def now():
    u_now = u"%s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    return u_now

######################## MODEL ################################################
table_prefix = config.get("linotpAudit.sql.table_prefix", "")
audit_table_name = '%saudit' % table_prefix

audit_table = schema.Table(audit_table_name, metadata,
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


AUDIT_ENCODE = ["action", "serial", "success", "user", "realm", "tokentype",
                "administrator", "action_detail", "info", "linotp_server",
                "client", "log_level"]


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

        self.serial = unicode(serial or '')
        self.action = unicode(action or '')
        self.success = unicode(success or '0')
        self.tokentype = unicode(tokentype or '')
        self.user = unicode(user or '')
        self.realm = unicode(realm or '')
        self.administrator = unicode(administrator or '')
        self.action_detail = unicode(action_detail or '')
        self.info = unicode(info or '')
        self.linotp_server = unicode(linotp_server or '')
        self.client = unicode(client or '')
        self.log_level = unicode(log_level or '')
        self.clearance_level = clearance_level
        self.timestamp = now()
        self.siganture = ' '

    def _get_field_len(self, col_name):
        leng = -1
        try:
            ll = audit_table.columns[col_name]
            ty = ll.type
            leng = ty.length
        except Exception as exx:
            leng = -1

        return leng

    def __setattr__(self, name, value):
        """
        to support unicode on all backends, we use the json encoder with
        the assci encode default

        :param name: db column name or class memeber
        :param value: the corresponding value

        :return: - nothing -
        """
        if type(value) in [str, unicode]:
            field_len = self._get_field_len(name)
            encoded_value = linotp.lib.crypt.uencode(value)
            if field_len != -1 and len(encoded_value) > field_len:
                log.warning("truncating audit data: [audit.%s] %s"
                            % (name, value))
                trunc_as_err = config.get("linotpAudit.error_on_truncation",
                                          False) or False
                if trunc_as_err != False:
                    raise Exception("truncating audit data: [audit.%s] %s"
                                    % (name, value))

                ## during the encoding the value might expand -
                ## so we take this additional length into account
                add_len = len(encoded_value) - len(value)
                value = value[:field_len - add_len]

        if name in AUDIT_ENCODE:
            ## encode data
            if value:
                value = linotp.lib.crypt.uencode(value)
        super(AuditTable, self).__setattr__(name, value)

    def __getattribute__(self, name):
        """
        to support unicode on all backends, we use the json decoder with
        the assci decode default

        :param name: db column name or class memeber

        :return: the corresponding value
        """
        #Default behaviour
        value = object.__getattribute__(self, name)
        if name in AUDIT_ENCODE:
            if value:
                value = linotp.lib.crypt.udecode(value)
            else:
                value = ""

        return value

orm.mapper(AuditTable, audit_table)


# replace sqlalchemy-migrate by the ability to ad a column
def add_column(engine, table, column):
    """
    small helper to add a column by calling a native 'ALTER TABLE' to
    replace the need for sqlalchemy-migrate

    from:
    http://stackoverflow.com/questions/7300948/add-column-to-sqlalchemy-table

    :param engine: the running sqlalchemy
    :param table: in which table should this column be added
    :param column: the sqlalchemy definition of a column

    :return: boolean of success or not
    """

    result = False

    table_name = table.description
    column_name = column.compile(dialect=engine.dialect)
    column_type = column.type.compile(engine.dialect)

    try:
        engine.execute('ALTER TABLE %s ADD COLUMN %s %s'
                                % (table_name, column_name, column_type))
        result = True

    except Exception as exx:
        # Obviously we already migrated the database.
        log.info("[__init__] Error during database migration: %r" % exx)
        result = False

    return result


###############################################################################
class Audit(AuditBase):
    """
    Audit Implementation to the generic audit interface
    """
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
            # AttributeError: 'MySQLCompiler_mysqldb' object has no
            # attribute 'returning_clause'
            # So we do not mention explicit_returning at all
            self.engine = create_engine(connect_string,
                                        pool_recycle=pool_recycle)
        else:
            self.engine = create_engine(connect_string,
                                        pool_recycle=pool_recycle,
                                        implicit_returning=False)

        metadata.bind = self.engine
        metadata.create_all()

        # Set up the session
        self.sm = orm.sessionmaker(bind=self.engine, autoflush=True,
                                   autocommit=True, expire_on_commit=True)
        self.session = orm.scoped_session(self.sm)

        # initialize signing keys
        self.readKeys()

        self.PublicKey = RSA.load_pub_key(config.get("linotpAudit.key.public"))
        self.VerifyEVP = EVP.PKey()
        self.VerifyEVP.reset_context(md='sha256')
        self.VerifyEVP.assign_rsa(self.PublicKey)

        # create the column "client"
        column = schema.Column("client", types.Unicode(80))
        add_column(self.engine, audit_table, column)

        return

    def _attr_to_dict(self, audit_line):

        line = {}
        line['number'] = audit_line.id
        line['id'] = audit_line.id
        line['date'] = str(audit_line.timestamp)
        line['timestamp'] = str(audit_line.timestamp)
        line['missing_line'] = ""
        line['serial'] = audit_line.serial
        line['action'] = audit_line.action
        line['action_detail'] = audit_line.action_detail
        line['success'] = audit_line.success
        line['token_type'] = audit_line.tokentype
        line['tokentype'] = audit_line.tokentype
        line['user'] = audit_line.user
        line['realm'] = audit_line.realm
        line['administrator'] = audit_line.administrator
        line['action_detail'] = audit_line.action_detail
        line['info'] = audit_line.info
        line['linotp_server'] = audit_line.linotp_server
        line["client"] = audit_line.client
        line['log_level'] = audit_line.log_level
        line['clearance_level'] = audit_line.clearance_level

        return line

    def _sign(self, audit_line):
        '''
        Create a signature of the audit object
        '''
        line = self._attr_to_dict(audit_line)
        s_audit = getAsString(line)
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
        res = False
        if not signature:
            log.debug("[_verify] missing signature %r" % auditline)
            return res

        s_audit = getAsString(auditline)
        log.debug("[_verify] verifying %s" % s_audit)

        self.VerifyEVP.verify_init()
        self.VerifyEVP.verify_update(s_audit)
        res = self.VerifyEVP.verify_final(unhexlify(signature))

        return res

    def log(self, param):
        '''
        This method is used to log the data. It splits information of
        multiple tokens (e.g from import) in multiple audit log entries
        '''
        log.debug("[log] writing audit log message")

        try:
            serial = param.get('serial', '') or ''
            if not serial:
                ## if no serial, do as before
                self.log_entry(param)
            else:
                ## look if we have multiple serials inside
                serials = serial.split(',')
                for serial in serials:
                    p = {}
                    p.update(param)
                    p['serial'] = serial
                    self.log_entry(p)

            #self.session.commit()
            log.debug("[log] writing log done!")

        except Exception as  exx:
            log.exception("[log] error writing log message: %r" % exx)
            self.session.rollback()
            raise exx

        finally:
            log.debug("[log] writing log done!")

        return

    def log_entry(self, param):
        '''
        This method is used to log the data.
        It should hash the data and do a hash chain and sign the data
        '''

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
        conditions = []
        boolCheck = and_
        if not AND:
            boolCheck = or_

        log.debug("[_buildCondition] building condition for params %s with %s"
                  % (param, AND))

        for k, v in param.items():
            if "" != v:
                if "serial" == k:
                    conditions.append(AuditTable.serial.like(v))
                elif "user" == k:
                    conditions.append(AuditTable.user.like(v))
                elif "realm" == k:
                    conditions.append(AuditTable.realm.like(v))
                elif "action" == k:
                    conditions.append(AuditTable.action.like(v))
                elif "action_detail" == k:
                    conditions.append(AuditTable.action_detail.like(v))
                elif "date" == k:
                    conditions.append(AuditTable.timestamp.like(v))
                elif "number" == k:
                    conditions.append(AuditTable.id.like(v))
                elif "success" == k:
                    conditions.append(AuditTable.success.like(v))
                elif "tokentype" == k:
                    conditions.append(AuditTable.tokentype.like(v))
                elif "administrator" == k:
                    conditions.append(AuditTable.administrator.like(v))
                elif "info" == k:
                    conditions.append(AuditTable.info.like(v))
                elif "linotp_server" == k:
                    conditions.append(AuditTable.linotp_server.like(v))
                elif "client" == k:
                    conditions.append(AuditTable.client.like(v))

        all_conditions = None
        if conditions:
            all_conditions = boolCheck(*conditions)

        log.debug("[_buildCondition] return %s" % all_conditions)
        return all_conditions

    def row2dict(self, audit_line):
        """
        convert an SQL audit db to a audit dict

        :param audit_line: audit db row
        :return: audit entry dict
        """

        line = self._attr_to_dict(audit_line)

        ## if we have an \uencoded data, we extract the unicode back
        for key, value in line.items():
            if value and type(value) in [str, unicode]:
                value = linotp.lib.crypt.udecode(value)
                line[key] = value
            elif value is None:
                line[key] = ''

        # Signature check
        # TODO: use instead the verify_init
        log.debug("[search] old sig = %s" % audit_line.signature)

        res = self._verify(line, audit_line.signature)
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
            a result object which has to be converted with iter() to an
            iterator
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
            page = 1
            offset = 0
            limit = 15

            if 'rp' in rp_dict:
                limit = int(rp_dict.get('rp'))

            if 'page' in rp_dict:
                page = int(rp_dict.get('page'))

            offset = limit * (page - 1)

            start = offset
            stop = offset + limit
            audit_q = audit_q.slice(start, stop)

        ## we drop here the ORM due to memory consumption
        ## and return a resultproxy for row iteration
        result = self.session.execute(audit_q.statement)
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


def getAsString(data):
    '''
    We need to distinguish, if this is an entry after the adding the
    client entry or before. Otherwise the old signatures will break!
    '''

    s = ("number=%s, date=%s, action=%s, %s, serial=%s, %s, user=%s, %s,"
         " admin=%s, %s, %s, server=%s, %s, %s") % (
                str(data.get('id')), str(data.get('timestamp')),
                data.get('action'), str(data.get('success')),
                data.get('serial'), data.get('tokentype'),
                data.get('user'), data.get('realm'),
                data.get('administrator'), data.get('action_detail'),
                data.get('info'), data.get('linotp_server'),
                data.get('log_level'), str(data.get('clearance_level')))

    if 'client' in data:
        s += ", client=%s" % data.get('client')
    return s


###eof#########################################################################
