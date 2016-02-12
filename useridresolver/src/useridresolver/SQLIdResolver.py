# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP userid resolvers.
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
This module implements the communication and data mapping to SQL servers.
The LinOTP server imports this module to use SQL databases as a userstore.

Dependencies: UserIdResolver
"""

#from sqlalchemy.event import listen

from sqlalchemy import create_engine
from sqlalchemy import types
from sqlalchemy.sql import expression
from sqlalchemy import Table, MetaData
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import NoSuchColumnError

from useridresolver.UserIdResolver import (UserIdResolver,
                                           ResolverLoadConfigError
                                           )

import re
import base64
import hashlib

import urllib


import crypt
try:
    import bcrypt
    _bcrypt_hashpw = bcrypt.hashpw
except ImportError:
    _bcrypt_hashpw = None

try:
    import json
except:
    import simplejson as json

import traceback
import logging
log = logging.getLogger(__name__)

DEFAULT_ENCODING = "utf-8"


def check_php_password(password, stored_hash):
    """
    from phppass: check certain kinds of phppassowrds

    :param password: the new, to be verified password
    :param stored_hash: the previously used password in a hashed form
    :return: boolean
    """
    result = False 

    if stored_hash.startswith('$2a$'):
        # bcrypt
        if _bcrypt_hashpw is None:
            raise NotImplementedError('The bcrypt module is required')
        hashed_password = _bcrypt_hashpw(password, stored_hash)
        result = hashed_password == stored_hash
    elif stored_hash.startswith('_'):
        # ext-des
        hashed_password = crypt.crypt(password, stored_hash)
        result = hashed_password == stored_hash
    else:
        log.info("Hashed password type not recognised!")

    return result


def testconnection(params):
    """
    This is used to test if the given parameter set will do a successful
    SQL connection and return the number of found users
    params are:

    - Driver
    - Server
    - Port
    - Database
    - User
    - Password
    - Table
    """
    log.debug('[testconnection] %s' % str(params))

    num = -1
    err_str = ""
    dbObj = dbObject()

    try:
        connect_str = make_connect(params.get("Driver"),
                                   params.get("User"),
                                   params.get("Password"),
                                   params.get("Server"),
                                   params.get("Port"),
                                   params.get("Database"),
                                   conParams=params.get('ConnectionParams', "")
                                   )

        log.debug("[testconnection] testing connection with connect str: %r"
                                                                % connect_str)
        dbObj.connect(connect_str)
        table = dbObj.getTable(params.get("Table"))
        num = dbObj.count(table, params.get("Where", ""))

    except Exception as e:
        log.exception('[testconnection] Exception: %r' % e)
        err_str = "%r" % e
    finally:
        dbObj.close()
        log.debug('[testconnection] done')

    return (num, err_str)


def make_connect(driver, user, pass_, server, port, db, conParams=""):
    '''
    create a connect string from decicated parts
    - to build a SQLAlchemy Uri

    :param    driver: mysql, postgres, ...
    :type     driver: string
    :param    user:   database connection user
    :type     user:   string
    :param    pass_:  password of the database user
    :type     pass_:  string
    :param    server: servername
    :type     server: string
    :param    port:   database connection port
    :type     port:   string or int
    :param    db:     database name
    :type     db:     string
    :param    conParams: additional connection parameters
    :type     conParams: string
    '''

    connect = ""
    if "?odbc_connect=" in driver:

        # we have the need to support the odbc_connect mode
        # where the parameters of the drivers will be concated
        # The template for the odbc_connect string is submitted
        # in the field "Additional connection parameters:"
        param_str = conParams
        settings = {}
        settings["{PORT}"] = port
        settings["{DBUSER}"] = user.strip()
        settings["{SERVER}"] = server.strip()
        settings["{PASSWORT}"] = pass_
        settings["{DATABASE}"] = db
        for key, value in settings.items():
            param_str = param_str.replace(key, value)

        url_quote = urllib.quote_plus(param_str)
        connect = "%s%s" % (driver, url_quote)
    else:
        connect = driver + "://"
        if len(user.strip()) > 0:
            connect = connect + user
        if len(pass_.strip()) > 0:
            connect = connect + ":" + pass_
        if len(server.strip()) > 0:
            if len(user.strip()) > 0:
                connect = connect + "@"
            connect = connect + server
        if len(port.strip()) > 0:
            connect = connect + ":" + str(port)
        # required db
        if db != "":
            connect = connect + "/" + db

        if conParams != "":
            connect = connect + "?" + conParams


    return connect


class dbObject():

    def __init__(self):
        '''
        constructor - initaialize the database object
        '''
        self.engine = None
        self.meta = None
        self.sess = None

        return None

    def connect(self, sqlConnect):
        """
        create a db session with the sqlConnect string

        :param sqlConnect: sql url for the connection
        """
        log.debug('[dbObject::connect] %s' % sqlConnect)

        args = {'echo': False, 'echo_pool': True}
        if 'sqlite' not in sqlConnect:
            args['pool_timeout'] = 30

        self.engine = create_engine(sqlConnect, **args)

        #listen(self.engine, 'connect', call_on_connect)
        self.meta = MetaData()
        # Session = sessionmaker(bind=self.engine)
        Session = sessionmaker(bind=self.engine, autoflush=True,
                               autocommit=True, expire_on_commit=True)
        self.sess = Session()

        return

    def getTable(self, tableName):
        log.debug('[dbObject::getTable] %s' % tableName)
        return Table(tableName, self.meta, autoload=True,
                                            autoload_with=self.engine)

    def count(self, table, where=""):
        log.debug('[dbObject::count] %s:%s' % (table, where))
        num = 0
        if where != "":
            num = self.sess.query(table).filter(where).count()
        else:
            num = self.sess.query(table).count()
        return num

    def query(self, select):
        log.debug('[dbObject::query] %s' % (select))
        return self.sess.execute(select)
        #return self.sess.query(select)

    def close(self):
        log.debug('[dbObject::close]')
        if self.sess is not None:
            self.sess.close()
        return


## connect callback
def call_on_connect(dbapi_con, connection_record):
    log.debug("[call_on_connect] new DBAPI connection: %s " % (str(dbapi_con)))
    return


def _check_hash_type(password, hash_type, hash_value, salt=None):
    '''
    Checks, if the password matches the given hash.

    :param password: The user password in clear text
    :type password: string
    :param hash_type: possible values are sha, ssha, sha256, ssha256
    :type hash_type: string
    :param hash_value: The hash value, base64 encoded
    :type hash_value: string
    :return: True or False
    '''
    log.debug("[_check_hash_type] hash type %r, hash_value %r" % (hash_type,
                                                                  hash_value))
    res = False
    if hash_type.lower() == "sha":
        hash_type = "sha1"
    if hash_type.lower() == "ssha":
        hash_type = "ssha1"

    if (hash_type.lower()[0:3] == "sha"):
        log.debug("[_check_hash_type] found a non-salted hash.")
        try:
            H = hashlib.new(hash_type)
            H.update(password)
            hashed_password = base64.b64encode(H.digest())
            res = (hashed_password == hash_value)
        except ValueError:
            log.exception("[_check_hash_type] Unsupported Hash type: %r"
                                                                % hash_type)

    elif (hash_type.lower()[0:4] == "ssha"):
        log.debug("[_check_hash_type] found a salted hash.")
        try:
            new_hash_type = hash_type[1:]
            # decode the base64 hash value to binary
            bin_value = base64.b64decode(hash_value)

            H = hashlib.new(new_hash_type)
            hash_len = H.digest_size

            # Carefully check for ASP.NET format (salt separated from hash)
            if salt and len(bin_value) == hash_len:
                # Salt separated from hash - probably ASP.NET format
                # For ASP.NET the format is 'hash(salt + password)' with
                # 'password' being a UTF-16 little-endian string
                bin_hash = bin_value
                password = password.encode('utf-16-le')
                bin_salt = base64.b64decode(salt)
                H.update(bin_salt + password)
            else:
                # split the hashed password from the binary salt
                bin_hash = bin_value[:hash_len]
                bin_salt = bin_value[hash_len:]
                H.update(password + bin_salt)

            bin_hashed_password = H.digest()
            res = (bin_hashed_password == bin_hash)
        except ValueError:
            log.exception("[_check_hash_type] Unsupported Hash type: %r"
                                                                % hash_type)

    return res


class IdResolver (UserIdResolver):

    @classmethod
    def setup(cls, config=None, cache_dir=None):
        '''
        this setup hook is triggered, when the server
        starts to serve the first request

        :param config: the linotp config
        :type  config: the linotp config dict
        '''
        log.info("Setting up the SQLResolver")
        return

    def __init__(self):
        ''' initialize the SQLResolver class '''
        self.sqlConnect = ''
        self.sqlTable = ''
        self.sqlWhere = ''
        self.sqlEncoding = ''
        self.sqlUserInfo = {}
        self.conf = ""
        self.driver = ""
        self.limit = 1000
        self.dbObj = None

    def connect(self, sqlConnect=None):
        """
        create a db connection and preserve session in self.dbObj
        """
        if self.dbObj is not None:
            return self.dbObj

        self.dbObj = dbObject()
        if sqlConnect is None:
            sqlConnect = self.sqlConnect

        self.dbObj.connect(sqlConnect)

        return self.dbObj

    def close(self):
        """
        close the db connection - will be called at the end of the request
        """
        if self.dbObj is not None:
            self.dbObj.close()
            self.dbObj = None
        return

    def getResolverId(self):
        """
        getResolverId - provide the resolver identifier

        :return: returns the resolver identifier string
                 or empty string if not exist
        :rtype : string
        """
        resolver = "SQLIdResolver.IdResolver"
        if self.conf != "":
            resolver = resolver + "." + self.conf
        return resolver

    def checkPass(self, uid, password):
        '''
        checkPass - checks the password for a given uid.

        :param uid: userid to be checked
        :type  uid: string
        :param password: user password
        :type  password: string

        :return :  true in case of success, false if password does not match
        :rtype :   boolean

        :todo: extend to support htpasswd passwords:
             http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
        '''

        log.info("[checkPass] checking password for user %s" % uid)
        userInfo = self.getUserInfo(uid)

        # adapt the encoding of the password to the encoding of the database
        if len(self.sqlEncoding) > 0:
            # FIXME: this fails at the moment
            #password = password.encode(self.sqlEncoding)
            pass

        # get the crypted password and the salt from the database
        # for doing crypt.crypt( "password", "salt" )
        if "password" in userInfo:
            # check if we have something like SHA or salted SHA
            m = re.match("^\{(.*)\}(.*)", userInfo["password"])
            # check if we have the PHP Password Framework like it is
            # used in Wordpress
            m_php = re.match("^\$P\$(.*)", userInfo["password"])
            if m:
                # The password field contains something like
                # {SHA256}abcdfef123456
                hash_type = m.group(1)
                hash_value = m.group(2)

                # Check for salt field in case the db splits salt from hash:
                salt = None
                if 'salt' in userInfo:
                    salt = userInfo['salt']
                return _check_hash_type(password, hash_type, hash_value, salt=salt)
            elif m_php:
                # The Password field contains something like
                # '$P$BPC00gOTHbTWl6RH6ZyfYVGWkX3Wec.'
                return check_php_password(password, userInfo["password"])
            else:
                # get the crypted password and the salt from the database
                # for doing crypt.crypt( "password", "salt" )
                salt = userInfo["password"][0:2]
                if "salt" in userInfo:
                    salt = userInfo["salt"]
                npw = crypt.crypt(password, salt)
                # check if the new crypted password matches the original one
                if npw == userInfo["password"]:
                    log.info("[checkPass] user %s authenticated successfully."
                                                                        % uid)
                    return True
                else:
                    log.warning("[checkPass] user %s failed to authenticate."
                                                                        % uid)
                    return False

        else:
            log.error("[checkPass] password is not defined in SQL mapping!")
            return False

    def getConfigEntry(self, config, key, conf, required=True, default=""):
        '''
        getConfigEntry - retrieve an entry from the config

        :param config: dict of all configs
        :type  config: dict
        :param key: key which is searched
        :type key: string
        :param conf: scope of the config eg. connect.sql
        :type conf: string
        :param required: if this value ist true and the key is not defined,
                         an exception sill be raised
        :type required:  boolean
        :param default: fallback value if confg has no such entry
        :type default: any

        :return: the value of the specified key
        :rtype:  value type - in most cases string ;-)

        '''
        ckey = key
        cval = default
        if conf != "" and conf != None:
            ckey = ckey + "." + conf
            if ckey in config:
                cval = config[ckey]
        if cval == "":
            if key in config:
                cval = config[key]
        if cval == "" and required:
            log.error("[getConfigEntry] missing config entry: %s" % key)
            raise Exception("[getConfigEntry] missing config entry: %s" % key)
        return cval

    @classmethod
    def getResolverClassType(cls):
        return 'sqlresolver'

    def getResolverType(self):
        '''
        getResolverType - return the type of the resolver

        :return: returns the string 'sqlresolver'
        :rtype:  string
        '''
        return IdResolver.getResolverClassType()

    @classmethod
    def getResolverClassDescriptor(cls):
        '''
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        '''
        descriptor = {}
        typ = cls.getResolverClassType()
        descriptor['clazz'] = "useridresolver.SQLIdResolver.IdResolver"
        descriptor['config'] = {
                                'Driver': 'string',
                                'Server': 'string',
                                'Port': 'string',
                                'Database': 'string',
                                'User': 'string',
                                'Password': 'password',
                                 }
        return {typ: descriptor}

    def getResolverDescriptor(self):
        return IdResolver.getResolverClassDescriptor()

    def loadConfig(self, config, conf=""):
        '''
        loadConfig - load the config for the resolver

        :param config: configuration for the sqlresolver
        :type  config: dict
        :param conf: configuration postfix
        :type  conf: string
        '''
        log.debug("[loadConfig]")

        connect = self.getConfigEntry(config,
                                      "linotp.sqlresolver.Connect.%s" % conf,
                                      "", False)
        self.conf = conf
        if connect == "":

            driver = self.getConfigEntry(config,
                                         'linotp.sqlresolver.Driver', conf)
            self.driver = driver
            server = self.getConfigEntry(config,
                                'linotp.sqlresolver.Server', conf, False)
            port = self.getConfigEntry(config,
                                'linotp.sqlresolver.Port', conf, False)
            db = self.getConfigEntry(config,
                                'linotp.sqlresolver.Database', conf, False)
            user = self.getConfigEntry(config,
                                       'linotp.sqlresolver.User', conf, False)
            conParams = self.getConfigEntry(config,
                    "linotp.sqlresolver.conParams", conf, False, default="")

            ## there might be an already decrypted pass_
            pass_ = self.getConfigEntry(config,
                                'enclinotp.sqlresolver.Password', conf, False,
                                default=None)
            if pass_ is None:
                pass_ = self.getConfigEntry(config,
                                    'linotp.sqlresolver.Password', conf,
                                    False)

            #        postgres://otpd:linotp2d@localhost:521/otpdb

            connect = make_connect(driver, user, pass_,
                                   server, port, db, conParams)

        self.sqlConnect = connect

        log.debug("[loadConfig] We got the following connect string: %s"
                                                            % self.sqlConnect)

        self.limit = int(self.getConfigEntry(config,
                            "linotp.sqlresolver.Limit", conf, False, "1000"))
        self.sqlTable = self.getConfigEntry(config,
                                            "linotp.sqlresolver.Table", conf)
        self.sqlWhere = self.getConfigEntry(config,
                                    "linotp.sqlresolver.Where", conf, False)
        self.sqlEncoding = self.getConfigEntry(config,
         "linotp.sqlresolver.Encoding", conf, False, default=DEFAULT_ENCODING)

        if self.sqlEncoding == "":
            self.sqlEncoding = DEFAULT_ENCODING

        userInfo = self.getConfigEntry(config, "linotp.sqlresolver.Map", conf)
        userInfo = userInfo.strip("'")
        userInfo = userInfo.strip('"')
        try:
            self.sqlUserInfo = json.loads(userInfo)
        except ValueError as exx:
            raise ResolverLoadConfigError("Invalid userinfo - no json "
                                          "document: %s %r" % (userInfo, exx))
        except Exception as  e:
            raise Exception("linotp.sqlresolver.Map: " + str(e))

        self.checkMapping()

        log.debug("[loadConfig] done")
        return self

    def checkMapping(self):
        """
        check the given sql field map against the sql table definition

        :return: -
        """
        log.debug("[checkMapping]")

        dbObj = self.connect(self.sqlConnect)
        try:

            table = dbObj.getTable(self.sqlTable)

            invalid_columns = []
            for key, sqlCol in self.sqlUserInfo.iteritems():
                column = table.c.get(sqlCol)
                if column is None:
                    log.error('Invalid mapping: %r => %r, column not found'
                                                            % (key, sqlCol))
                    invalid_columns.append(sqlCol)

            if invalid_columns:
                dbObj.close()
                raise Exception("Invalid map with invalid columns: %r. "
                                "Possible columns: %s" %
                        (invalid_columns, [co.name for co in table.columns]))
            else:
                log.info('Valid mapping: %r' % self.sqlUserInfo)
        except Exception as e:
            log.exception('[checkMapping] Exception: %s' % (str(e)))

        log.debug('[checkMapping] done')
        return

    def getUserId(self, loginName):
        '''
        return the userId which mappes to a loginname

        :param loginName: login name of the user
        :type loginName:  string

        :return: userid - unique idenitfier for this unser
        :rtype:  string
        '''

        if len(self.sqlEncoding) > 0:
            loginName = loginName.encode(self.sqlEncoding)

        log.debug("[getUserId] %s[%s]" % (loginName, type(loginName)))
        userId = ""

        dbObj = self.connect(self.sqlConnect)
        try:
            table = dbObj.getTable(self.sqlTable)
            filtr = self.__getUserIdFilter(table, loginName)
            log.debug("[getUserId] filtr: %s" % filtr)
            log.debug("[getUserId] filtr type: %s" % type(filtr))
            select = table.select(filtr)
            log.debug("[getUserId] select: %s" % select)

            rows = dbObj.query(select)
            log.debug("[getUserId] length of select statement %i" %
                                                                rows.rowcount)
            for row in rows:
                colName = self.sqlUserInfo.get("userid")
                userId = row[colName]
                log.info("[getUserId] getting userid %s for user %s" %
                                                        (userId, loginName))
        except Exception as e:
            log.exception('[getUserId] Exception: %s' % (str(e)))

        log.debug('[getUserId] done')
        return userId

    def getUsername(self, userId):
        '''
        get the loginname from the given userid

        :param userId: userid descriptor
        :type userId: string

        :return: loginname
        :rtype:  string
        '''
        log.debug("[getUsername] %s[%s]" % (userId, type(userId)))

        userName = ""

        dbObj = self.connect(self.sqlConnect)
        try:

            table = dbObj.getTable(self.sqlTable)
            select = table.select(self.__getUserNameFilter(table, userId))

            for row in dbObj.query(select):
                colName = self.sqlUserInfo.get("username")
                userName = row[colName]

        except Exception as e:
            log.exception('[getUsername] Exception: %s' % (str(e)))

        log.debug('[getUsername] done')

        return userName

    def getUserInfo(self, userId):
        '''
            return all user related information

            @param userId: specied user
            @type userId:  string
            @return: dictionary, containing all user related info
            @rtype:  dict

        '''
        log.debug("[getUserInfo] %s[%s]" % (userId, type(userId)))
        userInfo = {}

        dbObj = self.connect(self.sqlConnect)
        try:

            table = dbObj.getTable(self.sqlTable)
            select = table.select(self.__getUserNameFilter(table, userId))

            for row in dbObj.query(select):
                userInfo = self.__getUserInfo(dbObj, row)

        except Exception as e:
            log.exception('[getUserInfo] Exception: %s' % (str(e)))

        log.debug('[getUserInfo] done')
        return userInfo

    def getSearchFields(self):
        '''
        return all fields on which a search could be made

        :return: dictionary of the search fields and their types
        :rtype:  dict
        '''
        log.debug("[getSearchFields]")

        sf = {}

        dbObj = self.connect(self.sqlConnect)
        try:

            table = dbObj.getTable(self.sqlTable)

            for key in self.sqlUserInfo:
                sqlCol = self.sqlUserInfo.get(key)
                sqlTyp = table.c[sqlCol].type
                #print key, " - ", sqlCol, " {",sqlTyp,"} "
                typ = "text"
                if isinstance(sqlTyp, types.String):
                    typ = "text"
                elif isinstance(sqlTyp, types.Numeric):
                    typ = "numeric"
                elif isinstance(sqlTyp, types.Integer):
                    typ = "numeric"
                sf[key] = typ

        except Exception as e:
            log.exception('[getSearchFields] Exception: %s' % (str(e)))

        log.debug('[getSearchFields] done')
        return sf

    def getUserList(self, searchDict):
        '''
        retrieve a list of users

        :param searchDict: dictionary of the search criterias
        :type  searchDict: dict
        :return: list of user descriptions (as dict)
        '''
        log.debug("[getUserList] %s" % (str(searchDict)))

        ## we use a dict, where the return users are inserted to where key
        ## is userid to return only a distinct list of users
        users = {}

        dbObj = self.connect()
        self.checkMapping()

        regex_dict = {}

        try:
            table = dbObj.getTable(self.sqlTable)
            log.debug("[getUserList] getting SQL users from table %s" % table)

            ## as most of the SQL dialects dont support unicode, unicode chars
            ## are replaced in the __createSearchString as wildcards.
            ## To make the search more precise, we do postprocessing by
            ## a backward compare with the original search dict values,
            ## either regexp or exact compare.
            ## We build up here the regex dict in case of a wildcard,
            ## For all others we do the exact compare
            for key, value in searchDict.items():
                if "*" in value or "." in value:
                    regex_dict[key] = re.compile(value.replace("*", ".*"))

            sStr = self.__creatSearchString(dbObj, table, searchDict)
            log.debug("[getUserList] creating searchstring <<%s>>" % sStr)
            log.debug("[getUserList] type of searchString: %s" % type(sStr))
            select = table.select(sStr, limit=self.limit)

            rows = dbObj.query(select)

            for row in rows:
                log.debug("[getUserList]  row     : %s" % row)
                ui = self.__getUserInfo(dbObj, row)
                userid = ui['userid']
                log.debug("[getUserList] user info: %s" % ui)
                for s in searchDict:
                    if s in regex_dict:
                        if regex_dict[s].match(ui[s]):
                            users[userid] = ui
                    else:  # excat search
                        if ui[s] == searchDict[s]:
                            users[userid] = ui

        except KeyError as exx:
            log.exception('[getUserList] Invalid Mapping Error %r' % exx)
            raise KeyError("Invalid Mapping %r " % exx)

        except Exception as exx:
            log.exception('[getUserList] Exception: %r' % exx)

        log.debug("[getUserList] returning userlist %s" % users.values())
        return users.values()

#######################
#   Helper functions
#######################
    def __replaceChars(self, string, repl='*'):
        '''
        Replaces unwanted chars with ord()>127

        :param string: string to be replaced
        :param repl: replacement pattern

        :return: string with replaced patterns
        '''
        retString = u""
        for i in string:
            if ord(i) > 127:
                retString = u"%s%s" % (retString, repl)
            else:
                retString = u"%s%s" % (retString, i)

        if len(self.sqlEncoding) > 0:
            retString = retString. encode(self.sqlEncoding)

        return retString

    def __getUserInfo(self, dbObj, row):
        """
        internal helper to build up the user info dict

        :param sbObj: database handle
        :param row: the user object row data
        :return: user dict
        """
        userInfo = {}

        for key in self.sqlUserInfo:
            colName = self.sqlUserInfo.get(key)

            try:
                value = row[colName]
                log.debug("[__getUserInfo] %r:%r" % (value, type(value)))

                if type(value) in [str, unicode] and self.sqlEncoding != "":
                    value = value.decode(self.sqlEncoding)
                    log.debug("[__getUserInfo] convert %r to <%r>" %
                              (row[colName], value))

            except UnicodeEncodeError as exx:
                # here we use a fallback if conversion fails:
                # the upper layer has to deal with this native string
                log.warning("[__getUserInfo] decodeing error: %r " % exx)
                value = row[colName]

            except UnicodeDecodeError as e:
                log.warning("[__getUserInfo] encoding error: can not convert "
                                      "column %r of %r:%r" % (colName, row, e))
                log.warning("[__getUserInfo] %s" % traceback.format_exc())
                value = "-ERR: encoding-"

            except NoSuchColumnError as  e:
                log.exception("[__getUserInfo]")
                value = "-ERR: column mapping-"

            userInfo[key] = value

        return userInfo

    def __add_where_clause_to_filter(self, filtr):
        '''
        add to an existing filter the WHERE filter if it exist.
        This can be used for the getUserList or getUserId

        :param filtr: filter espression
        :return: new filter string
        '''
        # use the Where clause to only see certain users.
        if self.sqlWhere != "":
            clause = expression.text(self.sqlWhere)
            if filtr is None:
                filtr = clause
            else:
                filtr = clause & filtr
            log.debug("[__add_where_clause_filter] searchString: %r" % filtr)
        return filtr

    def __getUserIdFilter(self, table, loginName):
        """
        helper method to access userdata by username by creating an filter

        :param table: the database table
        :param loginname: the name of the user to be searched
        :return: filter condition, which will be added to the db query
        """
        #loginName = loginName.decode("latin1")
        column_name = self.sqlUserInfo.get("username")
        if column_name == None:
            log.error("[__getUserIdFilter] username column "
                                                        "definition required!")
            raise Exception("username column definition required!")
        log.debug("[__getUserIdFilter] type loginName: %s" % type(loginName))
        log.debug("[__getUserIdFilter] type filtr: %s" % type(column_name))

        ## DB2 will need the double quotes if the columns are not upper case.
        ## But as usually a DB2 admin uses upper case, we do not "
        ## need the double quotes.

        return self.__add_where_clause_to_filter(
                                        table.c[column_name] == loginName)

    def __getUserNameFilter(self, table, loginId):
        """
        helper method to access userdata by userid by creating an filter

        :param table: the database table
        :param loginId: the id of the user to be searched
        :return: filter condition, which will be added to the db query
        """

        column_name = self.sqlUserInfo.get("userid")
        if column_name == None:
            err = "[__getUserNameFilter] userid column definition required!"
            log.error(err)
            raise Exception(err)

        return self.__add_where_clause_to_filter(
                                            table.c[column_name] == loginId)

    def __creatSearchString(self, dbObj, table, searchDict):
        """
        Create search string
        """
        exp = None
        for key in searchDict:
            log.debug("[__createSearchString] proccessing key %s" % key)

            ## more tolerant mapping of column names for some sql dialects
            ## as you can define columnnames in mixed case but table mapping
            ## might be only available in upper or lower case (s. postgresql)
            try:
                column = table.c[self.sqlUserInfo[key]]
            except KeyError as _err:
                try:
                    column = table.c[self.sqlUserInfo[key].lower()]
                except KeyError as _err:
                    column = table.c[self.sqlUserInfo[key].upper()]

            ## for searching for names with german umlaute, they are replaced
            ## by wildcards, which is filtered in the upper level by
            ## postprocessing
            val = self.__replaceChars(searchDict.get(key))

            log.debug("[__createSearchString] key: %s, value: %s "
                                                                % (key, val))

            # First: replace wildcards. Our wildcards are * and . (shell-like),
            # and SQL wildcards are % and _.
            if '%' in val:
                val = val.replace('%', r'\%')

            if '_' in val:
                val = val.replace('_', r'\_')

            if '*' in val:
                val = val.replace('*', '%')

            if '.' in val:
                if not self.sqlConnect.startswith('mysql'):
                    val = val.replace('.', '_')
                else:
                    ## mysql replaces unicode chars with 2 placeholders,
                    ## so we rely more on postprocessing :-(
                    val = val.replace('.', '%')

            # don't match for whitespace at the beginning or the end.
            val = val.strip()

            # Now: predicates. <, <=, >=, > get translated,
            # everything else is `LIKE`.
            # No wildcards are supported for <, <=, >=, >.
            if val.startswith('<='):
                val = val[2:].strip()
                exp = column <= val

            elif val.startswith('>='):
                val = val[2:].strip()
                exp = column >= val

            elif val.startswith('>'):
                val = val[1:].strip()
                exp = column > val

            elif val.startswith('<'):
                val = val[1:].strip()
                exp = column < val

            else:
                ### for postgres no escape is required!!
                if self.sqlConnect.startswith('postg'):
                    exp = column.like(val)
                else:
                    exp = column.like(val, escape='\\')

            log.debug("[__createSearchString] searchStr : %s" % exp)

        # use the Where clause to only see certain users.
        return self.__add_where_clause_to_filter(exp)


if __name__ == "__main__":

    print "SQLIdResolver - password hashing test"

    assert _check_hash_type("password", "sha", "W6ph5Mm5Pz8GgiULbPgzG37mj9g=")

    assert _check_hash_type("password", "sha1",
                            "W6ph5Mm5Pz8GgiULbPgzG37mj9g=")
    assert _check_hash_type("password", "sha224",
                            "1j3JGeIB17xMglYw0s8l/ck9Sy8NRnBtKQONAQ==")
    assert _check_hash_type("password", "sha256",
                            "XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=")
    assert _check_hash_type("password", "sha512",
                            "sQnzu7wkTrgkQZF+0G1hi5AI3Qmzvv0bXgc5THBqi7mAsdd"
                            "4Xll27ASbRt9fEyavWi6m0QP9B8lThf+rDKy8hg==")

    assert _check_hash_type("password", "ssha",
                            "5ravvW12u10gQVQtfS4/rFuwVZMxMjM0")
    assert _check_hash_type("password", "ssha1",
                            "5ravvW12u10gQVQtfS4/rFuwVZMxMjM0")
    assert _check_hash_type("password", "ssha224",
                            "K2vvsx1noFJ/vCE1Bj6vsT4K2ghAb3MYIGt+ijEyMzQ=")
    assert _check_hash_type("password", "ssha256",
                            "uclQZA4bN0DpisuT5mnGV2b2Zw3RYJupH/QQUrpIxvMxMjM0")
    assert _check_hash_type("password", "ssha512",
                            "jHydFieKxgoZd28gTzEJscL8eC/4tnH0JCaoXPcrECGIfdnk"
                            "/r5CDc0hW6SZ/xLiMNr2ev/96L+Evv6GeogixDEyMzQ=")

    assert _check_hash_type("wrong password", "sha",
                            "W6ph5Mm5Pz8GgiULbPgzG37mj9g=") == False
    assert _check_hash_type("wrong password", "ssha",
                            "5ravvW12u10gQVQtfS4/rFuwVZMxMjM0") == False

    print "SQLIdResolver - IdResolver class test "

    #sqlR = getResolverClass("useridresolver.SQLIdResolver", "IdResolver")()
    sqlR = IdResolver()

    # sqlite:////home/virtualbox/project/linotp2/dev/linotpd/src/token.db
    config = {
            'linotp.sqlresolver.Driver': 'mysql',
            'linotp.sqlresolver.Port': '3306',
            'linotp.sqlresolver.Database': 'LinOTP2',
            'linotp.sqlresolver.Server': 'localhost',
            'linotp.sqlresolver.User': 'linotp21',
            'linotp.sqlresolver.Password': 'test123!',
            'linotp.sqlresolver.Table': 'users_temp',
            'linotp.sqlresolver.Map': '{ "username": "user",'
                                       '"userid" : "userid", '
                                       '"password": "password", '
                                       '"salt" : "salt", '
                                       '"description" : "user"}'
             }

    sqlR.loadConfig(config)
    print "JSON", json.dumps(config.get('linotp.sqlresolver.UserInfo'))

    userId = sqlR.getUserId("kay")
    print "getUserId:\n kay = ", userId

    userInfo = sqlR.getUserInfo(userId)
    print "getUserInfo:\n Id:", userId, "\n Info:", userInfo

    sf = sqlR.getSearchFields()
    print "getSearchFields: \n ", sf

    #, "id" : ">100"}
    searchDict = {"username": "k*%", "description": "*_Winkler*"}
    #searchDict=  {"userid" : ">100"}

    ulist = sqlR.getUserList(searchDict)
    print "getUserList: \n ", ulist

    #, "id" : ">100"}
    searchDict2 = {"description": "*Winkler*"}
    #searchDict=  {"id" : ">100"}

    ulist = sqlR.getUserList(searchDict2)
    print "getUserList2: \n ", ulist

    #, "id" : ">100"}
    searchDict3 = {"username": "k..", "description": "*Winkler.;*"}
    #searchDict=  {"id" : ">100"}

    ulist = sqlR.getUserList(searchDict3)
    print "getUserList3: \n ", ulist

    #, "id" : ">100"}
    searchDict4 = {"username": "*"}
    #searchDict=  {"id" : ">100"}

    ulist = sqlR.getUserList(searchDict4)
    print "getUserList4: \n ", ulist

    pwcheck = sqlR.checkPass("kay", "test123!")
    print "checkpass for kay: \n", pwcheck

    pwcheck = sqlR.checkPass("kay", "test!")
    print "checkpass for kay: \n", pwcheck

##eof##########################################################################
