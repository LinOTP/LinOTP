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
'''
This is the logic for the openid service

    Inspired by and code taken from
    https://bitbucket.org/tarek/server-openid/overview

'''

import hashlib
import cPickle
from base64 import b64encode, b64decode

import binascii

import hmac
import os
import time
import urlparse
import urllib

from linotp.lib.crypt import urandom

from linotp.lib.user import User
from linotp.lib.user import getUserId
from linotp.lib.user import getUserInfo

from linotp.lib.realm import getDefaultRealm

from hashlib import sha1

from sqlalchemy import create_engine
from pylons import config

import logging
log = logging.getLogger(__name__)


_DEFAULT_MOD = """
DCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61E
F75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D268370557
7D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E382
6634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB
"""
_DEFAULT_MOD = long("".join(_DEFAULT_MOD.split()), 16)
_DEFAULT_GEN = 2
_PROTO_2 = "http://specs.openid.net/auth/2.0"
_PROTO_1 = "http://openid.net/signon/1.1"

OPENID_1_0_NS = 'http://openid.net/xmlns/1.0'
OPENID_IDP_2_0_TYPE = 'http://specs.openid.net/auth/2.0/server'
OPENID_2_0_TYPE = 'http://specs.openid.net/auth/2.0/signon'
OPENID_1_1_TYPE = 'http://openid.net/signon/1.1'
OPENID_1_0_TYPE = 'http://openid.net/signon/1.0'



def xor(x, y):
    if len(x) != len(y):
        raise ValueError('Inputs to strxor must have the same length')

    xor = lambda (a, b): chr(ord(a) ^ ord(b))
    return "".join(map(xor, zip(x, y)))

def randchar():
    import string
    chars = string.letters + string.digits
    return urandom.choice(chars)

def get_nonce():
    now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    rand_chars = ''.join([randchar() for i in range(6)])
    res = now + rand_chars
    return res


def btwoc(value):
    res = cPickle.dumps(value, 2)
    return res[3 + ord(res[3]):3:-1]


def unbtwoc(value):
    load = chr(len(value)) + value[::-1] + '.'
    return cPickle.loads('\x80\x02\x8a' + load)


def create_handle(assoc_type):
    """Creates an association handle.

    Args:
        assoc_type: HMAC-SHA1 or HMAC-SHA256

    Returns:
        secret_b64, association handle
    """
    if assoc_type == 'HMAC-SHA1':
        size = 20
    elif assoc_type == 'HMAC-SHA256':
        size = 32
    else:
        raise NotImplementedError(assoc_type)

    secret_b64 = b64encode(os.urandom(size))
    uniq = b64encode(os.urandom(4))
    handle = '{%s}{%x}{%s}' % (assoc_type, int(time.time()), uniq)
    return secret_b64, handle


def get_dh_key(pubkey, session_type, secret_b64, gen=None, mod=None):
    """Returns a Diffie-Hellman encoded key

    Args:
        - the public key of the other side
        - session_type: DH-SHA1 or DH-SHA256
        - secret_b64: the shared secret, base 64 encoded
        - gen: generator. default to 2
        - mod: modulus, default to the default openid prime

    Return: base64(crypted(pubkey) xor mac_key), btwoc(pub)
    """
    if mod is None:
        mod = _DEFAULT_MOD

    if gen is None:
        gen = _DEFAULT_GEN

    # building the DH signature
    dh_private = urandom.randrange(1, mod - 1)
    dh_public = pow(gen, dh_private, mod)
    dh_shared = btwoc(pow(pubkey, dh_private, mod))

    if session_type == 'DH-SHA1':
        crypt = lambda x: hashlib.sha1(x).digest()
    else:
        crypt = lambda x: hashlib.sha256(x).digest()

    dh_shared = crypt(dh_shared)
    mac_key = xor(b64decode(secret_b64), dh_shared)
    return b64encode(mac_key), b64encode(btwoc(dh_public))


############################## Database tables and models ####################

from sqlalchemy import schema
from sqlalchemy import types
from sqlalchemy import orm
from sqlalchemy import and_

metadata = schema.MetaData()

openid_redirects_table = schema.Table('openid_redirects', metadata,
    schema.Column('token', types.Unicode(255), primary_key=True),
    schema.Column('url', types.Text(), default=u''),
    schema.Column('site', types.Text(), default=u''),
    schema.Column('handle', types.Text(), default=u'')
)

openid_handles_table = schema.Table('openid_handles', metadata,
    schema.Column('handler', types.Unicode(255), primary_key=True),
    schema.Column('secret', types.Text(), default=u''),
    schema.Column('assoc_type', types.Text(), default=u''),
    schema.Column('private', types.Boolean(), default=False)
)

openid_sites_table = schema.Table('openid_sites', metadata,
    schema.Column('id', types.Integer,
                  schema.Sequence('openid_sites_seq_id', optional=True),
                  primary_key=True),
    schema.Column('handle', types.Unicode(255)),
    schema.Column('site', types.Text(), default=u'')
)

openid_user_table = schema.Table('openid_user', metadata,
    schema.Column('user', types.Unicode(255), primary_key=True),
    schema.Column('token', types.Text(), default=u''),
    schema.Column('expire', types.Integer, default=0, index=True)
)

openid_trusted_table = schema.Table('openid_trustedroot', metadata,
    schema.Column('id', types.Integer,
                  schema.Sequence('openid_sites_seq_id', optional=True),
                  primary_key=True),
    schema.Column('user', types.Unicode(255), default=u''),
    schema.Column('site', types.Text(), default=u'')
)

class RedirectsTable(object):

    def __init__(self, token="", url="", site="",
                handle=""):
        log.debug("creating RedirectsTable object: token=%r, url=%r, site=%r,"
                  " handle=%r" % (token, url, site, handle))
        self.token = token
        self.url = url
        self.site = site
        self.handle = handle

class  HandlesTable(object):

    def __init__(self, handler="", secret_b64="", assoc_type="",
                private=False):
        log.debug("creating Handles object: handler=%r, "
                  "secret_b64=%r, assoc_type=%r" %
                  (handler, secret_b64, assoc_type))
        self.handler = handler
        # The .secret is the database column, which keeps the name
        # "secret" for backward compatibility
        self.secret = secret_b64
        self.assoc_type = assoc_type
        self.private = private

class SitesTable(object):

    def __init__(self, handle="", site=""):
        log.debug("creating SitesTable object: handle=%r, site=%r" %
                  (handle, site))
        self.site = site
        self.handle = handle

class UserTable(object):

    def __init__(self, user, token, expire):
        log.debug("creating UserTable object: user=%r, token=%r"
                  % (user, token))
        self.user = user
        self.token = token
        self.expire = expire

class TrustedRootTable(object):
    def __init__(self, user, site):
        log.debug("creating TrustedRoot object: user=%r, site=%r"
                  % (user, site))
        self.user = user
        self.site = site


orm.mapper(RedirectsTable, openid_redirects_table)
orm.mapper(HandlesTable, openid_handles_table)
orm.mapper(SitesTable, openid_sites_table)
orm.mapper(UserTable, openid_user_table)
orm.mapper(TrustedRootTable, openid_trusted_table)



class SQLStorage(object):

    def __init__(self):

        connect_string = config.get("linotpOpenID.sql.url")

        implicit_returning = config.get("linotpSQL.implicit_returning", True)
        self.engine = None

        if connect_string is None:
            log.info("[__init__] Missing linotpOpenID.sql.url parameter in "
                     "config file! Using the sqlalchemy.url")
            # raise Exception("Missing linotpOpenID.sql.url parameter in "
            # "config file!")
            connect_string = config.get("sqlalchemy.url")
        ########################## SESSION ##################################

        # Create an engine and create all the tables we need
        if implicit_returning:
            # If implicit_returning is explicitly set to True, we
            # get lots of mysql errors:
            # AttributeError: 'MySQLCompiler_mysqldb' object has no attribute
            # 'returning_clause' So we do not mention explicit_returning at all
            self.engine = create_engine(connect_string)
        else:
            self.engine = create_engine(connect_string,
                                        implicit_returning=False)

        metadata.bind = self.engine
        metadata.create_all()

        # Set up the session
        self.sm = orm.sessionmaker(bind=self.engine, autoflush=True,
                                   autocommit=False,
            expire_on_commit=True)
        self.session = orm.scoped_session(self.sm)

    @classmethod
    def get_name(self):
        return 'SQLStorage'

    def add_redirect(self, url, site, handle):
        log.debug("[add_redirect] url=%r, site=%r, handle=%r"
                  % (url, site, handle))
        token = sha1(url).hexdigest()
        rd = RedirectsTable(
                        token=token,
                        url=url,
                        site=site,
                        handle=handle)
        try:
            self.session.add(rd)
            self.session.flush()
            self.session.commit()
        except:
            self.session.rollback()
            log.error("Error storing redirect!")

        return token

    def get_redirect(self, redirect_token):
        log.debug("[get_redirect] redirect_token=%r" % redirect_token)
        redirect = self.session.query(RedirectsTable).\
                    filter(RedirectsTable.token == redirect_token)
        url = ""
        site = ""
        handle = ""
        for r in redirect:
            url = r.url
            site = r.site
            handle = r.handle
        log.debug("[get_redirect] url=%r, site=%r, handle=%r" %
                  (url, site, handle))
        return url, site, handle

    def add_association(self, handler, secret_b64, assoc_type, private=False,
                        expires_in=None):
        log.debug("[add_association] handler=%r, secret_b64=%r, assoc_type=%r,"
                  " expires_in=%r"
                  % (handler, secret_b64, assoc_type, expires_in))

        ha = HandlesTable(handler=handler,
                          secret_b64=secret_b64,
                          assoc_type=assoc_type,
                          private=private)
        try:
            self.session.add(ha)
            self.session.flush()
            self.session.commit()
        except:
            self.session.rollback()
            log.error("Error storing association!")

    def get_association(self, handler):
        log.debug("[get_association] handler=%r" % handler)
        assoc = self.session.query(HandlesTable).\
                    filter(HandlesTable.handler == handler)
        secret_b64 = ""
        assoc_type = ""
        private = False
        for a in assoc:
            secret_b64 = a.secret
            assoc_type = a.assoc_type
            private = a.private
        return secret_b64, assoc_type, private

    def del_association(self, handler):
        log.debug("[del_association] handler=%r" % handler)
        try:
            self.session.query(HandlesTable).\
                    filter(HandlesTable.handler == handler).\
                    delete(synchronize_session='fetch')
            self.session.flush()
            self.session.commit()
        except:
            self.session.rollback()
            log.error("Error deleting association")

    def add_site(self, site, handle):
        log.debug("[add_site] handle=%r, site=%r" % (handle, site))
        #if not self.check_auth( handle, site):
        si = SitesTable(site=site,
                    handle=handle)
        try:
            self.session.add(si)
            self.session.flush()
            self.session.commit()
        except:
            self.session.rollback()
            log.error("Error storing site")

    def get_sites(self, handle):
        log.debug("[get_site] handle=%r" % handle)
        site_list = []
        sites = self.session.query(SitesTable).\
                    filter(SitesTable.handle == handle)
        for site in sites:
            site_list.append(site.site)
        log.debug("[get_site] sites=%r" % site_list)
        return site_list

    def add_trusted_root(self, user, site):
        log.debug("[add_trusted_root] user=%r, site=%r" % (user, site))
        tr = TrustedRootTable(user=user, site=site)
        try:
            self.session.add(tr)
            self.session.flush()
            self.session.commit()
        except:
            self.session.rollback()
            log.error("Error storing trusted root")

    def get_trusted_roots(self, user):
        log.debug("[get_trusted_roots] getting trusted roots for user %r"
                  % user)
        root_list = []
        roots = self.session.query(TrustedRootTable).\
                    filter(TrustedRootTable.user == user)

        for root in roots:
            root_list.append(root.site)
        log.debug("[get_trusted_roots] trusted roots: %r" % root_list)
        return root_list

    def check_auth(self, handle, site):
        log.debug("[check_auth] handle=%r, site=%r" % (handle, site))
        sites = self.session.query(SitesTable).\
                    filter(and_(SitesTable.site == site,
                                SitesTable.handle == handle)).count()

        log.debug("[check_auth] sites = %r" % sites)
        return sites == 1


    def _create_token(self, user):

        seed = ""
        for i in range(32):
            seed += chr(urandom.randrange(0, 255))

        token = binascii.hexlify(hashlib.sha1(seed).digest())
        return token

    def set_user_token(self, user, expire=3600):
        '''
        This function sets the token of the user. This is the token,
        that is also stored in the cookie

        :param user: the username

        :param expire: the time in seconds, how long this token is valid.
            This corresponds to the cookie lifetime.
        '''
        token = self._create_token(user)

        try:
            self.session.query(UserTable).filter(UserTable.user == user).\
                    delete(synchronize_session='fetch')
            self.session.flush()
            self.session.commit()
        except:
            self.session.rollback()
            log.error("Error deleting user")

        log.debug("[set_expire_token] setting token expiration for user "
                  "%r: %r" % (user, expire))
        us = UserTable(user=user,
                        token=token,
                        expire=int(time.time()) + int(expire))
        try:
            self.session.add(us)
            self.session.flush()
            self.session.commit()
        except:
            self.session.rollback()
            log.error("Error storing user")

        return token

    def _expire_user_token(self, expire_time):
        self.session.query(UserTable).\
            filter(UserTable.expire < expire_time).\
            delete(synchronize_session='fetch')

        self.session.flush()
        self.session.commit()
        return


    def get_user_token(self, user):
        self._expire_user_token(expire_time=int(time.time()))
        token = 0
        qu_token = self.session.query(UserTable).filter(UserTable.user == user)
        for tok in qu_token:
            # Probably there is only one! ;-)
            token = tok.token
        return token

    def get_user_by_token(self, token):
        log.debug("[get_user_by_token] token: %r" % token)
        user = ""
        qu_user = self.session.query(UserTable).\
                        filter(UserTable.token == token)
        for u in qu_user:
            log.debug("[get_user_by_token] user = %r" % user)
            user = u.user
        return user



class IdResMessage(dict):

    def __init__(self, storage, host, expires_in=3600, **params):
        self.storage = config.get('openid_sql')
        self.expires_in = expires_in
        self.host = host
        self['openid.ns'] = params.get('openid.ns', _PROTO_2)
        self.identity = params.get('openid.identity')
        user = self.identity.split('/')[-1]
        self.user = user

        self['openid.mode'] = 'id_res'
        self['openid.identity'] = self.identity
        self['openid.claimed_id'] = params.get('openid.identity')
        self['openid.op_endpoint'] = self.host
        return_to = self['openid.return_to'] = params.get('openid.return_to')

        trust_root = params.get('openid.trust_root')
        if trust_root is not None:
            self['openid.trust_root'] = trust_root

        handle = params.get('openid.assoc_handle')
        stateless = handle is None
        if stateless:
            # dumb-mode, no association was created previously
            # creating a private one
            self['openid.assoc_handle'] = self._create_handle()
        else:
            self['openid.response_nonce'] = get_nonce()
            signed = ['mode', 'identity', 'assoc_handle', 'return_to',
                      'sreg.nickname', 'claimed_id', 'op_endpoint',
                      'response_nonce']

            if trust_root is not None:
                signed.append('trust_root')
            self.signed = signed
            self['openid.assoc_handle'] = handle

        site = params.get('openid.trust_root')
        if site is None:
            site = return_to
        self.site = site.split('?')[0]  # XXX
        self['openid.sreg.nickname'] = user

    def _dump(self):
        me_string = ""
        for key in self:
            log.debug("[IdResMessage._dump] %r" % key)
            me_string += "%s:%s," % (key, self[key])
        return me_string

    def _create_handle(self):
        client_ns = self['openid.ns']
        if client_ns == _PROTO_1:
            assoc_type = 'HMAC-SHA1'
        else:
            assoc_type = 'HMAC-SHA256'
        secret_b64, handle = create_handle(assoc_type)
        self.storage.add_association(handle, secret_b64,
                                     assoc_type, private=True,
                                     expires_in=self.expires_in)

        self['openid.response_nonce'] = get_nonce()
        signed = ['return_to', 'response_nonce', 'assoc_handle',
                    'claimed_id', 'identity', 'mode']
        if client_ns == _PROTO_2:
            self['openid.op_endpoint'] = self.host
            signed.append('op_endpoint')
            signed.append('ns')

        if self.get('openid.trust_root') is not None:
            signed.append('trust_root')
        self.signed = signed
        return handle

    def get_url(self):
        parsed = list(urlparse.urlparse(self['openid.return_to']))
        old_query = urlparse.parse_qs(parsed[4])
        for key, value in old_query.items():
            if key in self:
                continue
            self[key] = value[0]
        parsed[4] = urllib.urlencode(self)
        log.debug("[IdResMessage._get_url]" % self)
        return urlparse.urlunparse(parsed)

    def store_site(self):
        self.storage.add_site(self['openid.sreg.nickname'],
                              self.site, self['openid.assoc_handle'])

    def store_redirect(self):
        self.storage.session.commit()
        return self.storage.add_redirect(self.get_url(),
                              self.site, self['openid.assoc_handle'])

    def get_user_detail(self):
        """
        get detail info about openid cookie owner

        :return: tuple of (email,firstname,lastname,fullname)
        """

        email = ""
        fullname = ""
        firstname = ""
        lastname = ""

        ## search in userresolvers for user detail
        user = self.user
        if "@" not in user:
            user = "%s@%s" % (user, getDefaultRealm())
        login, realm = user.split('@')

        usr = User(login, realm)
        (userid, res_id, res_conf) = getUserId(usr)
        usr_detail = getUserInfo(userid, res_id, res_conf)

        if "email" in usr_detail:
            email = usr_detail["email"]

        if "givenname" in usr_detail:
            firstname = usr_detail["givenname"]

        if "surname" in usr_detail:
            lastname = usr_detail["surname"]

        if firstname and lastname:
            fullname = "%s %s" % (firstname, lastname)
        elif firstname:
            fullname = "%s" % firstname
        elif lastname:
            fullname = "%s" % lastname

        return (email, firstname, lastname, fullname)


    def sign(self):
        """Signs the message -
        calculate and add signature to self dict entry: 'openid.sig'

        :return: - nothing -
        """

        (email, firstname, lastname, fullname) = self.get_user_detail()

        self.signed.append('ns')

        self["openid.claimed_id"] = self["openid.identity"]
        self.signed.append('claimed_id')

        ## add  extension sreg info for std client
        self["openid.ns.sreg"] = "http://openid.net/extensions/sreg/1.1"
        self.signed.append('ns.sreg')
        self["openid.sreg.email"] = email
        self["openid.sreg.fullname"] = fullname

        self.signed.append('sreg.email')
        self.signed.append('sreg.fullname')
        self.signed.append('sreg.nickname')

        ## add extension ax to transfer user information
        self["openid.ns.ext1"] = "http://openid.net/srv/ax/1.0"
        self.signed.append('ns.ext1')

        self["openid.ext1.mode"] = "fetch_response"
        self["openid.ext1.type.Email"] = ("http://schema.openid.net/"
                                          "contact/email")
        self["openid.ext1.value.Email"] = email
        self["openid.ext1.type.FirstName"] = ("http://schema.openid.net/"
                                              "namePerson/first")
        self["openid.ext1.value.FirstName"] = firstname
        self["openid.ext1.type.LastName"] = ("http://schema.openid.net/"
                                             "namePerson/last")
        self["openid.ext1.value.LastName"] = lastname

        self.signed.append('ext1.mode')
        self.signed.append('ext1.type.Email')
        self.signed.append('ext1.value.Email')
        self.signed.append('ext1.type.FirstName')
        self.signed.append('ext1.value.FirstName')
        self.signed.append('ext1.type.LastName')
        self.signed.append('ext1.value.LastName')

        sorted_sign = sorted(set(self.signed))
        self['openid.signed'] = ','.join(sorted_sign)

        # collecting fields to sign
        fields = []
        for field in sorted_sign:
            value = self['openid.' + field]
            log.debug("[IdResMessage.sign] %r:%r" % (field, value))
            fields.append(u'%s:%s\n' % (field, value))
        fields = unicode(''.join(fields))

        # getting the handle
        mac_key, assoc_type = self._get_association()

        # picking the hash type
        if assoc_type == 'HMAC-SHA256':
            crypt = hashlib.sha256
        else:
            crypt = hashlib.sha1

        # signing the message
        hash = hmac.new(b64decode(mac_key), fields, crypt)
        self['openid.sig'] = b64encode(hash.digest())
        log.debug("[IdResMessage.sign] %r" % self)

    def _get_association(self):
        """
        getting the association handle

        :return: message auth and assoc_type
        """

        handle = self.get('openid.assoc_handle')
        try:
            mac_key, assoc_type, __ = self.storage.get_association(handle)
        except KeyError:
            # handle expired or not existing, switching to dumb mode
            self['openid.invalidate_handle'] = handle
            handle = self['openid.assoc_handle'] = self._create_handle()
            mac_key, assoc_type, __ = self.storage.get_association(handle)

        log.debug("[IdResMessage._get_association] %r" % self)
        return mac_key, assoc_type


def check_authentication(**params):
    """
    """
    storage = config.get('openid_sql')
    site = params.get('openid.trust_root')
    log.debug("[check_authentication] trust_root: %r" % site)

    if site is None:
        site = params.get('openid.return_to')
    site = site.split('?')[0]  # XXX
    log.debug("[check_authentication] site: %r" % site)
    handle = params.get('openid.assoc_handle')
    log.debug("[check_authentication] handle: %r" % handle)
    result = ['openid_mode:id_res\n']

    ret = storage.check_auth(handle, site)
    log.debug("[check_authentication] checking if site is in handle: %r" % ret)

    #result.append('is_valid:true\n')
    if ret:
        result.append('is_valid:true\n')
        storage.del_association(handle)
    else:
        result.append('is_valid:false\n')
    log.debug("[check_authentication] RESULT: %r" % result)
    return ''.join(result)


def create_association(storage, expires_in=3600, **params):
    """
    """
    log.debug("[create_association]")
    assoc_type = params['openid.assoc_type']
    session_type = params['openid.session_type']

    # creating association info
    secret_b64, assoc_handle = create_handle(assoc_type)

    res = {'ns': 'http://specs.openid.net/auth/2.0',
           'assoc_handle': assoc_handle,
           'session_type': session_type,
           'assoc_type': assoc_type,
           'expires_in': unicode(expires_in)}

    if session_type in ('DH-SHA1', 'DH-SHA256'):
        dh_pub = b64decode(params['openid.dh_consumer_public'])
        dh_pub = unbtwoc(dh_pub)

        if 'openid.dh_gen' in params:
            dh_gen = b64decode(params['openid.dh_gen'])
            dh_gen = unbtwoc(dh_gen)
        else:
            dh_gen = None

        if 'openid.dh_modulus' in params:
            dh_modulus = b64decode(params['openid.dh_modulus'])
            dh_modulus = unbtwoc(dh_modulus)
        else:
            dh_modulus = None

        # building the DH signature
        key, serv_pub = get_dh_key(dh_pub, session_type,
                                    secret_b64, dh_gen, dh_modulus)

        res['dh_server_public'] = serv_pub
        res['enc_mac_key'] = key

    elif session_type == 'no-encryption':
        res['mac_key'] = secret_b64

    storage.add_association(assoc_handle, secret_b64,
                            assoc_type, False, expires_in)

    res = ['%s:%s' % (key, value) for key, value in res.items()]
    return '\n'.join(res) + "\n"

