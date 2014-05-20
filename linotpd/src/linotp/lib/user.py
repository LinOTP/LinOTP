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
""" contains user - related functions """
import logging
import re
import traceback
import sys

from linotp.lib.error   import UserError
from linotp.lib.util    import getParam
from linotp.lib.config  import getFromConfig, storeConfig
from linotp.lib.config  import getLinotpConfig
from linotp.lib.realm   import setDefaultRealm
from linotp.lib.realm   import getDefaultRealm
from linotp.lib.realm   import getRealms

from linotp.lib.resolver import splitResolver
from linotp.lib.resolver import getResolverObject


from linotp.lib.realm import createDBRealm
from linotp.lib.selftest import isSelfTest


ENCODING = 'utf-8'

log = logging.getLogger(__name__)


class User(object):

    def __init__(self, login="", realm="", conf=""):
        log.debug("[User.__init__] creating user %r,%r,%r"
                  % (login, realm, conf))

        self.login = ""
        self.realm = ""
        self.conf = ""

        if login is not None:
            self.login = login
        if realm is not None:
            self.realm = realm
        if conf is not None:
            self.conf = conf
        log.debug("[User.__init__] user created ")

        self.resolverUid = {}
        self.resolverConf = {}
        self.resolvers_list = []

    def getRealm(self):
        return self.realm

    def getResConf(self):
        return self.conf

    def getUser(self):
        return self.login

    def isEmpty(self):
        ## ignore if only conf is set! as it makes no sense
        if len(self.login) + len(self.realm) == 0:
            return True
        else:
            return False
##def __eq__(self,other):
##    ret = False
##    if other is None:
##        if self.isEmpty() == True:
##            return True
##        else:
##            return False
##    if other.login == self.login and self.realm == other.realm and other.conf == self.conf:
##        return True
##    else:
##        return False

##def __ne__(self,other):
##      return not(self.__eq__(other))

    def __str__(self):
        ret = str(None)
        if self.isEmpty() == False:
            loginname = ""
            try:
                loginname = unicode(self.login)
            except UnicodeEncodeError:
                loginname = unicode(self.login.encode(ENCODING))

            conf = ''
            if self.conf is not None and len(self.conf) > 0:
                conf = '.%s' % (unicode(self.conf))
            ret = '<%s%s@%s>' % (loginname, conf, unicode(self.realm))

        return ret

    def __repr__(self):
        ret = ('User(login=%r, realm=%r, conf=%r ::resolverUid:%r, '
             'resolverConf:%r)' % (self.login, self.realm, self.conf,
                                   self.resolverUid, self.resolverConf))
        return ret

    def saveResolvers(self, resolvers):
        """
        save the resolver objects as list as part of the user
        """
        self.resolvers_list = resolvers

    def getResolvers(self):
        return self.resolverUid.keys()

    def addResolverUId(self, resolver, uid, conf="", resId="", resCId=""):
        self.resolverUid[resolver] = uid
        self.resolverConf[resolver] = (resId, resCId, conf)

    def getResolverUId(self, resolver):
        uid = ""
        if self.resolverUid.has_key(resolver):
            uid = self.resolverUid.get(resolver)

        return uid

    def getResolverConf(self, resolver):
        conf = ""
        if self.resolverConf.has_key(resolver):
            conf = self.resolverConf.get(resolver)

        return conf

def getUserResolverId(user, report=False):
    ## here we call the userid resolver!!"
    log.debug('getUserResolverId for %r' % user)

    (uuserid, uidResolver, uidResolverClass) = (u'', u'', u'')

    if (user is not None and user.isEmpty() != True):
        try:
            (uuserid, uidResolver, uidResolverClass) = getUserId(user)
        except Exception as e:
            log.error('[getUserResolverId] for %r@%r failed: %r' % (user.login, user.realm, e))
            log.error("[getUserResolverId] %s" % traceback.format_exc())
            if report == True:
                raise UserError("getUserResolverId failed: %r" % e, id=1112)

    return (uuserid, uidResolver, uidResolverClass)

def splitUser(username):

    user = username.strip()
    group = ""

    ## todo split the last
    l = user.split('@')
    if len(l) >= 2:
        (user, group) = user.rsplit('@')
    else:
        l = user.split('\\')
        if len(l) >= 2:
            (group, user) = user.rsplit('\\')

    return (user, group)

def getUserFromParam(param, optionalOrRequired):
    realm = ""
    conf = ""

    log.debug("[getUserFromParam] entering function")
    user = getParam(param, "user", optionalOrRequired)
    log.debug("[getUserFromParam] got user <<%r>>" % user)

    if user is None:
        user = ""
    else:
        splitAtSign = getFromConfig("splitAtSign", "true")

        if splitAtSign.lower() == "true":
            (user, realm) = splitUser(user)

    if param.has_key("realm"):
        realm = param["realm"]

    if user != "":
        if realm is None or realm == "" :
            realm = getDefaultRealm()

    usr = User(user, realm, "")

    if param.has_key("resConf"):
        conf = param["resConf"]
        ## with the short resolvernames, we have to extract the
        ## configuration name from the resolver spec
        if "(" in conf and ")" in conf:
            res_conf, resolver_typ = conf.split(" ")
            conf = res_conf
        usr.conf = conf
    else:
        if len(usr.login) > 0 or len(usr.realm) > 0 or len(usr.conf) > 0:
            res = getResolversOfUser(usr)
            usr.saveResolvers(res)
            if len(res) > 1:
                log.error("[getUserFromParam] user %r@%r in more than one "
                          "resolver: %r" % (user, realm, res))
                raise Exception("The user %s@%s is in more than one resolver:"
                                " %s" % (user, realm, unicode(res)))

    log.debug("[getUserFromParam] creating user object %r,%r,%r"
              % (user, realm, conf))
    log.debug("[getUserFromParam] created user object %r " % usr)

    return usr


def getUserFromRequest(request):
    '''
    This function first tries to get the user from
     * a DigestAuth and otherwise from
     * basic auth and otherwise from
     * the client certificate
    '''
    d_auth = { 'login' : '' }

    param = request.params

    try:
        # Do BasicAuth
        if request.environ.has_key('REMOTE_USER'):
            d_auth['login'] = request.environ['REMOTE_USER']
            log.debug("[getUserFromRequest] BasicAuth: found the "
                      "REMOTE_USER: %r" % d_auth)

        # Do DigestAuth
        elif request.environ.has_key('HTTP_AUTHORIZATION'):
            a_auth = request.environ['HTTP_AUTHORIZATION'].split(",")

            for field in a_auth:
                (key, _delimiter, value) = field.partition("=")
                d_auth[key.lstrip(' ')] = value.strip('"')

            if d_auth.has_key('Digest username'):
                d_auth['login'] = d_auth['Digest username']

            log.debug("[getUserFromRequest] DigestAuth: found "
                      "this HTTP_AUTHORIZATION: %r" % d_auth)

        # Do SSL Client Cert
        elif request.environ.has_key('SSL_CLIENT_S_DN_CN'):
            d_auth['login'] = request.environ.get('SSL_CLIENT_S_DN_CN')
            log.debug("[getUserFromRequest] SSLClientCert Auth: found "
                      "this SSL_CLIENT_S_DN_CN: %r" % d_auth)

        # In case of selftest
        log.debug("[getUserFromRequest] Doing selftest!: %r" % isSelfTest())

        if isSelfTest():
            log.debug("[getUserFromRequest] Doing selftest!")
            param = request.params
            d_auth['login'] = getParam(param, "selftest_admin", True)
            log.debug("[getUserFromRequest] Found the user: %r in the request."
                       % d_auth)

    except Exception as e:
        log.error("[getUserFromRequest] An error occurred when trying to fetch "
                  "the user from the request: %r" % e)
        pass

    return d_auth


def setRealm(realm, resolvers):

    realm = realm.lower().strip()
    realm = realm.replace(" ", "-")

    nameExp = "^[A-Za-z0-9_\-\.]*$"
    res = re.match(nameExp, realm)
    if res is None:
        e = Exception("non conformant characters in realm name:"
                      " %s (not in %s)" % (realm, nameExp))
        raise e

    ret = storeConfig("useridresolver.group.%s" % realm, resolvers)
    if ret == False:
        return ret

    createDBRealm(realm)

    ## if this is the first one, make it the default
    realms = getRealms()
    if 1 == len(realms):
        for name in realms:
            setDefaultRealm(name)

    return True

def getUserRealms(user):
    '''
    Returns the realms, a user belongs to.
    If the user has no realm but only a useridresolver, than all realms, containing this
    resolver are returned.
    This function is used for the policy module
    '''
    allRealms = getRealms()
    Realms = []
    if user.realm == "" and user.conf == "":
        defRealm = getDefaultRealm().lower()
        Realms.append(defRealm)
        user.realm = defRealm
    elif user.realm != "":
        Realms.append(user.realm.lower())
    else:
        # we got a resolver and will get all realms the resolver belongs to.
        for key, v in allRealms.items():
            log.debug("[getUserRealms] evaluating realm %r: %r " % (key, v))
            for reso in v['useridresolver']:
                resotype, resoname = reso.rsplit('.', 1)
                log.debug("[getUserRealms] found resolver %r of type %r" % (resoname, resotype))
                if resoname == user.conf:
                    Realms.append(key.lower())
                    log.debug("[getUserRealms] added realm %r to Realms due to resolver %r" % (key, user.conf))

    return Realms

def getRealmBox():
    '''
    returns the config value of selfservice.realmbox.
    if True, the realmbox in the selfservice login will be displayed.
    if False, the realmbox will not be displayed and the user needs to login via user@realm
    '''
    rb_string = "linotp.selfservice.realmbox"
    log.debug("[getRealmBox] getting realmbox setting")
    conf = getLinotpConfig()
    if rb_string in conf:
        log.debug("[getRealmBox] read setting: %r" % conf[rb_string])
        return "True" == conf[rb_string]
    else:
        return False

def getConf(Realms, Conf):
    """
    extract the configguration part from the resolver definition
    """
    for k in Realms:
        r = Realms[k]
        resIds = r["useridresolver"]
        for reso in resIds:
            (_package, _module, _class_, conf) = splitResolver(reso)
            if conf.lower() == Conf.lower():
                return reso
    return ""

def getResolvers(user):
    '''
    get the list of the Resolvers within a users.realm
    or from the resolver conf, if given in the user object

    :note:  It ignores the user.login attribute!

    :param user: User with realm or resolver conf
    :type  user: User object
    '''
    Resolver = []

    realms = getRealms();

    if user.conf != "":
        reso = getConf(realms, user.conf)
        if len(reso) > 0:
            Resolver.append(reso)
    else:
        if user.realm != "":
            if user.realm.lower() in realms:
                Resolver = realms[user.realm.lower()]["useridresolver"]
            else:
                resDict = {}
                if user.realm.endswith('*') and len(user.realm) > 1:
                    pattern = user.realm[:-1]
                    for r in realms:
                        if r.startswith(pattern):
                            for idres in realms[r]["useridresolver"]:
                                resDict[idres] = idres
                    for k in resDict:
                        Resolver.append(k)


                elif user.realm.endswith('*') and len(user.realm) == 1:
                    for r in realms:
                        for idres in realms[r]["useridresolver"]:
                            resDict[idres] = idres
                    for k in resDict:
                        Resolver.append(k)

        else:
            for k in realms:
                r = realms[k]
                if r.has_key("default"):
                    Resolver = r["useridresolver"]

    return Resolver

def getResolversOfUser(user):
    '''
    This returns the list of the Resolvers of a user in a given realm.
    Usually this should only return one resolver

    input:
        user.login, user.realm

    returns:
        array of resolvers, the user was found in
    '''

    login = user.login
    realm = user.realm

    Resolvers = user.getResolvers()

    if len(Resolvers) > 0:
        return Resolvers

    if realm is None or realm == "":
        realm = getDefaultRealm()

    #if realm is None or realm=="" or login is None or login == "":
    #    log.error("[getResolversOfUser] You need to specify the name ( %s) and the realm (%s) of a user with conf %s" % (login, realm, user.conf))

    realms = getRealms();

    if user.conf != "":
        reso = getConf(realms, user.conf)
        if len(reso) > 0:
            Resolvers.append(reso)
    else:
        Realm_resolvers = getResolvers(User("", realm, ""))

        log.debug("[getResolversOfUser] check if user %r is in resolver %r"
                   % (login, Realm_resolvers))
        # Search for user in each resolver in the realm_
        for realm_resolver in Realm_resolvers:
            log.debug("[getResolversOfUser] checking in %r" % realm_resolver)

            (package, module, class_, conf) = splitResolver(realm_resolver)
            module = package + "." + module

            y = getResolverObject(realm_resolver)
            if y is None:
                log.error("[getResolversOfUser] [ module %r not found!]"
                                                                    % (module))

            try:
                log.debug("[getResolversOfUser] checking in module %r" % y)
                uid = y.getUserId(login)
                log.debug("[getResolversOfUser] type of uid: %s" % type(uid))
                log.debug("[getResolversOfUser] type of realm_resolver: %s" % type(realm_resolver))
                log.debug("[getResolversOfUser] type of login: %s" % type(login))
                if uid not in ["", None]:
                    log.info("[getResolversOfUser] user %r found in resolver %r" % (login, realm_resolver))
                    log.info("[getResolversOfUser] userid resolved to %r " % uid)

                    ## Unicode Madness:
                    ## This will break as soon as the unicode "uid" is put into a tuple
                    ## v = (login, realm_resolver, uid)
                    ## log.info("[getResolversOfUser] %s %s %s" % v)
                    resId = y.getResolverId();
                    resCId = realm_resolver
                    Resolvers.append(realm_resolver)
                    user.addResolverUId(realm_resolver, uid, conf, resId, resCId)
                else:
                    log.debug("[getResolversOfUser] user %r not found"
                              " in resolver %r" % (login, realm_resolver))
            except Exception as e:
                log.error("[getResolversOfUser] error searching user in"
                          " module %r:%r" % (module, e))
                log.error("[getResolversOfUser] %s" % traceback.format_exc())

            log.debug("[getResolversOfUser] Resolvers: %r" % Resolvers)

    log.debug("[getResolversOfUser] Found the user %r in %r" % (login, Resolvers))
    return Resolvers

def getUserId(user):
    """
    getUserId (userObject)

    return (uid,resId,resIdC)
    """

    uid = ''
    loginUser = u''
    loginUser = user.login;

    resolvers = getResolversOfUser(user)
    for reso in resolvers:
        resId = ""
        resIdC = ""
        conf = ""
        uid = user.getResolverUId(reso)
        if uid != '':
            (resId, resIdC, conf) = user.getResolverConf(reso)
            break

        (package, module, class_, conf) = splitResolver(reso)

        if len(user.conf) > 0:
            if conf.lower() != user.conf.lower():
                continue

        ## try to load the UserIdResolver Class
        try:
            module = package + "." + module
            log.debug("[getUserId] Getting resolver class: [%r] [%r]"
                       % (module, class_))
            y = getResolverObject(reso)
            log.debug("[getUserId] Getting UserID for user %r"
                        % loginUser)
            uid = y.getUserId(loginUser)
            log.debug("[getUserId] Got UserId for user %r: %r"
                        % (loginUser, uid))

            log.debug("[getUserId] Retrieving ResolverID...")
            resId = y.getResolverId()

            resIdC = reso
            log.debug("[getUserId] Got ResolverID: %r, Loginuser: %r, "
                      "Uid: %r ]" % (resId, loginUser, uid))

            if uid != "":
                break;

        except Exception as e:
            log.error("[getUserId] module %r: %r ]" % (module, e))
            continue

    if (uid == ''):
        log.warning("[getUserId] No uid found for the user >%r< in realm %r"
                    % (loginUser, user.realm))
        raise UserError(u"getUserId failed: no user >%s< found!"
                         % unicode(loginUser), id=1205)

    log.debug("[getUserId] we are done!")
    return (unicode(uid), unicode(resId), unicode(resIdC))

def getSearchFields(User):

    searchFields = {}

    log.debug("[getSearchFields] entering function getSearchFields")

    for reso in getResolvers(User):
        """  """
        (_package, module, class_, conf) = splitResolver(reso)

        if len(User.conf) > 0:
            if conf.lower() != User.conf.lower():
                continue

        ## try to load the UserIdResolver Class
        try:
            y = getResolverObject(reso)
            sf = y.getSearchFields()
            searchFields[reso] = sf

        except Exception as e:
            log.warning("[getSearchField][ module %r: %r ]" % (module, e))
            continue

    return searchFields

def getUserList(param, User):

    users = []

    searchDict = {}
    log.debug("[getUserList] entering function getUserList")

    ## we have to recreate a new searchdict without the realm key
    ## as delete does not work
    for key in param:
        lval = param[key]
        if key == "realm":
            continue
        if key == "resConf":
            continue

        searchDict[key] = lval
        log.debug("[getUserList] Parameter key:%r=%r" % (key, lval))

    resolverrrs = getResolvers(User)

    for reso in resolverrrs:
        (package, module, class_, conf) = splitResolver(reso)
        module = package + "." + module

        if len(User.conf) > 0:
            if conf.lower() != User.conf.lower():
                continue

        ## try to load the UserIdResolver Class
        try:
            log.debug("[getUserList] Check for resolver class: %r" % reso)
            y = getResolverObject(reso)
            log.debug("[getUserList] with this search dictionary: %r " % searchDict)
            ulist = y.getUserList(searchDict)
            log.debug("[getUserList] setting the resolver <%r> for each user" % reso)
            for u in ulist:
                u["useridresolver"] = reso

            log.debug("[getUserList] Found this userlist: %r" % ulist)
            users.extend (ulist)

        except KeyError as exx:
            log.error("[getUserList][ module %r:%r ]" % (module, exx))
            log.error("[getUserList] %s" % traceback.format_exc())
            raise exx

        except Exception as exx:
            log.error("[getUserList][ module %r:%r ]" % (module, exx))
            log.error("[getUserList] %s" % traceback.format_exc())
            continue

    return users

def getUserInfo(userid, resolver, resolverC):
    log.debug("[getUserInfo] uid:%r resolver:%r class:%r" %
              (userid, resolver, resolverC))
                ## [PasswdIdResolver] [IdResolver]
    userInfo = {}
    module = ""

    if len(userid) == 0 or userid is None:
        return userInfo

    try:
        (package, module, class_, conf) = splitResolver(resolverC)
        module = package + "." + module

        y = getResolverObject(resolverC)
        log.debug("[getUserInfo] Getting user info for userid "
                  ">%r< in resolver" % userid)
        userInfo = y.getUserInfo(userid)

    except Exception as e:
        log.error("[getUserInfo][ module %r notfound! :%r ]" % (module, e))

    return userInfo

def getUserPhone(user, phone_type='phone'):
    '''
    Returns the phone numer of a user

    :param user: the user with the phone
    :type user: user object

    :param phone_type: The type of the phone, i.e. either mobile or phone (land line)
    :type phone_type: string

    :returns: list with phone numbers of this user object
    '''
    (uid, resId, resClass) = getUserId(user)
    log.debug("[getUserPhone] got uid %r, ResId %r, Class %r"
              % (uid, resId, resClass))
    userinfo = getUserInfo(uid, resId, resClass)
    if userinfo.has_key(phone_type):
        log.debug("[getUserPhone] got user phone %r of type %r"
                  % (userinfo[phone_type], phone_type))
        return userinfo[phone_type]
    else:
        log.warning("[getUserPhone] userobject (%r,%r,%r) has no phone of "
                    "type %r." % (uid, resId, resClass, phone_type))
        return ""

def check_user_password(username, realm, password):
    '''
    This is a helper function to check the username and password against
    a userstore.

    return

      success    --- This is the username of the authenticated user. If unsuccessful,
                      returns None
    '''
    success = None
    try:
        log.info("[check_user_password] User %r from realm %r tries to "
                 "authenticate to selfservice" % (username, realm))
        if type(username) != unicode:
            username = username.decode(ENCODING)
        u = User(username, realm, "")
        res = getResolversOfUser(u)
        # Now we know, the resolvers of this user and we can verify the password
        if (len(res) == 1):
            (uid, resolver, resolverC) = getUserId(u)
            log.info("[check_user_password] the user resolves to %r" % uid)
            log.info("[check_user_password] The username is found within the "
                     "resolver %r" % resolver)
            # Authenticate user
            try:
                (package, module, class_, conf) = splitResolver(resolverC)
                module = package + "." + module
                y = getResolverObject(resolverC)
            except Exception as e:
                log.error("[check_user_password] [ module %r notfound! :%r ]"
                          % (module, e))
            try:
                if  y.checkPass(uid, password):
                    log.debug("[check_user_password] Successfully "
                              "authenticated user %r." % username)
                    # try:
                    #identity = self.add_metadata( environ, identity )
                    success = username + '@' + realm
                else:
                    log.info("[check_user_password] user %r failed "
                             "to authenticate." % username)
            except Exception as e:
                log.error("[check_user_password] Error checking password "
                          "within module %r:%r" % (module, e))
                log.error("[check_user_password] %s" % traceback.format_exc())

        elif (len(res) == 0):
            log.error("[check_user_password] The username %r exists in NO "
                      "resolver within the realm %r." % (username, realm))
        else:
            log.error("[check_user_password] The username %r exists in more "
                      "than one resolver within the realm %r" % (username, realm))
            log.error(res)
    except UserError as e:
        log.error("[check_user_password] Error while trying to verify "
                  "the username: %r" % e.description)

    return success

#eof###########################################################################

