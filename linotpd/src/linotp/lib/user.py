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
""" contains user - related functions """
import logging
import re
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
from linotp.lib.resolver import getResolverClassName
from linotp.lib.resolver import getResolverList


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
        self.info = {}
        self.exist = False


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

    @staticmethod
    def getUserObject(login, realm=None, check_if_exist=False):

        f_realm = realm
        f_login = login

        if not realm:
            if '@' in login:
                realms = getRealms()
                lo, rea = login.rsplit('@', 1)
                if rea.lower() in realms:
                    f_realm = rea.lower()
                    f_login = lo
                else:
                    f_realm = getDefaultRealm()
                    f_login = login

        f_user = User(f_login, realm=f_realm)
        if check_if_exist:
            uid, resolver = f_user.get_uid_resolver()

        return f_user

    def does_exists(self, resolvers=None):
        """
        """
        uid, _resolver = self.get_uid_resolver(resolvers=resolvers)
        if uid is not None:
            return True
        return False

    def get_uid_resolver(self, resolvers=None):
        uid = None
        resolver = None
        resolvers_list = []

        if not resolvers:
            if self.realm:
                realms = getRealms()
                if self.realm.lower() in realms:
                    resolvers_list = realms.get(self.realm.lower(), {}).\
                                       get('useridresolver', [])
        else:
            resolvers_list = []
            for search_resolver in resolvers:
                fq_resolver = User.get_fq_resolver(search_resolver)
                if fq_resolver:
                    resolvers_list.append(fq_resolver)

        if not resolvers_list:
            return None, None

        for resolver in resolvers_list:
            try:
                y = getResolverObject(resolver)
                uid = y.getUserId(self.login)
                if not uid:
                    uid = None
                    continue
                self.resolverUid[resolver] = uid
                self.exist = True
                break

            except Exception as exx:
                log.exception("Error while accessing resolver %r", exx)

        return (uid, resolver)

    def getRealm(self):
        return self.realm

    def getResConf(self):
        return self.conf

    def getUser(self):
        return self.login

    def isEmpty(self):
        # ignore if only conf is set! as it makes no sense
        if len(self.login) + len(self.realm) == 0:
            return True
        else:
            return False
# def __eq__(self,other):
#    ret = False
#    if other is None:
#        if self.isEmpty() == True:
#            return True
#        else:
#            return False
#    if other.login == self.login and self.realm == other.realm and other.conf == self.conf:
#        return True
#    else:
#        return False

# def __ne__(self,other):
#      return not(self.__eq__(other))

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

    @staticmethod
    def get_fq_resolver(res):
        fq_resolver = None
        resolvers = getResolverList()
        if res in resolvers:
            match_res = resolvers.get(res)
            fq_resolver = getResolverClassName(match_res['type'],
                                               match_res['resolvername'])
        return fq_resolver

    def getUserInfo(self, resolver=None):
        userInfo = {}

        lookup_resolvers = None
        if resolver:
            lookup_resolvers = [resolver]

        userid, resolverC = self.get_uid_resolver(lookup_resolvers)

        if not userid:
            return {}

        try:
            (package, module, _class, _conf) = splitResolver(resolverC)
            module = package + "." + module

            y = getResolverObject(resolverC)
            log.debug("[getUserInfo] Getting user info for userid "
                      ">%r< in resolver" % userid)
            userInfo = y.getUserInfo(userid)
            self.info[resolverC] = userInfo

        except Exception as e:
            log.exception("[getUserInfo][ module %r notfound! :%r ]" % (module, e))

        return userInfo


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

    def getUserPerConf(self):
        """
        a wildcard usr (realm = *) could have multiple configurations
        this method will return a list of uniq users, one per configuration

        :return: list of users
        """
        resolvers = self.getResolvers()
        if len(resolvers) == 1:
            return [self]

        # if we have multiple resolvers in this wildcard user
        # we create one user per config and add this user to the list
        # of all users to be checked
        userlist = []
        for resolver in resolvers:
            (resId, resClass, resConf) = self.getResolverConf(resolver)
            uid = self.getResolverUId(resolver)
            n_user = User(self.login)
            n_user.addResolverUId(resClass, uid, resConf, resId, resClass)
            userlist.append(n_user)

        return userlist


    def getResolverConf(self, resolver):
        conf = ""
        if self.resolverConf.has_key(resolver):
            conf = self.resolverConf.get(resolver)

        return conf

def getUserResolverId(user, report=False):
    # here we call the userid resolver!!"
    log.debug('getUserResolverId for %r' % user)

    (uuserid, uidResolver, uidResolverClass) = (u'', u'', u'')

    if (user is not None and user.isEmpty() != True):
        try:
            (uuserid, uidResolver, uidResolverClass) = getUserId(user)
        except Exception as e:
            log.exception('[getUserResolverId] for %r@%r failed: %r' % (user.login, user.realm, e))
            if report == True:
                raise UserError("getUserResolverId failed: %r" % e, id=1112)

    return (uuserid, uidResolver, uidResolverClass)


def splitUser(username):
    """
    split the username into the user and realm

    :param username: the given username
    :return: tuple of (user and group/realm)
    """

    user = username.strip()
    group = ""


    if '@' in user:
        (user, group) = user.rsplit('@', 1)
    elif '\\' in user:
        (group, user) = user.split('\\', 1)

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
        # with the short resolvernames, we have to extract the
        # configuration name from the resolver spec
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
        log.exception("[getUserFromRequest] An error occurred when trying to fetch "
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

    # if this is the first one, make it the default
    realms = getRealms()
    if 0 == len(realms):
        setDefaultRealm(realm, check_if_exists=False)

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


def getSplitAtSign():
    '''
    returns the config value of splitAtSign.
    if True, the username should be split if there is an at sign.
    if False, the username will be taken unchanged for loginname.
    '''
    splitAtSign = getFromConfig("splitAtSign", "true") or 'true'
    return "true" == splitAtSign.lower()


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

def getResolversOfUser(user, use_default_realm=True):
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

    if not login:
        return Resolvers

    if realm is None or realm == "":
        if use_default_realm:
            realm = getDefaultRealm()

    # if realm is None or realm=="" or login is None or login == "":
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

                    # Unicode Madness:
                    # This will break as soon as the unicode "uid" is put into a tuple
                    # v = (login, realm_resolver, uid)
                    # log.info("[getResolversOfUser] %s %s %s" % v)
                    resId = y.getResolverId();
                    resCId = realm_resolver
                    Resolvers.append(realm_resolver)
                    user.addResolverUId(realm_resolver, uid, conf, resId, resCId)
                else:
                    log.debug("[getResolversOfUser] user %r not found"
                              " in resolver %r" % (login, realm_resolver))
            except Exception as e:
                log.exception("[getResolversOfUser] error searching user in"
                          " module %r:%r" % (module, e))

            log.debug("[getResolversOfUser] Resolvers: %r" % Resolvers)

    log.debug("[getResolversOfUser] Found the user %r in %r" % (login, Resolvers))
    return Resolvers

def getUserId(user, resolvers=None):
    """
    getUserId (userObject)

    return (uid,resId,resIdC)
    """

    uid = ''
    loginUser = u''
    loginUser = user.login;

    if not resolvers:
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

        # try to load the UserIdResolver Class
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
            log.exception("[getUserId] module %r: %r ]" % (module, e))
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

        # try to load the UserIdResolver Class
        try:
            y = getResolverObject(reso)
            sf = y.getSearchFields()
            searchFields[reso] = sf

        except Exception as e:
            log.warning("[getSearchField][ module %r: %r ]" % (module, e))
            continue

    return searchFields

def getUserList(param, search_user):

    users = []

    searchDict = {}
    log.debug("[getUserList] entering function getUserList")

    # we have to recreate a new searchdict without the realm key
    # as delete does not work
    for key in param:
        lval = param[key]
        if key == "realm":
            continue
        if key == "resConf":
            continue

        searchDict[key] = lval
        log.debug("[getUserList] Parameter key:%r=%r" % (key, lval))

    resolverrrs = getResolvers(search_user)

    for reso in resolverrrs:
        (package, module, _class, conf) = splitResolver(reso)
        module = package + "." + module

        if len(search_user.conf) > 0:
            if conf.lower() != search_user.conf.lower():
                continue

        # try to load the UserIdResolver Class
        try:

            log.debug("[getUserList] Check for resolver class: %r" % reso)
            y = getResolverObject(reso)
            log.debug("[getUserList] with this search dictionary: %r "
                      % searchDict)

            if hasattr(y, 'getUserListIterator'):
                try:
                    ulist_gen = y.getUserListIterator(searchDict)
                    while True:
                        ulist = ulist_gen.next()
                        log.debug("[getUserList] setting the resolver <%r> "
                                  "for each user" % reso)
                        for u in ulist:
                            u["useridresolver"] = reso
                        log.debug("[getUserList] Found this userlist: %r"
                                  % ulist)
                        users.extend(ulist)

                except StopIteration as exx:
                    # we are done: all users are fetched or
                    # page size limit reached
                    pass
            else:
                ulist = y.getUserList(searchDict)
                for u in ulist:
                    u["useridresolver"] = reso
                log.debug("[getUserList] Found this userlist: %r" % ulist)
                users.extend(ulist)

        except KeyError as exx:
            log.exception("[getUserList][ module %r:%r ]" % (module, exx))
            raise exx

        except Exception as exx:
            log.exception("[getUserList][ module %r:%r ]" % (module, exx))
            continue

    return users


def getUserListIterators(param, search_user):
    """
    return a list of iterators for all userid resolvers

    :param param: request params (dict), which might be realm or resolver conf
    :param search_user: restrict the resolvers to those of the search_user
    """
    user_iters = []
    searchDict = {}

    log.debug("Entering function getUserListIterator")

    searchDict.update(param)
    if 'realm' in searchDict:
        del searchDict['realm']
    if 'resConf' in searchDict:
        del searchDict['resConf']
    log.debug("searchDict %r" % searchDict)

    resolverrrs = getResolvers(search_user)
    for reso in resolverrrs:
        (package, module, _class, conf) = splitResolver(reso)
        module = package + "." + module

        if len(search_user.conf) > 0:
            if conf.lower() != search_user.conf.lower():
                continue

        # try to load the UserIdResolver Class
        try:
            log.debug("Check for resolver class: %r" % reso)
            y = getResolverObject(reso)
            log.debug("With this search dictionary: %r " % searchDict)

            if hasattr(y, 'getUserListIterator'):
                uit = y.getUserListIterator(searchDict, limit_size=False)
            else:
                uit = iter(y.getUserList(searchDict))

            user_iters.append((uit, reso))

        except KeyError as exx:
            log.exception("[ module %r:%r ]" % (module, exx))
            raise exx

        except Exception as exx:
            log.exception("[ module %r:%r ]" % (module, exx))
            continue

    return user_iters


def getUserInfo(userid, resolver, resolverC):
    log.debug("[getUserInfo] uid:%r resolver:%r class:%r" %
              (userid, resolver, resolverC))
                # [PasswdIdResolver] [IdResolver]
    userInfo = {}
    module = ""

    if not(userid):
        return userInfo

    try:
        (package, module, _class, _conf) = splitResolver(resolverC)
        module = package + "." + module

        y = getResolverObject(resolverC)
        log.debug("[getUserInfo] Getting user info for userid "
                  ">%r< in resolver" % userid)
        userInfo = y.getUserInfo(userid)

    except Exception as e:
        log.exception("[getUserInfo][ module %r notfound! :%r ]" % (module, e))

    return userInfo


def getUserDetail(user):
    '''
    Returns userinfo of an user

    :param user: the user
    :returns: the userinfo dict
    '''
    (uid, resId, resClass) = getUserId(user)
    log.debug("got uid %r, ResId %r, Class %r"
              % (uid, resId, resClass))
    userinfo = getUserInfo(uid, resId, resClass)
    return userinfo


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


def get_authenticated_user(username, realm, password=None,
                           realm_box=False, authenticate=True,
                           options=None):
    '''
    check the username and password against a userstore.

    remark: the method is called in the context of repoze.who
            during authentication and during auto_enrollToken/auto_assignToken

    :param username: the user login name
    :param realm: the realm, where the user belongs to
    :param password: the to be checked userstore password
    :param realm_box: take the information, if realmbox is displayed
    :parm authenticate: for the selftest, we skip the authentication

    :return: None or authenticated user object
    '''

    log.info("User %r from realm %r tries to authenticate to selfservice"
             % (username, realm))

    if type(username) != unicode:
        username = username.decode(ENCODING)

    # ease the handling of options
    if not options:
        options = {}

    users = []
    uid = None
    resolver = None
    resolverC = None

    # if we have an realmbox, we take the user as it is
    # - the realm is always given
    # - appended realms result in error
    if realm_box:
        user = User(username, realm, "")
        users.append(user)

    # else if no realm box is given
    #   and realm is not empty:
    #    - create the user from the values (as we are in auto_assign, etc)
    #   and the realm is empty! (s. login.mako
    #    - the user either appends his realm
    #    - or will get the realm appended
    #
    else:
        if realm:
            user = User(username, realm, "")
            users.append(user)
        else:
            def_realm = options.get('defaultRealm', getDefaultRealm())
            if def_realm:
                user = User(username, def_realm, "")
                users.append(user)
            if '@' in username:
                u_name, u_realm = username.rsplit('@', 1)
                user = User(u_name, u_realm, "")
                users.append(user)

    identified_users = []
    for user in users:
        username = user.login
        realm = user.realm
        res = getResolversOfUser(user, use_default_realm=False)
        if (len(res) != 1):
            if (len(res) == 0):
                log.info("The username %r exists in NO resolver within the "
                          "realm %r." % (username, realm))
            else:
                log.info("The username %r exists in more than one resolver "
                          "within the realm %r" % (username, realm))
            continue

        # we got one resolver, so lets check if user exists
        (uid, resolver, resolverC) = getUserId(user)
        identified_users.append((user, uid, resolver, resolverC))
        log.info("the user resolves to %r" % uid)
        log.info("The username is found within the resolver %r" % resolver)

    ide_user = len(identified_users)
    if ide_user != 1:
        if ide_user > 1:
            log.info("The username %s could not be identified uniquely" %
                     username)
        if ide_user == 0:
            log.info("The username %s could not be found." % username)
        return None

    (user, uid, resolver, resolverC) = identified_users[0]
    if not authenticate:
        return user

    # Authenticate user
    auth_user = None
    try:
        (package, module, class_, conf) = splitResolver(resolverC)
        module = package + "." + module
        y = getResolverObject(resolverC)

        if  y.checkPass(uid, password):
            log.debug("Successfully authenticated user %r." % username)
            auth_user = user
        else:
            log.info("user %r failed to authenticate." % username)

    except UserError as exx:
        log.info("failed to verify the username: %s@%s" % (user.login,
                                                           user.realm))

    if not auth_user:
        log.error("Error while trying to verify the username: %s" % username)

    return auth_user

#eof###########################################################################
