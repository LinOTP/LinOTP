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
"""realm processing logic"""

from linotp.model import Realm, TokenRealm
from linotp.model.meta import Session

from linotp.lib.config import getLinotpConfig
from linotp.lib.config import storeConfig
from linotp.lib.config import getFromConfig

from sqlalchemy import func

import logging
log = logging.getLogger(__name__)


def createDBRealm(realm):
    '''
    Store Realm in the DB Realm Table.
    If the realm already exist, we do not need to store it

    :param realm: the realm name
    :type  realm: string

    :return : if realm is created(True) or already esists(False)
    :rtype  : boolean
    '''

    ret = False
    if not getRealmObject(name=realm):
        log.debug("[createDBRealm] No realm with name %s exist in database. Creating new" % realm)
        r = Realm(realm)
        r.storeRealm()
        ret = True

    return ret

def realm2Objects(realmList):
    '''
    convert a list of realm names to a list of realmObjects

    :param realmList: list of realnames
    :type  realmList: list

    :return: list of realmObjects
    :rtype:  list
    '''
    realm_set = set()
    realmObjList = []
    if realmList is not None:

        # make the requested realms uniq
        for r in realmList:
            realm_set.add(r)

        for r in list(realm_set):
            realmObj = getRealmObject(name=r)
            if realmObj is not None:
                log.debug("[setRealms] added realm %s to realmObjList" % realmObj)
                realmObjList.append(realmObj)
    return realmObjList

def getRealmObject(name=u"", id=0):
    '''
    returns the Realm Object for a given realm name.
    If the given realm name is not found, it returns "None"

    :param name: realmname to be searched
    :type  name: string

    TODO: search by id not implemented, yet
    :param id:   id of the realm object
    :type  id:   integer

    :return : realmObject - the database object
    :rtype  : the sql db object
    '''

    log.debug("[getRealmObject] getting Realm object for name=%s, id=%i" % (name, id))
    realmObj = None
    name = u'' + str(name)
    if (0 == id):
        realmObjects = Session.query(Realm).filter(func.lower(Realm.name) == name.lower())
        if realmObjects.count() > 0:
            realmObj = realmObjects[0]
    return realmObj

def getRealms(aRealmName=""):
    '''
    lookup for a defined realm or all realms

    :note:  the realms dict is inserted into the LinOtp Config object
    so that a lookup has not to reparse the whole config again

    :param aRealmName: a realmname - the realm, that is of interestet, if =="" all realms are returned
    :type  aRealmName: string

    :return:  a dict with realm description like
    :rtype :  dict : {
                u'myotherrealm': {'realmname': u'myotherrealm',
                                'useridresolver': ['useridresolver.PasswdIdResolver.IdResolver.myOtherRes'],
                                'entry': u'linotp.useridresolver.group.myotherrealm'},
                u'mydefrealm': {'default': 'true',
                                'realmname': u'mydefrealm',
                                'useridresolver': ['useridresolver.PasswdIdResolver.IdResolver.myDefRes'],
                                'entry': u'linotp.useridresolver.group.mydefrealm'},
               u'mymixrealm': {'realmname': u'mymixrealm',
                               'useridresolver': ['useridresolver.PasswdIdResolver.IdResolver.myOtherRes', 'useridresolver.PasswdIdResolver.IdResolver.myDefRes'],
                               'entry': u'linotp.useridresolver.group.mymixrealm'}}

    '''
    ret = {}

    config = getLinotpConfig()

    realms = config.getRealms()
    ''' only parse once per session '''
    if realms is None:
        realms = _initalGetRealms()
        config.setRealms(realms)

    ''' check if only one realm is searched '''
    if aRealmName != "" :
        if realms.has_key(aRealmName):
            ret[aRealmName] = realms.get(aRealmName)
    else:
        ret.update(realms)
    return ret

def _initalGetRealms():
    '''
    initaly parse all config entries, and extract the realm definition

    :return : a dict with all realm definitions
    :rtype  : dict of definitions
    '''

    Realms = {}
    defRealmConf = "linotp.useridresolver"
    realmConf = "linotp.useridresolver.group."
    defaultRealmDef = "linotp.DefaultRealm"
    defaultRealm = None


    dc = getLinotpConfig()
    for entry in dc:

        if entry.startswith(realmConf):

            #the realm might contain dots "."
            # so take all after the 3rd dot for realm
            r = {}
            realm = entry.split(".", 3)
            theRealm = realm[3].lower()
            r["realmname"] = realm[3]
            r["entry"] = entry

            ##resids          = env.config[entry]
            resids = getFromConfig(entry)

            # we adjust here the *ee resolvers from the config
            # so we only have to deal with the un-ee resolvers in the server
            # which match the available resolver classes

            resids = resids.replace("useridresolveree.", "useridresolver.")
            r["useridresolver"] = resids.split(",")

            Realms[theRealm] = r

        if entry == defRealmConf:
            r = {}

            theRealm = "_default_"
            r["realmname"] = theRealm
            r["entry"] = defRealmConf

            #resids          = env.config[entry]
            resids = getFromConfig(entry)
            r["useridresolver"] = resids.split(",")

            defaultRealm = "_default_"
            Realms[theRealm] = r

        if entry == defaultRealmDef:
            defaultRealm = getFromConfig(defaultRealmDef)

    if defaultRealm is not None:
        _setDefaultRealm(Realms, defaultRealm)

    return Realms

def _setDefaultRealm(realms, defaultRealm):
    """
    internal method to set in the realm array the default attribute
    (used by the _initalGetRealms)

    :param realms: dict of all realm descriptions
    :type  realms: dict
    :param defaultRealm : name of the default realm
    :type  defaultRelam : string

    :return success or not
    :rtype  boolean
    """

    ret = False
    for k in realms:
        '''
            there could be only one default realm
            - all other defaults will be removed
        '''
        r = realms.get(k)
        if k == defaultRealm.lower():
            r["default"] = "true"
            ret = True
        else:
            if r.has_key("default"):
                del r["default"]
    return ret

def isRealmDefined(realm):
    '''
    check, if a realm already exists or not

    :param realm: the realm, that should be verified
    :type  realm: string

    :return :found or not found
    :rtype  :boolean
    '''
    ret = False
    realms = getRealms();
    if realms.has_key(realm.lower()):
        ret = True
    return ret


def setDefaultRealm(defaultRealm, check_if_exists=True):
    """
    set the defualt realm attrbute

    :note: verify, if the defualtRealm could be empty :""

    :param defaultRealm: the default realm name
    :type  defualtRealm: string

    :return:  success or not
    :rtype:   boolean
    """

    if check_if_exists:
        ret = isRealmDefined(defaultRealm)
    else:
        ret = True

    if ret is True or defaultRealm == "":
        storeConfig(u"linotp.DefaultRealm", defaultRealm)

    return ret


def getDefaultRealm():
    """
    return the default realm
    - lookup in the config for the DefaultRealm key

    :return: the realm name
    :rtype : string
    """

    defaultRealmDef = "linotp.DefaultRealm"
    defaultRealm = getFromConfig(defaultRealmDef, "")

    if defaultRealm is None or defaultRealm == "":
        log.info("Configuration issue: no Default Realm defined!")
        defaultRealm = ""

    return defaultRealm.lower()

def deleteRealm(realmname):
    '''
    delete the realm from the Database Table with the given name

    :param realmname: the to be deleted realm
    :type  realmname: string
    '''

    log.debug("[delete] delete Realm object with name=%s" % realmname)
    r = getRealmObject(name=realmname)
    if r is None:
        ''' if no realm is found, we re-try the lowercase name for backward compatibility '''
        r = getRealmObject(name=realmname.lower())
    realmId = 0
    if r is not None:
        realmId = r.id

        if realmId != 0:
            log.debug("[deleteRealm] Now deleting all realations with realm_id=%i" % realmId)
            Session.query(TokenRealm).filter(TokenRealm.realm_id == realmId).delete()
        Session.delete(r)

    else:
        log.warning("[deleteRealm] There is no realm object with the name %s to be deleted." % realmname)
        return False
    # now delete all relations, i.e. remove all Tokens from this realm.

    return True

###eof#########################################################################
