# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
"""realm processing logic"""

import json
import logging
from functools import partial

from sqlalchemy import func

from flask import current_app

from linotp.lib.cache import get_cache
from linotp.lib.config import getFromConfig, getLinotpConfig, storeConfig
from linotp.lib.config.parsing import ConfigNotRecognized, ConfigTree
from linotp.lib.context import request_context as context
from linotp.model import Realm, TokenRealm, db

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------

# on module load integrate the parser functions for realm config
# into the ConfigTree class


def parse_realm(composite_key, value):
    """Parses realm data from a config entry"""

    if not composite_key.startswith("linotp.useridresolver.group."):
        raise ConfigNotRecognized(composite_key)

    object_id = composite_key[len("linotp.useridresolver.group.") :]

    return object_id, {"resolvers": value}


def parse_default_realm(composite_key, value):
    """
    Sets the attribute pair {default: True} to the default realm
    in the tree.
    """

    if composite_key != "linotp.DefaultRealm":
        raise ConfigNotRecognized(composite_key)

    return value, {"default": True}


ConfigTree.add_parser("realms", parse_realm)
ConfigTree.add_parser("realms", parse_default_realm)

# ------------------------------------------------------------------------------


def createDBRealm(realm):
    """
    Store Realm in the DB Realm Table.
    If the realm already exist, we do not need to store it

    :param realm: the realm name
    :type  realm: string

    :return : if realm is created(True) or already esists(False)
    :rtype  : boolean
    """

    ret = False
    if not getRealmObject(name=realm):
        r = Realm(realm)
        r.storeRealm()
        ret = True

    return ret


def realm2Objects(realmList):
    """
    convert a list of realm names to a list of realmObjects

    :param realmList: list of realnames
    :type  realmList: list

    :return: list of realmObjects
    :rtype:  list
    """
    realm_set = set()
    realmObjList = []
    if realmList is not None:

        # make the requested realms uniq
        for r in realmList:
            realm_set.add(r)

        for r in list(realm_set):
            realmObj = getRealmObject(name=r)
            if realmObj is not None:
                realmObjList.append(realmObj)
    return realmObjList


def getRealmObject(name="", id=0):
    """
    returns the Realm Object for a given realm name.
    If the given realm name is not found, it returns "None"

    :param name: realmname to be searched
    :type  name: string

    TODO: search by id not implemented, yet
    :param id:   id of the realm object
    :type  id:   integer

    :return : realmObject - the database object
    :rtype  : the sql db object
    """

    log.debug("Getting realm object for name=%s, id=%i", name, id)
    realmObj = None

    name = "" + str(name)
    if 0 == id:
        realmObjects = Realm.query.filter(
            func.lower(Realm.name) == name.lower()
        )
        if realmObjects.count() > 0:
            realmObj = realmObjects[0]

    return realmObj


def _check_for_cache_flush(realm_name, realm_definition):
    """
    Check if the realm_resolver cache should be flushed. This detected by
    checking if the resolver definition in a realm has changed.

    :param realm_name: the name of the realm
    :param realm_definition: the new realm definition with its resolvers
    :return: -nothing-
    """

    # get the resolvers list of the realm definition
    realm_resolvers = realm_definition.get("useridresolver", [])

    # and the former definition from the local cache
    former_realm_resolvers = _lookup_realm_config(realm_name, realm_resolvers)

    # we check if there has been something dropped from the
    # former resolver definition by using set().difference
    former_res_set = set(former_realm_resolvers)
    new_res_set = set(realm_resolvers)
    flush_resolvers = former_res_set.difference(new_res_set)

    if flush_resolvers:

        # refresh the user resolver lookup in the realm user cache
        from linotp.lib.user import delete_realm_resolver_cache

        delete_realm_resolver_cache(realm_name)

        # maintain the new realm configuration in the cache
        _delete_from_realm_config_cache(realm_name)
        _lookup_realm_config(realm_name, realm_resolvers)


def getRealms(aRealmName=""):
    """
    lookup for a defined realm or all realms

    :note:  the realms dict is inserted into the LinOtp Config object
    so that a lookup has not to reparse the whole config again

    :param aRealmName: a realmname - the realm, that is of interestet,
                                     if empty, all realms are returned
    :type  aRealmName: string

    :return:  a dict with realm description like
    :rtype :  dict : {
                u'myotherrealm': {
                    'realmname': u'myotherrealm',
                    'useridresolver': [
                        'useridresolver.PasswdIdResolver.IdResolver.myOtherRes'
                        ],
                    'entry': u'linotp.useridresolver.group.myotherrealm'},
                u'mydefrealm': {
                    'default': 'true',
                    'realmname': u'mydefrealm',
                    'useridresolver': [
                        'useridresolver.PasswdIdResolver.IdResolver.myDefRes'
                        ],
                    'entry': u'linotp.useridresolver.group.mydefrealm'},
               u'mymixrealm': {
                    'realmname': u'mymixrealm',
                    'useridresolver': [
                        'useridresolver.PasswdIdResolver.IdResolver.myOtherRes',
                        'useridresolver.PasswdIdResolver.IdResolver.myDefRes'
                        ],
                    entry': u'linotp.useridresolver.group.mymixrealm'}}

    """

    admin_realm_name = current_app.config["ADMIN_REALM_NAME"].lower()

    config = context["Config"]
    realms = config.getRealms()

    # only parse once per session
    if realms is None:
        realms = _initalGetRealms()
        config.setRealms(realms)

    # -- ------------------------------------------------------------ --
    # for each realm definition we check if there are some
    # resolvers dropped from the former resolver list
    # in this case, we have to delete the realm_resolver_cache
    # which is used for the user resolver lookup for a given realm
    # -- ------------------------------------------------------------ --

    for realm_name, realm_defintion in realms.items():

        _check_for_cache_flush(realm_name, realm_defintion)

        realm_defintion["admin"] = realm_name == admin_realm_name

    # check if any realm is searched
    if not isinstance(aRealmName, str):
        return realms

    aRealmName = aRealmName.strip().lower()

    # check if only one realm is searched
    if aRealmName in realms:
        return {aRealmName: realms[aRealmName]}

    return realms


def _lookup_realm_config(realm_name, realm_defintion=None):
    """
    realm configuration cache handling -
        per realm the list of resolvers are stored

    - as the other caches, this cache lookup is using the inner function
    - the additional argument, the resolver definition is used to fill
      the cache

    :param realm_name: the realm name
    :param realm_defintion: the list of the resolvers

    :return: return the list of resolver strings or None
    """

    def __lookup_realm_config(realm_name, realm_definition=None):
        """
        realm definition lookup function which retrieves the value
            only called on a cache miss

        :param realm_name: the realm name
        :param realm_defintion: the list of the resolvers
               - used to fill the cache

        :return: return the list of resolver strings or None
        """

        if realm_definition:
            return json.dumps(realm_definition)

        log.debug("cache miss for realm with name %r", realm_name)
        return None

    realm_config_cache = _get_realm_config_cache()

    if not realm_config_cache:
        conf_entry = __lookup_realm_config(realm_name, realm_defintion)
        if conf_entry:
            conf_entry = json.loads(conf_entry)
        return conf_entry

    p_lookup_resolver_config = partial(
        __lookup_realm_config, realm_name, realm_defintion
    )

    p_key = realm_name

    conf_entry = realm_config_cache.get_value(
        key=p_key,
        createfunc=p_lookup_resolver_config,
    )

    if conf_entry:
        conf_entry = json.loads(conf_entry)
    return conf_entry


def _get_realm_config_cache():
    """
    helper - common getter to access the realm_config cache

    the realm config cache is used to track the realm definition
    changes. therefore for each realm name the realm config is stored
    in a cache. In case of an request the comparison of the realm config
    with the cache value is made and in case of inconsistancy the
    realm -> resolver cache could be flushed.

    :remark: This cache is only enabled, if the resolver user lookup cache
             is enabled too

    :return: the realm config cache
    """

    return get_cache(cache_name="realm_lookup")


def _delete_from_realm_config_cache(realm_name):
    """
    delete one entry from the realm config cache
    """
    realm_config_cache = _get_realm_config_cache()
    if realm_config_cache:
        realm_config_cache.remove_value(key=realm_name)


def _initalGetRealms():
    """
    initaly parse all config entries, and extract the realm definition

    :return : a dict with all realm definitions
    :rtype  : dict of definitions
    """

    Realms = {}
    defRealmConf = "linotp.useridresolver"
    realmConf = "linotp.useridresolver.group."
    defaultRealmDef = "linotp.DefaultRealm"
    defaultRealm = None

    dc = getLinotpConfig()
    for entry in dc:

        if entry.startswith(realmConf):

            # the realm might contain dots "."
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

            # resids          = env.config[entry]
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
        """
        there could be only one default realm
        - all other defaults will be removed
        """
        r = realms.get(k)
        if k == defaultRealm.lower():
            r["default"] = "true"
            ret = True
        else:
            if "default" in r:
                del r["default"]
    return ret


def isRealmDefined(realm):
    """
    check, if a realm already exists or not

    :param realm: the realm, that should be verified
    :type  realm: string

    :return :found or not found
    :rtype  :boolean
    """
    ret = False
    realms = getRealms()
    if realm.lower() in realms:
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

    # TODO: verify merge
    if check_if_exists:
        ret = isRealmDefined(defaultRealm)
    else:
        ret = True

    if ret is True or defaultRealm == "":
        storeConfig("linotp.DefaultRealm", defaultRealm)

    return ret


def getDefaultRealm(config=None):
    """
    return the default realm
    - lookup in the config for the DefaultRealm key

    :return: the realm name
    :rtype : string
    """

    defaultRealmDef = "linotp.DefaultRealm"
    if not config:
        defaultRealm = getFromConfig(defaultRealmDef, "")
    else:
        defaultRealm = config.get(defaultRealmDef, "")

    if defaultRealm is None or defaultRealm == "":
        log.info("Configuration issue: No default realm defined.")
        defaultRealm = ""

    return defaultRealm.lower()


def deleteRealm(realmname):
    """
    delete the realm from the Database Table with the given name

    :param realmname: the to be deleted realm
    :type  realmname: string
    """

    log.debug("deleting realm object with name=%s", realmname)
    r = getRealmObject(name=realmname)
    if r is None:
        """if no realm is found, we re-try the lowercase name for backward compatibility"""
        r = getRealmObject(name=realmname.lower())
    realmId = 0
    if r is not None:
        realmId = r.id

        if realmId != 0:
            log.debug("Deleting token relations for realm with id %r", realmId)
            TokenRealm.query.filter_by(realm_id=realmId).delete()
        db.session.delete(r)

    else:
        log.warning("Realm with name %s was not found.", realmname)
        return False
    # now delete all relations, i.e. remove all Tokens from this realm.

    # finally we delete the 'realmname' cache
    from linotp.lib.user import delete_realm_resolver_cache

    delete_realm_resolver_cache(realmname)

    return True


def match_realms(request_realms, allowed_realms):
    """
    Check if all requested realms are also allowed realms
    and that all allowed realms exist and
    return a filtered list with only the matched realms.
    In case of '*' in reques_realms, return all allowed realms
    including /:no realm:/

    :param allowed_realms: list of realms from request (without '*')
    :param request_realms: list of allowed realms according to policies
    :return: list of realms which were in both lists
    """

    all_realms = list(getRealms().keys())
    all_allowed_realms = set()
    for realm in allowed_realms:
        if realm in all_realms:
            all_allowed_realms.add(realm)
        else:
            log.info("Policy allowed a realm that does not exist: %r", realm)

    realms = []

    _ = context["translate"]

    if not request_realms or request_realms == [""]:
        realms = list(all_allowed_realms)
    # support for empty realms or no realms by realm = *
    elif "*" in request_realms:
        realms = list(all_allowed_realms)
        realms.append("/:no realm:/")
    # other cases, we iterate through the realm list
    elif len(request_realms) > 0 and not (request_realms == [""]):
        invalid_realms = []
        for search_realm in request_realms:
            search_realm = search_realm.strip().lower()
            if search_realm in all_allowed_realms:
                realms.append(search_realm)
            elif search_realm == "/:no realm:/":
                realms.append(search_realm)
            else:
                invalid_realms.append(search_realm)
        if not realms and invalid_realms:
            from linotp.lib.policy import PolicyException

            raise PolicyException(
                _(
                    "You do not have the rights to see these "
                    "realms: %r. Check the policies!"
                )
                % invalid_realms
            )

    return realms


def get_realms_from_params(param, acls=None):

    if "realm" not in param or param["realm"] == "*":

        if acls and acls["active"]:

            if "*" in acls["realms"]:
                return getRealms().keys()

            return acls["realms"]

        return getRealms().keys()

    realm = param["realm"]

    if realm.strip() == "":
        return [getDefaultRealm()]

    return [x.strip() for x in realm.split(",")]


# eof ########################################################################
