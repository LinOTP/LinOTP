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
"""
The security provider is a dynamic handler for security relevant tasks like
random, crypt, decrypt, sign
"""

import _thread
import time
import logging

from linotp.lib.rw_lock import RWLock
from linotp.lib.crypto.utils import zerome
from linotp.lib.error import HSMException
from linotp.lib.security import FatalHSMException

DEFAULT_KEY = 0
CONFIG_KEY = 1
TOKEN_KEY = 2
VALUE_KEY = 3


log = logging.getLogger(__name__)


class SecurityProvider(object):
    """
    the security provider is the singleton in the server who provides
    the security modules to run security relevant methods

    - read the hsm configurations
    - set up a pool of hsm modules
    - bind a hsm to one session
    - free the hsm from session after usage

    the thread id is used as session identifier
    """

    def __init__(self):
        """
        setup the security provider, which is called on server startup
        from the flask app init

        :param secLock: RWLock() to support server wide locking
        :type  secLock: RWLock

        :return: -

        """
        self.config = {}
        self.security_modules = {}
        self.activeOne = "default"
        self.hsmpool = {}
        self.rwLock = RWLock()
        self.max_retry = 5

    def load_config(self, config):
        """
        load the security modules configuration
        """

        try:
            security_provider = config.get("ACTIVE_SECURITY_MODULE", "default")
            self.activeOne = security_provider  # self.active one is legacy.. therefore we set it here
            log.debug(
                "[SecurityProvider:load_config] setting active"
                " security module: %s",
                self.activeOne,
            )

            # add active provider config to self.config with the active
            # provider as key and the config dict as value
            if self.activeOne == "default":
                default_security_provider_config = config.get(
                    "HSM_DEFAULT_CONFIG"
                )
                keyFile = config["SECRET_FILE"]
                default_security_provider_config["file"] = keyFile
                security_provider_config = {
                    "default": default_security_provider_config
                }
                self.config.update(security_provider_config)

            if self.activeOne == "pkcs11":
                security_provider_config = {
                    "pkcs11": config.get("HSM_PKCS11_CONFIG")
                }
                self.config.update(security_provider_config)

        except Exception as e:
            log.exception("[load_config] failed to identify module")
            error = "failed to identify module: %r " % e
            raise HSMException(error, id=707)

        # now create a pool of hsm objects for each module
        self.rwLock.acquire_write()
        try:
            for id in self.config:
                self.createHSMPool(id)
        finally:
            self.rwLock.release()

        return

    def loadSecurityModule(self, id=None):
        """
        return the specified security module

        :param id:  identifier for the security module (from the configuration)
        :type  id:  String or None

        :return:    None or the created object
        :rtype:     security module
        """

        ret = None

        if id is None:
            id = self.activeOne

        log.debug("[loadSecurityModule] Loading module %s" % id)

        if id not in self.config:
            return ret

        config = self.config.get(id)
        if "module" not in config:
            return ret

        module = config.get("module")
        methods = ["encrypt", "decrypt", "random", "setup_module"]
        method = ""

        parts = module.split(".")
        className = parts[-1]
        packageName = ".".join(parts[:-1])

        mod = __import__(packageName, globals(), locals(), [className], 0)
        klass = getattr(mod, className)
        config_name = klass.getAdditionalClassConfig()
        additional_config = self.get_config_entries(config_name)

        for method in methods:
            if hasattr(klass, method) is False:
                error = (
                    "[loadSecurityModule] Security Module %r misses the "
                    "following interface: %r" % (module, method)
                )
                log.error(error)
                raise NameError(error)

        ret = klass(config, add_conf=additional_config)
        self.security_modules[id] = ret

        log.debug("[loadSecurityModule] returning %r" % ret)

        return ret

    def get_config_entries(self, config_name):
        """
        :param names: list of config entries by modulename
        :return: dict
        """
        merged_config = {}

        for provider, provider_config in list(self.config.items()):

            module = provider_config.get("module")
            provider_class = module.split(".")[-1]
            if provider_class in config_name:
                merged_config = self.config[provider]

        return merged_config

    def _getHsmPool_(self, hsm_id):
        ret = None
        if hsm_id in self.hsmpool:
            ret = self.hsmpool.get(hsm_id)
        return ret

    def setupModule(self, hsm_id, config=None):
        """
        setupModule is called during runtime to define
        the config parameters like password or connection strings
        """
        self.rwLock.acquire_write()
        try:
            pool = self._getHsmPool_(hsm_id)
            if pool is None:
                error = (
                    "[setupModule] failed to retieve pool "
                    "for hsm_id: %r" % hsm_id
                )
                log.error(error)
                raise HSMException(error, id=707)

            for entry in pool:
                hsm = entry.get("obj")
                hsm.setup_module(config)

            self.activeOne = hsm_id
        except Exception as e:
            error = "[setupModule] failed to load hsm : %r" % e
            log.exception(error)
            raise HSMException(error, id=707)

        finally:
            self.rwLock.release()
        return self.activeOne

    def createHSMPool(self, hsm_id=None, *args, **kw):
        """
        setup a pool of security providers
        """
        pool = None
        # amount has to be taken from the hsm-id config
        if hsm_id is None:
            provider_ids = self.config
        else:
            if hsm_id in self.config:
                provider_ids = []
                provider_ids.append(hsm_id)
            else:
                error = "[createHSMPool] failed to find hsm_id: %r" % hsm_id
                log.error(error)
                raise HSMException(error, id=707)

        for provider_id in provider_ids:
            pool = self._getHsmPool_(provider_id)
            log.debug("[createHSMPool] already got this pool: %r" % pool)
            if pool is None:
                # get the number of entries from the hsd (id) config
                conf = self.config.get(provider_id)
                poolsize = int(conf.get("poolsize", 10))
                log.debug(
                    "[createHSMPool] creating pool for %r with size %r",
                    provider_id,
                    poolsize,
                )

                pool = []
                for _i in range(0, poolsize):
                    error = ""
                    hsm = None
                    try:
                        hsm = self.loadSecurityModule(provider_id)
                    except FatalHSMException as exx:
                        log.exception(
                            "[createHSMPool] %r %r ", provider_id, exx
                        )
                        if provider_id == self.activeOne:
                            raise exx
                        error = "%r: %r" % (provider_id, exx)

                    except Exception as exx:
                        log.exception("[createHSMPool] %r ", exx)
                        error = "%r: %r" % (provider_id, exx)

                    pool.append({"obj": hsm, "session": 0, "error": error})

                self.hsmpool[provider_id] = pool
        return pool

    def _findHSM4Session(self, pool, sessionId):
        found = None
        # find session
        for hsm in pool:
            hsession = hsm.get("session")
            if hsession == sessionId:
                found = hsm
        return found

    def _createHSM4Session(self, pool, sessionId):
        found = None
        for hsm in pool:
            hsession = hsm.get("session")
            if str(hsession) == "0":
                hsm["session"] = sessionId
                found = hsm
                break
        return found

    def _freeHSMSession(self, pool, sessionId):
        hsm = None
        for hsm in pool:
            hsession = hsm.get("session")
            if str(hsession) == str(sessionId):
                hsm["session"] = 0
                break
        return hsm

    def dropSecurityModule(self, hsm_id=None, sessionId=None):
        found = None
        if hsm_id is None:
            hsm_id = self.activeOne
        if sessionId is None:
            sessionId = str(_thread.get_ident())

        if hsm_id not in self.config:
            error = (
                "[SecurityProvider:dropSecurityModule] no config found "
                "for hsm with id %r " % hsm_id
            )
            log.error(error)
            raise HSMException(error, id=707)
            return None

        # find session
        try:
            pool = self._getHsmPool_(hsm_id)
            self.rwLock.acquire_write()
            found = self._findHSM4Session(pool, sessionId)
            if found is None:
                log.info(
                    "[SecurityProvider:dropSecurityModule] could not bind "
                    "hsm to session %r " % hsm_id
                )
            else:
                self._freeHSMSession(pool, sessionId)
        finally:
            self.rwLock.release()
        return True

    def getSecurityModule(self, hsm_id=None, sessionId=None):
        found = None
        if hsm_id is None:
            hsm_id = self.activeOne
        if sessionId is None:
            sessionId = str(_thread.get_ident())

        if hsm_id not in self.config:
            error = (
                "[SecurityProvider:getSecurityModule] no config found for "
                "hsm with id %r " % hsm_id
            )
            log.error(error)
            raise HSMException(error, id=707)

        retry = True
        tries = 0
        locked = False

        while retry is True:
            try:
                pool = self._getHsmPool_(hsm_id)
                self.rwLock.acquire_write()
                locked = True
                # find session
                found = self._findHSM4Session(pool, sessionId)
                if found is not None:
                    # if session is ok - return
                    self.rwLock.release()
                    locked = False
                    retry = False
                    log.debug(
                        "[getSecurityModule] using existing pool session %s"
                        % found
                    )
                    return found
                else:
                    # create new entry
                    log.debug(
                        "[getSecurityModule] getting new Session (%s) "
                        "from pool %s" % (sessionId, pool)
                    )
                    found = self._createHSM4Session(pool, sessionId)
                    self.rwLock.release()
                    locked = False
                    if found is None:
                        tries += 1
                        delay = 1 + int(0.2 * tries)
                        log.warning(
                            "try %d: could not bind hsm to session  - "
                            "going to sleep for %r" % (tries, delay)
                        )
                        time.sleep(delay)
                        if tries >= self.max_retry:
                            error = (
                                "[SecurityProvider:getSecurityModule] "
                                "%d retries: could not bind hsm to "
                                "session for %d seconds" % (tries, delay)
                            )
                            log.error(error)
                            raise Exception(error)
                        retry = True
                    else:
                        retry = False

            finally:
                if locked is True:
                    self.rwLock.release()

        return found


def main():
    class DummySecLock:
        def release(self):
            return

        def acquire_write(self):
            return

    # hook for local provider test
    sep = SecurityProvider(secLock=DummySecLock())
    sep.load_config({})
    sep.createHSMPool("default")
    sep.setupModule("default", {"passwd": "test123"})

    # runtime catch an hsm for session
    hsm = sep.getSecurityModule()

    passwo = "password"
    encpass = hsm.encryptPassword(passwo)
    passw = hsm.decryptPassword(encpass)

    zerome(passw)

    hsm2 = sep.getSecurityModule(sessionId="session2")

    passwo = "password"
    encpass = hsm2.encryptPassword(passwo)
    passw = hsm2.decryptPassword(encpass)

    zerome(passw)

    # session shutdown
    sep.dropSecurityModule(sessionId="session2")
    sep.dropSecurityModule()

    return True


if __name__ == "__main__":

    main()
