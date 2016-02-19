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
migration controller -
    support the migration of encrypted data towards
    new encryption key or mew hsm
"""

import os

try:
    import json
except ImportError:
    import simplejson as json

import binascii
import hashlib

from pylons import request, response

from linotp.model.meta import Session

from linotp.lib.base import BaseController

from linotp.lib.reply   import sendResult, sendError

from linotp.lib.policy import PolicyException
from linotp.lib.migrate import MigrationHandler
from linotp.lib.migrate import DecryptionError

import logging
log = logging.getLogger(__name__)


class MigrateController(BaseController):
    '''
    '''

    def __before__(self, action, **params):
        '''
        __before__ is called before every action
             so we can check the authorization (fixed?)

        :param action: name of the to be called action
        :param params: the list of http parameters

        :return: return response
        :rtype:  pylon response
        '''
        log.debug("[__before__::%r] %r" % (action, params))
        try:

            return response

        except Exception as exx:
            log.exception("[__before__::%r] exception %r" % (action, exx))
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')

        finally:
            log.debug("[__before__::%r] done" % (action))

    def __after__(self):
        '''
        __after is called after every action

        :return: return the response
        :rtype:  pylons response
        '''
        try:
            return response

        except Exception as exx:
            log.exception("[__after__] exception %r" % (exx))
            Session.rollback()
            return sendError(response, exx, context='after')

        finally:
            Session.close()
            log.debug("[__after__] done")

    def backup(self):
        """
        create a backup of
        - the encrypted token data, which could be
            seed or pin (if encrypted) or userpin (used in motp, ocra)
        - the config entries of type password

        the data
            - is encrypte with a given passphrase
            - and stored in an backup file (defined by the hash of backupid)

        :param pass: passphrase used for encrypting data in the backup file
        :param backupid: used to controll the intermediate backup file

        """
        params = {}
        try:
            params.update(request.params)

            try:
                backupid = params['backupid']
                passphrase = params['pass']
            except KeyError as exx:
                raise Exception("missing Parameter:%r" % exx)

            backup_data = {}

            mig = MigrationHandler()
            salt = mig.setup(passphrase=passphrase)

            # create the backup file
            b_name = hashlib.sha256(backupid).digest()[:16]
            b_name = "%s.hbak" % binascii.hexlify(b_name)

            with open(b_name, 'w') as f:
                f.write(json.dumps({'Salt': binascii.hexlify(salt)}))
                f.write("\n")

                i = 0
                for data in mig.get_config_items():
                    f.write(json.dumps({"Config": data}))
                    f.write("\n")
                    i += 1
                backup_data["Config"] = i

                i = 0
                for data in mig.get_token_data():
                    f.write(json.dumps({"Token": data}))
                    f.write("\n")
                    i += 1
                backup_data["Token"] = i

                mac = mig.calculate_mac(json.dumps(backup_data))
                f.write(json.dumps({"Counter": backup_data,
                                    'mac': binascii.hexlify(mac)}))
                f.write("\n")

            result = {}
            for val in ['Token', 'Config']:
                result[val] = backup_data[val]

            return sendResult(response, result)

        except PolicyException as pe:
            log.exception('[show] policy failed: %r' % pe)
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception('[show] failed: %r' % e)
            return sendError(response, e)

        finally:
            log.debug("[show] done")

    def restore(self):
        """
        restore the encrypted config and token data from a backup file

        the restore relies on a backup file, which was created by
        the migrate/backup command. The file contains per line a config or
        token entry, where each line is a json dump. The first line of the
        backup file contains the salt, the last one the number of entries
        written

        :param pass: passphrase used for encrypting data in the backup file
        :param backupid: used to controll the intermediate backup file
        :param remove_backup (optional): if set to False, backup file will not
                be deleted after backup.
                Default is that backup is deleted, even in case of error

        """
        params = {}
        backup_file = ""
        remove_backup_file = True

        # error conditions
        missing_param = False
        decryption_error = False

        try:
            params.update(request.params)

            try:
                backupid = params['backupid']
                passphrase = params['pass']
                remove_backup_file = (
                            params.get("remove_backup", "True") == "True")
            except KeyError as exx:
                missing_param = True
                raise Exception("missing Parameter:%r" % exx)

            mig = None

            # get the backup file
            backup_file = hashlib.sha256(backupid).digest()[:16]
            backup_file = "%s.hbak" % binascii.hexlify(backup_file)

            if not os.path.isfile(backup_file):
                raise Exception("No restore file found for backupid=%s"
                                % backupid)

            counters = {}
            counter_check_done = False
            with open(backup_file, 'r') as f:
                for data in f.readlines():

                    if not data.strip():  # skip empty lines
                        continue

                    restore_data = json.loads(data)

                    if not mig and  "Salt" in restore_data:
                        salt = restore_data["Salt"]
                        mig = MigrationHandler()
                        mig.setup(passphrase=passphrase,
                                  salt=binascii.unhexlify(salt))

                    elif "Config" in restore_data and mig:
                        config_entry = restore_data['Config']
                        mig.set_config_entry(config_entry)
                        counters["Config"] = counters.get("Config", 0) + 1

                    elif "Token" in restore_data and mig:
                        token_entry = restore_data['Token']
                        mig.set_token_data(token_entry)
                        counters["Token"] = counters.get("Token", 0) + 1

                    # Counters is the last entry - compare the counters
                    elif "Counter" in restore_data and mig:

                        # check inzegryty for 'number of entries'
                        backup_data = restore_data["Counter"]

                        mac = mig.calculate_mac(json.dumps(backup_data))
                        if binascii.hexlify(mac) != restore_data["mac"]:
                            raise Exception("Restore Lines mismatch")

                        if (restore_data["Counter"].get("Token") !=
                                counters.get("Token", 0)):
                            raise Exception("Restore Token mismatch")

                        if (restore_data["Counter"].get("Config") !=
                                counters.get("Config", 0)):
                            raise Exception("Restore Config mismatch")

                        counter_check_done = True

                    else:
                        if not mig:
                            raise Exception('MigrationHandler not initialized!')
                        else:
                            log.info("unknown entry")

            # if somebody removed the last line, we cry for it
            if not counter_check_done:
                raise Exception('incomplete migration file!')

            return sendResult(response, counters)

        except PolicyException as pe:
            log.exception('[show] policy failed: %r' % pe)
            return sendError(response, unicode(pe), 1)

        except DecryptionError as err:
            decryption_error = True
            log.exception('Error - failed with %r' % err)
            Session.rollback()
            return sendError(response, err)

        except Exception as err:
            log.exception('Error - failed with %r' % err)
            Session.rollback()
            return sendError(response, err)

        finally:
            if remove_backup_file and os.path.isfile(backup_file):
                if not missing_param and not decryption_error:
                    os.remove(backup_file)
            Session.close()
            log.debug("[restore] done")

#eof###########################################################################
