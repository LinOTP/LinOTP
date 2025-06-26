#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

"""
migration controller -
    support the migration of encrypted data towards
    new encryption key or new hsm
"""

import binascii
import hashlib
import json
import logging
import os

from linotp.controllers.base import BaseController, methods
from linotp.lib.migrate import DecryptionError, MigrationHandler
from linotp.lib.policy import PolicyException
from linotp.lib.reply import sendError, sendResult
from linotp.model import db

log = logging.getLogger(__name__)


class MigrateController(BaseController):
    """"""

    def __before__(self, **params):
        """
        __before__ is called before every action
             so we can check the authorization (fixed?)

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'
        """

        return

    @staticmethod
    def __after__(response):
        """
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        """
        return response

    @methods(["POST"])
    def backup(self):
        """
        create a backup of
          - the encrypted token data, which could be
            seed or pin (if encrypted) or userpin (used in motp, ocra2)
          - the config entries of type password

        the data
            - is encrypted with a given passphrase
            - and stored in an backup file (defined by the hash of backupid)

        :param pass: passphrase used for encrypting data in the backup file
        :param backupid: used to control the intermediate backup file

        """

        try:
            try:
                backupid = self.request_params["backupid"]
                passphrase = self.request_params["pass"]
            except KeyError as exx:
                raise Exception(f"missing Parameter:{exx!r}") from exx

            backup_data = {}

            mig = MigrationHandler()
            salt = mig.setup(passphrase=passphrase)

            # create the backup file
            b_name = hashlib.sha256(backupid).digest()[:16]
            b_name = f"{binascii.hexlify(b_name)}.hbak"

            with open(b_name, "w") as f:
                f.write(json.dumps({"Salt": binascii.hexlify(salt)}))
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
                f.write(
                    json.dumps({"Counter": backup_data, "mac": binascii.hexlify(mac)})
                )
                f.write("\n")

            result = {}
            for val in ["Token", "Config"]:
                result[val] = backup_data[val]

            return sendResult(result)

        except PolicyException as pe:
            db.session.rollback()
            log.error("[backup] policy failed: %r", pe)
            return sendError(pe, 1)

        except Exception as exx:
            db.session.rollback()
            log.error("[backup] failed: %r", exx)
            return sendError(exx)

    @methods(["POST"])
    def restore(self):
        """
        restore the encrypted config and token data from a backup file

        the restore relies on a backup file, which was created by
        the migrate/backup command. The file contains per line a config or
        token entry, where each line is a json dump. The first line of the
        backup file contains the salt, the last one the number of entries
        written

        :param pass: passphrase used for encrypting data in the backup file
        :param backupid: used to control the intermediate backup file
        :param remove_backup (optional): if set to False, backup file will not
                be deleted after backup.
                Default is that backup is deleted, even in case of error

        """
        backup_file = ""
        remove_backup_file = True

        # error conditions
        missing_param = False
        decryption_error = False

        try:
            try:
                backupid = self.request_params["backupid"]
                passphrase = self.request_params["pass"]
                remove_backup_file = (
                    self.request_params.get("remove_backup", "true").lower() == "true"
                )
            except KeyError as exx:
                missing_param = True
                raise Exception(f"missing Parameter:{exx!r}") from exx

            mig = None

            # get the backup file
            backup_file = hashlib.sha256(backupid).digest()[:16]
            backup_file = f"{binascii.hexlify(backup_file)}.hbak"

            if not os.path.isfile(backup_file):
                raise Exception(f"No restore file found for backupid={backupid}")

            counters = {}
            counter_check_done = False
            with open(backup_file) as f:
                for data in f.readlines():
                    if not data.strip():  # skip empty lines
                        continue

                    restore_data = json.loads(data)

                    if not mig and "Salt" in restore_data:
                        salt = restore_data["Salt"]
                        mig = MigrationHandler()
                        mig.setup(
                            passphrase=passphrase,
                            salt=binascii.unhexlify(salt),
                        )

                    elif "Config" in restore_data and mig:
                        config_entry = restore_data["Config"]
                        mig.set_config_entry(config_entry)
                        counters["Config"] = counters.get("Config", 0) + 1

                    elif "Token" in restore_data and mig:
                        token_entry = restore_data["Token"]
                        mig.set_token_data(token_entry)
                        counters["Token"] = counters.get("Token", 0) + 1

                    # Counters is the last entry - compare the counters
                    elif "Counter" in restore_data and mig:
                        # check integrity for 'number of entries'
                        backup_data = restore_data["Counter"]

                        mac = mig.calculate_mac(json.dumps(backup_data))
                        if binascii.hexlify(mac) != restore_data["mac"]:
                            raise Exception("Restore Lines mismatch")

                        if restore_data["Counter"].get("Token") != counters.get(
                            "Token", 0
                        ):
                            raise Exception("Restore Token mismatch")

                        if restore_data["Counter"].get("Config") != counters.get(
                            "Config", 0
                        ):
                            raise Exception("Restore Config mismatch")

                        counter_check_done = True

                    else:
                        if not mig:
                            raise Exception("MigrationHandler not initialized!")
                        else:
                            log.info("unknown entry")

            # if somebody removed the last line, we cry for it
            if not counter_check_done:
                raise Exception("incomplete migration file!")

            db.session.commit()
            log.debug("[restore] success")
            return sendResult(counters)

        except PolicyException as pe:
            log.error("[restore] policy failed: %r", pe)
            return sendError(pe, 1)

        except DecryptionError as err:
            decryption_error = True
            log.error("Error - failed with %r", err)
            db.session.rollback()
            return sendError(err)

        except Exception as err:
            log.error("Error - failed with %r", err)
            db.session.rollback()
            return sendError(err)

        finally:
            if remove_backup_file and os.path.isfile(backup_file):
                if not missing_param and not decryption_error:
                    os.remove(backup_file)
                    log.debug("removed backup file %r", backup_file)


# eof #########################################################################
