# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2019 KeyIdentity GmbH
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

import imp
import os
import unittest

from mock import patch
from sqlalchemy.engine import create_engine

# from linotp.lib.audit.SQLAudit import metadata as audit_metadata
from linotp.model import db

# -------------------------------------------------------------------------- --


class ScriptTester(unittest.TestCase):
    """
    Base class for unit testing linotp scripts
    """

    script_name = None
    "The script file we are testing. Set to name of script in the child class"

    script_module = None
    "The module under test. This is loaded directly to allow underscores in the filename"

    def setUp(self):
        super(ScriptTester, self).setUp()
        self.load_script(self.script_name)

        self.engine_patcher = self.create_database_patcher()
        self.engine_patcher.start()

    def tearDown(self):
        self.engine_patcher.stop()

    def create_database_patcher(self):
        """
        Create an in memory database, and a mock patcher for create_engine.

        This ensures that our in memory database is used when the scripts
        access the database
        """
        self.engine = self.setup_database_in_memory()
        engine_patcher = patch(
            ".".join([self.script_module.__name__, "create_engine"]),
            return_value=self.engine,
        )
        return engine_patcher

    def load_script(self, scriptname):
        """
        Load script directly from sources directory
        """
        testscriptdir = os.path.dirname(os.path.realpath(__file__))
        scriptpath = os.path.join(
            testscriptdir, "..", "..", "..", "..", "tools", scriptname
        )

        with patch("logging.config.fileConfig"):
            self.script_module = imp.load_source(
                scriptname.replace("-", "_"), scriptpath
            )

        assert self.script_module is not None

    def setup_database_in_memory(self):
        engine = create_engine("sqlite://")

        # Create blank databases
        db.create_all(engine)

        return engine
