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

"""
test to verify that the linotp cli for admin fix-db-encoding

the test does not cover a real conversion as this could only be verified
against a mysql database which could not be used in a unit test
"""

import pytest
from datetime import datetime
from pathlib import Path

from linotp.cli import main as cli_main



@pytest.fixture
def runner(app):
    """Set common configuration."""

    env = {
        'LINOTP_AUDIT_DATABASE_URI': 'OFF',  # FIXME: 'SHARED',
    }
    return app.test_cli_runner(env=env, mix_stderr=False, echo_stdin=True)


def test_fix_db_encoding(app, runner, freezer):
    """Verify the fix-db-encoding will be triggerd.

    1.
      a: insert iso8859 encode data and
      b: set flag that conversion is suggested

    2. run conversion by cli command

    3.
      a: verify that the iso8859 data is now in utf format
      b: the conversion flag is removed

    """

    from linotp import model
    from linotp.model import db

    # --------------------------------------------------------------------- --

    #1. add db entries

    db.init_app(app)

    # 1.a add iso8859 encoded data

    utf8_str = 'äöüß€'
    iso8859_15_str = bytes(utf8_str, encoding='utf-8').decode('iso-8859-15')

    assert utf8_str != iso8859_15_str

    config_entry = model.Config(
        Key='test_encode', Value=iso8859_15_str
        )
    model.db.session.add(config_entry)

    # 1.b add conversion suggested flag

    config_entry = model.Config(
        Key='utf8_conversion', Value='suggested'
        )

    model.db.session.add(config_entry)
    model.db.session.commit()

    # --------------------------------------------------------------------- --

    # 2. run cli command for conversion

    result = runner.invoke(cli_main, ['admin', 'fix-db-encoding'])
    assert result.exit_code == 0

    # --------------------------------------------------------------------- --

    # 3.a check that the data is converted

    converted = model.Config.query.filter(
        model.Config.Key == 'linotp.test_encode').first()

    assert converted.Value == utf8_str

    # 3.b and the flag is removed

    conversion_flag = model.Config.query.filter(
        model.Config.Key == "linotp.utf8_conversion").first()

    assert conversion_flag is None

def test_migration(app, runner, freezer):
    """Verify the that the conversion hint is set.

    1.
      a: add Comfig timestamp and
      b: set db schema version to pre 3.0

    2. run linotp init database to set the conversion hint

    3.
      a: the conversion flag is set and
      b: the db schema version is updated

    """

    from linotp import model
    from linotp.model import db

    # --------------------------------------------------------------------- --

    #1. add db entries

    db.init_app(app)

    # 1.a add Config timestamp if not there - for is_untouched

    config_timestamp = model.Config.query.filter(
        model.Config.Key == "linotp.Config").first()

    if config_timestamp is None:

        config_entry = model.Config(
            Key='Config', Value='2020-12-02 10:42:07'
            )
        model.db.session.add(config_entry)

    # 1.b set db schema version to pre 3.0

    db_schema_version_pre = '2.12.0.0'

    db_schema = model.Config.query.filter(
        model.Config.Key == "linotp.sql_data_model_version").first()

    if db_schema is not None:

        update_data = {
            model.Config.Value: db_schema_version_pre,
        }

        # replace by the primary key: Key

        model.Config.query.filter(
            model.Config.Key == db_schema.Key
            ).update(update_data , synchronize_session = False)

    else:

        config_entry = model.Config(
            Key='sql_data_model_version', Value=db_schema_version_pre
            )

        model.db.session.add(config_entry)

    model.db.session.commit()

    # --------------------------------------------------------------------- --

    # 2. run cli command for mogration

    result = runner.invoke(cli_main, ['init', 'database'])
    assert result.exit_code == 0

    # --------------------------------------------------------------------- --

    # 3.a cobversion flag is set

    conversion_flag = model.Config.query.filter(
        model.Config.Key == "linotp.utf8_conversion").first()

    assert conversion_flag and conversion_flag.Value == 'suggested'

    # 3.b check that the db schema version is updated

    converted = model.Config.query.filter(
        model.Config.Key == 'linotp.sql_data_model_version').first()

    assert converted.Value != db_schema_version_pre
