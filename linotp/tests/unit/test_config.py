# Unit tests for the LinOTP 3 configuration mechanism

import os
import re
from pathlib import PosixPath

import pytest

from linotp import settings as s
from linotp.app import ExtFlaskConfig, _configure_app

# Tests for validation functions.


def validate_result_tester(validate, value, result, msg):
    if result == "OK":
        assert validate("k", value) is None
    else:
        with pytest.raises(s.LinOTPConfigValueError) as ex:
            validate("k", value)
        assert str(ex.value) == msg


@pytest.mark.parametrize(
    "min,max,value,result,msg",
    [
        (0, None, 0, "OK", ""),
        (0, None, -1, "ERR", "k is -1 but must be at least 0"),
        (0, None, 999999999, "OK", ""),
        (None, 0, 1, "ERR", "k is 1 but must be at most 0"),
        (None, 0, 0, "OK", ""),
        (None, 0, -999999999, "OK", ""),
        (0, 10, 0, "OK", ""),
        (0, 10, 10, "OK", ""),
        (0, 10, -1, "ERR", "k is -1 but must be at least 0"),
        (0, 10, 11, "ERR", "k is 11 but must be at most 10"),
    ],
)
def test_check_int_in_range_result(min, max, value, result, msg):
    validate_result_tester(s.check_int_in_range(min, max), value, result, msg)


@pytest.mark.parametrize(
    "min,max,doc",
    [
        (0, None, "value >= 0"),
        (None, 0, "value <= 0"),
        (0, 1, "0 <= value <= 1"),
    ],
)
def test_check_int_in_range_doc(min, max, doc):
    validate = s.check_int_in_range(min, max)
    assert validate.__doc__ == doc


json_schema = {
    "type": "object",
    "properties": {
        "foo": {"type": "string", "maxLength": 5},
        "bar": {"type": "integer"},
    },
    "required": [
        "foo",
    ],
}


@pytest.mark.parametrize(
    "schema,value,result",
    [
        (json_schema, {"foo": "baz", "bar": 123}, "OK"),
        (json_schema, {"foo": "yabbadabbadoo", "bar": 123}, "ERR"),
        (json_schema, {"foo": "baz", "bar": "quux"}, "ERR"),
        (json_schema, {"foo": "baz", "bar": 123.45}, "ERR"),
        (json_schema, {"foo": "baz"}, "OK"),
        (json_schema, {"bar": 123}, "ERR"),  # required `foo` missing
    ],
)
def test_check_json_schema(schema, value, result):
    validator = s.check_json_schema(schema)
    if result == "OK":
        assert validator("k", value) is None
    else:
        with pytest.raises(s.LinOTPConfigValueError) as ex:
            validator("k", value)
        assert str(ex.value) == f"{value} does not agree with schema {schema}."


@pytest.mark.parametrize(
    "allowed,value,result,msg",
    [
        ({"A", "B"}, "A", "OK", ""),
        ({"A", "B"}, "C", "ERR", "k is C but must be one of 'A', 'B'."),
    ],
)
def test_check_membership_result(allowed, value, result, msg):
    validate_result_tester(s.check_membership(allowed), value, result, msg)


def test_check_membership_doc():
    validate = s.check_membership({"A", "B"})
    assert validate.__doc__ == "value in {'A', 'B'}"


@pytest.mark.parametrize(
    "value,result,msg",
    [
        ("/foo", "OK", ""),
        ("bar", "ERR", "k must be an absolute path name but bar is relative."),
        ("", "ERR", "k must be an absolute path name but  is relative."),
    ],
)
def test_check_absolute_pathname_result(value, result, msg):
    validate_result_tester(s.check_absolute_pathname(), value, result, msg)


def test_check_absolute_pathname_doc():
    validate = s.check_absolute_pathname()
    assert validate.__doc__ == "value is an absolute path name"


# Tests for `ConfigSchema`.


@pytest.fixture
def schema():
    return [
        s.ConfigItem("FOO", str, default="bar", help="help for FOO"),
        s.ConfigItem("BAZ", int, default=123, help="help for BAZ"),
        s.ConfigItem(
            "POS",
            int,
            validate=s.check_int_in_range(0, None),
            default=123,
            help="help for POS",
        ),
        s.ConfigItem(
            "CVT",
            int,
            convert=lambda s: int(s) + 1,
            default=0,
            help="help for CVT",
        ),
        s.ConfigItem(
            "DBURI",
            s.DBURI,
            convert=s.DBURI.from_string,
            default="",
            help="help for DBURI",
        ),
    ]


@pytest.mark.parametrize(
    "use_schema,refuse_unknown",
    [
        (False, False),
        (False, True),
        (True, False),
        (True, True),
    ],
)
def test_configschema_init(schema, use_schema, refuse_unknown):
    cs = s.ConfigSchema(schema if use_schema else None, refuse_unknown)
    assert cs.schema == ({item.name: item for item in schema} if use_schema else {})
    assert cs.refuse_unknown == refuse_unknown


@pytest.mark.parametrize(
    "key,result",
    [
        ("FOO", "OK"),
        ("BAZ", "OK"),
        ("QUUX", None),
    ],
)
def test_configschema_find_item(schema, key, result):
    cs = s.ConfigSchema(schema=schema)
    item = cs.find_item(key)
    if result == "OK":
        assert item.name == key
        assert item.help == f"help for {key}"
    else:
        assert item is None


@pytest.mark.parametrize(
    "key,value,refuse_unknown,result,result_value,warning",
    [
        ("FOO", "bar", False, "OK", "bar", None),
        ("BAZ", "456", False, "OK", 456, None),
        ("BAZ", 456, False, "OK", 456, None),
        ("XYZ", "666", False, "OK", "666", None),
        (
            "XYZ",
            "666",
            True,
            s.LinOTPConfigKeyError,
            "Unknown configuration item 'XYZ'",
            None,
        ),
        ("CVT", "123", False, "OK", 124, None),
        (
            "POS",
            "-123",
            False,
            s.LinOTPConfigValueError,
            "POS is -123 but must be at least 0",
            None,
        ),
        (
            "DBURI",
            "postgresql://foo/bar",
            False,
            "OK",
            "postgresql://foo/bar",
            None,
        ),
        (
            "DBURI",
            "postgres://foo/bar",
            False,
            "OK",
            "postgresql://foo/bar",
            r"^Rewriting DB URI 'postgres://.*' to 'postgresql://'$",
        ),
    ],
)
def test_configschema_check_item(
    schema,
    caplog,
    key,
    value,
    refuse_unknown,
    result,
    result_value,
    warning,
):
    cs = s.ConfigSchema(schema=schema, refuse_unknown=refuse_unknown)
    if result == "OK":
        value = cs.check_item(key, value)
        assert value == result_value
        if warning:
            assert len(caplog.records) == 1
            rec = caplog.records[0]
            assert re.match(warning, rec.message), "Not the expected warning"
        else:
            assert not caplog.records, "Didn't expect a warning but got one"
    else:
        with pytest.raises(result) as ex:
            cs.check_item(key, value)
        assert result_value in str(ex.value)


def test_configschema_as_dict_empty():
    cs = s.ConfigSchema()
    assert cs.as_dict() == {}


def test_configschema_as_dict_schema(schema):
    cs = s.ConfigSchema(schema=schema)
    assert cs.as_dict() == {item.name: item.default for item in schema}


# Tests for `ExtFlaskConfig`.


def test_efc_init(schema):
    cs = s.ConfigSchema(schema=schema)
    efc = ExtFlaskConfig("/")
    assert efc.config_schema is None
    efc = ExtFlaskConfig("/", config_schema=cs)
    assert efc.config_schema == cs


def test_efc_set_schema(schema):
    cs = s.ConfigSchema(schema=schema)
    efc = ExtFlaskConfig("/")
    assert efc.config_schema is None
    efc.set_schema(cs)
    assert efc.config_schema == cs


def test_efc_dunder_setitem_getitem_no_schema():
    """This tests the simplest code path."""
    efc = ExtFlaskConfig("/")
    efc["FOO"] = "bar"
    assert super(ExtFlaskConfig, efc).__getitem__("FOO") == "bar"
    assert efc["FOO"] == "bar"


@pytest.mark.parametrize(
    "item_name",
    [
        "BAR_DIR",
        "BAZ_FILE",
    ],
)
def test_efc_relative_file_hack(item_name):
    efc = ExtFlaskConfig("/")
    efc[item_name] = "quux"
    # We use a convoluted method to get at the actual value of `efc[…]`
    # because retrieving `efc[…]` directly will yield the result of
    # `os.path.join()`, which is a string.
    assert isinstance(
        super(ExtFlaskConfig, efc).__getitem__(item_name),
        ExtFlaskConfig.RelativePathName,
    )
    # In real life, `ROOT_DIR` will be `app.root_path`, but we're not in an
    # app context here. This doesn't matter because we're only testing that
    # `ROOT_DIR` is prepended to a relative path name; the actual value of
    # `ROOT_DIR` is immaterial.
    assert efc[item_name] == "/ROOT_DIR_UNSET/./quux"
    efc[item_name] = "/quux"
    assert efc[item_name] == "/quux"  # nothing prepended


def test_efc_relative_file_hack_btd():
    efc = ExtFlaskConfig("/")
    BTD = "BABEL_TRANSLATION_DIRECTORIES"
    efc[BTD] = "foo;/bar/baz"
    assert efc[BTD] == "/ROOT_DIR_UNSET/./foo;/bar/baz"


def test_efc_normal_get():
    efc = ExtFlaskConfig("/")
    efc["FOO"] = "bar"
    assert efc["FOO"] == efc.get("FOO")


@pytest.mark.parametrize(
    "default",
    [
        None,
        "baz",
    ],
)
def test_efc_normal_get_second_arg_deprecated(caplog, default):
    # This test ensures that calling `ExtFlaskConfig.get()` with an
    # undefined value emits a warning. This is because we don't want
    # people to scatter random default values all over the code. For
    # the time being we don't raise an actual exception but we might
    # get to that in the future.

    efc = ExtFlaskConfig("/")
    caplog.clear()

    assert efc.get("FOO_FILE", default) == default
    assert len(caplog.messages) == 1
    assert "violates the DRY principle" in caplog.messages[0]

    caplog.clear()
    assert efc.get("FOO_DIR", default) == default
    assert len(caplog.messages) == 1
    assert "violates the DRY principle" in caplog.messages[0]


def test_efc_relative_file_hack_get():
    efc = ExtFlaskConfig("/")
    efc["FOO_DIR"] = "bar"
    assert efc.get("FOO_DIR") == "/ROOT_DIR_UNSET/./bar"
    efc["FOO_DIR"] = "/bar"
    assert efc.get("FOO_DIR") == "/bar"


def test_efc_root_dir():
    # Security blanket to make sure asking for `config['ROOT_DIR']`
    # doesn't cause an infinite regression.
    efc = ExtFlaskConfig("/")
    efc["ROOT_DIR"] = "/etc/linotp"
    assert efc["ROOT_DIR"] == "/etc/linotp"


@pytest.mark.parametrize(
    "key,value,result,result_value",
    [
        ("FOO", "bar", "OK", "bar"),
        ("BAZ", "456", "OK", 456),
        ("BAZ", 456, "OK", 456),
        (
            "POS",
            "-123",
            s.LinOTPConfigValueError,
            "POS is -123 but must be at least 0",
        ),
    ],
)
def test_efc_dunder_setitem_schema(schema, key, value, result, result_value):
    cs = s.ConfigSchema(schema=schema)
    efc = ExtFlaskConfig("/", config_schema=cs)
    if result == "OK":
        efc[key] = value
        assert efc[key] == result_value
    else:
        with pytest.raises(result) as ex:
            efc[key] = value
        assert result_value in str(ex.value)


@pytest.mark.parametrize(
    "from_uri,to_uri,expect_warning",
    [
        ("postgresql://foo/bar", "postgresql://foo/bar", False),
        ("postgres://foo/bar", "postgresql://foo/bar", True),
    ],
)
def test_efc_dburi_get(schema, caplog, from_uri, to_uri, expect_warning):
    cs = s.ConfigSchema(schema=schema)
    efc = ExtFlaskConfig("/", config_schema=cs)
    efc["DBURI"] = from_uri
    assert efc["DBURI"] == to_uri
    if expect_warning:
        assert len(caplog.records) == 1
        rec = caplog.records[0]
        assert rec.message.startswith("Rewriting DB URI '"), "Not the expected warning"
    else:
        assert not caplog.records, "Didn't expect a warning but got one"


def test_efc_from_env_variables(monkeypatch, schema):
    mock_env = {
        "LINOTP_FOO": "quux",
        "LINOTP_CFG": "doh",  # This should be ignored (reserved name)
        "LINOTP_QUUX": "xyzzy",  # This should also be ignored (not in schema)
    }
    monkeypatch.setattr(os, "environ", mock_env)
    cs = s.ConfigSchema(schema=schema)
    efc = ExtFlaskConfig("/", config_schema=cs)
    efc.from_env_variables()
    assert efc["FOO"] == "quux"
    assert "CFG" not in efc
    assert "QUUX" not in efc


# Tests for `_configure_app`.

# We don't need a full-blown `LinOTPApp()` here, so we can lose a lot of
# baggage and just stick with the basics we need for configuration.


@pytest.fixture
def app_(monkeypatch, schema):
    cs = s.ConfigSchema(schema=schema)

    # Fake a `Config` class like in `settings.py` and install it as `default`.
    # If we don't do this, our “app” will pick up the complete standard
    # `DevelopmentConfig` configuration, which only confuses things.

    _attrs = {"init_app": staticmethod(lambda app: app.config.set_schema(cs))}
    _attrs.update(cs.as_dict())
    Config = type("Config", (object,), _attrs)
    monkeypatch.setitem(s.configs, "default", Config)

    class App:
        def __init__(self):
            self.config = ExtFlaskConfig("/ROOT_PATH")
            self.root_path = "/ROOT_PATH"

    return App()


@pytest.mark.parametrize(
    "path,expected_seen",
    [
        ("", []),
        ("linotp.cfg", ["/ROOT_PATH/linotp.cfg"]),
        ("/foo/linotp.cfg", ["/foo/linotp.cfg"]),
        (
            "linotp.cfg:/foo/linotp.cfg",
            ["/ROOT_PATH/linotp.cfg", "/foo/linotp.cfg"],
        ),
        ("/foo/*.cfg", ["/foo/linotp.cfg", "/foo/quux.cfg"]),
        ("/foo", ["/foo/linotp.cfg", "/foo/quux.cfg"]),
    ],
)
def test_configure_app_linotp_cfg_path(monkeypatch, app_, path, expected_seen):
    monkeypatch.setenv("LINOTP_CFG", path)
    monkeypatch.setenv("LINOTP_CONFIG", "default")

    def mocked_glob(self, g):
        if g == "foo":
            return [self / "foo" / "linotp.cfg", self / "foo" / "quux.cfg"]
        elif g == "*.cfg":
            return [self / "linotp.cfg", self / "quux.cfg"]
        return [self / g]

    # We don't need to test `ExtFlaskConfig.from_pyfile()` because the Flask
    # people have presumably done this for us (we just inherit the method
    # from Flask's `Config` class, anyway). Therefore we concentrate on
    # ensuring that the correct files are being read.

    files_seen = []
    monkeypatch.setattr(PosixPath, "glob", mocked_glob)
    monkeypatch.setattr(
        ExtFlaskConfig,
        "from_pyfile",
        lambda self, fn, **kwargs: files_seen.append(str(fn)),
    )

    _configure_app(app_)
    assert files_seen == expected_seen


@pytest.mark.parametrize(
    "path,silent",
    [
        ("/foo/linotp.cfg", False),
        ("-/foo/linotp.cfg", True),
    ],
)
def test_configure_app_linotp_cfg_silent(monkeypatch, capsys, app_, path, silent):
    monkeypatch.setenv("LINOTP_CONFIG", "default")
    monkeypatch.setenv("LINOTP_CFG", path)
    monkeypatch.setattr(ExtFlaskConfig, "from_pyfile", lambda self, fn, **kwargs: False)

    _configure_app(app_)
    captured = capsys.readouterr()
    if silent:
        assert not captured.err
    else:
        assert re.match("Configuration from .*? failed", captured.err)


def test_configure_app_from_env_variables(monkeypatch, app_):
    mock_env = {
        "LINOTP_CONFIG": "default",
        "LINOTP_FOO": "quux",
        "LINOTP_CFG": "",  # This should be ignored (reserved name)
        "LINOTP_QUUX": "xyzzy",  # This should also be ignored (not in schema)
    }
    monkeypatch.setattr(os, "environ", mock_env)

    _configure_app(app_)
    assert app_.config["FOO"] == "quux"
    assert "CFG" not in app_.config
    assert "QUUX" not in app_.config
