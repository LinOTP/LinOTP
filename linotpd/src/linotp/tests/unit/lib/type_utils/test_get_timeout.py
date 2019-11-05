
import unittest
from datetime import datetime

from linotp.lib.type_utils import get_timeout
import pytest

class GetTimeoutTest(unittest.TestCase):

    def test_get_timout_str(self):

        assert get_timeout("5") == 5.0

        assert get_timeout("5 , ") == 5.0

        assert get_timeout("5, 3") == (5.0, 3.0)

        assert get_timeout("5, 3 , ") == (5.0, 3.0)

    def test_get_timout_types(self):

        assert get_timeout((5,2)) == (5,2)

        assert get_timeout(5.0) == 5.0

        assert get_timeout(5) == 5


    def test_get_timeout_fail_type(self):

        with pytest.raises(ValueError) as exx:
            get_timeout(datetime.now())

        assert "Unsupported timeout input type" in exx.exception.args[0]

    def test_get_timeout_fail_string(self):

        with pytest.raises(ValueError) as exx:
            get_timeout("5 , , ,")

        assert "Failed to convert timeout" in str(exx.exception)

        with pytest.raises(ValueError) as exx:
            get_timeout("5 , 3.0,     ,")

        assert "Failed to convert timeout" in str(exx.exception)
