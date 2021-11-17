from typing import Any, Dict, List
from unittest.mock import Mock, patch

import pytest

from linotp.lib.tools.import_user.SQLImportHandler import (
    DuplicateUserError,
    SQLImportHandler,
)


class FakeSession:
    def __init__(self, all_values: List[str]):
        self.all_values = all_values

    def query(self, *args: Any, **kwargs: Dict) -> Any:
        return self

    def filter(self, *args: Any, **kwargs: Dict) -> Any:
        return self

    def delete(self, *args: Any, **kwargs: Dict) -> Any:
        return self

    def all(self, *args: Any, **kwargs: Dict) -> List[str]:
        return self.all_values


class TestSqlImportHandler:
    @patch.object(FakeSession, "delete")
    def test_delete_by_id(
        self,
        mock_fake_session: Mock,
    ) -> None:

        fake_session = FakeSession(["user_1"])

        db_context_mock = Mock()
        db_context_mock.get_session.return_value = fake_session

        import_handler = SQLImportHandler(
            groupid="grp_id",
            resolver_name="res_name",
            database_context=db_context_mock,
        )

        import_handler.delete_by_id("some_user")

        assert mock_fake_session.call_count == 1
        mock_fake_session.assert_called_with("user_1")

    def test_delete_by_id_exception(self) -> None:

        fake_session = FakeSession(["user_1", "user_2"])

        db_context_mock = Mock()
        db_context_mock.get_session.return_value = fake_session

        import_handler = SQLImportHandler(
            groupid="grp_id",
            resolver_name="res_name",
            database_context=db_context_mock,
        )

        with pytest.raises(DuplicateUserError):
            import_handler.delete_by_id("some_user")
