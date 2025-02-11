import shutil
import subprocess
from pathlib import Path

import pytest

# Get the absolute path of the entrypoint script relative to the test file
TEST_DIR = Path(__file__).resolve().parent
ENTRYPOINT_SCRIPT = (
    TEST_DIR.parent.parent.parent.parent / "docker/linotp/entrypoint.sh"
)

# Mock commands called in entrypoint to avoid failure
MOCK_DOAS = 'doas() { echo "Mocked doas: $@";}'
MOCK_GUNICORN = 'gunicorn() { echo "Mocked gunicorn: $@";}'
MOCK_PYTHON_SUCCESS = 'python() { echo "mocked python" && return 0;}'
MOCK_PYTHON_FAILED_CREDS = 'python() { echo "mocked python" && return 1;}'


class TestDockerLinotpEntrypoint:
    linotp_root: Path

    @staticmethod
    def get_mocked_linotp_command(
        fail_commands: str | list[str] | None = None,
    ) -> str:
        """Get a mocked linotp command that can fail on given fail_commands"""
        if fail_commands is None:
            fail_commands = []
        elif isinstance(fail_commands, str):
            fail_commands = [fail_commands]
        # Ensure each command is wrapped in quotes to handle spaces correctly
        fail_commands_escaped = [f'"{command}"' for command in fail_commands]

        return f"""
        # Mock linotp command based on passed arguments
        FAIL_COMMANDS=({" ".join(fail_commands_escaped)})
        
        linotp() {{
            for fail_command in "${{FAIL_COMMANDS[@]}}"; do
                if [[ "$@" == *"$fail_command"* ]]; then
                    echo >&2 "failed on: $fail_command"
                    exit 1  # Simulate failure
                fi
            done
            return 0
        }}
        """

    @pytest.fixture
    def setup_env(self, tmp_path, monkeypatch: pytest.MonkeyPatch):
        """Sets up a temporary environment for testing using monkeypatch."""
        self.linotp_root = tmp_path

        # Use monkeypatch to set environment variables for the test
        monkeypatch.setenv("LINOTP_CFG", "")
        monkeypatch.setenv("LINOTP_ROOT_DIR", str(self.linotp_root))
        monkeypatch.setenv("LINOTP_ADMIN_USER", "testadmin")
        monkeypatch.setenv(
            "LINOTP_DATABASE_URI", f"sqlite:///{self.linotp_root}/test.db"
        )
        monkeypatch.setenv("LINOTP_DB_WAITTIME", "0s")

        yield self.linotp_root
        # Cleanup after test
        if self.linotp_root.exists():
            shutil.rmtree(self.linotp_root)

    def run_entrypoint_script(
        self, mock_commands: list[str], entry_point_args: str = ""
    ):
        """Helper to run entrypoint script with mocked commands."""
        mock_commands_str = "\n".join(mock_commands)

        test_script = f"""
        #!/bin/bash
        {mock_commands_str}
        source "{ENTRYPOINT_SCRIPT}" {entry_point_args}
        """
        return subprocess.run(
            ["bash", "-c", test_script],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_entrypoint_with_bootstrap(self, setup_env):
        """Ensure --with-bootstrap runs correctly"""
        result = self.run_entrypoint_script(
            mock_commands=[
                MOCK_DOAS,
                MOCK_GUNICORN,
                MOCK_PYTHON_SUCCESS,
                self.get_mocked_linotp_command(),
            ],
            entry_point_args="--with-bootstrap",
        )
        stderr = result.stderr

        # Check that bootstrap-related messages are in stderr
        assert "Bootstrapping LinOTP" in stderr, stderr
        assert "Bootstrapping done" in stderr, stderr
        assert self.linotp_root.joinpath("bootstrapped").exists()
        # Check command succeeded
        assert "failed on: " not in stderr, stderr
        assert result.returncode == 0, stderr

    def test_entrypoint_with_bootstrap_fails_on_unknown_host_in_uri(
        self, setup_env, monkeypatch: pytest.MonkeyPatch
    ):
        """Ensure --with-bootstrap fails with invalid LINOTP_DATABASE_URI"""
        uri = "postgres://user:pass@unknown_host/linotp_db"  # gitleaks:allow
        monkeypatch.setenv("LINOTP_DATABASE_URI", uri)

        result = self.run_entrypoint_script(
            mock_commands=[
                MOCK_DOAS,
                MOCK_GUNICORN,
                self.get_mocked_linotp_command(),
            ],
            entry_point_args="--with-bootstrap",
        )
        stderr = result.stderr

        # Check that bootstrap-related messages are in stderr
        assert "Bootstrapping LinOTP" not in stderr, stderr
        assert "Bootstrapping done" not in stderr, stderr
        assert not self.linotp_root.joinpath("bootstrapped").exists()
        # Check command failed
        assert f"Unknown host in LINOTP_DATABASE_URI={uri}" in stderr, stderr
        assert result.returncode == 1, stderr

    def test_entrypoint_with_bootstrap_fails_on_invalid_cred_in_uri(
        self, setup_env, monkeypatch: pytest.MonkeyPatch
    ):
        """Ensure --with-bootstrap fails with invalid LINOTP_DATABASE_URI"""
        uri = "postgres://user:pass@unknown_host/linotp_db"  # gitleaks:allow
        monkeypatch.setenv("LINOTP_DATABASE_URI", uri)

        result = self.run_entrypoint_script(
            mock_commands=[
                MOCK_DOAS,
                MOCK_GUNICORN,
                MOCK_PYTHON_FAILED_CREDS,
                self.get_mocked_linotp_command(),
            ],
            entry_point_args="--with-bootstrap",
        )
        stderr = result.stderr

        # Check that bootstrap-related messages are in stderr
        assert "Bootstrapping LinOTP" not in stderr, stderr
        assert "Bootstrapping done" not in stderr, stderr
        assert not self.linotp_root.joinpath("bootstrapped").exists()
        # Check command failed
        assert "Authentication error detected" in stderr, stderr
        # returncode is 0 so that docker doesnt restart
        assert result.returncode == 0, stderr

    @pytest.mark.parametrize(
        "fail_command",
        [
            "init all",
            "local-admins add",
            "local-admins password",
        ],
    )
    def test_entrypoint_with_bootstrap_fails_on_linotp_command(
        self, setup_env, fail_command
    ):
        """Ensure --with-bootstrap fails on given linotp command"""
        result = self.run_entrypoint_script(
            mock_commands=[
                MOCK_DOAS,
                MOCK_GUNICORN,
                MOCK_PYTHON_SUCCESS,
                self.get_mocked_linotp_command(fail_command),
            ],
            entry_point_args="--with-bootstrap",
        )
        stderr = result.stderr

        # Check that bootstrap-related messages are in stderr
        assert "Bootstrapping LinOTP" in stderr, stderr
        assert "Bootstrapping done" not in stderr, stderr
        assert not self.linotp_root.joinpath("bootstrapped").exists()
        # Check command failed
        assert f"failed on: {fail_command}" in stderr, stderr
        assert result.returncode == 1, stderr

    def test_entrypoint_fails_on_doas(self, setup_env):
        """Ensure --with-bootstrap fails on doas failure"""
        result = self.run_entrypoint_script(
            mock_commands=["doas() { echo 'failing doas: $@' && exit 1;}"],
            entry_point_args="--with-bootstrap",
        )
        stderr = result.stderr

        # Check that bootstrap-related messages are in stderr
        assert "Bootstrapping LinOTP" not in stderr, stderr
        assert "Bootstrapping done" not in stderr, stderr
        assert not self.linotp_root.joinpath("bootstrapped").exists()
        # Check that doas failure is captured
        assert "failing doas" in result.stdout, result.stdout
        assert result.returncode == 1, stderr

    def test_entrypoint_fails_on_unset_env(
        self, setup_env, monkeypatch: pytest.MonkeyPatch
    ):
        """Ensure entrypoint fails on unset env"""
        unset_env = "LINOTP_ROOT_DIR"
        monkeypatch.delenv(unset_env)

        result = self.run_entrypoint_script(
            mock_commands=[
                MOCK_DOAS,
                MOCK_GUNICORN,
                MOCK_PYTHON_SUCCESS,
                self.get_mocked_linotp_command(),
            ],
            entry_point_args="--with-bootstrap",
        )
        stderr = result.stderr

        # Check that bootstrap-related messages are in stderr
        assert "Bootstrapping LinOTP" in stderr, stderr
        assert "Bootstrapping done" not in stderr, stderr
        assert not self.linotp_root.joinpath("bootstrapped").exists()
        # Check that env failure is captured
        assert f"{unset_env}" in stderr.splitlines()[-1], stderr
        assert result.returncode == 1, stderr
