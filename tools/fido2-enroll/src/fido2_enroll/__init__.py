from importlib.metadata import version

__version__ = version("fido2_enroll")

from .enroll import LinOTPError, enroll_token  # noqa: F401
from .main import main  # noqa: F401
