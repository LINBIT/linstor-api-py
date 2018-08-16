from .linstorapi import LinstorError, LinstorNetworkError, LinstorTimeoutError
from .linstorapi import ObjectIdentifier
from .linstorapi import ApiCallResponse, ErrorReport
from .linstorapi import Linstor
from .size_calc import SizeCalc
from . import sharedconsts as consts

VERSION = "0.5.0"

try:
    from linstor.consts_githash import GITHASH
except ImportError:
    GITHASH = 'GIT-hash: UNKNOWN'
