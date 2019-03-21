from .linstorapi import ObjectIdentifier
from .linstorapi import ApiCallResponse, ErrorReport
from .linstorapi import Linstor, MultiLinstor
from .resource import Resource, Volume
from .kv import KV
from .config import Config
from .responses import StoragePoolDriver
from .linstorapi import ResourceData
from .size_calc import SizeCalc
from .errors import LinstorError, LinstorTimeoutError, LinstorNetworkError, LinstorApiCallError
from .errors import LinstorReadOnlyAfterSetError
from . import sharedconsts as consts

VERSION = "0.9.1"

try:
    from linstor.consts_githash import GITHASH
except ImportError:
    GITHASH = 'GIT-hash: UNKNOWN'
