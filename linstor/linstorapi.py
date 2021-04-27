"""
Linstorapi module
"""

import logging
import socket
import time
import json
import zlib
import ssl
import base64
import re
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime
from distutils.version import StrictVersion

from linstor.version import VERSION
import linstor.sharedconsts as apiconsts
from linstor.errors import LinstorError, LinstorNetworkError, LinstorTimeoutError
from linstor.errors import LinstorApiCallError, LinstorArgumentError
from linstor.responses import ApiCallResponse, ErrorReport, StoragePoolListResponse, StoragePoolDriver
from linstor.responses import NodeListResponse, KeyValueStoresResponse, KeyValueStore, ResourceDefinitionResponse
from linstor.responses import ResourceResponse, VolumeDefinitionResponse, VolumeResponse, ResourceConnectionsResponse
from linstor.responses import RESTMessageResponse, SnapshotResponse, ControllerProperties, ResourceConnection
from linstor.responses import StoragePoolDefinitionResponse, MaxVolumeSizeResponse, ControllerVersion
from linstor.responses import ResourceGroupResponse, VolumeGroupResponse, PhysicalStorageList, SnapshotShippingResponse
from linstor.responses import SpaceReport, ExosListResponse, ExosExecResponse, \
    ExosEnclosureEventListResponse, ExosMapListResponse, ExosDefaults
from linstor.size_calc import SizeCalc

try:
    from urlparse import urlparse
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlparse
    from urllib.parse import urlencode

try:
    from httplib import HTTPConnection, HTTPSConnection, BadStatusLine, HTTPResponse
except ImportError:
    from http.client import HTTPConnection, HTTPSConnection, BadStatusLine, HTTPResponse


API_VERSION_MIN = "1.0.4"
API_VERSION = API_VERSION_MIN


logging.basicConfig(level=logging.WARNING)


class ResourceData(object):
    def __init__(
            self,
            node_name,
            rsc_name,
            diskless=False,
            storage_pool=None,
            node_id=None,
            layer_list=None,
            drbd_diskless=False,
            nvme_initiator=False,
            active=True):
        """
        :param str node_name: The node on which to place the resource
        :param str rsc_name: The resource definition to place
        :param bool diskless: Should the resource be diskless
        :param str storage_pool: The storage pool to use
        :param int node_id: Use this DRBD node_id
        :param list[str] layer_list: Set of layer names to use.
        """
        self._node_name = node_name
        self._rsc_name = rsc_name
        self._diskless = diskless
        self._storage_pool = storage_pool
        self._node_id = node_id
        self._layer_list = layer_list
        self._drbd_diskless = drbd_diskless
        self._nvme_initiator = nvme_initiator
        self._active = active

    @property
    def node_name(self):
        return self._node_name

    @property
    def rsc_name(self):
        return self._rsc_name

    @property
    def diskless(self):
        return self._diskless

    @property
    def storage_pool(self):
        return self._storage_pool

    @property
    def node_id(self):
        return self._node_id

    @property
    def layer_list(self):
        return self._layer_list

    @property
    def drbd_diskless(self):
        return self._drbd_diskless

    @property
    def nvme_initiator(self):
        return self._nvme_initiator

    @property
    def active(self):
        return self._active


class Linstor(object):
    """
    Linstor class represents a client connection to the Linstor controller.
    It has all methods to manipulate all kind of objects on the controller.

    The controller host address has to be specified as linstor url.
    e.g: ``linstor://localhost``, ``linstor+ssl://localhost``

    Note: This client is not thread-safe, only one request can be in flight at a time.

    :param str ctrl_host: Linstor uri to the controller e.g. ``linstor://192.168.0.1``
    :param bool keep_alive: Tries to keep the connection alive
    """
    _node_types = [
        apiconsts.VAL_NODE_TYPE_CTRL,
        apiconsts.VAL_NODE_TYPE_AUX,
        apiconsts.VAL_NODE_TYPE_CMBD,
        apiconsts.VAL_NODE_TYPE_STLT,
        apiconsts.VAL_NODE_TYPE_OPENFLEX_TARGET
    ]

    API_SINGLE_NODE_REQ = "API_SINGLE_NODE_REQ"

    APICALL2RESPONSE = {
        apiconsts.API_LST_NODE: NodeListResponse,
        apiconsts.API_LST_STOR_POOL: StoragePoolListResponse,
        apiconsts.API_LST_RSC_DFN: ResourceDefinitionResponse,
        apiconsts.API_LST_RSC_GRP: ResourceGroupResponse,
        apiconsts.API_LST_VLM_GRP: VolumeGroupResponse,
        apiconsts.API_LST_VLM_DFN: VolumeDefinitionResponse,
        apiconsts.API_LST_RSC: ResourceResponse,
        apiconsts.API_LST_VLM: VolumeResponse,
        apiconsts.API_LST_SNAPSHOT_DFN: SnapshotResponse,
        apiconsts.API_LST_SNAPSHOT_SHIPPINGS: SnapshotShippingResponse,
        apiconsts.API_REQ_ERROR_REPORTS: ErrorReport,
        apiconsts.API_LST_CTRL_PROPS: ControllerProperties,
        apiconsts.API_REQ_RSC_CONN_LIST: ResourceConnectionsResponse,
        apiconsts.API_LST_STOR_POOL_DFN: StoragePoolDefinitionResponse,
        apiconsts.API_QRY_MAX_VLM_SIZE: MaxVolumeSizeResponse,
        apiconsts.API_LST_KVS: KeyValueStoresResponse,
        apiconsts.API_VERSION: ControllerVersion,
        apiconsts.API_LST_PHYS_STOR: PhysicalStorageList,
        apiconsts.API_RPT_SPC: SpaceReport,
        API_SINGLE_NODE_REQ: ResourceConnection,
        apiconsts.API_LST_EXOS_ENCLOSURES: ExosListResponse,
        apiconsts.API_EXOS_ENCLOSURE_EVENTS: ExosEnclosureEventListResponse,
        apiconsts.API_EXOS_EXEC: ExosExecResponse,
        apiconsts.API_EXOS_MAP: ExosMapListResponse,
        apiconsts.API_LST_EXOS_DFLTS: ExosDefaults
    }

    REST_PORT = 3370
    REST_HTTPS_PORT = 3371

    def __init__(self, ctrl_host, timeout=300, keep_alive=False):
        self._ctrl_host = ctrl_host
        self._logger = logging.getLogger('Linstor')
        self._timeout = timeout
        self._keep_alive = keep_alive
        self._rest_conn = None  # type: Optional[HTTPConnection]
        self._connected = False
        self._mode_curl = False
        self._ctrl_version = None
        self._username = None
        self._password = None
        self._certfile = None
        self._keyfile = None
        self._cafile = None
        self._allow_insecure = False
        self._times_entered = 0

        self._http_headers = {
            "User-Agent": "PythonLinstor/{v} (API{a})".format(v=VERSION, a=API_VERSION_MIN),
            "Connection": "keep-alive",
            "Accept-Encoding": "gzip"
        }

    def __del__(self):
        self.disconnect()

    def __enter__(self):
        if self._times_entered == 0:
            self.connect()  # raises exception if error
        self._times_entered += 1
        return self

    def __exit__(self, type, value, traceback):
        self._times_entered -= 1
        if self._times_entered == 0:
            self.disconnect()

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, username):
        self._username = username

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, password):
        self._password = password

    @property
    def certfile(self):
        return self._certfile

    @certfile.setter
    def certfile(self, certfile):
        self._certfile = certfile

    @property
    def keyfile(self):
        return self._keyfile

    @keyfile.setter
    def keyfile(self, keyfile):
        self._keyfile = keyfile

    @property
    def cafile(self):
        return self._cafile

    @cafile.setter
    def cafile(self, cafile):
        self._cafile = cafile

    @property
    def allow_insecure(self):
        return self._allow_insecure

    @allow_insecure.setter
    def allow_insecure(self, val):
        self._allow_insecure = val

    def __output_curl_command(self, method, path, body):
        url = urlparse(self._ctrl_host)
        cmd = ["curl", "-X", method]
        if body is not None:
            cmd += ['-H "Content-Type: application/json"']
            cmd += ["-d '" + json.dumps(body) + "'"]

        port = url.port if url.port else Linstor.REST_PORT
        is_https = True if url.scheme == "linstor+ssl" else False

        port = port if not is_https else Linstor.REST_HTTPS_PORT

        scheme = "https" if is_https else "http"
        cmd += [scheme + "://" + url.hostname + ":" + str(port) + path]
        print(" ".join(cmd))

    @classmethod
    def _current_milli_time(cls):
        return int(round(time.time() * 1000))

    @classmethod
    def parse_volume_size_to_kib(cls, size_str):
        """
        Parses a string e.g. "1g" to computer size units and return KiB

        :param str size_str: string to parse
        :return: KiB of the parsed string
        :rtype: int
        :raises LinstorArgumentError: If string can not be parsed as number
        """
        m = re.match(r'(\d+)(\D*)', size_str)

        size = 0
        try:
            size = int(m.group(1))
        except AttributeError:
            raise LinstorArgumentError("Size '{s}' is not a valid number".format(s=size_str))

        unit_str = m.group(2)
        if unit_str == "":
            unit_str = "GiB"
        try:
            _, unit = SizeCalc.UNITS_MAP[unit_str.lower()]
        except KeyError:
            raise LinstorArgumentError(
                '"%s" is not a valid unit!\nValid units: %s' % (unit_str, SizeCalc.UNITS_LIST_STR)
            )

        _, unit = SizeCalc.UNITS_MAP[unit_str.lower()]

        if unit != SizeCalc.UNIT_KiB:
            size = SizeCalc.convert_round_up(size, unit,
                                             SizeCalc.UNIT_KiB)

        return size

    @classmethod
    def _decode_response_data(cls, response):
        data = response.read()
        if response.getheader("Content-Encoding", "text") == "gzip":
            return zlib.decompress(data, zlib.MAX_WBITS | 16).decode('utf-8')
        return data.decode('utf-8')

    def _require_version(self, required_version, msg="REST action not supported by server"):
        """

        :param str required_version: semantic version string
        :return: True if supported
        :raises: LinstorError if server version is lower than required version
        """
        if self._ctrl_version and StrictVersion(self._ctrl_version.rest_api_version) < StrictVersion(required_version):
            raise LinstorError(
                msg + ", REST-API-VERSION: " + self._ctrl_version.rest_api_version +
                "; needed " + required_version
            )

    def api_version_smaller(self, version):
        """

        :param str version: semantic version string
        :return: True if server version is smaller than given version
        :rtype: bool
        """
        return self._ctrl_version and StrictVersion(self._ctrl_version.rest_api_version) < StrictVersion(version)

    def _rest_request_base(self, apicall, method, path, body=None, reconnect=True):
        """

        :param str apicall: linstor apicall strid
        :param str method: One of GET, POST, PUT, DELETE, OPTIONS
        :param str path: object path on the server
        :param Union[dict[str,Any], list[Any] body: body data
        :return: HTTP response object, except --curl is set, then None
        :rtype: Optional[HTTPResponse]
        """
        if self._mode_curl:
            self.__output_curl_command(method, path, body)
            return None

        try:
            headers = {}
            headers.update(self._http_headers)
            if self.username:
                auth_token = self.username + ":" + self.password
                headers["Authorization"] = "Basic " + base64.b64encode(auth_token.encode()).decode()
            self._rest_conn.request(
                method=method,
                url=path,
                body=json.dumps(body) if body is not None else None,
                headers=headers
            )
        except socket.error as err:
            if self._keep_alive and reconnect:
                self.connect()
                return self._rest_request_base(apicall, method, path, body, reconnect=False)
            else:
                raise LinstorNetworkError("Unable to send request to {hp}: {err}".format(hp=self._ctrl_host, err=err))

        try:
            return self._rest_conn.getresponse()
        except socket.timeout:
            raise LinstorTimeoutError("Socket timeout, no data received for more than {t}s.".format(t=self._timeout))
        except socket.error as err:
            if self._keep_alive and reconnect:
                self.connect()
                return self._rest_request_base(apicall, method, path, body, reconnect=False)
            else:
                raise LinstorNetworkError("Error reading response from {hp}: {err}".format(hp=self._ctrl_host, err=err))
        except BadStatusLine:  # python2 raises BadStatusLine on connection closed
            if self._keep_alive and reconnect:
                self.connect()
                return self._rest_request_base(apicall, method, path, body, reconnect=False)
            else:
                raise

    def _handle_response_error(self, response, method, path):
        error_data_raw = self._decode_response_data(response)
        if error_data_raw:
            if response.getheader("Content-Type", "text").startswith('application/json'):
                try:
                    error_data = json.loads(error_data_raw)
                except ValueError as ve:
                    raise LinstorError(
                        "Unable to parse REST json data: " + str(ve) + "\n"
                                                                       "Request-Uri: " + path
                    )
                return [ApiCallResponse(x) for x in error_data]
            else:
                # try to get an error message from html
                root = ET.fromstring(error_data_raw)
                # get head error message
                error_msg = "Request failed."
                for child in root.find("body"):
                    if "header" in child.attrib.get("class"):
                        error_msg = child.text
                        break
                raise LinstorError("HTTP-Status({s})/{err}".format(s=response.status, err=error_msg))
        raise LinstorError("REST api call method '{m}' to resource '{p}' returned status {s} with no data."
                           .format(m=method, p=path, s=response.status))

    def _rest_request(self, apicall, method, path, body=None, reconnect=True):
        """

        :param str apicall: linstor apicall strid
        :param str method: One of GET, POST, PUT, DELETE, OPTIONS
        :param str path: object path on the server
        :param Union[dict[str,Any], list[Any] body: body data
        :return:
        :rtype: list[Union[ApiCallRESTResponse, ResourceResponse]]
        """
        response = None
        try:
            response = self._rest_request_base(apicall, method, path, body, reconnect)

            if response is None:  # --curl
                return []

            if response.status < 400:
                return self.__convert_rest_response(apicall, response, path)
            else:
                return self._handle_response_error(response, method, path)
        finally:
            if response:
                response.close()

    def _rest_request_download(self, apicall, method, path, body=None, reconnect=True, to_file=None):
        response = None
        try:
            response = self._rest_request_base(apicall, method, path, body, reconnect)

            if response is None:  # --curl
                return []

            if response.status < 400:
                save_file = "linstor.out"
                if to_file:
                    save_file = to_file
                else:
                    content_disp = response.getheader('content-disposition')
                    # TODO do prober rfc6266 header field parsing
                    filename = re.findall(r"attachment;\s*filename\s*=\s*(\S+)", content_disp)
                    save_file = filename[0] if filename else save_file
                with open(save_file, "wb+") as f:
                    shutil.copyfileobj(response, f)
                return [ApiCallResponse.from_json(
                    {"ret_code": 0, "message": "File saved to: " + save_file, "obj_refs": {"path": save_file}})]
            else:
                return self._handle_response_error(response, method, path)
        finally:
            if response:
                response.close()

    def __convert_rest_response(self, apicall, response, path):
        resp_data = self._decode_response_data(response)
        try:
            data = json.loads(resp_data)
        except ValueError as ve:
            raise LinstorError(
                "Unable to parse REST json data: " + str(ve) + "\n"
                "Request-Uri: " + path + "; Status: " + str(response.status)
            )

        response_list = []
        response_class = self.APICALL2RESPONSE.get(apicall, ApiCallResponse)
        if response_class in [ApiCallResponse, ErrorReport]:
            response_list = [response_class(x) for x in data]
        else:
            if "ret_code" in data:
                response_list += [ApiCallResponse(x) for x in data]
            else:
                response_list += [response_class(data)]

        return response_list

    @property
    def curl(self):
        return self._mode_curl

    @curl.setter
    def curl(self, enable):
        """
        Set the curl mode on or off.
        If on it will not execute any commands and instead will only print equivalent curl commands.

        :param bool enable: enable or disable curl mode
        :return: None
        """
        self._mode_curl = enable

    @classmethod
    def all_api_responses_no_error(cls, replies):
        """
        Checks if none of the responses has an error.

        :param list[ApiCallResponse] replies: apicallresponse to check
        :return: True if none of the replies has an error.
        :rtype: bool
        """
        return all([not r.is_error() for r in replies])

    @classmethod
    def all_api_responses_success(cls, replies):
        """
        Checks if none of the responses has an error.

        :param list[ApiCallResponse] replies: apicallresponse to check
        :return: True if all replies are success
        :rtype: bool
        """
        return all([r.is_success() for r in replies])

    @classmethod
    def filter_api_call_response(cls, replies):
        """
        Filters api call responses from Controller replies.

        :param list[ApiCallResponse] replies: controller reply list
        :return: Returns all only ApiCallResponses from replies or empty list.
        :rtype: [ApiCallResponse]
        """
        return [reply for reply in replies if isinstance(reply, ApiCallResponse) or isinstance(reply, ApiCallResponse)]

    @classmethod
    def filter_api_call_response_errors(cls, replies):
        """
        Filters api call responses and only returns errors contained in the replies list.

        :param list[ApiCallResponse] replies: list of ApiCallResponses
        :return: List only containing error responses
        :rtype: [ApiCallResponse]
        """
        return [reply for reply in replies if reply.is_error()]

    @classmethod
    def return_if_failure(cls, replies_):
        """
        Returns None if any of the replies is no success.

        :param list[ApiCallResponse] replies_: list of api call responses
        :return: None if any is not success, else all given replies
        """
        if not cls.all_api_responses_success(replies_):
            return replies_
        return None

    @classmethod
    def return_if_error(cls, replies_):
        """
        Returns None if any of the replies is an error.

        :param list[ApiCallResponse] replies_: list of api call responses
        :return: None if any is not success, else all given replies
        """
        if not cls.all_api_responses_no_error(replies_):
            return replies_
        return None

    @classmethod
    def _modify_props(cls, msg, property_dict, delete_props=None):
        if property_dict:
            for key, val in property_dict.items():
                lin_kv = msg.override_props.add()
                lin_kv.key = key
                lin_kv.value = val

        if delete_props:
            msg.delete_prop_keys.extend(delete_props)
        return msg

    @classmethod
    def has_linstor_https(cls, hostname, port):
        """
        Returns the redirect https port.

        :param hostname: hostname/ip of the linstor server
        :param port: http port to check for redirect
        :return: The https port of linstor if enabled, otherwise 0
        :rtype: int
        """
        conn = HTTPConnection(hostname, port, timeout=3)
        try:
            conn.connect()
            conn.request("GET", "/v1/controller/version")
            response = conn.getresponse()
            if response.status == 302:
                https_url = urlparse(response.getheader("Location"))
                return https_url.port
        except socket.error:
            return 0
        return 0

    def connect(self):
        """
        Connects the internal linstor network client.

        :return: True
        """
        if self._mode_curl:
            self._connected = True
            return True
        url = urlparse(self._ctrl_host)
        port = url.port if url.port else Linstor.REST_PORT
        is_https = False

        if url.scheme == "linstor+ssl" or url.scheme == "https":
            is_https = True
            if url.port is None:
                port = Linstor.REST_HTTPS_PORT
        else:
            https_port = self.has_linstor_https(url.hostname, port)
            if https_port:
                is_https = True
                port = https_port

        if is_https:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else 2)
            if self._certfile or self._keyfile:
                context.load_cert_chain(self._certfile, self._keyfile)
            if self._cafile:
                context.load_verify_locations(self._cafile)
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True

            self._rest_conn = HTTPSConnection(
                host=url.hostname,
                port=port,
                timeout=self._timeout,
                context=context
            )
        else:
            if self.username and not self.allow_insecure:
                raise LinstorNetworkError("Password authentication with HTTP not allowed, until explicitly enabled.")
            self._rest_conn = HTTPConnection(host=url.hostname, port=port, timeout=self._timeout)

        try:
            self._rest_conn.connect()
            self._ctrl_version = self.controller_version()
            if not self._ctrl_version.rest_api_version.startswith("1") or \
                    StrictVersion(API_VERSION_MIN) > StrictVersion(self._ctrl_version.rest_api_version):
                self._rest_conn.close()
                raise LinstorApiCallError(
                    "Client doesn't support Controller rest api version: " + self._ctrl_version.rest_api_version +
                    "; Minimal version needed: " + API_VERSION_MIN
                )
            self._connected = True
        except socket.error as err:
            hosturl = self._ctrl_host
            if is_https:
                hosturl = "linstor+ssl://" + url.hostname + ":" + str(port)
            raise LinstorNetworkError("Unable to connect to {hp}: {err}".format(hp=hosturl, err=err))
        return True

    @property
    def connected(self):
        """
        Checks if the Linstor object is connect to a controller.

        :return: True if connected, else False.
        """
        return self._connected

    @property
    def is_secure_connection(self):
        """
        Returns True if the connection to linstor uses HTTPS.

        :return: True if using https else False
        :rtype: bool
        """
        return isinstance(self._rest_conn, HTTPSConnection)

    def disconnect(self):
        """
        Disconnects the current connection.

        :return: True if the object was connected else False.
        """
        self._connected = False
        if self._rest_conn:
            self._rest_conn.close()

    def _require_node_is_active(self, net_interface, value=True):
        """
        Adds 'is_active' property if supported by controller.

        :param dict[str, Any] net_interface:
        :param bool value: Value for is_active
        :return:
        """
        # is_active is added with API 1.0.7, before active stlt conn was set via property
        if self._ctrl_version and StrictVersion(self._ctrl_version.rest_api_version) >= StrictVersion("1.0.7"):
            net_interface["is_active"] = value

    def node_create(
            self,
            node_name,
            node_type,
            ip,
            com_type=apiconsts.VAL_NETCOM_TYPE_PLAIN,
            port=None,
            netif_name='default',
            property_dict=None
    ):
        """
        Creates a node on the controller.

        :param str node_name: Name of the node.
        :param str node_type: Node type of the new node, one of linstor.consts.VAL_NODE_TYPE*
        :param str ip: IP address to use for the nodes default netinterface.
        :param str com_type: Communication type of the node.
        :param int port: Port number of the node.
        :param str netif_name: Netinterface name that is created.
        :param dict[str, str] property_dict: Node properties.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        node_type_lower = node_type.lower()
        if node_type_lower not in [nt.lower() for nt in self._node_types]:
            raise LinstorError(
                "Unknown node type '{nt}'. Known types are: {kt}".format(nt=node_type, kt=", ".join(self._node_types))
            )

        if port is None:
            com_lower = com_type.lower()
            if com_lower == apiconsts.VAL_NETCOM_TYPE_PLAIN.lower():
                port = apiconsts.DFLT_CTRL_PORT_PLAIN \
                    if node_type_lower == apiconsts.VAL_NODE_TYPE_CTRL.lower() else apiconsts.DFLT_STLT_PORT_PLAIN
            elif com_lower == apiconsts.VAL_NETCOM_TYPE_SSL.lower():
                if node_type_lower == apiconsts.VAL_NODE_TYPE_STLT.lower():
                    port = apiconsts.DFLT_STLT_PORT_SSL
                else:
                    port = apiconsts.DFLT_CTRL_PORT_SSL
            else:
                raise LinstorError("Communication type %s has no default port" % com_type)

        body = {
            "name": node_name,
            "type": node_type,
            "net_interfaces": [
                {
                    "name": netif_name,
                    "address": ip,
                    "satellite_port": port,
                    "satellite_encryption_type": com_type
                }
            ]
        }

        if property_dict:
            body["props"] = property_dict

        self._require_node_is_active(body["net_interfaces"][0])

        return self._rest_request(apiconsts.API_CRT_NODE, "POST", "/v1/nodes", body)

    def node_modify(self, node_name, node_type=None, property_dict=None, delete_props=None):
        """
        Modify the properties of a given node.

        :param str node_name: Name of the node to modify.
        :param int node_type: Type of the node, any of VAL_NODE_TYPE_*
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param list[str] delete_props: List of properties to delete
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {}
        if node_type is not None:
            body["node_type"] = node_type

        if property_dict:
            body["override_props"] = property_dict

        if delete_props:
            body["delete_props"] = delete_props

        return self._rest_request(apiconsts.API_MOD_NODE, "PUT", "/v1/nodes/" + node_name, body)

    def node_delete(self, node_name, async_msg=False):
        """
        Deletes the given node on the controller.

        :param str node_name: Node name to delete.
        :param bool async_msg: True to return without waiting for the action to complete on the satellites.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        return self._rest_request(apiconsts.API_DEL_NODE, "DELETE", "/v1/nodes/" + node_name)

    def node_lost(self, node_name, async_msg=False):
        """
        Deletes an unrecoverable node on the controller.

        :param str node_name: Node name to delete.
        :param bool async_msg: True to return without waiting for the action to complete on the satellites.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        return self._rest_request(apiconsts.API_LOST_NODE, "DELETE", "/v1/nodes/" + node_name + "/lost")

    def node_reconnect(self, node_names):
        """
        Forces the controller to drop a connection on a satellite and reconnect.

        :param list[str] node_names: List of nodes to reconnect.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        replies = []
        for node_name in node_names:
            replies += self._rest_request(apiconsts.API_NODE_RECONNECT, "PUT", "/v1/nodes/" + node_name + "/reconnect")
        return replies

    def node_restore(self, node_name):
        """
        Restores an evicted node.

        :param str node_name: Node name to restore
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        return self._rest_request(apiconsts.API_NODE_RESTORE, "PUT", "/v1/nodes/" + node_name + "/restore")

    def netinterface_create(self, node_name, interface_name, ip, port=None, com_type=None, is_active=False):
        """
        Create a netinterface for a given node.

        :param str node_name: Name of the node to add the interface.
        :param str interface_name: Name of the new interface.
        :param str ip: IP address of the interface.
        :param int port: Port of the interface
        :param str com_type: Communication type to use on the interface.
        :param bool is_active: True if the net interface should become the active satellite connection
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {
            "name": interface_name,
            "address": ip
        }

        if port:
            body["satellite_port"] = port
            body["satellite_encryption_type"] = com_type

        self._require_node_is_active(body, is_active)

        return self._rest_request(apiconsts.API_CRT_NET_IF, "POST", "/v1/nodes/" + node_name + "/net-interfaces", body)

    def netinterface_modify(self, node_name, interface_name, ip=None, port=None, com_type=None, is_active=False):
        """
        Modify a netinterface on the given node.

        :param str node_name: Name of the node.
        :param str interface_name: Name of the netinterface to modify.
        :param str ip: New IP address of the netinterface
        :param int port: New Port of the netinterface
        :param str com_type: New communication type of the netinterface
        :param bool is_active: True if the net interface should become the active satellite connection
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {"name": interface_name}

        if ip:
            body["address"] = ip

        if port:
            body["satellite_port"] = port
            body["satellite_encryption_type"] = com_type

        self._require_node_is_active(body, is_active)

        return self._rest_request(
            apiconsts.API_CRT_NET_IF,
            "PUT", "/v1/nodes/" + node_name + "/net-interfaces/" + interface_name,
            body
        )

    def netinterface_delete(self, node_name, interface_name):
        """
        Deletes a netinterface on the given node.

        :param str node_name: Name of the node.
        :param str interface_name: Name of the netinterface to delete.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        return self._rest_request(
            apiconsts.API_DEL_NET_IF,
            "DELETE",
            "/v1/nodes/" + node_name + "/net-interfaces/" + interface_name
        )

    # unused
    def net_interface_list(self, node_name):
        """
        Request a list of all netinterfaces of a node known to the controller.

        :param str node_name: Name of the node.
        :return: A REST message containing all information.
        :rtype: list[RESTMessageResponse]
        """
        return self._rest_request(apiconsts.API_LST_NET_IF, "GET", "/v1/nodes/" + node_name + "/net-interfaces")

    def node_list(self, filter_by_nodes=None, filter_by_props=None):
        """
        Request a list of all nodes known to the controller.

        :param list[str] filter_by_nodes: Filter by nodes.
        :param Optional[list[str]] filter_by_props: Filter nodes by properties.
        :return: A MsgLstNode proto message containing all information.
        :rtype: list[RESTMessageResponse]
        """
        query_params = []
        if filter_by_nodes:
            query_params += ["nodes=" + x for x in filter_by_nodes]

        if filter_by_props:
            query_params += ["props=" + x for x in filter_by_props]

        path = "/v1/nodes"
        if query_params:
            path += "?" + "&".join(query_params)
        return self._rest_request(
            apiconsts.API_LST_NODE,
            "GET",
            path
        )

    def node_list_raise(self, filter_by_nodes=None, filter_by_props=None):
        """
        Request a list of all nodes known to the controller.

        :param list[str] filter_by_nodes: Filter by nodes.
        :param Optional[list[str]] filter_by_props: Filter nodes by properties.
        :return: Node list response objects
        :rtype: NodeListResponse
        :raises LinstorError: if apicall error or no data received.
        :raises LinstorApiCallError: on an apicall error from controller
        """
        list_res = self.node_list(filter_by_nodes=filter_by_nodes, filter_by_props=filter_by_props)
        if list_res:
            if isinstance(list_res[0], NodeListResponse):
                return list_res[0]
            raise LinstorApiCallError(list_res[0])
        raise LinstorError("No list response received.")

    def node_types(self):
        """
        Returns all allowed node types by the api.

        :return: A list containing all node type strings.
        :rtype: list[str]
        """
        return self._node_types

    def storage_pool_dfn_create(self, name):
        """
        Creates a new storage pool definition on the controller.

        :param str name: Storage pool definition name.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {
            "storage_pool_name": name
        }

        return self._rest_request(
            apiconsts.API_CRT_STOR_POOL_DFN,
            "POST", "/v1/storage-pool-definitions",
            body
        )

    def storage_pool_dfn_modify(self, name, property_dict, delete_props=None):
        """
        Modify properties of a given storage pool definition.

        :param str name: Storage pool definition name to modify
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param list[str] delete_props: List of properties to delete
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {}
        if property_dict:
            body["override_props"] = property_dict

        if delete_props:
            body["delete_props"] = delete_props

        return self._rest_request(
            apiconsts.API_MOD_STOR_POOL_DFN,
            "PUT", "/v1/storage-pool-definitions/" + name,
            body
        )

    def storage_pool_dfn_delete(self, name):
        """
        Delete a given storage pool definition.

        :param str name: Storage pool definition name to delete.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        return self._rest_request(apiconsts.API_DEL_STOR_POOL_DFN, "DELETE", "/v1/storage-pool-definitions/" + name)

    def storage_pool_dfn_list(self):
        """
        Request a list of all storage pool definitions known to the controller.

        :return: A MsgLstStorPoolDfn proto message containing all information.
        :rtype: list[StoragePoolDefinitionResponse]
        """
        return self._rest_request(apiconsts.API_LST_STOR_POOL_DFN, "GET", "/v1/storage-pool-definitions")

    def storage_pool_dfn_max_vlm_sizes(
            self,
            place_count,
            storage_pool_name=None,
            do_not_place_with=None,
            do_not_place_with_regex=None,
            replicas_on_same=None,
            replicas_on_different=None
    ):
        """
        Auto places(deploys) a resource to the amount of place_count.

        :param int place_count: Number of placements, on how many different nodes
        :param str storage_pool_name: Only check for the given storage pool name
        :param list[str] do_not_place_with: Do not place with resource names in this list
        :param str do_not_place_with_regex: A regex string that rules out resources
        :param list[str] replicas_on_same: A list of node property names, their values should match
        :param list[str] replicas_on_different: A list of node property names, their values should not match
        :return: A list containing ApiCallResponses (with MsgRspMaxVlmSizes)
        :rtype: Union[list[ApiCallResponse], list[RESTMessageResponse]]
        """
        body = {
            "place_count": place_count
        }

        if storage_pool_name:
            body["storage_pool"] = storage_pool_name
        if do_not_place_with:
            body["not_place_with_rsc"] = do_not_place_with
        if do_not_place_with_regex:
            body["not_place_with_rsc_regex"] = do_not_place_with_regex
        if replicas_on_same:
            body["replicas_on_same"] = replicas_on_same
        if replicas_on_different:
            body["replicas_on_different"] = replicas_on_different

        return self._rest_request(
            apiconsts.API_QRY_MAX_VLM_SIZE,
            "OPTIONS",
            "/v1/query-max-volume-size",
            body
        )

    @staticmethod
    def _filter_props(props, namespace=''):
        return {prop: props[prop] for prop in props if prop.startswith(namespace)}

    def storage_pool_create(
            self,
            node_name,
            storage_pool_name,
            storage_driver,
            driver_pool_name,
            shared_space=None,
            property_dict=None,
            external_locking=False
    ):
        """
        Creates a new storage pool on the given node.
        If there doesn't yet exist a storage pool definition the controller will implicitly create one.

        :param str node_name: Node on which to create the storage pool.
        :param str storage_pool_name: Name of the storage pool.
        :param str storage_driver: Storage driver to use.
        :param Optional[str] driver_pool_name: Name of the pool the storage driver should use on the node.
        :param Optional[str] shared_space: Name of a shared space, if used.
        :param Optional[dict] property_dict: Initial properties for the storage pool.
        :param bool external_locking: if the pool uses external locking.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        if storage_driver not in StoragePoolDriver.list():
            raise LinstorError("Unknown storage driver: " + storage_driver)

        body = {
            "storage_pool_name": storage_pool_name,
            "provider_kind": storage_driver
        }

        if shared_space:
            body["free_space_mgr_name"] = shared_space
        if external_locking:
            body["external_locking"] = True

        # set driver device pool properties
        if storage_driver not in [StoragePoolDriver.Diskless]:
            if not driver_pool_name:
                raise LinstorError(
                    "Driver '{drv}' needs a driver pool name.".format(drv=storage_driver)
                )

            if self.api_version_smaller("1.2.0"):
                body["props"] = StoragePoolDriver.storage_driver_pool_to_props(storage_driver, driver_pool_name)
            else:
                body["props"] = {
                    apiconsts.NAMESPC_STORAGE_DRIVER + "/" + apiconsts.KEY_STOR_POOL_NAME: driver_pool_name}

        if property_dict:
            body["props"].update(property_dict)

        return self._rest_request(
            apiconsts.API_CRT_STOR_POOL,
            "POST",
            "/v1/nodes/" + node_name + "/storage-pools",
            body
        )

    def storage_pool_modify(self, node_name, storage_pool_name, property_dict, delete_props=None):
        """
        Modify properties of a given storage pool on the given node.

        :param str node_name: Node on which the storage pool resides.
        :param str storage_pool_name: Name of the storage pool.
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param list[str] delete_props: List of properties to delete
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {}

        if property_dict:
            body["override_props"] = property_dict

        if delete_props:
            body["delete_props"] = delete_props

        return self._rest_request(
            apiconsts.API_MOD_STOR_POOL,
            "PUT",
            "/v1/nodes/" + node_name + "/storage-pools/" + storage_pool_name,
            body
        )

    def storage_pool_delete(self, node_name, storage_pool_name):
        """
        Deletes a storage pool on the given node.

        :param str node_name: Node on which the storage pool resides.
        :param str storage_pool_name: Name of the storage pool.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        return self._rest_request(
            apiconsts.API_DEL_STOR_POOL,
            "DELETE",
            "/v1/nodes/" + node_name + "/storage-pools/" + storage_pool_name
        )

    def storage_pool_list(self, filter_by_nodes=None, filter_by_stor_pools=None, filter_by_props=None):
        """
        Request a list of all storage pools known to the controller.

        :param list[str] filter_by_nodes: Filter storage pools by nodes.
        :param list[str] filter_by_stor_pools: Filter storage pools by storage pool names.
        :param Optional[list[str]] filter_by_props: Filter nodes by properties.
        :return: A MsgLstStorPool proto message containing all information.
        :rtype: list[RESTMessageResponse]
        """
        query_params = []
        if filter_by_nodes:
            query_params += ["nodes=" + x for x in filter_by_nodes]
        if filter_by_stor_pools:
            query_params += ["storage_pools=" + x for x in filter_by_stor_pools]
        if filter_by_props:
            query_params += ["props=" + x for x in filter_by_props]

        path = "/v1/view/storage-pools"
        if query_params:
            path += "?" + "&".join(query_params)
        storage_pool_res = self._rest_request(
            apiconsts.API_LST_STOR_POOL,
            "GET",
            path
        )  # type: List[StoragePoolListResponse]

        result = []
        errors = []
        if storage_pool_res and isinstance(storage_pool_res[0], StoragePoolListResponse):
            result += storage_pool_res
        else:
            errors += storage_pool_res

        return result + errors

    def storage_pool_list_raise(self, filter_by_nodes=None, filter_by_stor_pools=None, filter_by_props=None):
        """

        :param Optional[list[str]] filter_by_nodes: node names to filter
        :param Optional[list[str]] filter_by_stor_pools: storage pool names to filter
        :param Optional[list[str]] filter_by_props: Filter nodes by properties.
        :return: StoragePoolListResponse object
        :rtype: StoragePoolListResponse
        :raises LinstorError: if apicall error or no data received.
        :raises LinstorApiCallError: on an apicall error from controller
        """
        list_res = self.storage_pool_list(
            filter_by_nodes=filter_by_nodes,
            filter_by_stor_pools=filter_by_stor_pools,
            filter_by_props=filter_by_props)
        if list_res:
            if isinstance(list_res[0], StoragePoolListResponse):
                return list_res[0]
            raise LinstorApiCallError(list_res[0])
        raise LinstorError("No list response received.")

    @classmethod
    def layer_list(cls):
        """
        Gives a set of possible layer names.

        :return: Set of layer names
        :rtype: set[str]
        """
        return {x.value for x in apiconsts.DeviceLayerKind}

    @classmethod
    def provider_list(cls):
        """
        Gives a set of possible provider names.

        :return: Set of provider names
        :rtype: set[str]
        """
        return StoragePoolDriver.list()

    def resource_group_create(
            self,
            name,
            description=None,
            place_count=None,
            storage_pool=None,
            do_not_place_with=None,
            do_not_place_with_regex=None,
            replicas_on_same=None,
            replicas_on_different=None,
            diskless_on_remaining=None,
            layer_list=None,
            provider_list=None,
            property_dict=None,
            diskless_storage_pool=None
    ):
        """
        Create resource group with values.

        :param str name: Name of the resource group to modify.
        :param str description: description for the resource group.
        :param int place_count: Number of placements, on how many different nodes
        :param list[str] storage_pool: List of storage pools to use
        :param list[str] do_not_place_with: Do not place with resource names in this list
        :param str do_not_place_with_regex: A regex string that rules out resources
        :param list[str] replicas_on_same: A list of node property names, their values should match
        :param list[str] replicas_on_different: A list of node property names, their values should not match
        :param bool diskless_on_remaining: If True all remaining nodes will add a diskless resource
        :param list[str] layer_list: Define layers for the resource
        :param list[str] provider_list: Filter provider kinds
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param optional[list[str]] diskless_storage_pool: List of diskless pools to use
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.0.8", msg="Resource group create not supported by server")
        body = {
            "name": name
        }

        if description:
            body["description"] = description

        if property_dict:
            body["props"] = property_dict

        if storage_pool is not None and not isinstance(storage_pool, list):
            storage_pool = [storage_pool]

        self._set_select_filter_body(
            body,
            place_count=place_count,
            storage_pool=storage_pool,
            do_not_place_with=do_not_place_with,
            do_not_place_with_regex=do_not_place_with_regex,
            replicas_on_same=replicas_on_same,
            replicas_on_different=replicas_on_different,
            diskless_on_remaining=diskless_on_remaining,
            layer_list=layer_list,
            provider_list=provider_list,
            additional_place_count=None,
            diskless_type=None,
            diskless_storage_pool=diskless_storage_pool
        )

        return self._rest_request(
            apiconsts.API_CRT_RSC_GRP,
            "POST", "/v1/resource-groups",
            body
        )

    def resource_group_modify(
            self,
            name,
            description=None,
            place_count=None,
            storage_pool=None,
            do_not_place_with=None,
            do_not_place_with_regex=None,
            replicas_on_same=None,
            replicas_on_different=None,
            diskless_on_remaining=None,
            layer_list=None,
            provider_list=None,
            property_dict=None,
            delete_props=None,
            diskless_storage_pool=None):
        """
        Modify the given resource group.

        :param str name: Name of the resource group to modify.
        :param str description: description for the resource group.
        :param int place_count: Number of placements, on how many different nodes
        :param list[str] storage_pool: List of storage pools to use
        :param list[str] do_not_place_with: Do not place with resource names in this list
        :param str do_not_place_with_regex: A regex string that rules out resources
        :param list[str] replicas_on_same: A list of node property names, their values should match
        :param list[str] replicas_on_different: A list of node property names, their values should not match
        :param bool diskless_on_remaining: If True all remaining nodes will add a diskless resource
        :param list[str] layer_list: Define layers for the resource
        :param list[str] provider_list: Filter provider kinds
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param list[str] delete_props: List of properties to delete
        :param optional[list[str]] diskless_storage_pool: List of diskless pools to use
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.0.8", msg="Resource group modify not supported by server")
        body = {}

        if description is not None:
            body["description"] = description

        if storage_pool is not None and not isinstance(storage_pool, list):
            storage_pool = [storage_pool]

        self._set_select_filter_body(
            body,
            place_count=place_count,
            additional_place_count=None, # rsc_grps will never ask for "additional" resources
            storage_pool=storage_pool,
            do_not_place_with=do_not_place_with,
            do_not_place_with_regex=do_not_place_with_regex,
            replicas_on_same=replicas_on_same,
            replicas_on_different=replicas_on_different,
            diskless_on_remaining=diskless_on_remaining,
            layer_list=layer_list,
            provider_list=provider_list,
            diskless_type=None,  # rsc_grps will never ask to place diskless resources
            diskless_storage_pool=diskless_storage_pool
        )

        if property_dict:
            body["override_props"] = property_dict

        if delete_props:
            body["delete_props"] = delete_props

        return self._rest_request(
            apiconsts.API_MOD_RSC_GRP,
            "PUT", "/v1/resource-groups/" + name,
            body
        )

    def resource_group_delete(self, name):
        """
        Delete a given resource group.

        :param str name: Resource group name to delete.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.0.8", msg="Resource group delete not supported by server")
        return self._rest_request(apiconsts.API_DEL_RSC_GRP, "DELETE", "/v1/resource-groups/" + name)

    def resource_group_list_raise(self, filter_by_resource_groups=None, filter_by_props=None):
        """
        Request a list of all resource groups known to the controller.

        :param list[str] filter_by_resource_groups: Filter by the given resource group names.
        :param Optional[list[str]] filter_by_props: Filter nodes by properties.
        :return: A ResourceGroupListResponse object
        :rtype: ResourceGroupResponse
        :raises LinstorError: if apicall error or no data received.
        :raises LinstorApiCallError: on an apicall error from controller
        """
        self._require_version("1.0.8", msg="Resource group list not supported by server")

        query_params = []
        if filter_by_resource_groups:
            query_params += ["resource_groups=" + x for x in filter_by_resource_groups]
        if filter_by_props:
            query_params += ["props=" + x for x in filter_by_props]

        path = "/v1/resource-groups"
        if query_params:
            path += "?" + "&".join(query_params)

        list_res = self._rest_request(apiconsts.API_LST_RSC_GRP, "GET", path)

        if list_res:
            if isinstance(list_res[0], ResourceGroupResponse):
                return list_res[0]
            raise LinstorApiCallError(list_res[0])
        raise LinstorError("No list response received.")

    def resource_group_spawn(
            self,
            rsc_grp_name,
            rsc_dfn_name,
            vlm_sizes,
            partial=False,
            definitions_only=False,
            external_name=None):
        """
        Spawns resource for the given resource group.

        :param str rsc_grp_name: Name of the resource group to spawn from.
        :param str rsc_dfn_name: Name of the new resource definition.
        :param list[str] vlm_sizes: Volume definitions to spawn
        :param bool partial: If false, the length of the vlm_sizes has to match the number of volume-groups or an
                             error is returned.
        :param bool definitions_only: Do not auto place resource, just create the definitions
        :param Optional[str] external_name: External name to set for the resource definition, if this is specified
                                            the resource definition name will be ignored
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.0.8", msg="Resource group API not supported by server")
        vlm_sizes_int = []
        for size in vlm_sizes:
            if isinstance(size, int):
                vlm_sizes_int.append(size)
            else:
                vlm_sizes_int.append(self.parse_volume_size_to_kib(size))

        body = {
            "resource_definition_name": rsc_dfn_name,
            "volume_sizes": vlm_sizes_int,
            "partial": partial,
            "definitions_only": definitions_only
        }

        if external_name:
            self._require_version("1.0.16", msg="Spawn with external name not supported by server")
            body["resource_definition_name"] = ""
            body["resource_definition_external_name"] = external_name

        return self._rest_request(
            apiconsts.API_SPAWN_RSC_DFN,
            "POST",
            "/v1/resource-groups/" + rsc_grp_name + "/spawn",
            body
        )

    def resource_group_qmvs(self, rsc_grp_name):
        """
        Queries maximum volume size from the given resource group

        This is basically the same as the qmvs on controller level, but
        this API reads all auto-place settings from the given resource group.

        :param str rsc_grp_name: Name of the resource group to fetch the query filters
        """
        self._require_version("1.0.12", msg="Query max volume size on resource group API not supported by server")

        return self._rest_request(
            apiconsts.API_QRY_MAX_VLM_SIZE,
            "GET",
            "/v1/resource-groups/" + rsc_grp_name + "/query-max-volume-size"
        )

    def volume_group_create(
            self,
            resource_grp_name,
            volume_nr=None,
            property_dict=None,
            gross=False
    ):
        """
        Create a volume group.

        :param str resource_grp_name: Name of the resource group.
        :param int volume_nr: Volume number to set, might be None.
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param bool gross: Specified size should be interpreted as gross size.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.0.8", msg="Resource group API not supported by server")
        body = {}

        if volume_nr is not None:
            body["volume_number"] = volume_nr

        if property_dict:
            body["props"] = property_dict

        if gross:
            self._require_version("1.0.13", msg="Gross-size not supported by server")
            body["flags"] = [apiconsts.FLAG_GROSS_SIZE]

        return self._rest_request(
            apiconsts.API_CRT_VLM_GRP,
            "POST", "/v1/resource-groups/" + str(resource_grp_name) + "/volume-groups",
            body
        )

    def volume_group_modify(
            self,
            resource_grp_name,
            volume_nr,
            property_dict=None,
            delete_props=None,
            gross=None):
        """
        Modify properties of the given volume group.

        :param str resource_grp_name: Name of the resource group to modify.
        :param int volume_nr: Volume number to edit.
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param list[str] delete_props: List of properties to delete
        :param Optional[bool] gross: Specified size should be interpreted as gross size, False will use net-size again.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.0.8", msg="Resource group API not supported by server")
        body = {}

        if property_dict:
            body["override_props"] = property_dict

        if delete_props:
            body["delete_props"] = delete_props

        if gross is not None:
            self._require_version("1.0.13", msg="Modify volume-group with gross size not supported.")
            if gross:
                body["flags"] = [apiconsts.FLAG_GROSS_SIZE] if gross else ["-" + apiconsts.FLAG_GROSS_SIZE]

        return self._rest_request(
            apiconsts.API_MOD_VLM_GRP,
            "PUT", "/v1/resource-groups/" + resource_grp_name + "/volume-groups/" + str(volume_nr),
            body
        )

    def volume_group_delete(self, resource_grp_name, volume_nr):
        """
        Delete a given resource group.

        :param str resource_grp_name: Resource group name.
        :param int volume_nr: Volume nr to delete.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.0.8", msg="Resource group API not supported by server")
        return self._rest_request(
            apiconsts.API_DEL_VLM_GRP,
            "DELETE",
            "/v1/resource-groups/" + resource_grp_name + "/volume-groups/" + str(volume_nr)
        )

    def volume_group_list_raise(self, resource_grp_name):
        """
        Request a list of all resource groups known to the controller.

        :return: A VolumeGroupResponse object
        :rtype: VolumeGroupResponse
        :raises LinstorError: if apicall error or no data received.
        :raises LinstorApiCallError: on an apicall error from controller
        """
        self._require_version("1.0.8", msg="Resource group API not supported by server")
        list_res = self._rest_request(
            apiconsts.API_LST_VLM_GRP,
            "GET",
            "/v1/resource-groups/" + resource_grp_name + "/volume-groups"
        )

        if list_res:
            if isinstance(list_res[0], VolumeGroupResponse):
                return list_res[0]
            raise LinstorApiCallError(list_res[0])
        raise LinstorError("No list response received.")

    def resource_dfn_create(self, name, port=None, external_name=None, layer_list=None, resource_group=None):
        """
        Creates a resource definition.

        :param str name: Name of the new resource definition.
        :param int port: Port the resource definition should use.
        :param list[str] layer_list: Set of layer names to use.
        :param str external_name: Unicode string of the user specified name.
        :param str resource_group: Name of the resource group the definition should be linked to.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {
            "resource_definition": {"name": name}
        }
        if port is not None:
            body["drbd_port"] = port
        if external_name:
            body["resource_definition"]["external_name"] = external_name
            del body["resource_definition"]["name"]

        # if args.secret:
        #     p.secret = args.secret
        if layer_list:
            body["resource_definition"]["layer_data"] = []
            for layer in layer_list:
                body["resource_definition"]["layer_data"].append({"type": layer})

        if resource_group:
            body["resource_definition"]["resource_group_name"] = resource_group

        return self._rest_request(
            apiconsts.API_CRT_RSC_DFN,
            "POST", "/v1/resource-definitions",
            body
        )

    def resource_dfn_modify(self, name, property_dict, delete_props=None, peer_slots=None, resource_group=None):
        """
        Modify properties of the given resource definition.

        :param str name: Name of the resource definition to modify.
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param list[str] delete_props: List of properties to delete
        :param int peer_slots: peer slot count for new resources of this resource dfn
        :param Optional[str] resource_group: Change resource group to the given name
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {}

        if peer_slots is not None:
            body["drbd_peer_slots"] = peer_slots

        if property_dict:
            body["override_props"] = property_dict

        if delete_props:
            body["delete_props"] = delete_props

        if resource_group:
            body["resource_group"] = resource_group

        return self._rest_request(
            apiconsts.API_MOD_RSC_DFN,
            "PUT", "/v1/resource-definitions/" + name,
            body
        )

    def resource_dfn_delete(self, name, async_msg=False):
        """
        Delete a given resource definition.

        :param str name: Resource definition name to delete.
        :param bool async_msg: True to return without waiting for the action to complete on the satellites.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        return self._rest_request(apiconsts.API_DEL_RSC_DFN, "DELETE", "/v1/resource-definitions/" + name)

    def resource_dfn_list(
            self,
            query_volume_definitions=True,
            filter_by_resource_definitions=None,
            filter_by_props=None):
        """
        Request a list of all resource definitions known to the controller.

        :param bool query_volume_definitions: Query the volume definitions of this resource definition.
        :param list[str] filter_by_resource_definitions: Filter resource definitions by resource definition names.
        :param Optional[list[str]] filter_by_props: Filter nodes by properties
        :return: A ResourceDefinitionResponse object
        :rtype: list[ResourceDefinitionResponse]
        """
        if self.api_version_smaller("1.0.10"):
            rsc_dfns_resp = self._rest_request(apiconsts.API_LST_RSC_DFN, "GET", "/v1/resource-definitions")

            if rsc_dfns_resp:
                for rsc_dfn in rsc_dfns_resp[0].resource_definitions:
                    if query_volume_definitions:
                        vlm_dfn = self._rest_request(
                            apiconsts.API_LST_VLM_DFN,
                            "GET",
                            "/v1/resource-definitions/" + rsc_dfn.name + "/volume-definitions"
                        )
                        if vlm_dfn and isinstance(vlm_dfn[0], VolumeDefinitionResponse):
                            rsc_dfn._rest_data["volume_definitions"] = vlm_dfn[0].rest_data

            return rsc_dfns_resp
        else:
            query_params = []
            if filter_by_resource_definitions:
                query_params += ["resource_definitions=" + x for x in filter_by_resource_definitions]
            if query_volume_definitions:
                query_params += ["with_volume_definitions=true"]
            if filter_by_props:
                query_params += ["props=" + x for x in filter_by_props]

            path = "/v1/resource-definitions"
            if query_params:
                path += "?" + "&".join(query_params)
            resource_definition_res = self._rest_request(
                apiconsts.API_LST_RSC_DFN,
                "GET",
                path
            )  # type: List[ResourceDefinitionResponse]

            return resource_definition_res

    def resource_dfn_list_raise(
            self,
            query_volume_definitions=True,
            filter_by_resource_definitions=None,
            filter_by_props=None):
        """
        Request a list of all resource definitions known to the controller.

        :param bool query_volume_definitions: Query the volume definitions of this resource definition.
        :param list[str] filter_by_resource_definitions: Filter resource definitions by resource definition names.
        :param Optional[list[str]] filter_by_props: Filter nodes by properties
        :return: A ResourceDefinitionResponse object
        :rtype: ResourceDefinitionResponse
        :raises LinstorError: if apicall error or no data received.
        :raises LinstorApiCallError: on an apicall error from controller
        """
        list_res = self.resource_dfn_list(
            query_volume_definitions=query_volume_definitions,
            filter_by_resource_definitions=filter_by_resource_definitions,
            filter_by_props=filter_by_props
        )
        if list_res:
            if isinstance(list_res[0], ResourceDefinitionResponse):
                return list_res[0]
            raise LinstorApiCallError(list_res[0])
        raise LinstorError("No list response received.")

    def resource_dfn_props_list(self, rsc_name, filter_by_namespace=''):
        """
        Return a dictionary containing keys for a resource definition filtered by namespace.

        :param str rsc_name: Name of the resource definition it is linked to.
        :param str filter_by_namespace: Return only keys starting with the given prefix.
        :return: dict containing matching keys
        :raises LinstorError: if resource can not be found
        """
        rsc_dfn_list_replies = self.resource_dfn_list(
            query_volume_definitions=False,
            filter_by_resource_definitions=[rsc_name])
        if not rsc_dfn_list_replies or not rsc_dfn_list_replies[0]:
            raise LinstorError('Could not list resource definitions, or they are empty')

        rsc_dfn_list_reply = rsc_dfn_list_replies[0]  # type: ResourceDefinitionResponse
        for rsc_dfn in rsc_dfn_list_reply.resource_definitions:
            if rsc_dfn.name.lower() == rsc_name.lower():
                return Linstor._filter_props(rsc_dfn.properties, filter_by_namespace)

        return {}

    def volume_dfn_create(
            self,
            rsc_name,
            size,
            volume_nr=None,
            minor_nr=None,
            encrypt=False,
            storage_pool=None,
            gross=False
    ):
        """
        Create a new volume definition on the controller.

        :param str rsc_name: Name of the resource definition it is linked to.
        :param int size: Size of the volume definition in kibibytes.
        :param int volume_nr: Volume number to use.
        :param int minor_nr: Minor number to use.
        :param bool encrypt: Encrypt created volumes from this volume definition.
        :param storage_pool: Storage pool this volume definition will use.
        :param bool gross: Specified size should be interpreted as gross size.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {"volume_definition": {"size_kib": size, "flags": []}}

        if minor_nr is not None:
            body["drbd_minor_number"] = minor_nr

        if volume_nr is not None:
            body["volume_definition"]["volume_number"] = volume_nr

        if encrypt:
            body["volume_definition"]["flags"] += [apiconsts.FLAG_ENCRYPTED]

        if gross:
            body["volume_definition"]["flags"] += [apiconsts.FLAG_GROSS_SIZE]

        if storage_pool:
            body["volume_definition"]["props"] = {apiconsts.KEY_STOR_POOL_NAME: storage_pool}

        if not body["volume_definition"]["flags"]:
            del body["volume_definition"]["flags"]

        return self._rest_request(
            apiconsts.API_CRT_VLM_DFN,
            "POST", "/v1/resource-definitions/" + rsc_name + "/volume-definitions",
            body
        )

    def volume_dfn_modify(
            self,
            rsc_name,
            volume_nr,
            set_properties=None,
            delete_properties=None,
            size=None,
            gross=None
    ):
        """
        Modify properties of the given volume definition.

        :param str rsc_name: Name of the resource definition.
        :param int volume_nr: Volume number of the volume definition.
        :param dict[str, str] set_properties: Dict containing key, value pairs for new values.
        :param list[str] delete_properties: List of properties to delete
        :param int size: New size of the volume definition in kibibytes.
        :param Optional[bool] gross: Specified size should be interpreted as gross size, False will use net-size again.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {}

        if size:
            body["size_kib"] = size

        if set_properties:
            body["override_props"] = set_properties

        if delete_properties:
            body["delete_props"] = delete_properties

        if gross is not None:
            self._require_version("1.0.13", msg="Modify volume-definition with gross size not supported.")
            if gross:
                body["flags"] = [apiconsts.FLAG_GROSS_SIZE] if gross else ["-" + apiconsts.FLAG_GROSS_SIZE]

        return self._rest_request(
            apiconsts.API_MOD_VLM_DFN,
            "PUT", "/v1/resource-definitions/" + rsc_name + "/volume-definitions/" + str(volume_nr),
            body
        )

    def volume_dfn_delete(self, rsc_name, volume_nr, async_msg=False):
        """
        Delete a given volume definition.

        :param str rsc_name: Resource definition name of the volume definition.
        :param volume_nr: Volume number.
        :param bool async_msg: True to return without waiting for the action to complete on the satellites.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        return self._rest_request(
            apiconsts.API_DEL_VLM_DFN,
            "DELETE", "/v1/resource-definitions/" + rsc_name + "/volume-definitions/" + str(volume_nr)
        )

    def _volume_dfn_size(self, rsc_name, volume_nr):
        """
        Return size of given volume for given resource.

        :param str rsc_name: Resource definition name
        :param volume_nr: Volume number.
        :return: Size of the volume definition in kibibytes. IMPORTANT: This will change to a tuple/dict type
        :raises LinstorError: if resource or volume_nr can not be found
        """
        rsc_dfn_list_replies = self.resource_dfn_list(
            query_volume_definitions=True,
            filter_by_resource_definitions=[rsc_name]
        )
        if not rsc_dfn_list_replies or not rsc_dfn_list_replies[0]:
            raise LinstorError('Could not list resource definitions, or they are empty')

        rsc_dfn_list_reply = rsc_dfn_list_replies[0]  # type: ResourceDefinitionResponse
        for rsc_dfn in rsc_dfn_list_reply.resource_definitions:
            if rsc_dfn.name.lower() == rsc_name.lower():
                for vlm_dfn in rsc_dfn.volume_definitions:
                    if vlm_dfn.number == volume_nr:
                        return vlm_dfn.size

        raise LinstorError('Could not find volume number {} in resource {}'.format(volume_nr, rsc_name))

    def resource_create(self, rscs, async_msg=False):
        """
        Creates new resources in a resource definition.

        :param list[ResourceData] rscs: Resources to create
        :param bool async_msg: True to return without waiting for the action to complete on the satellites.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = []
        rsc_name = rscs[0].rsc_name

        for rsc in rscs:
            rsc_data = {
                "resource": {
                    "node_name": rsc.node_name
                }
            }

            rsc_data["resource"]["flags"] = []

            if rsc.storage_pool:
                rsc_data["resource"]["props"] = {apiconsts.KEY_STOR_POOL_NAME: rsc.storage_pool}

            if rsc.diskless:
                rsc_data["resource"]["flags"] += [apiconsts.FLAG_DISKLESS]

            if rsc.drbd_diskless:
                rsc_data["resource"]["flags"] += [apiconsts.FLAG_DRBD_DISKLESS]

            if rsc.nvme_initiator:
                rsc_data["resource"]["flags"] += [apiconsts.FLAG_NVME_INITIATOR]

            if not rsc.active:
                rsc_data["resource"]["flags"] += [apiconsts.FLAG_RSC_INACTIVE]

            if rsc.node_id is not None:
                rsc_data["drbd_node_id"] = rsc.node_id

            if rsc.layer_list:
                rsc_data["layer_list"] = rsc.layer_list

            if not rsc_data["resource"]["flags"]:
                del rsc_data["resource"]["flags"]

            body.append(rsc_data)

        return self._rest_request(
            apiconsts.API_CRT_RSC,
            "POST", "/v1/resource-definitions/" + rsc_name + "/resources",
            body
        )

    def _set_select_filter_body(
            self,
            body,
            place_count,
            storage_pool,
            do_not_place_with,
            do_not_place_with_regex,
            replicas_on_same,
            replicas_on_different,
            diskless_on_remaining,
            layer_list,
            provider_list,
            additional_place_count,
            diskless_type,
            diskless_storage_pool
    ):
        """

        :param dict[Any] body:
        :param Optional[int] place_count:
        :param Optional[List[str]] storage_pool:
        :param Optional[List[str]] do_not_place_with:
        :param Optional[str] do_not_place_with_regex:
        :param Optional[List[str]] replicas_on_same:
        :param Optional[List[str]] replicas_on_different:
        :param Optional[bool] diskless_on_remaining:
        :param Optional[List[str]] layer_list:
        :param Optional[List[str]] provider_list:
        :param Optional[int] additional_place_count:
        :param Optional[List[str]] storage_pool_diskless_list:
        :return:
        """
        if "select_filter" not in body:
            body["select_filter"] = {}

        if place_count is not None:
            body["select_filter"]["place_count"] = place_count

        if additional_place_count is not None and additional_place_count != 0:
            if self.api_version_smaller("1.6.0"):
                raise LinstorArgumentError("linstor-controller version doesn't support additional place count")
            body["select_filter"]["additional_place_count"] = additional_place_count

        if diskless_type:
            body["select_filter"]["diskless_type"] = diskless_type

        if diskless_on_remaining is not None:
            body["select_filter"]["diskless_on_remaining"] = diskless_on_remaining

        if storage_pool is not None:
            if self.api_version_smaller("1.1.0"):
                if len(storage_pool) > 1:
                    raise LinstorArgumentError("linstor-controller version doesn't support multiple storage pools")
                body["select_filter"]["storage_pool"] = storage_pool[0]
            else:
                pool_list = storage_pool if storage_pool and storage_pool[0] else []
                body["select_filter"]["storage_pool_list"] = pool_list

        if diskless_storage_pool is not None:
            self._require_version("1.7.0")
            body["select_filter"]["storage_pool_diskless_list"] = diskless_storage_pool

        if do_not_place_with is not None:
            body["select_filter"]["not_place_with_rsc"] = do_not_place_with
        if do_not_place_with_regex is not None:
            body["select_filter"]["not_place_with_rsc_regex"] = do_not_place_with_regex
        if replicas_on_same is not None:
            body["select_filter"]["replicas_on_same"] = replicas_on_same
        if replicas_on_different is not None:
            body["select_filter"]["replicas_on_different"] = replicas_on_different

        if layer_list is not None:
            body["select_filter"]["layer_stack"] = layer_list

        if provider_list is not None:
            body["select_filter"]["provider_list"] = provider_list
        return body

    def resource_auto_place(
            self,
            rsc_name,
            place_count,
            storage_pool=None,
            do_not_place_with=None,
            do_not_place_with_regex=None,
            replicas_on_same=None,
            replicas_on_different=None,
            diskless_on_remaining=False,
            async_msg=False,
            layer_list=None,
            provider_list=None,
            additional_place_count=None,
            diskless_type=None,
            diskless_storage_pool=None
    ):
        """
        Auto places(deploys) a resource to the amount of place_count.

        :param str rsc_name: Name of the resource definition to deploy
        :param optional[int] place_count: Number of placements to reach, on how many different nodes.
            either place_count or additional_place_count must be present
        :param list[str] storage_pool: List of storage pools to use
        :param list[str] do_not_place_with: Do not place with resource names in this list
        :param str do_not_place_with_regex: A regex string that rules out resources
        :param list[str] replicas_on_same: A list of node property names, their values should match
        :param list[str] replicas_on_different: A list of node property names, their values should not match
        :param bool diskless_on_remaining: If True all remaining nodes will add a diskless resource
        :param bool async_msg: True to return without waiting for the action to complete on the satellites
        :param list[str] layer_list: Define layers for the resource
        :param list[str] provider_list: Filter provider kinds
        :param optional[int] additional_place_count: Number of additional placements.
            either place_count or additional_place_count must be present
        :param optional[str] diskless_type: Either apiconst.FLAG_DRBD_DISKLESS or apiconst.FLAG_NVME_INITIATOR
        :param optional[list[str]] diskless_storage_pool: List of diskless pools to use
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {
            "diskless_on_remaining": diskless_on_remaining
        }

        if storage_pool is not None and not isinstance(storage_pool, list):
            storage_pool = [storage_pool]

        self._set_select_filter_body(
            body,
            place_count=place_count,
            storage_pool=storage_pool,
            do_not_place_with=do_not_place_with,
            do_not_place_with_regex=do_not_place_with_regex,
            replicas_on_same=replicas_on_same,
            replicas_on_different=replicas_on_different,
            diskless_on_remaining=diskless_on_remaining,
            layer_list=layer_list,
            provider_list=provider_list,
            additional_place_count=additional_place_count,
            diskless_type=diskless_type,
            diskless_storage_pool=diskless_storage_pool
        )

        if layer_list:
            body["layer_list"] = layer_list

        return self._rest_request(
            apiconsts.API_AUTO_PLACE_RSC,
            "POST", "/v1/resource-definitions/" + rsc_name + "/autoplace",
            body
        )

    def resource_create_and_auto_place(self, rsc_name, size, place_count, storage_pool=None,
                                       diskless_on_remaining=False):
        """
        This is a convenience method mainly intended for plugins.
        It is quite usual that plugins have a "create" step where they auto-place a resource.
        Later, these plugins have an "open" call where they might create diskless assignments.

        :param str rsc_name: Name of the new resource definition.
        :param int size: Size of the volume definition in kibibytes.
        :param int place_count: Number of placements, on how many different nodes
        :param str storage_pool: Storage pool to use
        :param bool diskless_on_remaining: If True all remaining nodes will add a diskless resource
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        replies = self.resource_dfn_create(rsc_name)
        if not replies[0].is_success():
            return replies

        replies = self.volume_dfn_create(rsc_name, size, storage_pool=storage_pool)
        if not replies[0].is_success():
            return replies

        return self.resource_auto_place(rsc_name, place_count, storage_pool=storage_pool,
                                        diskless_on_remaining=diskless_on_remaining)

    def resource_modify(self, node_name, rsc_name, property_dict, delete_props=None):
        """
        Modify properties of a given resource.

        :param str node_name: Node name where the resource is deployed.
        :param str rsc_name: Name of the resource.
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param list[str] delete_props: List of properties to delete
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {}

        if property_dict:
            body["override_props"] = property_dict

        if delete_props:
            body["delete_props"] = delete_props

        return self._rest_request(
            apiconsts.API_MOD_RSC,
            "PUT", "/v1/resource-definitions/" + rsc_name + "/resources/" + node_name,
            body
        )

    def resource_delete(self, node_name, rsc_name, async_msg=False):
        """
        Deletes a given resource on the given node.

        :param str node_name: Name of the node where the resource is deployed.
        :param str rsc_name: Name of the resource.
        :param bool async_msg: True to return without waiting for the action to complete on the satellites.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        return self._rest_request(
            apiconsts.API_DEL_RSC,
            "DELETE", "/v1/resource-definitions/" + rsc_name + "/resources/" + node_name
        )

    def resource_delete_if_diskless(self, node_name, rsc_name):
        """
        Deletes a given resource if, and only if, diskless on the given node.
        If the resource does not even exit, then the delete is considered successful (NOOP).
        If the resource is not diskless, then the action is considered successful.

        :param str node_name: Name of the node where the resource is deployed.
        :param str rsc_name: Name of the resource.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        apiresp_json = {
            "ret_code": apiconsts.MASK_SUCCESS
        }

        # maximum number of ressources is 1 when filtering per node and resource
        rsc_list_replies = self.resource_list(filter_by_nodes=[node_name], filter_by_resources=[rsc_name])
        if not rsc_list_replies or not rsc_list_replies[0]:
            apiresp_json["message"] = 'Resource {} did not exist on node {}'.format(rsc_name, node_name)
            return [ApiCallResponse(apiresp_json)]

        # did something else went wrong?
        rsc_list_reply = rsc_list_replies[0]  # type: ResourceResponse
        if isinstance(rsc_list_reply, ApiCallResponse):
            return rsc_list_replies

        if apiconsts.FLAG_DISKLESS in rsc_list_reply.resources[0].flags:
            return self.resource_delete(rsc_name=rsc_name, node_name=node_name)
        else:
            apiresp_json["message"] = 'Resource {} not diskless on node {}, not deleted'.format(rsc_name, node_name)
            return [ApiCallResponse(apiresp_json)]

    def resource_activate(self, node_name, rsc_name):
        """
        Activate a resource on the given node.

        :param str node_name: node name of the resource
        :param str rsc_name: resource name
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.2.0")
        return self._rest_request(
            apiconsts.API_ACTIVATE_RSC,
            "POST", "/v1/resource-definitions/" + rsc_name + "/resources/" + node_name + "/activate"
        )

    def resource_deactivate(self, node_name, rsc_name):
        """
        De-activate a resource on the given node.

        :param str node_name: node name of the resource
        :param str rsc_name: resource name
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.2.0")
        return self._rest_request(
            apiconsts.API_DEACTIVATE_RSC,
            "POST", "/v1/resource-definitions/" + rsc_name + "/resources/" + node_name + "/deactivate"
        )

    def resource_list(self, filter_by_nodes=None, filter_by_resources=None, filter_by_props=None):
        """
        Request a list of all resources known to the controller.

        :param list[str] filter_by_nodes: filter resources by nodes
        :param list[str] filter_by_resources: filter resources by resource names
        :param Optional[list[str]] filter_by_props: Filter nodes by properties

        :return: A list containing a ResourceResponse object
        :rtype: list[ResourceResponse]
        """
        return self.volume_list(
            filter_by_nodes=filter_by_nodes, filter_by_resources=filter_by_resources, filter_by_props=filter_by_props)

    def resource_list_raise(self, filter_by_nodes=None, filter_by_resources=None, filter_by_props=None):
        """
        Request a list of all resources known to the controller.

        :param list[str] filter_by_nodes: filter resources by nodes
        :param list[str] filter_by_resources: filter resources by resource names
        :param Optional[list[str]] filter_by_props: Filter nodes by properties
        :return: A ResourceResponse object
        :rtype: ResourceResponse
        :raises LinstorError: if apicall error or no data received.
        :raises LinstorApiCallError: on an apicall error from controller
        """
        return self.volume_list_raise(
            filter_by_nodes=filter_by_nodes,
            filter_by_resources=filter_by_resources,
            filter_by_props=filter_by_props)

    def volume_list(
            self,
            filter_by_nodes=None,
            filter_by_stor_pools=None,
            filter_by_resources=None,
            filter_by_props=None):
        """
        Request a list of all volumes known to the controller.

        :param list[str] filter_by_nodes: filter resources by nodes
        :param list[str] filter_by_stor_pools: filter resources by storage pool names
        :param list[str] filter_by_resources: filter resources by resource names
        :param Optional[list[str]] filter_by_props: Filter nodes by properties
        :return: A list containing a ResourceResponse object
        :rtype: list[RESTMessageResponse]
        """
        result = []
        errors = []
        query_params = []
        if filter_by_nodes:
            query_params += ["nodes=" + x for x in filter_by_nodes]
        if filter_by_stor_pools:
            query_params += ["storage_pools=" + x for x in filter_by_stor_pools]
        if filter_by_resources:
            query_params += ["resources=" + x for x in filter_by_resources]
        if filter_by_props:
            query_params += ["props=" + x for x in filter_by_props]
        path = "/v1/view/resources"
        if query_params:
            path += "?" + "&".join(query_params)
        resource_resp = self._rest_request(
            apiconsts.API_LST_RSC,
            "GET",
            path
        )  # type: List[ResourceResponse]
        if resource_resp and isinstance(resource_resp[0], ResourceResponse):
            result += resource_resp
        else:
            errors += resource_resp

        return result + errors

    def volume_list_raise(
            self,
            filter_by_nodes=None,
            filter_by_stor_pools=None,
            filter_by_resources=None,
            filter_by_props=None):
        """
        Request a list of all volumes known to the controller.

        :param list[str] filter_by_nodes: filter resources by nodes
        :param list[str] filter_by_stor_pools: filter resources by storage pool names
        :param list[str] filter_by_resources: filter resources by resource names
        :param Optional[list[str]] filter_by_props: Filter nodes by properties
        :return: A ResourceResponse object
        :rtype: ResourceResponse
        :raises LinstorError: if apicall error or no data received.
        :raises LinstorApiCallError: on an apicall error from controller
        """
        list_res = self.volume_list(
            filter_by_nodes=filter_by_nodes,
            filter_by_stor_pools=filter_by_stor_pools,
            filter_by_resources=filter_by_resources,
            filter_by_props=filter_by_props)
        if list_res:
            if isinstance(list_res[0], ResourceResponse):
                return list_res[0]
            raise LinstorApiCallError(list_res[0])
        raise LinstorError("No list response received.")

    def volume_modify(self, node_name, rsc_name, vlm_nr, property_dict, delete_props=None):
        """
        Modify properties of a given resource.

        :param str node_name: Node name where the resource is deployed.
        :param str rsc_name: Name of the resource.
        :param int vlm_nr: Number of the volume
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param list[str] delete_props: List of properties to delete
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.0.6", msg="Volume modify not supported by server")

        body = {}

        if property_dict:
            body["override_props"] = property_dict

        if delete_props:
            body["delete_props"] = delete_props

        return self._rest_request(
            apiconsts.API_MOD_VLM,
            "PUT", "/v1/resource-definitions/" + rsc_name + "/resources/" + node_name + "/volumes/" + str(vlm_nr),
            body
        )

    def resource_toggle_disk(
            self,
            node_name,
            rsc_name,
            storage_pool=None,
            diskless=False,
            async_msg=False,
            migrate_from=None
    ):
        """
        Toggles a resource between diskless and having a disk.

        :param str node_name: Node name where the resource is deployed.
        :param str rsc_name: Name of the resource.
        :param bool async_msg: True to return without waiting for the action to complete on the satellites.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        path = "/v1/resource-definitions/" + rsc_name + "/resources/" + node_name

        if migrate_from:
            path += "/migrate-disk/" + migrate_from
        else:
            path += "/toggle-disk/"
            path += "diskless" if diskless else "diskful"

        if storage_pool:
            path += "/" + storage_pool

        return self._rest_request(
            apiconsts.API_TOGGLE_DISK,
            "PUT", path
        )

    def controller_props(self):
        """
        Request a list of all controller properties.

        :return: A MsgLstCtrlCfgProps proto message containing all controller props.
        :rtype: list
        """
        return self._rest_request(apiconsts.API_LST_CTRL_PROPS, "GET", "/v1/controller/properties")

    @classmethod
    def _split_prop_key(cls, fkey):
        key = fkey
        namespace = None
        ns_pos = key.rfind('/')
        if ns_pos >= 0:
            namespace = key[:ns_pos]
            key = key[ns_pos + 1:]

        return key, namespace

    def controller_set_prop(self, key, value):
        """
        Sets a property on the controller.

        :param str key: Key of the property.
        :param str value:  New Value of the property.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {
            "override_props": {
                key: value
            }
        }
        return self._rest_request(
            apiconsts.API_SET_CTRL_PROP,
            "POST", "/v1/controller/properties",
            body
        )

    def controller_del_prop(self, key):
        """
        Deletes a property on the controller.

        :param key: Key of the property.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {
            "delete_props": [key]
        }

        return self._rest_request(
            apiconsts.API_SET_CTRL_PROP,
            "POST", "/v1/controller/properties",
            body
        )

    def controller_info(self):
        """
        If connected this method returns the controller info string.

        :return: Controller info string or None if not connected.
        :rtype: str
        """
        cversion_list = self._rest_request(
            apiconsts.API_VERSION,
            "GET", "/v1/controller/version"
        )  # type: List[ControllerVersion]

        if cversion_list:
            cversion = cversion_list[0]

            return "LINSTOR,Controller," + cversion.version + "," + cversion.git_hash + "," + cversion.build_time
        return None

    def controller_version(self):
        """
        If connected this method returns the controller version object.

        :return: Controller info string or None if not connected.
        :rtype: ControllerVersion
        """
        return self._rest_request(
            apiconsts.API_VERSION,
            "GET", "/v1/controller/version"
        )[0]

    def controller_host(self):
        """
        Returns the used controller hostname.

        :return: Uri used to connect.
        :rtype: str
        """
        return self._ctrl_host

    def crypt_create_passphrase(self, passphrase):
        """
        Create a new crypt passphrase on the controller.

        :param passphrase: New passphrase.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {"new_passphrase": passphrase}

        return self._rest_request(
            apiconsts.API_CRT_CRYPT_PASS,
            "POST", "/v1/encryption/passphrase",
            body
        )

    def crypt_enter_passphrase(self, passphrase):
        """
        Send the master passphrase to unlock crypted volumes.

        :param passphrase: Passphrase to send to the controller.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        return self._rest_request(
            apiconsts.API_ENTER_CRYPT_PASS,
            "PATCH", "/v1/encryption/passphrase",
            passphrase
        )

    def crypt_modify_passphrase(self, old_passphrase, new_passphrase):
        """
        Modify the current crypt passphrase.

        :param old_passphrase: Old passphrase, need for decrypt current volumes.
        :param new_passphrase: New passphrase.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {
            "new_passphrase": new_passphrase,
            "old_passphrase": old_passphrase
        }

        return self._rest_request(
            apiconsts.API_MOD_CRYPT_PASS,
            "PUT", "/v1/encryption/passphrase",
            body
        )

    def resource_conn_modify(self, rsc_name, node_a, node_b, property_dict, delete_props):
        """
        Modify properties of a resource connection.
        Identified by the resource name, node1 and node2 arguments.

        :param str rsc_name: Name of the resource.
        :param str node_a: Name of the first node.
        :param str node_b: Name of the second node.
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param list[str] delete_props: List of properties to delete
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {}
        if property_dict:
            body["override_props"] = property_dict

        if delete_props:
            body["delete_props"] = delete_props

        return self._rest_request(
            apiconsts.API_MOD_RSC_CONN,
            "PUT", "/v1/resource-definitions/" + rsc_name + "/resource-connections/" + node_a + "/" + node_b,
            body
        )

    def resource_conn_list(self, rsc_name):
        """
        Request a list of all resource connection to the given resource name.

        :param str rsc_name: Name of the resource to get the connections.
        :return: List of ResourceConnectionsResponse or ApiCallRcResponse
        :rtype: list[RESTMessageResponse]
        """
        return self._rest_request(
            apiconsts.API_REQ_RSC_CONN_LIST,
            "GET",
            "/v1/resource-definitions/" + rsc_name + "/resource-connections"
        )

    def resource_conn_list_raise(self, rsc_name):
        """
        Request a list of all resource connection to the given resource name.

        :param str rsc_name: Name of the resource to get the connections.
        :return: ResourceConnectionsResponse object
        :rtype: ResourceConnectionsResponse
        :raises LinstorError: if apicall error or no data received.
        :raises LinstorApiCallError: on an apicall error from controller
        """
        list_res = self.resource_conn_list(rsc_name)
        if list_res:
            if isinstance(list_res[0], ResourceConnectionsResponse):
                return list_res[0]
            raise LinstorApiCallError(list_res[0])
        raise LinstorError("No list response received.")

    def resource_conn_node_list_raise(self, rsc_name, node_a, node_b):
        """
        Request a list of all resource connection to the given resource name.

        :param str rsc_name: Name of the resource to get the connections.
        :param str node_a: Name of the first node
        :param str node_b: Name of the second node
        :return: List of ResourceConnectionsResponse or ApiCallRcResponse
        :rtype: list[ResourceConnection]
        """
        list_res = self._rest_request(
            Linstor.API_SINGLE_NODE_REQ,
            "GET",
            "/v1/resource-definitions/" + rsc_name + "/resource-connections/" + node_a + "/" + node_b
        )
        if list_res:
            if isinstance(list_res[0], ResourceConnection):
                return list_res[0]
            raise LinstorApiCallError(list_res[0])
        raise LinstorError("No list response received.")

    def drbd_proxy_enable(self, rsc_name, node_a, node_b, port=None):
        """
        Enables DRBD Proxy on a resource connection.
        Identified by the resource name, node1 and node2 arguments.

        :param str rsc_name: Name of the resource.
        :param str node_a: Name of the first node.
        :param str node_b: Name of the second node.
        :param int port: Port the Proxy connection should use.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {}
        if port is not None:
            body["port"] = port

        return self._rest_request(
            apiconsts.API_ENABLE_DRBD_PROXY,
            "POST", "/v1/resource-definitions/" + rsc_name + "/drbd-proxy/enable/" + node_a + "/" + node_b,
            body
        )

    def drbd_proxy_disable(self, rsc_name, node_a, node_b):
        """
        Disables DRBD Proxy on a resource connection.
        Identified by the resource name, node1 and node2 arguments.

        :param str rsc_name: Name of the resource.
        :param str node_a: Name of the first node.
        :param str node_b: Name of the second node.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        return self._rest_request(
            apiconsts.API_ENABLE_DRBD_PROXY,
            "POST", "/v1/resource-definitions/" + rsc_name + "/drbd-proxy/disable/" + node_a + "/" + node_b
        )

    def drbd_proxy_modify(
            self,
            rsc_name,
            property_dict=None,
            delete_props=None,
            compression_type=None,
            compression_property_dict=None
    ):
        """
        Configure DRBD Proxy for the given resource definition.

        :param str rsc_name: Name of the resource definition to modify.
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param list[str] delete_props: List of properties to delete
        :param str compression_type: The compression type to use.
        :param dict[str, str] compression_property_dict: Dict containing key, value pairs for compression values.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {}

        if property_dict:
            body["override_props"] = property_dict

        if delete_props:
            body["delete_props"] = delete_props

        if compression_type:
            body["compression_type"] = compression_type

            if compression_property_dict:
                body["compression_props"] = compression_property_dict

        return self._rest_request(
            apiconsts.API_MOD_DRBD_PROXY,
            "PUT", "/v1/resource-definitions/" + rsc_name + "/drbd-proxy",
            body
        )

    def snapshot_create(self, node_names, rsc_name, snapshot_name, async_msg=False):
        """
        Create a snapshot.

        :param list[str] node_names: Names of the nodes, if empty or None snapshot will be created on all nodes.
        :param str rsc_name: Name of the resource.
        :param str snapshot_name: Name of the new snapshot.
        :param bool async_msg: True to return without waiting for the action to complete on the nodes.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {
            "name": snapshot_name
        }

        if node_names:
            body["nodes"] = node_names

        return self._rest_request(
            apiconsts.API_CRT_SNAPSHOT,
            "POST", "/v1/resource-definitions/" + rsc_name + "/snapshots",
            body
        )

    def snapshot_volume_definition_restore(self, from_resource, from_snapshot, to_resource):
        """
        Create volume definitions from a snapshot.

        :param str from_resource: Name of the snapshot resource.
        :param str from_snapshot: Name of the snapshot.
        :param str to_resource: Name of the new resource.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {
            "to_resource": to_resource
        }

        return self._rest_request(
            apiconsts.API_RESTORE_VLM_DFN,
            "POST",
            "/v1/resource-definitions/" + from_resource + "/snapshot-restore-volume-definition/" + from_snapshot,
            body
        )

    def snapshot_resource_restore(self, node_names, from_resource, from_snapshot, to_resource):
        """
        Restore from a snapshot.

        :param list[str] node_names: Names of the nodes.
        :param str from_resource: Name of the snapshot resource.
        :param str from_snapshot: Name of the snapshot.
        :param str to_resource: Name of the new resource.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {
            "to_resource": to_resource
        }

        if node_names:
            body["nodes"] = node_names

        return self._rest_request(
            apiconsts.API_RESTORE_SNAPSHOT,
            "POST",
            "/v1/resource-definitions/" + from_resource + "/snapshot-restore-resource/" + from_snapshot,
            body
        )

    def snapshot_delete(self, rsc_name, snapshot_name):
        """
        Delete a snapshot.

        :param str rsc_name: Name of the resource.
        :param str snapshot_name: Name of the snapshot.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        return self._rest_request(
            apiconsts.API_DEL_SNAPSHOT,
            "DELETE",
            "/v1/resource-definitions/" + rsc_name + "/snapshots/" + snapshot_name
        )

    def snapshot_rollback(self, rsc_name, snapshot_name):
        """
        Roll a resource back to a snapshot state.

        :param str rsc_name: Name of the resource.
        :param str snapshot_name: Name of the snapshot.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        return self._rest_request(
            apiconsts.API_ROLLBACK_SNAPSHOT,
            "POST",
            "/v1/resource-definitions/" + rsc_name + "/snapshot-rollback/" + snapshot_name
        )

    def snapshot_ship(self, from_node, to_node, rsc_name):
        """
        Roll a resource back to a snapshot state.

        :param str rsc_name: Name of the resource.
        :param str from_node: Snapshot source node.
        :param str to_node: Snapshot target node.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.2.0")
        body = {
            "from_node": from_node,
            "to_node": to_node
        }
        return self._rest_request(
            apiconsts.API_SHIP_SNAPSHOT,
            "POST",
            "/v1/resource-definitions/" + rsc_name + "/snapshot-shipping",
            body
        )

    def snapshot_shipping_list(self,
                      filter_by_nodes=None,
                      filter_by_resources=None,
                      filter_by_snapshots=None,
                      filter_by_status=None):
        """
        Request a list of all snapshot shippings known to the controller.

        :param list[str] filter_by_nodes: filter resources by nodes
        :param list[str] filter_by_resources: filter resources by resource names
        :param list[str] filter_by_snapshots: filter shippings by snapshot names
        :param list[str] filter_by_status: filter shippings by status
        :return: A MsgLstSnapshotDfn proto message containing all information.
        :rtype: list[SnapshotShippingResponse]
        """
        self._require_version("1.3.0")
        query_params = []
        if filter_by_nodes:
            query_params += ["nodes=" + x for x in filter_by_nodes]
        if filter_by_resources:
            query_params += ["resources=" + x for x in filter_by_resources]
        if filter_by_snapshots:
            query_params += ["snapshots=" + x for x in filter_by_snapshots]
        if filter_by_status:
            query_params += ["status=" + x for x in filter_by_status]
        path = "/v1/view/snapshot-shippings"
        if query_params:
            path += "?" + "&".join(query_params)
        return self._rest_request(
            apiconsts.API_LST_SNAPSHOT_SHIPPINGS,
            "GET", path)

    def snapshot_dfn_list(self, filter_by_nodes=None, filter_by_resources=None):
        """
        Request a list of all snapshot definitions known to the controller.

        :param list[str] filter_by_nodes: filter snapshots by nodes
        :param list[str] filter_by_resources: filter snapshots by resource names
        :return: A LstSnapshotDfn REST response containing all information.
        :rtype: list[SnapshotsResponse]
        """
        if self.api_version_smaller("1.1.0"):
            rsc_dfns = self.resource_dfn_list()[0]

            result = []
            for rsc_dfn in rsc_dfns.resource_definitions:
                snapshots = self._rest_request(
                    apiconsts.API_LST_SNAPSHOT_DFN,
                    "GET", "/v1/resource-definitions/" + rsc_dfn.name + "/snapshots"
                )
                if snapshots and isinstance(snapshots[0], SnapshotResponse):
                    result += snapshots[0]._rest_data
            return [SnapshotResponse(result)]
        else:
            query_params = []
            if filter_by_nodes:
                query_params += ["nodes=" + x for x in filter_by_nodes]
            if filter_by_resources:
                query_params += ["resources=" + x for x in filter_by_resources]
            path = "/v1/view/snapshots"
            if query_params:
                path += "?" + "&".join(query_params)
            return self._rest_request(
                apiconsts.API_LST_SNAPSHOT_DFN,
                "GET", path)

    def snapshot_dfn_list_raise(self, filter_by_nodes=None, filter_by_resources=None):
        """
        Request a list of all snapshot definitions known to the controller.

        :param list[str] filter_by_nodes: filter resources by nodes
        :param list[str] filter_by_resources: filter resources by resource names
        :return: A MsgLstSnapshotDfn proto message containing all information.
        :rtype: SnapshotsResponse
        :raises LinstorError: if no response
        :raises LinstorApiCallError: on an apicall error from controller
        """
        list_res = self.snapshot_dfn_list(filter_by_nodes=filter_by_nodes, filter_by_resources=filter_by_resources)
        if list_res:
            if isinstance(list_res[0], SnapshotResponse):
                return list_res[0]
            raise LinstorApiCallError(list_res[0])
        raise LinstorError("No list response received.")

    def error_report_list(self, nodes=None, with_content=False, since=None, to=None, ids=None):
        """
        Retrieves an error report list from the controller.

        :param list[str] nodes: Nodes to filter, if None all
        :param bool with_content: If true the full log content will be retrieved
        :param datetime since: Start datetime from when to include, if None all
        :param datetime to: Until datetime to include error reports, if None all
        :param list[str] ids: Ids there string starts with to include, if None all
        :return: A list containing ErrorReport from the controller.
        :rtype: list[ErrorReport]
        """
        query_params = {
            "withContent": with_content
        }

        if since:
            query_params["since"] = int(time.mktime(since.timetuple()) * 1000)
        if to:
            query_params["to"] = int(time.mktime(to.timetuple()) * 1000)

        result = []
        query_str = urlencode(query_params)
        if ids:
            for id in ids:
                err = self._rest_request(
                    apiconsts.API_REQ_ERROR_REPORTS,
                    "GET", "/v1/error-reports/" + id + "?" + query_str
                )
                if err:
                    result.append(err[0])
        else:
            if nodes:
                for node in nodes:
                    query_params["node"] = node
                    query_str = urlencode(query_params)
                    result += self._rest_request(
                        apiconsts.API_REQ_ERROR_REPORTS,
                        "GET",
                        "/v1/error-reports?" + query_str
                    )
            else:
                result = self._rest_request(apiconsts.API_REQ_ERROR_REPORTS, "GET", "/v1/error-reports?" + query_str)

        return result

    def error_report_delete(
            self,
            nodes=None,
            since=None,
            to=None,
            exception=None,
            version=None,
            ids=None):
        """
        Deletes error-reports on the linstor cluster, filtered by the given parameters

        :param list[str] nodes: Only delete error-reports from this nodes, if None or empty all
        :param datetime since: Start datetime from when to delete
        :param datetime to: Until datetime to delete
        :param str exception: Delete error reports matching this exception string
        :param str version: Delete error reports matching this version string
        :param list[str] ids: Error report ids to delete
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.4.0", msg="Error report delete API not supported by server")

        body = {}

        if nodes:
            body["nodes"] = nodes

        if since:
            body["since"] = int(time.mktime(since.timetuple()) * 1000)
        if to:
            body["to"] = int(time.mktime(to.timetuple()) * 1000)

        if exception:
            body["exception"] = exception

        if version:
            body["version"] = version

        if ids:
            body["ids"] = ids

        return self._rest_request(apiconsts.API_DEL_ERROR_REPORTS, "PATCH", "/v1/error-reports", body)

    def keyvaluestore_modify(self, instance_name, property_dict=None, delete_props=None):
        """
        Modify the properties of a given key value store instance.

        :param str instance_name: Name of the Key/Value store to modify.
        :param Optional[dict[str, str]] property_dict: Dict containing key, value pairs for new values.
        :param Optional[list[str]] delete_props: List of properties to delete
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        body = {}
        if property_dict:
            body["override_props"] = property_dict

        if delete_props:
            body["delete_props"] = delete_props

        return self._rest_request(
            apiconsts.API_MOD_KVS,
            "PUT", "/v1/key-value-store/" + instance_name,
            body
        )

    def keyvaluestores(self):
        """
        Requests all known KeyValue stores known to linstor and returns them in a KeyValueStoresResponse.

        :return: Key/Value store list response objects
        :rtype: KeyValueStoresResponse
        :raise LinstorError: if apicallerror or no response received
        """
        list_res = self._rest_request(
            apiconsts.API_LST_KVS,
            "GET", "/v1/key-value-store"
        )

        if list_res:
            if isinstance(list_res[0], KeyValueStoresResponse):
                return list_res[0]
            raise LinstorApiCallError(list_res[0])
        raise LinstorError("No list response received.")

    def keyvaluestore_list(self, instance_name):
        """
        Request key values for the given instance_name. Note that for implementation and historic reasons keys
        with a '/' as prefix are returned with out this '/'. linstor.KV() might be a better fit in general.

        :return: Key/Value store list response objects
        :rtype: KeyValueStore
        :raise LinstorError: if apicallerror or no response received
        """
        kvs = self.keyvaluestores()
        return kvs.instance(instance_name)

    def physical_storage_list(self):
        """
        Returns a grouped list of physical storage device, to be used for pools.
        Requires API version 1.0.10

        :return: PhysicalStorageList object
        :rtype: PhysicalStorageList
        :raises: LinstorError
        """
        self._require_version("1.0.10", msg="Physical storage API not supported by server")
        phys_list = self._rest_request(
            apiconsts.API_LST_PHYS_STOR,
            "GET", "/v1/physical-storage"
        )

        if phys_list:
            if isinstance(phys_list[0], PhysicalStorageList):
                return phys_list[0]
            else:
                raise LinstorError("Unexpected physical storage list response: " + str(phys_list))

    def physical_storage_create_device_pool(
            self,
            node_name,
            provider_kind,
            device_paths,
            pool_name=None,
            raid_level="JBOD",
            vdo_enable=False,
            vdo_logical_size_kib=None,
            vdo_slab_size_kib=None,
            storage_pool_name=None,
            storage_pool_props=None
    ):
        """
        Creates a device pool on the given device and node.

        :param str node_name: Node name where the device pool should be created.
        :param str provider_kind: Pool type to create, ['LVM', 'LVMTHIN', 'ZFS']
        :param List[str] device_paths: List of full device path on the node.
        :param str raid_level: For 'JBOD' only.
        :param Optional[str] pool_name: Pool name
        :param bool vdo_enable: True or False if VDO should be used.
        :param Optional[int] vdo_logical_size_kib: Logical pool size for VDO
        :param Optional[int] vdo_slab_size_kib: Slab size for VDO
        :param Optional[str] storage_pool_name: If provided creates also a storage pool with that name
        :param Optional[Dict[str,str]] storage_pool_props: Additional storage pool props
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.0.10", msg="Physical storage API not supported by server")
        body = {
            "device_paths": device_paths,
            "provider_kind": provider_kind,
            "pool_name": pool_name,
            "vdo_enable": vdo_enable
        }

        if vdo_logical_size_kib:
            body["vdo_logical_size_kib"] = vdo_logical_size_kib

        if vdo_enable and vdo_slab_size_kib:
            body["vdo_slab_size_kib"] = vdo_slab_size_kib

        if storage_pool_name:
            body["with_storage_pool"] = {
                "name": storage_pool_name
            }
            if storage_pool_props:
                body["with_storage_pool"]["props"] = storage_pool_props

        return self._rest_request(
            apiconsts.API_CREATE_DEVICE_POOL,
            "POST",
            "/v1/physical-storage/" + node_name,
            body
        )

    def sos_report_create(
            self,
            since=None):
        """
        Api call to create a SOS report on the controller node.

        :param Optional[datetime] since: used to limit journalctl messages
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.2.0", msg="SOS API not supported by server")
        query_params = {}
        if since:
            query_params["since"] = int(time.mktime(since.timetuple()) * 1000)

        query_str = urlencode(query_params)
        path = "/v1/sos-report"
        if query_str:
            path += "?" + query_str
        return self._rest_request(
            apiconsts.API_REQ_SOS_REPORT,
            "GET",
            path
        )

    def sos_report_download(
            self,
            since=None,
            to_file=None):
        """
        Create and download a sos report from the controller node.

        :param Optional[datetime] since: used to limit journalctl messages
        :param Optional[str] to_file: path where to store the sos report, if None server given filename will be used.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        self._require_version("1.2.0", msg="SOS API not supported by server")
        query_params = {}
        if since:
            query_params["since"] = int(time.mktime(since.timetuple()) * 1000)

        query_str = urlencode(query_params)
        path = "/v1/sos-report/download"
        if query_str:
            path += "?" + query_str
        return self._rest_request_download(
            apiconsts.API_REQ_SOS_REPORT,
            "GET",
            path,
            to_file=to_file
        )

    def space_reporting_query(self):
        """
        Acquire the hashed space reporting string for commercial customers.

        :return: Space reporting object from controller
        :rtype: list[SpaceReport]
        """
        self._require_version("1.5.0", msg="Space reporting API not supported by server")

        path = "/v1/space-report"
        return self._rest_request(
            apiconsts.API_RPT_SPC,
            "GET",
            path
        )

    def stats(self):
        """
        Returns a printable string containing network statistics.

        :return: A string containing network stats.s
        :rtype: str
        """
        return ""

    def exos_get_defaults(self):
        """
        Gets the default values for all EXOS enclosures

        :return: The default values from the Linstor controller.
        :rtype: ExosDefaults
        """

        self._require_version("1.7.0", msg="EXOS API not supported by server")
        return self._rest_request(
            apiconsts.API_LST_EXOS_DFLTS,
            "GET",
            "/v1/vendor/seagate/exos/defaults"
        )

    def exos_set_defaults(
            self,
            username=None,
            username_env=None,
            password=None,
            password_env=None,
            unset=None):
        """
        Sets the default values for all EXOS enclosures

        :param Optional[str] username: EXOS API username
        :param Optional[str] username_env: Environment variable containing the
            EXOS API username
        :param Optional[str] password: EXOS API password
        :param Optional[str] password_env: Environment variable containing the
            EXOS API password
        :param Optional[List[str]] unset: Unsets default keys
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """

        self._require_version("1.7.0", msg="EXOS API not supported by server")
        return self._rest_request(
            apiconsts.API_MOD_EXOS_DFLTS,
            "PUT",
            "/v1/vendor/seagate/exos/defaults",
            {
                "username": username,
                "username_env": username_env,
                "password": password,
                "password_env": password_env,
                "unset_keys": unset
            }
        )

    def exos_enclosure_create(
            self,
            enclosure_name,
            ctrl_a_ip,
            ctrl_b_ip=None,
            username=None,
            username_env=None,
            password=None,
            password_env=None):
        """
        Creates a new EXOS enclosures

        :param str enclosure_name: Name of the enclosure
        :param str ctrl_a_ip: IP address of the first EXOS controller
        :param Optional[str] ctrl_b_ip: IP address of the second EXOS
            controller
        :param Optional[str] username: Username for the given EXOS enclosure
        :param Optional[str] username_env: Environment variable containing the
            username for theEXOS enclosure
        :param Optional[str] password: Password for the given EXOS enclosure
        :param Optional[str] password_env: Environment variable containing the
            password for theEXOS enclosure
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """

        body = {
            "name": enclosure_name,
            "ctrl_a_ip": ctrl_a_ip
        }
        if ctrl_b_ip:
            body["ctrl_b_ip"] = ctrl_b_ip
        if username:
            body["username"] = username
        if username_env:
            body["username_env"] = username_env
        if password:
            body["password"] = password
        if password_env:
            body["password_env"] = password_env

        self._require_version("1.7.0", msg="EXOS API not supported by server")
        return self._rest_request(
            apiconsts.API_CRT_EXOS_ENCLOSURE,
            "POST",
            "/v1/vendor/seagate/exos/enclosures",
            body
        )

    def exos_enclosure_modify(
            self,
            enclosure_name,
            ctrl_a_ip=None,
            ctrl_b_ip=None,
            username=None,
            username_env=None,
            password=None,
            password_env=None):
        """
        Modifies a given EXOS enclosures

        :param str enclosure_name: Name of the enclosure
        :param Optional[str] ctrl_a_ip: IP address of the first EXOS controller
        :param Optional[str] ctrl_b_ip: IP address of the second EXOS
            controller
        :param Optional[str] username: Username for the given EXOS enclosure
        :param Optional[str] username_env: Environment variable containing the
            username for theEXOS enclosure
        :param Optional[str] password: Password for the given EXOS enclosure
        :param Optional[str] password_env: Environment variable containing the
            password for theEXOS enclosure
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """

        self._require_version("1.7.0", msg="EXOS API not supported by server")

        body = {"name": enclosure_name}
        if ctrl_a_ip:
            body["ctrl_a_ip"] = ctrl_a_ip
        if ctrl_b_ip:
            body["ctrl_b_ip"] = ctrl_b_ip
        if username:
            body["username"] = username
        if username_env:
            body["username_env"] = username_env
        if password:
            body["password"] = password
        if password_env:
            body["password_env"] = password_env

        return self._rest_request(
            apiconsts.API_MOD_EXOS_ENCLOSURE,
            "PUT",
            "/v1/vendor/seagate/exos/enclosures/" + enclosure_name,
            body
        )

    def exos_enclosure_delete(
            self,
            enclosure_name):
        """
        Deletes the given EXOS enclosures

        :param str enclosure_name: Name of the enclosure
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """

        self._require_version("1.7.0", msg="EXOS API not supported by server")

        return self._rest_request(
            apiconsts.API_DEL_EXOS_ENCLOSURE,
            "DELETE",
            "/v1/vendor/seagate/exos/enclosures/" + enclosure_name
        )

    def exos_list_enclosures(
            self,
            nocache=None):
        """
        Lists all known EXOS enclosures inlcuind health status

        :param bool nocache: Whether or not Linstor should refetch data before
            responding
        :return: A list containing ExosEnclosure from the controller.
        :rtype: list[ExosListResponse]
        """

        self._require_version("1.7.0", msg="EXOS API not supported by server")

        query_params = []
        if nocache:
            query_params += ["nocache=true"]

        path = "/v1/vendor/seagate/exos/enclosures"
        if query_params:
            path += "?" + "&".join(query_params)

        return self._rest_request(
            apiconsts.API_LST_EXOS_ENCLOSURES,
            "GET",
            path
        )

    def exos_enclosure_events(
            self,
            enclosure_name,
            count=None):
        """
        Lists all EXOS events from the given enclosures

        :param str enclosure_name: Name of the enclosure
        :param Optional[int] count: Number of events
        :return: A list containing ExosEnclosureEventResponse from the
            controller
        :rtype: ExosEnclosureEventListResponse
        """

        self._require_version("1.7.0", msg="EXOS API not supported by server")

        query_params = []
        if count:
            query_params += ["count=" + str(count)]

        path = "/v1/vendor/seagate/exos/enclosures/" + enclosure_name + "/events"
        if query_params:
            path += "?" + "&".join(query_params)

        return self._rest_request(
            apiconsts.API_EXOS_ENCLOSURE_EVENTS,
            "GET",
            path
        )

    def exos_exec(
            self,
            enclosure_name,
            cmds):
        """
        Passthrough to the EXOS API through one of the EXOS controllers of
        the given enclosure

        :param str enclosure_name: Name of the enclosure
        :param List[str] cmds: EXOS commands to execute
        :return: Passthrough from the EXOS API
        """

        self._require_version("1.7.0", msg="EXOS API not supported by server")

        return self._rest_request(
            apiconsts.API_EXOS_EXEC,
            "GET",
            "/v1/vendor/seagate/exos/enclosures/" + enclosure_name + "/exec/" + "/".join(cmds)
        )

    def exos_map(self):
        """
        Gathers information which Linstor node is connected to which EXOS
        controller

        :return: A list containing ExosMapResponse from the controller.
        :rtype: list[ExosMapResponse]
        """

        self._require_version("1.7.0", msg="EXOS API not supported by server")

        return self._rest_request(
            apiconsts.API_EXOS_MAP,
            "GET",
            "/v1/vendor/seagate/exos/map"
        )


class MultiLinstor(Linstor):
    def __init__(self, ctrl_host_list, timeout=300, keep_alive=False):
        """A Linstor client that tries connecting to a list of controllers

        This is intended to support high availability deployments with multiple Controllers, with only one controller
        active at a time.

        :param list[str] ctrl_host_list: The list of controller uris. See linstor.Linstor for the exact format
        :param timeout: connection timeout. See linstor.Linstor
        :param keep_alive: See linstor.Linstor
        """
        super(MultiLinstor, self).__init__(ctrl_host_list[0], timeout, keep_alive)
        self._ctrl_host_list = ctrl_host_list  # type: List[str]

    def connect(self):
        conn_errors = []
        for ctrl_host in self._ctrl_host_list:
            self._ctrl_host = ctrl_host
            try:
                return super(MultiLinstor, self).connect()
            except LinstorNetworkError as lne:
                conn_errors.append(lne)

        if len(conn_errors) == len(self._ctrl_host_list):
            raise LinstorNetworkError(
                "Unable to connect to any of the given controller hosts: " + str(self._ctrl_host_list),
                conn_errors)

    @classmethod
    def controller_uri_list(cls, controller_list):
        """
        Converts a simple '10.0.0.1,10.0.0.2' ip/host list to ['linstor://10.0.0.1', 'linstor://10.0.0.2'] uris.
        :param str controller_list: list of controller addresses separated by comma
        :return: List of linstor uris
        :rtype: list[str]
        """
        servers = []
        # add linstor uri scheme
        for hp in controller_list.split(','):
            if hp:
                if '://' in hp:
                    servers.append(hp)
                else:
                    servers.append("linstor://" + hp)
        return servers


if __name__ == "__main__":
    lin = MultiLinstor(["linstor://localhost"])
    lin.connect()
    print(lin.controller_host())

    node_list = lin.node_list_raise()
    for node in node_list.nodes:
        print(node)
    # print(lin.resource_list())
    stor_pools = lin.storage_pool_list_raise()
    for stor_pool in stor_pools.storage_pools:
        print(stor_pool.name, stor_pool.node_name, stor_pool.supports_snapshots(), stor_pool.is_thin())
        print(" + ", stor_pool.free_space)
