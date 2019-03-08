"""
Linstorapi module
"""

import struct
import threading
import logging
import socket
import select
import ssl
import time
import os
from collections import deque
from datetime import datetime
from google.protobuf.internal import encoder
from google.protobuf.internal import decoder

from .errors import LinstorError, LinstorNetworkError, LinstorTimeoutError, LinstorApiCallError
from .responses import ProtoMessageResponse, ApiCallResponse, ErrorReport, StoragePoolListResponse, StoragePoolDriver
from .responses import NodeListResponse, KeyValueStoresResponse, KeyValueStore, ResourceDefinitionResponse
from .responses import ResourceResponse

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

from linstor.proto.MsgHeader_pb2 import MsgHeader
from linstor.proto.responses.MsgApiVersion_pb2 import MsgApiVersion
from linstor.proto.common.ApiCallResponse_pb2 import ApiCallResponse as ApiCallResponseProto
from linstor.proto.responses.MsgEvent_pb2 import MsgEvent
from linstor.proto.requests.MsgCrtNode_pb2 import MsgCrtNode
from linstor.proto.requests.MsgModNode_pb2 import MsgModNode
from linstor.proto.requests.MsgDelNode_pb2 import MsgDelNode
from linstor.proto.requests.MsgCrtNetInterface_pb2 import MsgCrtNetInterface
from linstor.proto.requests.MsgModNetInterface_pb2 import MsgModNetInterface
from linstor.proto.requests.MsgDelNetInterface_pb2 import MsgDelNetInterface
from linstor.proto.responses.MsgLstNode_pb2 import MsgLstNode
from linstor.proto.requests.MsgCrtStorPoolDfn_pb2 import MsgCrtStorPoolDfn
from linstor.proto.requests.MsgModStorPoolDfn_pb2 import MsgModStorPoolDfn
from linstor.proto.requests.MsgDelStorPoolDfn_pb2 import MsgDelStorPoolDfn
from linstor.proto.responses.MsgLstStorPoolDfn_pb2 import MsgLstStorPoolDfn
from linstor.proto.requests.MsgCrtStorPool_pb2 import MsgCrtStorPool
from linstor.proto.requests.MsgModStorPool_pb2 import MsgModStorPool
from linstor.proto.requests.MsgDelStorPool_pb2 import MsgDelStorPool
from linstor.proto.responses.MsgLstStorPool_pb2 import MsgLstStorPool
from linstor.proto.requests.MsgCrtRscDfn_pb2 import MsgCrtRscDfn
from linstor.proto.requests.MsgModRscDfn_pb2 import MsgModRscDfn
from linstor.proto.requests.MsgDelRscDfn_pb2 import MsgDelRscDfn
from linstor.proto.responses.MsgLstRscDfn_pb2 import MsgLstRscDfn
from linstor.proto.requests.MsgCrtVlmDfn_pb2 import MsgCrtVlmDfn
from linstor.proto.requests.MsgAutoPlaceRsc_pb2 import MsgAutoPlaceRsc
from linstor.proto.requests.MsgModVlmDfn_pb2 import MsgModVlmDfn
from linstor.proto.requests.MsgDelVlmDfn_pb2 import MsgDelVlmDfn
from linstor.proto.requests.MsgCrtRsc_pb2 import MsgCrtRsc
from linstor.proto.requests.MsgModRsc_pb2 import MsgModRsc
from linstor.proto.requests.MsgDelRsc_pb2 import MsgDelRsc
from linstor.proto.requests.MsgToggleDisk_pb2 import MsgToggleDisk
from linstor.proto.responses.MsgLstRsc_pb2 import MsgLstRsc
from linstor.proto.responses.MsgLstSnapshotDfn_pb2 import MsgLstSnapshotDfn
from linstor.proto.requests.MsgModCtrl_pb2 import MsgModCtrl
from linstor.proto.responses.MsgLstCtrlCfgProps_pb2 import MsgLstCtrlCfgProps
from linstor.proto.requests.MsgEnterCryptPassphrase_pb2 import MsgEnterCryptPassphrase
from linstor.proto.requests.MsgCrtCryptPassphrase_pb2 import MsgCrtCryptPassphrase
from linstor.proto.requests.MsgModCryptPassphrase_pb2 import MsgModCryptPassphrase
from linstor.proto.requests.MsgModRscConn_pb2 import MsgModRscConn
from linstor.proto.requests.MsgReqErrorReport_pb2 import MsgReqErrorReport
from linstor.proto.responses.MsgErrorReport_pb2 import MsgErrorReport
from linstor.proto.responses.MsgHostname_pb2 import MsgHostname
from linstor.proto.requests.MsgPrepareDisks_pb2 import MsgPrepareDisks
from linstor.proto.requests.MsgCrtSnapshot_pb2 import MsgCrtSnapshot
from linstor.proto.requests.MsgDelSnapshot_pb2 import MsgDelSnapshot
from linstor.proto.requests.MsgRollbackSnapshot_pb2 import MsgRollbackSnapshot
from linstor.proto.requests.MsgRestoreSnapshotVlmDfn_pb2 import MsgRestoreSnapshotVlmDfn
from linstor.proto.requests.MsgRestoreSnapshotRsc_pb2 import MsgRestoreSnapshotRsc
from linstor.proto.common.Filter_pb2 import Filter
from linstor.proto.eventdata.EventVlmDiskState_pb2 import EventVlmDiskState
from linstor.proto.eventdata.EventRscState_pb2 import EventRscState
from linstor.proto.requests.MsgQryMaxVlmSizes_pb2 import MsgQryMaxVlmSizes
from linstor.proto.responses.MsgRspMaxVlmSizes_pb2 import MsgRspMaxVlmSizes
from linstor.proto.requests.MsgCrtSfTargetNode_pb2 import MsgCrtSfTargetNode
from linstor.proto.requests.MsgReqRscConn_pb2 import MsgReqRscConn
from linstor.proto.responses.MsgLstRscConn_pb2 import MsgLstRscConn
from linstor.proto.requests.MsgEnableDrbdProxy_pb2 import MsgEnableDrbdProxy
from linstor.proto.requests.MsgDisableDrbdProxy_pb2 import MsgDisableDrbdProxy
from linstor.proto.requests.MsgModDrbdProxy_pb2 import MsgModDrbdProxy
from linstor.proto.requests.MsgNodeReconnect_pb2 import MsgNodeReconnect
from linstor.proto.requests.MsgModKvs_pb2 import MsgModKvs
from linstor.proto.responses.MsgRspKvs_pb2 import MsgRspKvs
import linstor.proto.common.LayerType_pb2 as LayerType
import linstor.sharedconsts as apiconsts

API_VERSION = 4
API_VERSION_MIN = 4


logging.basicConfig(level=logging.WARNING)


class AtomicInt(object):
    """
    This is a thread-safe integer type for incrementing, mostly reassembling modern atomic types,
    but with the overhead of a lock.
    """
    def __init__(self, init=0):
        self.val = init
        self.lock = threading.RLock()

    def get_and_inc(self):
        with self.lock:
            val = self.val
            self.val += 1
        return val


class ObjectIdentifier(object):
    def __init__(
            self,
            node_name=None,
            resource_name=None,
            volume_number=None,
            snapshot_name=None):
        self._node_name = node_name
        self._resource_name = resource_name
        self._volume_number = volume_number
        self._snapshot_name = snapshot_name

    def write_to_create_watch_msg(self, msg):
        if self._node_name is not None:
            msg.node_name = self._node_name
        if self._resource_name is not None:
            msg.resource_name = self._resource_name
        if self._volume_number is not None:
            msg.filter_by_volume_number = True
            msg.volume_number = self._volume_number
        if self._snapshot_name is not None:
            msg.snapshot_name = self._snapshot_name


class _LinstorNetClient(threading.Thread):
    IO_SIZE = 4096
    HDR_LEN = 16

    COMPLETE_ANSWERS = object()
    END_OF_IMMEDIATE_ANSWERS = object()

    REPLY_MAP = {
        apiconsts.API_PONG: (None, None),
        apiconsts.API_REPLY: (ApiCallResponseProto, ApiCallResponse),
        apiconsts.API_END_OF_IMMEDIATE_ANSWERS: (None, None),
        apiconsts.API_LST_STOR_POOL_DFN: (MsgLstStorPoolDfn, ProtoMessageResponse),
        apiconsts.API_LST_STOR_POOL: (MsgLstStorPool, StoragePoolListResponse),
        apiconsts.API_LST_NODE: (MsgLstNode, NodeListResponse),
        apiconsts.API_LST_RSC_DFN: (MsgLstRscDfn, ResourceDefinitionResponse),
        apiconsts.API_LST_RSC: (MsgLstRsc, ResourceResponse),
        apiconsts.API_LST_VLM: (MsgLstRsc, ResourceResponse),
        apiconsts.API_LST_SNAPSHOT_DFN: (MsgLstSnapshotDfn, ProtoMessageResponse),
        apiconsts.API_LST_CTRL_PROPS: (MsgLstCtrlCfgProps, ProtoMessageResponse),
        apiconsts.API_LST_RSC_CONN: (MsgLstRscConn, ProtoMessageResponse),
        apiconsts.API_HOSTNAME: (MsgHostname, ProtoMessageResponse),
        apiconsts.API_LST_ERROR_REPORTS: (MsgErrorReport, ErrorReport),
        apiconsts.API_RSP_MAX_VLM_SIZE: (MsgRspMaxVlmSizes, ProtoMessageResponse),
        apiconsts.API_LST_KVS: (MsgRspKvs, KeyValueStoresResponse)
    }

    EVENT_READER_TABLE = {
        apiconsts.EVENT_VOLUME_DISK_STATE: EventVlmDiskState,
        apiconsts.EVENT_RESOURCE_STATE: EventRscState
    }

    URL_SCHEMA_MAP = {
        'linstor': apiconsts.DFLT_CTRL_PORT_PLAIN,
        'linstor+ssl': apiconsts.DFLT_CTRL_PORT_SSL,
        'linstorstlt': apiconsts.DFLT_STLT_PORT_PLAIN,
        'linstorstlt+ssl': apiconsts.DFLT_STLT_PORT_SSL
    }

    def __init__(self, timeout, keep_alive):
        super(_LinstorNetClient, self).__init__()
        self._socket = None  # type: socket.socket
        self._notify_pipe = os.pipe()
        self._host = None  # type: str
        self._timeout = timeout
        self._slock = threading.RLock()
        self._cv_sock = threading.Condition(self._slock)
        self._logger = logging.getLogger('LinstorNetClient')
        self._replies = {}
        self._ignore_replies = set()
        self._events = {}
        self._errors = []  # list of errors that happened in the select thread
        self._api_version = None
        self._cur_api_call_id = AtomicInt(1)
        self._cur_watch_id = AtomicInt(1)
        self._stats_received = 0
        self._controller_info = None  # type: str
        self._keep_alive = keep_alive  # type: bool
        self._run_disconnect_lock = threading.RLock()

    def __del__(self):
        self.disconnect()

    @classmethod
    def parse_host(cls, host_str):
        """
        Tries to parse an ipv4, ipv6 or host address.

        Args:
            host_str (str): host/ip string
        Returns:
          Tuple(str, str): a tuple with the ip/host and port
        """
        if not host_str:
            return host_str, None

        if host_str[0] == '[':
            # ipv6 with port
            brace_close_pos = host_str.rfind(']')
            if brace_close_pos == -1:
                raise ValueError("No closing brace found in '{s}'".format(s=host_str))

            host_ipv6 = host_str[:brace_close_pos + 1].strip('[]')
            port_ipv6 = host_str[brace_close_pos + 2:]
            return host_ipv6, port_ipv6 if port_ipv6 else None

        if host_str.count(':') == 1:
            return host_str.split(':')

        return host_str, None

    @classmethod
    def _split_proto_msgs(cls, payload):
        """
        Splits a linstor payload into each raw proto buf message
        :param bytes payload: payload data
        :return: list of raw proto buf messages
        :rtype: list
        """
        # split payload, just a list of pbs, the receiver has to deal with them
        pb_msgs = []
        n = 0
        while n < len(payload):
            msg_len, new_pos = decoder._DecodeVarint32(payload, n)
            n = new_pos
            msg_buf = payload[n:n + msg_len]
            n += msg_len
            pb_msgs.append(msg_buf)
        return pb_msgs

    @classmethod
    def _parse_event(cls, event_name, event_data_bytes):
        """
        Parses the given byte data according to the event header name.

        :param event_name: Event header name
        :param event_data_bytes: Data bytes for protobuf message
        :return: parsed protobuf message
        """
        event_reader = cls.EVENT_READER_TABLE.get(event_name)

        if event_reader is None:
            return None

        event_data = event_reader()
        event_data.ParseFromString(event_data_bytes)
        return event_data

    @classmethod
    def _parse_proto_msgs(cls, type_tuple, data):
        """
        Parses a list of proto buf messages into their protobuf and/or wrapper classes,
        defined in the type_tuple.
        :param type_tuple: first item specifies the protobuf message, second item is a wrapper class or None
        :param list data: a list of raw protobuf message data
        :return: A list with protobuf or wrapper classes from the data
        """
        msg_resps = []
        msg_type = type_tuple[0]
        wrapper_type = type_tuple[1]

        if msg_type is None:
            return msg_resps

        for msg in data:
            resp = msg_type()
            resp.ParseFromString(msg)
            if wrapper_type:
                msg_resps.append(wrapper_type(resp))
            else:
                msg_resps.append(resp)
        return msg_resps

    @classmethod
    def _parse_proto_msg(cls, msg_type, data):
        msg = msg_type()
        msg.ParseFromString(data)
        return msg

    def _parse_api_version(self, data):
        """
        Parses data as a MsgApiVersion and checks if we support the api version.

        :param bytes data: byte data containing the MsgApiVersion message
        :return: True if parsed correctly and version supported
        :raises LinstorError: if the parsed api version is not supported
        """
        msg = self._parse_proto_msg(MsgApiVersion, data)
        if self._api_version is None:
            self._controller_info = msg.controller_info
            self._api_version = msg.version
            if API_VERSION_MIN > msg.version or msg.version > API_VERSION:
                raise LinstorError(
                    "Client API version '{v}' is incompatible with controller version '{r}', please update your client."
                    .format(
                        v=API_VERSION,
                        r=msg.version)
                )
        else:
            self._logger.warning("API version message already received.")
        return True

    @classmethod
    def _parse_payload_length(cls, header):
        """
        Parses the payload length from a linstor header.

        :param bytes header: 16 bytes header data
        :return: Length of the payload
        """
        struct_format = "!xxxxIxxxxxxxx"
        assert struct.calcsize(struct_format) == len(header), "Header has unexpected size"
        exp_pkg_len, = struct.unpack(struct_format, header)
        return exp_pkg_len

    def _read_api_version_blocking(self):
        """
        Receives a api version message with blocking reads from the _socket and parses/checks it.

        :return: True
        """
        api_msg_data = self._socket.recv(self.IO_SIZE)
        while len(api_msg_data) < 16:
            api_msg_data += self._socket.recv(self.IO_SIZE)

        pkg_len = self._parse_payload_length(api_msg_data[:16])

        while len(api_msg_data) < pkg_len + 16:
            api_msg_data += self._socket.recv(self.IO_SIZE)

        msgs = self._split_proto_msgs(api_msg_data[16:])
        assert len(msgs) > 0, "Api version header message missing"
        hdr = self._parse_proto_msg(MsgHeader, msgs[0])

        assert hdr.msg_content == apiconsts.API_VERSION, "Unexpected message for API_VERSION"
        self._parse_api_version(msgs[1])
        return True

    def fetch_errors(self):
        """
        Get all errors that are currently on this object, list will be cleared.
        This error list will contain all errors that happened within the select thread.
        Usually you want this list after your socket was closed unexpected.

        :return: A list of LinstorErrors
        :rtype: list[LinstorError]
        """
        errors = self._errors
        self._errors = []
        return errors

    def connect(self, server):
        """
        Connects to the given server.
        The url has to be given in the linstor uri scheme. either linstor:// or linstor+ssl://

        :param str server: uri to the server
        :return: True if connected, else raises an LinstorError
        :raise LinstorError: if connection fails.
        """
        self._logger.debug("connecting to " + server)
        try:
            url = urlparse(server)

            if url.scheme not in _LinstorNetClient.URL_SCHEMA_MAP:
                raise LinstorError("Unknown uri scheme '{sc}' in '{uri}'.".format(sc=url.scheme, uri=server))

            host, port = self.parse_host(url.netloc)
            if not port:
                port = _LinstorNetClient.URL_SCHEMA_MAP[url.scheme]
            self._socket = socket.create_connection((host, port), timeout=self._timeout)

            # check if ssl
            if url.scheme.endswith('+ssl'):
                self._socket = ssl.wrap_socket(self._socket)
            self._socket.settimeout(self._timeout)

            # read api version
            if not url.scheme.startswith('linstorstlt'):
                self._read_api_version_blocking()

            self._socket.setblocking(0)
            self._logger.debug("connected to " + server)
            self._host = server
            return True
        except socket.error as err:
            self._socket = None
            raise LinstorNetworkError("Unable connecting to {hp}: {err}".format(hp=server, err=err))

    def disconnect(self):
        """
        Disconnects your current connection.

        :return: True if socket was connected, else False
        """
        ret = False
        with self._slock:
            if self._socket:
                self._logger.debug("disconnecting")
                self._socket.close()
                self._socket = None
                os.write(self._notify_pipe[1], "\n".encode('utf8'))
                ret = True
        self._run_disconnect_lock.acquire()
        return ret

    def controller_info(self):
        """
        Returns the controller info string parsed from the MsgApiVersion after connecting

        :return: String the controller sent as info
        :rtype: str
        """
        return self._controller_info

    @classmethod
    def _current_milli_time(cls):
        return int(round(time.time() * 1000))

    def run(self):
        with self._run_disconnect_lock:
            self._run()

    def _run(self):
        """
        Runs the main select loop that handles incoming messages, parses them and
        puts them on the self._replies map.
        Errors that happen within this thread will be collected on the self._errors list
        and can be fetched with the fetch_errors() methods.

        :return:
        """
        self._errors = []
        package = bytes()  # current package data
        exp_pkg_len = 0  # expected package length

        last_read_time = self._current_milli_time()
        last_ping_time = self._current_milli_time()
        while self._socket:
            rds = []
            wds = []
            eds = []
            try:
                rds, wds, eds = select.select([self._socket, self._notify_pipe[0]], [], [self._socket], 2)
            except Exception as e:  # (IOError, TypeError):
                if self._socket is None:  # disconnect closed it
                    break
                if not (e is IOError or e is TypeError):
                    raise e

            self._logger.debug("select exit with:" + ",".join([str(rds), str(wds), str(eds)]))

            if eds:
                self._logger.debug("Socket exception on {hp}".format(hp=self._adrtuple2str(self._socket.getpeername())))
                self._errors.append(LinstorNetworkError(
                    "Socket exception on {hp}".format(hp=self._adrtuple2str(self._socket.getpeername()))))

            if last_read_time + (self._timeout * 1000) < self._current_milli_time():
                self._socket.close()
                self._socket = None
                self._errors.append(LinstorTimeoutError(
                    "Socket timeout, no data received since {t}ms.".format(
                        t=(self._current_milli_time()-last_read_time)
                    )
                ))

            if self._keep_alive and last_ping_time + 5000 < self._current_milli_time():
                self.send_msg(apiconsts.API_PING)
                last_ping_time = self._current_milli_time()

            for sock in rds:
                with self._slock:
                    if self._socket is None:  # socket was closed
                        break

                    read = self._socket.recv(_LinstorNetClient.IO_SIZE)

                    if len(read) == 0:
                        self._logger.debug(
                            "No data from {hp}, closing connection".format(
                                hp=self._adrtuple2str(self._socket.getpeername())))
                        self._socket.close()
                        self._socket = None
                        self._errors.append(
                            LinstorNetworkError("Remote '{hp}' closed connection dropped.".format(hp=self._host)))

                    last_read_time = self._current_milli_time()

                    package += read
                    pkg_len = len(package)
                    self._stats_received += pkg_len
                    self._logger.debug("pkg_len: " + str(pkg_len))

                    def has_hdr():  # used as macro
                        return pkg_len > _LinstorNetClient.HDR_LEN - 1 and exp_pkg_len == 0

                    def has_more_data():  # used as macro
                        return pkg_len >= (exp_pkg_len + _LinstorNetClient.HDR_LEN) and exp_pkg_len

                    while has_hdr() or has_more_data():
                        if has_hdr():  # header is 16 bytes
                            exp_pkg_len = self._parse_payload_length(package[:_LinstorNetClient.HDR_LEN])

                        self._logger.debug("exp_pkg_len: " + str(exp_pkg_len))

                        if has_more_data():
                            # cut out the parsing package
                            parse_buf = package[_LinstorNetClient.HDR_LEN:exp_pkg_len + _LinstorNetClient.HDR_LEN]
                            msgs = self._split_proto_msgs(parse_buf)
                            assert len(msgs) > 0, "we should have at least a header message"

                            # update buffer and length variables
                            package = package[exp_pkg_len + _LinstorNetClient.HDR_LEN:]  # put data into next parse run
                            pkg_len = len(package)  # update package length
                            self._logger.debug("pkg_len upd: " + str(len(package)))
                            exp_pkg_len = 0

                            self._process_msgs(msgs)

    def _process_msgs(self, msgs):
        hdr = self._parse_proto_msg(MsgHeader, msgs[0])  # parse header
        self._logger.debug(str(hdr))

        if hdr.msg_type == MsgHeader.MsgType.Value('API_CALL'):
            self._header_parsing_error(hdr)

        elif hdr.msg_type == MsgHeader.MsgType.Value('ONEWAY'):
            if hdr.msg_content == apiconsts.API_EVENT:
                event_header = MsgEvent()
                event_header.ParseFromString(msgs[1])
                self._logger.debug(
                    "Event '" + event_header.event_name + "', action " + event_header.event_action + " received")
                if event_header.event_action == apiconsts.EVENT_STREAM_VALUE:
                    event_data = self._parse_event(event_header.event_name, msgs[2]) \
                        if len(msgs) > 2 else None
                else:
                    event_data = None
                with self._cv_sock:
                    if event_header.watch_id in self._events:
                        self._events[event_header.watch_id].append((event_header, event_data))
                        self._cv_sock.notifyAll()
            else:
                self._header_parsing_error(hdr)

        elif hdr.msg_type == MsgHeader.MsgType.Value('ANSWER'):
            if hdr.msg_content in self.REPLY_MAP:
                # parse other message according to the reply_map and add them to the self._replies
                replies = self._parse_proto_msgs(self.REPLY_MAP[hdr.msg_content], msgs[1:])
                with self._cv_sock:
                    if hdr.api_call_id not in self._ignore_replies:
                        reply_deque = self._replies.get(hdr.api_call_id)
                        if reply_deque is None:
                            self._logger.warning(
                                "Unexpected answer received for API call ID " + str(hdr.api_call_id))
                        else:
                            if hdr.msg_content == apiconsts.API_END_OF_IMMEDIATE_ANSWERS:
                                reply_deque.append(self.END_OF_IMMEDIATE_ANSWERS)
                            else:
                                reply_deque.extend(replies)
                            self._cv_sock.notifyAll()
            else:
                self._header_parsing_error(hdr)

        elif hdr.msg_type == MsgHeader.MsgType.Value('COMPLETE'):
            with self._cv_sock:
                if hdr.api_call_id in self._ignore_replies:
                    self._ignore_replies.remove(hdr.api_call_id)
                else:
                    reply_deque = self._replies.get(hdr.api_call_id)
                    if reply_deque is None:
                        self._logger.warning(
                            "Unexpected completion received for API call ID " + str(hdr.api_call_id))
                    else:
                        reply_deque.append(self.COMPLETE_ANSWERS)
                        self._cv_sock.notifyAll()

        else:
            self._header_parsing_error(hdr)

    def _header_parsing_error(self, hdr):
        self._logger.error(
            "Unknown message of type " + MsgHeader.MsgType.Name(hdr.msg_type) +
            ("" if hdr.msg_content == "" else " and content " + hdr.msg_content) + " received ")
        self.disconnect()
        with self._cv_sock:
            self._cv_sock.notifyAll()

    @property
    def connected(self):
        """Check if the socket is currently connected."""
        return self._socket is not None

    def send_msg(self, api_call_type, msg=None):
        """
        Sends a single or just a header message.

        :param str api_call_type: api call type that is set in the header message.
        :param msg: Message to be sent, if None only the header will be sent.
        :return: Message id of the message for wait_for_result()
        :rtype: int
        """
        return self.send_msgs(api_call_type, [msg] if msg else None)

    def send_msgs(self, api_call_type, msgs=None):
        """
        Sends a list of message or just a header.

        :param str api_call_type: api call type that is set in the header message.
        :param list msgs: List of message to be sent, if None only the header will be sent.
        :return: Message id of the message for wait_for_result()
        :rtype: int
        """
        hdr_msg = MsgHeader()
        hdr_msg.msg_content = api_call_type

        api_call_id = self._cur_api_call_id.get_and_inc()
        with self._cv_sock:
            self._replies[api_call_id] = deque()

        hdr_msg.msg_type = MsgHeader.MsgType.Value('API_CALL')
        hdr_msg.api_call_id = api_call_id

        h_type = struct.pack("!I", 0)  # currently always 0, 32 bit
        h_reserved = struct.pack("!Q", 0)  # reserved, 64 bit

        msg_serialized = bytes()

        header_serialized = hdr_msg.SerializeToString()
        delim = encoder._VarintBytes(len(header_serialized))
        msg_serialized += delim + header_serialized

        if msgs:
            for msg in msgs:
                payload_serialized = msg.SerializeToString()
                delim = encoder._VarintBytes(len(payload_serialized))
                msg_serialized += delim + payload_serialized

        h_payload_length = len(msg_serialized)
        h_payload_length = struct.pack("!I", h_payload_length)  # 32 bit

        full_msg = h_type + h_payload_length + h_reserved + msg_serialized

        with self._slock:
            if not self.connected:
                raise LinstorNetworkError("Not connected to controller.", self.fetch_errors())

            msg_len = len(full_msg)
            self._logger.debug("sending " + str(msg_len))
            sent = 0
            while sent < msg_len:
                sent += self._socket.send(full_msg)
            self._logger.debug("sent " + str(sent))
        return hdr_msg.api_call_id

    def wait_for_result(self, api_call_id, answer_handler):
        """
        This method blocks and waits for all answers to the given api_call_id.

        :param int api_call_id: identifies the answers to wait for
        :param Callable answer_handler: function that is called for each answer that is received and returns whether
            to continue waiting
        """
        with self._cv_sock:
            try:
                while api_call_id in self._replies:
                    if not self.connected:
                        return

                    self._cv_sock.wait(1)

                    if api_call_id in self._replies:
                        reply_deque = self._replies[api_call_id]
                        while len(reply_deque) > 0:
                            reply = reply_deque.popleft()
                            if reply == self.COMPLETE_ANSWERS:
                                return
                            else:
                                continue_wait = answer_handler(reply)
                                if not continue_wait:
                                    self._ignore_replies.add(api_call_id)
                                    return
            finally:
                self._replies.pop(api_call_id)

    def wait_for_events(self, watch_id, event_handler):
        """
        This method blocks and waits for any events.
        The handler function is called for each event.
        When the value returned by the handler is not None, this method returns that value.

        :param int watch_id: watch id to watch for
        :param Callable event_handler: function that is called if an event was received.
        :return: The result of the handler function if it returns not None
        """
        local_queue = deque()
        while True:
            with self._cv_sock:
                if not self.connected:
                    return None

                self._cv_sock.wait(0.2)

                while watch_id in self._events and self._events[watch_id]:
                    # copy events to local queue to allow to run event_handler without lock
                    local_queue.append(self._events[watch_id].popleft())

            while local_queue:
                event_handler_result = event_handler(*local_queue.popleft())
                if event_handler_result is not None:
                    return event_handler_result

    def register_watch(self, watch_id):
        """
        Add a queue entry into the events map.

        :param watch_id: watch id to add
        :return: None
        """
        with self._slock:
            self._events[watch_id] = deque()

    def deregister_watch(self, watch_id):
        """
        Remove a queue entry from the events map.
        :param watch_id: watch id to remove
        :return: None
        """
        with self._slock:
            del self._events[watch_id]

    def next_watch_id(self):
        return self._cur_watch_id.get_and_inc()

    def stats(self):
        """
        Returns network statistics as printable string.

        :return: Returns network statistics as printable string.
        :rtype: str
        """
        return "Received bytes: {b}".format(b=self._stats_received)

    @staticmethod
    def _adrtuple2str(tuple):
        ip = tuple[0]
        port = tuple[1]
        s = "[{ip}]".format(ip=ip) if ':' in ip else ip
        s += ":" + str(port)
        return s


class ResourceData(object):
    def __init__(self, node_name, rsc_name, diskless=False, storage_pool=None, node_id=None, layer_list=None):
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


class Linstor(object):
    """
    Linstor class represents a client connection to the Linstor controller.
    It has all methods to manipulate all kind of objects on the controller.

    The controller host address has to be specified as linstor url.
    e.g: ``linstor://localhost``, ``linstor+ssl://localhost``

    :param str ctrl_host: Linstor uri to the controller e.g. ``linstor://192.168.0.1``
    :param bool keep_alive: Sends PING messages to the controller
    """
    _node_types = [
        apiconsts.VAL_NODE_TYPE_CTRL,
        apiconsts.VAL_NODE_TYPE_AUX,
        apiconsts.VAL_NODE_TYPE_CMBD,
        apiconsts.VAL_NODE_TYPE_STLT
    ]

    def __init__(self, ctrl_host, timeout=300, keep_alive=False):
        self._ctrl_host = ctrl_host
        self._linstor_client = None  # type: _LinstorNetClient
        self._logger = logging.getLogger('Linstor')
        self._timeout = timeout
        self._keep_alive = keep_alive

    def __del__(self):
        self.disconnect()

    def __enter__(self):
        self.connect()  # raises exception if error
        return self

    def __exit__(self, type, value, traceback):
        self.disconnect()

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

        :param list[ProtoMessageResponse] replies: controller reply list
        :return: Returns all only ApiCallResponses from replies or empty list.
        :rtype: [ApiCallResponse]
        """
        return [reply for reply in replies if isinstance(reply, ApiCallResponse)]

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

    def _send_and_wait(self, api_call, msg=None, allow_no_reply=False, async_msg=False):
        """
        Helper function that sends a api call[+msg] and waits for the answer from the controller

        :param str api_call: API call identifier
        :param msg: Proto message to send
        :param bool allow_no_reply: Do not raise an error if there are no replies.
        :param bool async_msg: Terminate as soon as immediate replies have been received
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        api_call_id = self._linstor_client.send_msg(api_call, msg)
        replies = []

        def answer_handler(answer):
            if answer != _LinstorNetClient.END_OF_IMMEDIATE_ANSWERS:
                replies.append(answer)
            elif async_msg:
                return False
            return True

        self._linstor_client.wait_for_result(api_call_id, answer_handler)

        errors = self._linstor_client.fetch_errors()
        if errors:
            raise errors[0]  # for now only send the first error

        if not allow_no_reply and len(replies) == 0:
            raise LinstorNetworkError("No answer received for api_call '{id}:{c}'".format(id=api_call_id, c=api_call))

        return replies

    def connect(self):
        """
        Connects the internal linstor network client.

        :return: True
        """
        self._linstor_client = _LinstorNetClient(timeout=self._timeout, keep_alive=self._keep_alive)
        self._linstor_client.connect(self._ctrl_host)
        self._linstor_client.daemon = True
        self._linstor_client.start()
        return True

    @property
    def connected(self):
        """
        Checks if the Linstor object is connect to a controller.

        :return: True if connected, else False.
        """
        return self._linstor_client.connected

    def disconnect(self):
        """
        Disconnects the current connection.

        :return: True if the object was connected else False.
        """
        return self._linstor_client.disconnect()

    def node_create(
            self,
            node_name,
            node_type,
            ip,
            com_type=apiconsts.VAL_NETCOM_TYPE_PLAIN,
            port=None,
            netif_name='default'
    ):
        """
        Creates a node on the controller.

        :param str node_name: Name of the node.
        :param str node_type: Node type of the new node, one of linstor.consts.VAL_NODE_TYPE*
        :param str ip: IP address to use for the nodes default netinterface.
        :param str com_type: Communication type of the node.
        :param int port: Port number of the node.
        :param str netif_name: Netinterface name that is created.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgCrtNode()

        msg.node.name = node_name
        if node_type not in self._node_types:
            raise LinstorError(
                "Unknown node type '{nt}'. Known types are: {kt}".format(nt=node_type, kt=", ".join(self._node_types))
            )
        msg.node.type = node_type
        netif = msg.node.net_interfaces.add()
        netif.name = netif_name
        netif.address = ip

        if port is None:
            if com_type == apiconsts.VAL_NETCOM_TYPE_PLAIN:
                port = apiconsts.DFLT_CTRL_PORT_PLAIN \
                    if msg.node.type == apiconsts.VAL_NODE_TYPE_CTRL else apiconsts.DFLT_STLT_PORT_PLAIN
            elif com_type == apiconsts.VAL_NETCOM_TYPE_SSL:
                if msg.node.type == apiconsts.VAL_NODE_TYPE_STLT:
                    port = apiconsts.DFLT_STLT_PORT_SSL
                else:
                    port = apiconsts.DFLT_CTRL_PORT_SSL
            else:
                raise LinstorError("Communication type %s has no default port" % com_type)

        netif.stlt_port = port
        netif.stlt_encryption_type = com_type

        return self._send_and_wait(apiconsts.API_CRT_NODE, msg)

    def node_create_swordfish_target(self, node_name, storage_service):
        msg = MsgCrtSfTargetNode()
        msg.name = node_name

        prop = msg.props.add()
        prop.key = apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_SF_STOR_SVC
        prop.value = storage_service

        return self._send_and_wait(apiconsts.API_CRT_SF_TARGET_NODE, msg)

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
        msg = MsgModNode()
        msg.node_name = node_name

        if node_type is not None:
            msg.node_type = node_type

        self._modify_props(msg, property_dict, delete_props)

        return self._send_and_wait(apiconsts.API_MOD_NODE, msg)

    def node_delete(self, node_name, async_msg=False):
        """
        Deletes the given node on the controller.

        :param str node_name: Node name to delete.
        :param bool async_msg: True to return without waiting for the action to complete on the satellites.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgDelNode()
        msg.node_name = node_name

        return self._send_and_wait(apiconsts.API_DEL_NODE, msg, async_msg=async_msg)

    def node_lost(self, node_name, async_msg=False):
        """
        Deletes an unrecoverable node on the controller.

        :param str node_name: Node name to delete.
        :param bool async_msg: True to return without waiting for the action to complete on the satellites.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgDelNode()
        msg.node_name = node_name

        return self._send_and_wait(apiconsts.API_LOST_NODE, msg, async_msg=async_msg)

    def node_reconnect(self, node_names):
        """
        Forces the controller to drop a connection on a satellite and reconnect.

        :param list[str] node_names: List of nodes to reconnect.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgNodeReconnect()
        msg.nodes.extend(node_names)

        return self._send_and_wait(apiconsts.API_NODE_RECONNECT, msg)

    def netinterface_create(self, node_name, interface_name, ip, port=None, com_type=None):
        """
        Create a netinterface for a given node.

        :param str node_name: Name of the node to add the interface.
        :param str interface_name: Name of the new interface.
        :param str ip: IP address of the interface.
        :param int port: Port of the interface
        :param str com_type: Communication type to use on the interface.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgCrtNetInterface()
        msg.node_name = node_name

        msg.net_if.name = interface_name
        msg.net_if.address = ip

        if port:
            msg.net_if.stlt_port = port
            msg.net_if.stlt_encryption_type = com_type

        return self._send_and_wait(apiconsts.API_CRT_NET_IF, msg)

    def netinterface_modify(self, node_name, interface_name, ip, port=None, com_type=None):
        """
        Modify a netinterface on the given node.

        :param str node_name: Name of the node.
        :param str interface_name: Name of the netinterface to modify.
        :param str ip: New IP address of the netinterface
        :param int port: New Port of the netinterface
        :param str com_type: New communication type of the netinterface
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgModNetInterface()

        msg.node_name = node_name
        msg.net_if.name = interface_name
        msg.net_if.address = ip

        if port:
            msg.net_if.stlt_port = port
            msg.net_if.stlt_encryption_type = com_type

        return self._send_and_wait(apiconsts.API_MOD_NET_IF, msg)

    def netinterface_delete(self, node_name, interface_name):
        """
        Deletes a netinterface on the given node.

        :param str node_name: Name of the node.
        :param str interface_name: Name of the netinterface to delete.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgDelNetInterface()
        msg.node_name = node_name
        msg.net_if_name = interface_name

        return self._send_and_wait(apiconsts.API_DEL_NET_IF, msg)

    def node_list(self):
        """
        Request a list of all nodes known to the controller.

        :return: A MsgLstNode proto message containing all information.
        :rtype: list[ProtoMessageResponse]
        """
        return self._send_and_wait(apiconsts.API_LST_NODE)

    def node_list_raise(self):
        """
        Request a list of all nodes known to the controller.

        :return: Node list response objects
        :rtype: NodeListResponse
        :raise LinstorError: if apicallerror or no response received
        """
        list_res = self.node_list()
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
        msg = MsgCrtStorPoolDfn()
        msg.stor_pool_dfn.stor_pool_name = name

        return self._send_and_wait(apiconsts.API_CRT_STOR_POOL_DFN, msg)

    def storage_pool_dfn_modify(self, name, property_dict, delete_props=None):
        """
        Modify properties of a given storage pool definition.

        :param str name: Storage pool definition name to modify
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param list[str] delete_props: List of properties to delete
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgModStorPoolDfn()
        msg.stor_pool_name = name

        msg = self._modify_props(msg, property_dict, delete_props)

        return self._send_and_wait(apiconsts.API_MOD_STOR_POOL_DFN, msg)

    def storage_pool_dfn_delete(self, name):
        """
        Delete a given storage pool definition.

        :param str name: Storage pool definition name to delete.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgDelStorPoolDfn()
        msg.stor_pool_name = name

        return self._send_and_wait(apiconsts.API_DEL_STOR_POOL_DFN, msg)

    def storage_pool_dfn_list(self):
        """
        Request a list of all storage pool definitions known to the controller.

        :return: A MsgLstStorPoolDfn proto message containing all information.
        :rtype: list[ProtoMessageResponse]
        """
        return self._send_and_wait(apiconsts.API_LST_STOR_POOL_DFN)

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
        :return: A list containing ApiCallResponses or ProtoMessageResponse (with MsgRspMaxVlmSizes)
        :rtype: Union[list[ApiCallResponse], list[ProtoMessageResponse]]
        """
        msg = MsgQryMaxVlmSizes()
        msg_filter = msg.select_filter
        msg_filter.place_count = place_count

        if storage_pool_name:
            msg_filter.storage_pool = storage_pool_name
        if do_not_place_with:
            msg_filter.not_place_with_rsc.extend(do_not_place_with)
        if do_not_place_with_regex:
            msg_filter.not_place_with_rsc_regex = do_not_place_with_regex
        if replicas_on_same:
            msg_filter.replicas_on_same.extend(replicas_on_same)
        if replicas_on_different:
            msg_filter.replicas_on_different.extend(replicas_on_different)

        return self._send_and_wait(apiconsts.API_QRY_MAX_VLM_SIZE, msg)

    @staticmethod
    def _filter_props(props, namespace=''):
        return {prop.key: prop.value for prop in props if prop.key.startswith(namespace)}

    def storage_pool_create(
            self,
            node_name,
            storage_pool_name,
            storage_driver,
            driver_pool_name,
            shared_space=None,
            property_dict=None
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
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgCrtStorPool()
        msg.stor_pool.stor_pool_name = storage_pool_name
        msg.stor_pool.node_name = node_name
        if storage_driver not in StoragePoolDriver.list():
            raise LinstorError("Unknown storage driver: " + storage_driver)
        msg.stor_pool.provider_kind = storage_driver
        if shared_space:
            msg.stor_pool.free_space_mgr_name = shared_space

        # set driver device pool properties
        for key, value in StoragePoolDriver.storage_driver_pool_to_props(storage_driver, driver_pool_name):
            prop = msg.stor_pool.props.add()
            prop.key = key
            prop.value = value

        if property_dict:
            for key, value in property_dict.items():
                prop = msg.stor_pool.props.add()
                prop.key = key
                prop.value = value

        return self._send_and_wait(apiconsts.API_CRT_STOR_POOL, msg)

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
        msg = MsgModStorPool()
        msg.node_name = node_name
        msg.stor_pool_name = storage_pool_name

        msg = self._modify_props(msg, property_dict, delete_props)

        return self._send_and_wait(apiconsts.API_MOD_STOR_POOL, msg)

    def storage_pool_delete(self, node_name, storage_pool_name):
        """
        Deletes a storage pool on the given node.

        :param str node_name: Node on which the storage pool resides.
        :param str storage_pool_name: Name of the storage pool.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgDelStorPool()
        msg.node_name = node_name
        msg.stor_pool_name = storage_pool_name

        return self._send_and_wait(apiconsts.API_DEL_STOR_POOL, msg)

    def storage_pool_list(self, filter_by_nodes=None, filter_by_stor_pools=None):
        """
        Request a list of all storage pool known to the controller.

        :param list[str] filter_by_nodes: Filter storage pools by nodes.
        :param list[str] filter_by_stor_pools: Filter storage pools by storage pool names.
        :return: A MsgLstStorPool proto message containing all information.
        :rtype: list[ProtoMessageResponse]
        """
        f = Filter()
        if filter_by_nodes:
            f.node_names.extend(filter_by_nodes)
        if filter_by_stor_pools:
            f.stor_pool_names.extend(filter_by_stor_pools)
        return self._send_and_wait(apiconsts.API_LST_STOR_POOL, f)

    def storage_pool_list_raise(self, filter_by_nodes=None, filter_by_stor_pools=None):
        """

        :param filter_by_nodes:
        :param filter_by_stor_pools:
        :return:
        :rtype: StoragePoolListResponse
        """
        list_res = self.storage_pool_list(filter_by_nodes=filter_by_nodes, filter_by_stor_pools=filter_by_stor_pools)
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
        return {
            'drbd',
            'luks',
            'storage'
        }

    def resource_dfn_create(self, name, port=None, external_name=None, layer_list=None):
        """
        Creates a resource definition.

        :param str name: Name of the new resource definition.
        :param int port: Port the resource definition should use.
        :param list[str] layer_list: Set of layer names to use.
        :param str external_name: User specified name.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgCrtRscDfn()
        msg.rsc_dfn.rsc_name = name
        if port is not None:
            msg.drbd_port = port
        if external_name:
            msg.rsc_dfn.external_name = external_name
            msg.rsc_dfn.rsc_name = ""
        else:
            msg.rsc_dfn.rsc_name = name
        # if args.secret:
        #     p.secret = args.secret
        if layer_list:
            for layer_name in layer_list:
                layer_data = msg.rsc_dfn.layer_data.add()
                layer_data.layer_type = LayerType.LayerType.Value(layer_name.upper())
        return self._send_and_wait(apiconsts.API_CRT_RSC_DFN, msg)

    def resource_dfn_modify(self, name, property_dict, delete_props=None):
        """
        Modify properties of the given resource definition.

        :param str name: Name of the resource definition to modify.
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param list[str] delete_props: List of properties to delete
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgModRscDfn()
        msg.rsc_name = name

        msg = self._modify_props(msg, property_dict, delete_props)

        return self._send_and_wait(apiconsts.API_MOD_RSC_DFN, msg)

    def resource_dfn_delete(self, name, async_msg=False):
        """
        Delete a given resource definition.

        :param str name: Resource definition name to delete.
        :param bool async_msg: True to return without waiting for the action to complete on the satellites.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgDelRscDfn()
        msg.rsc_name = name

        return self._send_and_wait(apiconsts.API_DEL_RSC_DFN, msg, async_msg=async_msg)

    def resource_dfn_list(self):
        """
        Request a list of all resource definitions known to the controller.

        :return: A MsgLstRscDfn proto message containing all information.
        :rtype: list[ResourceDefinitionResponse]
        """
        return self._send_and_wait(apiconsts.API_LST_RSC_DFN)

    def resource_dfn_props_list(self, rsc_name, filter_by_namespace=''):
        """
        Return a dictionary containing keys for a resource definition filtered by namespace.

        :param str rsc_name: Name of the resource definition it is linked to.
        :param str filter_by_namespace: Return only keys starting with the given prefix.
        :return: dict containing mathing keys
        :raises LinstorError: if resource can not be found
        """
        rsc_dfn_list_replies = self.resource_dfn_list()
        if not rsc_dfn_list_replies or not rsc_dfn_list_replies[0]:
            raise LinstorError('Could not list resource definitions, or they are empty')

        rsc_dfn_list_reply = rsc_dfn_list_replies[0]
        for rsc_dfn in rsc_dfn_list_reply.proto_msg.rsc_dfns:
            if rsc_dfn.rsc_name.lower() == rsc_name.lower():
                return Linstor._filter_props(rsc_dfn.rsc_dfn_props, filter_by_namespace)

        return {}

    def volume_dfn_create(
            self,
            rsc_name,
            size,
            volume_nr=None,
            minor_nr=None,
            encrypt=False,
            storage_pool=None
    ):
        """
        Create a new volume definition on the controller.

        :param str rsc_name: Name of the resource definition it is linked to.
        :param int size: Size of the volume definition in kibibytes.
        :param int volume_nr: Volume number to use.
        :param int minor_nr: Minor number to use.
        :param bool encrypt: Encrypt created volumes from this volume definition.
        :param storage_pool: Storage pool this volume definition will use.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgCrtVlmDfn()
        msg.rsc_name = rsc_name

        vlmdf = msg.vlm_dfns.add()
        vlmdf.vlm_dfn.vlm_size = size
        if minor_nr is not None:
            vlmdf.drbd_minor_nr = minor_nr

        if volume_nr is not None:
            vlmdf.vlm_dfn.vlm_nr = volume_nr

        if encrypt:
            vlmdf.vlm_dfn.vlm_flags.extend([apiconsts.FLAG_ENCRYPTED])

        if storage_pool:
            prop = vlmdf.vlm_dfn.vlm_props.add()
            prop.key = apiconsts.KEY_STOR_POOL_NAME
            prop.value = storage_pool

        return self._send_and_wait(apiconsts.API_CRT_VLM_DFN, msg)

    def volume_dfn_modify(self, rsc_name, volume_nr, set_properties=None, delete_properties=None, size=None):
        """
        Modify properties of the given volume definition.

        :param str rsc_name: Name of the resource definition.
        :param int volume_nr: Volume number of the volume definition.
        :param dict[str, str] set_properties: Dict containing key, value pairs for new values.
        :param list[str] delete_properties: List of properties to delete
        :param int size: New size of the volume definition in kibibytes.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgModVlmDfn()
        msg.rsc_name = rsc_name
        msg.vlm_nr = volume_nr

        if size:
            msg.vlm_size = size

        msg = self._modify_props(msg, set_properties, delete_properties)

        return self._send_and_wait(apiconsts.API_MOD_VLM_DFN, msg)

    def volume_dfn_delete(self, rsc_name, volume_nr, async_msg=False):
        """
        Delete a given volume definition.

        :param str rsc_name: Resource definition name of the volume definition.
        :param volume_nr: Volume number.
        :param bool async_msg: True to return without waiting for the action to complete on the satellites.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgDelVlmDfn()
        msg.rsc_name = rsc_name
        msg.vlm_nr = volume_nr

        return self._send_and_wait(apiconsts.API_DEL_VLM_DFN, msg, async_msg=async_msg)

    def _volume_dfn_size(self, rsc_name, volume_nr):
        """
        Return size of given volume for given resource.

        :param str rsc_name: Resource definition name
        :param volume_nr: Volume number.
        :return: Size of the volume definition in kibibytes. IMPORTANT: This will change to a tuple/dict type
        :raises LinstorError: if resource or volume_nr can not be found
        """
        rsc_dfn_list_replies = self.resource_dfn_list()
        if not rsc_dfn_list_replies or not rsc_dfn_list_replies[0]:
            raise LinstorError('Could not list resource definitions, or they are empty')

        rsc_dfn_list_reply = rsc_dfn_list_replies[0]
        for rsc_dfn in rsc_dfn_list_reply.proto_msg.rsc_dfns:
            if rsc_dfn.rsc_name == rsc_name:
                for vlm_dfn in rsc_dfn.vlm_dfns:
                    if vlm_dfn.vlm_nr == volume_nr:
                        return vlm_dfn.vlm_size

        raise LinstorError('Could not find volume number {} in resource {}'.format(volume_nr, rsc_name))

    def resource_create(self, rscs, async_msg=False):
        """
        Creates new resources in a resource definition.

        :param list[ResourceData] rscs: Resources to create
        :param bool async_msg: True to return without waiting for the action to complete on the satellites.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgCrtRsc()

        for rsc in rscs:
            proto_rsc_payload = msg.rscs.add()

            proto_rsc_payload.rsc.name = rsc.rsc_name
            proto_rsc_payload.rsc.node_name = rsc.node_name

            if rsc.storage_pool:
                prop = proto_rsc_payload.rsc.props.add()
                prop.key = apiconsts.KEY_STOR_POOL_NAME
                prop.value = rsc.storage_pool

            if rsc.diskless:
                proto_rsc_payload.rsc.rsc_flags.append(apiconsts.FLAG_DISKLESS)

            if rsc.node_id is not None:
                proto_rsc_payload.drbd_node_id = rsc.node_id

            if rsc.layer_list:
                for layer_name in rsc.layer_list:
                    proto_rsc_payload.layer_stack.append(LayerType.LayerType.Value(layer_name.upper()))

        return self._send_and_wait(apiconsts.API_CRT_RSC, msg, async_msg=async_msg)

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
            layer_list=None
    ):
        """
        Auto places(deploys) a resource to the amount of place_count.

        :param str rsc_name: Name of the resource definition to deploy
        :param int place_count: Number of placements, on how many different nodes
        :param str storage_pool: Storage pool to use
        :param list[str] do_not_place_with: Do not place with resource names in this list
        :param str do_not_place_with_regex: A regex string that rules out resources
        :param list[str] replicas_on_same: A list of node property names, their values should match
        :param list[str] replicas_on_different: A list of node property names, their values should not match
        :param bool diskless_on_remaining: If True all remaining nodes will add a diskless resource
        :param bool async_msg: True to return without waiting for the action to complete on the satellites
        :param list[str] layer_list: Define layers for the resource
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgAutoPlaceRsc()
        msg.rsc_name = rsc_name
        msg.diskless_on_remaining = diskless_on_remaining
        msg_filter = msg.select_filter
        msg_filter.place_count = place_count

        if storage_pool:
            msg_filter.storage_pool = storage_pool
        if do_not_place_with:
            msg_filter.not_place_with_rsc.extend(do_not_place_with)
        if do_not_place_with_regex:
            msg_filter.not_place_with_rsc_regex = do_not_place_with_regex
        if replicas_on_same:
            msg_filter.replicas_on_same.extend(replicas_on_same)
        if replicas_on_different:
            msg_filter.replicas_on_different.extend(replicas_on_different)

        if layer_list:
            for layer_name in layer_list:
                msg.layer_stack.append(LayerType.LayerType.Value(layer_name.upper()))

        return self._send_and_wait(apiconsts.API_AUTO_PLACE_RSC, msg, async_msg=async_msg)

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
        msg = MsgModRsc()
        msg.node_name = node_name
        msg.rsc_name = rsc_name

        msg = self._modify_props(msg, property_dict, delete_props)

        return self._send_and_wait(apiconsts.API_MOD_RSC, msg)

    def resource_delete(self, node_name, rsc_name, async_msg=False):
        """
        Deletes a given resource on the given node.

        :param str node_name: Name of the node where the resource is deployed.
        :param str rsc_name: Name of the resource.
        :param bool async_msg: True to return without waiting for the action to complete on the satellites.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgDelRsc()
        msg.node_name = node_name
        msg.rsc_name = rsc_name

        return self._send_and_wait(apiconsts.API_DEL_RSC, msg, async_msg=async_msg)

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
        apiresp = ApiCallResponseProto()
        apiresp.ret_code = apiconsts.MASK_SUCCESS

        # maximum number of ressources is 1 when filtering per node and resource
        rsc_list_replies = self.resource_list(filter_by_nodes=[node_name], filter_by_resources=[rsc_name])
        if not rsc_list_replies or not rsc_list_replies[0]:
            apiresp.message = 'Resource {} did not exist on node {}'.format(rsc_name, node_name)
            return [ApiCallResponse(apiresp)]

        # did something else went wrong?
        rsc_list_reply = rsc_list_replies[0]
        if isinstance(rsc_list_reply, ApiCallResponse):
            return rsc_list_replies

        if apiconsts.FLAG_DISKLESS in rsc_list_reply.proto_msg.resources[0].rsc_flags:
            return self.resource_delete(rsc_name=rsc_name, node_name=node_name)
        else:
            apiresp.message = 'Resource {} not diskless on node {}, not deleted'.format(rsc_name, node_name)
            return [ApiCallResponse(apiresp)]

    def resource_list(self, filter_by_nodes=None, filter_by_resources=None):
        """
        Request a list of all resources known to the controller.

        :param list[str] filter_by_nodes: filter resources by nodes
        :param list[str] filter_by_resources: filter resources by resource names
        :return: A MsgLstRsc proto message containing all information.
        :rtype: list[ProtoMessageResponse]
        """
        f = Filter()
        if filter_by_nodes:
            f.node_names.extend(filter_by_nodes)
        if filter_by_resources:
            f.resource_names.extend(filter_by_resources)
        return self._send_and_wait(apiconsts.API_LST_RSC, f)

    def volume_list(self, filter_by_nodes=None, filter_by_stor_pools=None, filter_by_resources=None):
        """
        Request a list of all volumes known to the controller.

        :param list[str] filter_by_nodes: filter resources by nodes
        :param list[str] filter_by_stor_pools: filter resources by storage pool names
        :param list[str] filter_by_resources: filter resources by resource names
        :return: A MsgLstRsc proto message containing all information.
        :rtype: list[ProtoMessageResponse]
        """
        f = Filter()
        if filter_by_nodes:
            f.node_names.extend(filter_by_nodes)
        if filter_by_stor_pools:
            f.stor_pool_names.extend(filter_by_stor_pools)
        if filter_by_resources:
            f.resource_names.extend(filter_by_resources)
        return self._send_and_wait(apiconsts.API_LST_VLM, f)

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
        msg = MsgToggleDisk()
        msg.node_name = node_name
        msg.rsc_name = rsc_name

        if storage_pool:
            msg.stor_pool_name = storage_pool

        if migrate_from:
            msg.migrate_from = migrate_from

        msg.diskless = diskless

        return self._send_and_wait(apiconsts.API_TOGGLE_DISK, msg, async_msg=async_msg)

    def controller_props(self):
        """
        Request a list of all controller properties.

        :return: A MsgLstCtrlCfgProps proto message containing all controller props.
        :rtype: list
        """
        return self._send_and_wait(apiconsts.API_LST_CTRL_PROPS)

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
        msg = MsgModCtrl()
        prop = msg.override_props.add()
        prop.key = key
        prop.value = value

        return self._send_and_wait(apiconsts.API_SET_CTRL_PROP, msg)

    def controller_del_prop(self, key):
        """
        Deletes a property on the controller.

        :param key: Key of the property.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgModCtrl()
        msg.delete_prop_keys.extend([key])

        return self._send_and_wait(apiconsts.API_SET_CTRL_PROP, msg)

    def controller_info(self):
        """
        If connected this method returns the controller info string.

        :return: Controller info string or None if not connected.
        :rtype: str
        """
        return self._linstor_client.controller_info()

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
        msg = MsgCrtCryptPassphrase()
        msg.passphrase = passphrase
        return self._send_and_wait(apiconsts.API_CRT_CRYPT_PASS, msg)

    def crypt_enter_passphrase(self, passphrase):
        """
        Send the master passphrase to unlock crypted volumes.

        :param passphrase: Passphrase to send to the controller.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgEnterCryptPassphrase()
        msg.passphrase = passphrase
        return self._send_and_wait(apiconsts.API_ENTER_CRYPT_PASS, msg)

    def crypt_modify_passphrase(self, old_passphrase, new_passphrase):
        """
        Modify the current crypt passphrase.

        :param old_passphrase: Old passphrase, need for decrypt current volumes.
        :param new_passphrase: New passphrase.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgModCryptPassphrase()
        msg.old_passphrase = old_passphrase
        msg.new_passphrase = new_passphrase
        return self._send_and_wait(apiconsts.API_MOD_CRYPT_PASS, msg)

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
        msg = MsgModRscConn()

        msg.rsc_name = rsc_name
        msg.node_1_name = node_a
        msg.node_2_name = node_b
        msg = self._modify_props(msg, property_dict, delete_props)
        return self._send_and_wait(apiconsts.API_MOD_RSC_CONN, msg)

    def resource_conn_list(self, rsc_name):
        """
        Request a list of all resource connection to the given resource name.

        :param rsc_name: Name of the resource to get the connections.
        :return: MsgLstRscConn
        :rtype: list[ProtoMessageResponse]
        """
        msg = MsgReqRscConn()
        msg.rsc_name = rsc_name
        return self._send_and_wait(apiconsts.API_REQ_RSC_CONN_LIST, msg)

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
        msg = MsgEnableDrbdProxy()

        msg.rsc_name = rsc_name
        msg.node_1_name = node_a
        msg.node_2_name = node_b
        if port is not None:
            msg.port = port
        return self._send_and_wait(apiconsts.API_ENABLE_DRBD_PROXY, msg)

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
        msg = MsgDisableDrbdProxy()

        msg.rsc_name = rsc_name
        msg.node_1_name = node_a
        msg.node_2_name = node_b
        return self._send_and_wait(apiconsts.API_DISABLE_DRBD_PROXY, msg)

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
        msg = MsgModDrbdProxy()
        msg.rsc_name = rsc_name

        msg = self._modify_props(msg, property_dict, delete_props)

        if compression_type:
            msg.compression_type = compression_type

            if compression_property_dict:
                for key, val in compression_property_dict.items():
                    lin_kv = msg.compression_props.add()
                    lin_kv.key = key
                    lin_kv.value = val

        return self._send_and_wait(apiconsts.API_MOD_DRBD_PROXY, msg)

    def snapshot_create(self, node_names, rsc_name, snapshot_name, async_msg):
        """
        Create a snapshot.

        :param list[str] node_names: Names of the nodes.
        :param str rsc_name: Name of the resource.
        :param str snapshot_name: Name of the new snapshot.
        :param bool async_msg: True to return without waiting for the action to complete on the satellites.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgCrtSnapshot()

        for node_name in node_names:
            snapshot = msg.snapshot_dfn.snapshots.add()
            snapshot.node_name = node_name

        msg.snapshot_dfn.rsc_name = rsc_name
        msg.snapshot_dfn.snapshot_name = snapshot_name
        return self._send_and_wait(
            apiconsts.API_CRT_SNAPSHOT,
            msg,
            async_msg=async_msg
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
        msg = MsgRestoreSnapshotVlmDfn()
        msg.from_resource_name = from_resource
        msg.from_snapshot_name = from_snapshot
        msg.to_resource_name = to_resource
        return self._send_and_wait(apiconsts.API_RESTORE_VLM_DFN, msg)

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
        msg = MsgRestoreSnapshotRsc()

        for node_name in node_names:
            node = msg.nodes.add()
            node.name = node_name

        msg.from_resource_name = from_resource
        msg.from_snapshot_name = from_snapshot
        msg.to_resource_name = to_resource
        return self._send_and_wait(apiconsts.API_RESTORE_SNAPSHOT, msg)

    def snapshot_delete(self, rsc_name, snapshot_name):
        """
        Delete a snapshot.

        :param str rsc_name: Name of the resource.
        :param str snapshot_name: Name of the snapshot.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgDelSnapshot()

        msg.rsc_name = rsc_name
        msg.snapshot_name = snapshot_name
        return self._send_and_wait(apiconsts.API_DEL_SNAPSHOT, msg)

    def snapshot_rollback(self, rsc_name, snapshot_name):
        """
        Roll a resource back to a snapshot state.

        :param str rsc_name: Name of the resource.
        :param str snapshot_name: Name of the snapshot.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgRollbackSnapshot()

        msg.rsc_name = rsc_name
        msg.snapshot_name = snapshot_name
        return self._send_and_wait(apiconsts.API_ROLLBACK_SNAPSHOT, msg)

    def snapshot_dfn_list(self):
        """
        Request a list of all snapshot definitions known to the controller.

        :return: A MsgLstSnapshotDfn proto message containing all information.
        :rtype: list[ProtoMessageResponse]
        """
        return self._send_and_wait(apiconsts.API_LST_SNAPSHOT_DFN)

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
        msg = MsgReqErrorReport()
        for node in nodes if nodes else []:
            msg.node_names.extend([node])
        msg.with_content = with_content
        if since:
            msg.since = int(time.mktime(since.timetuple()) * 1000)
        if to:
            msg.to = int(time.mktime(to.timetuple()) * 1000)
        if ids:
            msg.ids.extend(ids)
        return self._send_and_wait(apiconsts.API_REQ_ERROR_REPORTS, msg, allow_no_reply=True)

    def keyvaluestore_modify(self, instance_name, property_dict=None, delete_props=None):
        """
        Modify the properties of a given key value store instance.

        :param str instance_name: Name of the Key/Value store to modify.
        :param dict[str, str] property_dict: Dict containing key, value pairs for new values.
        :param list[str] delete_props: List of properties to delete
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        msg = MsgModKvs()
        msg.kvs_name = instance_name

        self._modify_props(msg, property_dict, delete_props)

        return self._send_and_wait(apiconsts.API_MOD_KVS, msg)

    def keyvaluestores(self):
        """
        Requests all known KeyValue stores known to linstor and returns them in a KeyValueStoresResponse.

        :return: Key/Value store list response objects
        :rtype: KeyValueStoresResponse
        :raise LinstorError: if apicallerror or no response received
        """
        list_res = self._send_and_wait(apiconsts.API_LST_KVS)

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

    def hostname(self):
        """
        Sends an hostname request and should return the `uname -n` output.
        This is a call that is actually used if connected to a satellite.

        :return: List containing 1 MsgHostname proto
        :rtype: list[ProtoMsgResponse]
        """
        return self._send_and_wait(apiconsts.API_HOSTNAME)

    def prepare_disks(self, nvme_filter=None, detect_pmem=True):
        """
        A satellite only api for now, that will detect NVME and PMEM and prepare them
        for use as a lvm volume group.

        :param str nvme_filter: Regex filtering on NVME model number
        :param bool detect_pmem: If pmem should be detected and setup
        :return: List of ApiCallRcs with create information
        :rtype: list[ApiCallResponse]
        """
        msg = MsgPrepareDisks()
        if nvme_filter is not None:
            msg.nvme_filter = nvme_filter
        msg.detect_pmem = detect_pmem

        return self._send_and_wait(apiconsts.API_PREPARE_DISKS, msg)

    def ping(self):
        """
        Sends a ping message to the controller.

        :return: Message id used for this message
        :rtype: int
        """
        return self._linstor_client.send_msg(apiconsts.API_PING)

    def wait_for_message(self, api_call_id):
        """
        Wait for a message from the controller.

        :param int api_call_id: Message id to wait for.
        :return: A list containing ApiCallResponses from the controller.
        :rtype: list[ApiCallResponse]
        """
        def answer_handler(answer):
            return answer
        return self._linstor_client.wait_for_result(api_call_id, answer_handler)

    def stats(self):
        """
        Returns a printable string containing network statistics.

        :return: A string containing network stats.s
        :rtype: str
        """
        return self._linstor_client.stats()


class MultiLinstor(Linstor):
    def __init__(self, ctrl_host_list, timeout=300, keep_alive=False):
        """

        :param list[str] ctrl_host_list:
        :param timeout:
        :param keep_alive:
        """
        super(MultiLinstor, self).__init__(ctrl_host_list[0], timeout, keep_alive)
        self._ctrl_host_list = ctrl_host_list  # type: list[str]

    def connect(self):
        conn_errors = []
        for ctrl_host in self._ctrl_host_list:
            self._ctrl_host = ctrl_host
            try:
                return super(MultiLinstor, self).connect()
            except LinstorNetworkError as lne:
                conn_errors.append(lne)

        if len(conn_errors) == len(self._ctrl_host_list):
            raise LinstorNetworkError("Unable to connect to any of the given controller hosts.", conn_errors)

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
    id_ = lin.ping()
    print(id_)
    lin.wait_for_message(id_)

    node_list = lin.node_list_raise()
    for node in node_list.nodes:
        print(node)
    # print(lin.resource_list())
    stor_pools = lin.storage_pool_list_raise()
    for stor_pool in stor_pools.storage_pools:
        print(stor_pool.name, stor_pool.node_name, stor_pool.supports_snapshots(), stor_pool.is_thin())
        print(" + ", stor_pool.free_space)
