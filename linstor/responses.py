"""
Linstor response module

Contains various classes of linstorapi responses wrappers.
"""

from datetime import datetime

from linstor.proto.common.ApiCallResponse_pb2 import ApiCallResponse as ApiCallResponseProto
import linstor.proto.common.Node_pb2 as NodeProto

import linstor.sharedconsts as apiconsts
from .errors import LinstorError


class ProtoMessageResponse(object):
    """
    A base protobuf wrapper class, all api response use.
    """
    def __init__(self, proto_response):
        self._proto_msg = proto_response

    @property
    def proto_msg(self):
        """
        Returns the stored protobuf message object.

        :return: A protobuf message object.
        """
        return self._proto_msg

    def __nonzero__(self):
        return self.__bool__()

    def __bool__(self):
        return self._proto_msg.ByteSize() > 0

    def __str__(self):
        return str(self._proto_msg)

    def __repr__(self):
        return "ProtoMessageResponse(" + repr(self._proto_msg) + ")"


class ApiCallResponse(ProtoMessageResponse):
    """
    This is a wrapper class for a proto MsgApiCallResponse.
    It provides some additional methods for easier state checking of the ApiCallResponse.
    """
    def __init__(self, proto_response):
        super(ApiCallResponse, self).__init__(proto_response)

    @classmethod
    def from_json(cls, json_data):
        """
        Creates a ApiCallResponse from a data block.

        :param json_data: Parsed json data with "ret_code", "message" and "details" fields.
        :return: a new ApiCallResponse()
        """
        apiresp = ApiCallResponseProto()
        apiresp.ret_code = json_data["ret_code"]
        if "message" in json_data:
            apiresp.message = json_data["message"]
        if "details" in json_data:
            apiresp.details = json_data["details"]

        return ApiCallResponse(apiresp)

    def is_error(self, code=None):
        """
        Returns True if the ApiCallResponse is any error and "code" is unset.
        If "code" is set, return True if the given "code" matches the response code.

        :return: True if it is any error and "code" unset. If "code" is set return True if "code" matches
         response code. In any other cases (e.g., not an error at all), return False.
        """
        if self.ret_code & apiconsts.MASK_ERROR != apiconsts.MASK_ERROR:
            return False  # not an error at all

        return ((code | self.ret_code) != 0) if code else True

    def is_warning(self):
        """
        Returns True if the ApiCallResponse is a warning.

        :return: True if it is a warning.
        """
        return True if self.ret_code & apiconsts.MASK_WARN == apiconsts.MASK_WARN else False

    def is_info(self):
        """
        Returns True if the ApiCallResponse is an info.

        :return: True if it is an info.
        """
        return True if self.ret_code & apiconsts.MASK_INFO == apiconsts.MASK_INFO else False

    def is_success(self):
        """
        Returns True if the ApiCallResponse is a success message.

        :return: True if it is a success message.
        """
        return not self.is_error() and not self.is_warning() and not self.is_info()

    @property
    def ret_code(self):
        """
        Returns the numeric return code mask.

        :return: Return code mask value
        """
        return self._proto_msg.ret_code

    @property
    def message(self):
        return self._proto_msg.message

    @property
    def object_refs(self):
        """
        Returns a dict generator with the object_references.

        :return: Dict with object references
        :rtype: dict[str, str]
        """
        return {x.key: x.value for x in self._proto_msg.obj_refs}

    @property
    def error_report_ids(self):
        return self._proto_msg.error_report_ids

    def __str__(self):
        return self._proto_msg.message

    def __repr__(self):
        return "ApiCallResponse({retcode}, {msg})".format(retcode=self.ret_code, msg=self.proto_msg.message)


class ErrorReport(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(ErrorReport, self).__init__(protobuf)

    @property
    def datetime(self):
        dt = datetime.fromtimestamp(self._proto_msg.error_time / 1000)
        return dt.replace(microsecond=(self._proto_msg.error_time % 1000) * 1000)

    @property
    def id(self):
        return self._proto_msg.filename[len("ErrorReport-"):-len(".log")]

    @property
    def text(self):
        return self._proto_msg.text

    @property
    def node_names(self):
        return self._proto_msg.node_names


class NodeInterface(object):
    def __init__(self, netif_proto):
        self._netif_proto = netif_proto

    @property
    def name(self):
        return self._netif_proto.name

    @property
    def address(self):
        return self._netif_proto.address

    @property
    def stlt_port(self):
        return self._netif_proto.stlt_port

    @property
    def stlt_encryption_type(self):
        return self._netif_proto.stlt_encryption_type


class NodeType(object):
    CONTROLLER = apiconsts.VAL_NODE_TYPE_CTRL
    SATELLITE = apiconsts.VAL_NODE_TYPE_STLT
    COMBINED = apiconsts.VAL_NODE_TYPE_CMBD
    AUXILIARY = apiconsts.VAL_NODE_TYPE_AUX
    SWORDFISH_TARGET = apiconsts.VAL_NODE_TYPE_SWFISH_TARGET


class ConnectionStatus(object):
    def __init__(self, status):
        self._status = status

    @property
    def status(self):
        return self._status

    def __str__(self):
        return NodeProto.Node.ConnectionStatus.Name(self._status)


class Node(object):
    def __init__(self, node_proto):
        self._node_proto = node_proto

    @property
    def name(self):
        return self._node_proto.name

    @property
    def type(self):
        return self._node_proto.type

    @property
    def connection_status(self):
        return ConnectionStatus(self._node_proto.connection_status)

    @property
    def net_interfaces(self):
        return [NodeInterface(x) for x in self._node_proto.net_interfaces]

    def __str__(self):
        return "Node({n}, {t}, {con})".format(n=self.name, t=self.type, con=self.connection_status)


class NodeListResponse(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(NodeListResponse, self).__init__(protobuf)

    @property
    def nodes(self):
        """
        Returns a list with all nodes.

        :return: The node list.
        :rtype: list[Node]
        """
        return [Node(x) for x in self._proto_msg.nodes]

    def node(self, node_name):
        """
        Returns the specified node from the nodelist.

        :param str node_name: Node name
        :return: Node object of the node, or None
        :rtype: Node
        """
        for n in self.nodes:
            if n.name == node_name:
                return n
        return None


class FreeSpace(object):
    def __init__(self, freespace_proto):
        self._freespace = freespace_proto
        
    @property
    def free_capacity(self):
        return self._freespace.free_capacity

    @property
    def total_capacity(self):
        return self._freespace.total_capacity

    def __str__(self):
        return "{used}/{total} Kib used".format(used=self.total_capacity-self.free_capacity, total=self.total_capacity)


class StoragePoolDriver(object):
    LVM = "LvmDriver"
    LVMThin = "LvmThinDriver"
    ZFS = "ZfsDriver"
    ZFSThin = "ZfsThinDriver"
    Diskless = "DisklessDriver"
    SwordfishTarget = "SwordfishTargetDriver"
    SwordfishInitiator = "SwordfishInitiatorDriver"

    @staticmethod
    def list():
        return [
            StoragePoolDriver.LVM,
            StoragePoolDriver.LVMThin,
            StoragePoolDriver.ZFS,
            StoragePoolDriver.ZFSThin,
            StoragePoolDriver.Diskless,
            StoragePoolDriver.SwordfishTarget,
            StoragePoolDriver.SwordfishInitiator
        ]

    @classmethod
    def diskless_driver(cls):
        return [
            StoragePoolDriver.Diskless,
            StoragePoolDriver.SwordfishInitiator
        ]

    @staticmethod
    def _find_prop(props, search_key, default):
        for entry in props:
            if entry.key == search_key:
                return entry.value
        return default

    @staticmethod
    def storage_driver_pool_to_props(storage_driver, driver_pool_name):
        if storage_driver in [
                StoragePoolDriver.Diskless,
                StoragePoolDriver.SwordfishTarget,
                StoragePoolDriver.SwordfishInitiator]:
            return []

        if not driver_pool_name:
            raise LinstorError(
                "Driver '{drv}' needs a driver pool name.".format(drv=storage_driver)
            )

        if storage_driver == StoragePoolDriver.LVM:
            return [(apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_VOLUME_GROUP, driver_pool_name)]

        if storage_driver == StoragePoolDriver.LVMThin:
            driver_pool_parts = driver_pool_name.split('/')
            if not len(driver_pool_parts) == 2:
                raise LinstorError("Pool name '{dp}' does not have format VG/LV".format(dp=driver_pool_name))
            return \
                [(apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_VOLUME_GROUP, driver_pool_parts[0]),
                 (apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_THIN_POOL, driver_pool_parts[1])]

        if storage_driver == StoragePoolDriver.ZFS:
            return [(apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_ZPOOL, driver_pool_name)]

        if storage_driver == StoragePoolDriver.ZFSThin:
            return [(apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_ZPOOLTHIN, driver_pool_name)]

        raise LinstorError(
            "Unknown storage driver '{drv}', known drivers: "
            "lvm, lvmthin, zfs, swordfish, diskless".format(drv=storage_driver)
        )

    @classmethod
    def storage_props_to_driver_pool(cls, storage_driver, props):
        """
        Find the storage pool value for the given storage_driver in the given props.

        :param str storage_driver: String specifying a storage driver [``Lvm``, ``LvmThin``, ``Zfs``]
        :param props: Properties to search the storage pool value.
        :return: If found the storage pool value, else ''
        :rtype: str
        """
        if storage_driver == StoragePoolDriver.LVM:
            return cls._find_prop(
                props, apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_VOLUME_GROUP, ''
            )

        if storage_driver == StoragePoolDriver.LVMThin:
            vg = cls._find_prop(
                props, apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_VOLUME_GROUP, ''
            )
            lv = cls._find_prop(
                props, apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_THIN_POOL, ''
            )
            return "{vg}/{lv}".format(vg=vg, lv=lv)

        if storage_driver == StoragePoolDriver.ZFS:
            return cls._find_prop(
                props, apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_ZPOOL, ''
            )

        if storage_driver == StoragePoolDriver.ZFSThin:
            return cls._find_prop(
                props, apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_ZPOOLTHIN, ''
            )

        return ''


class StoragePool(object):
    def __init__(self, stor_pool_proto):
        self._stor_pool = stor_pool_proto

    @property
    def name(self):
        return self._stor_pool.stor_pool_name

    @property
    def node_name(self):
        return self._stor_pool.node_name

    @property
    def driver(self):
        return self._stor_pool.driver

    @property
    def free_space(self):
        """
        Returns the free space object of the storage pool
        :return:
        :rtype: FreeSpace
        """
        return FreeSpace(self._stor_pool.free_space)

    def supports_snapshots(self):
        snapshot_trait = [x for x in self._stor_pool.static_traits if x.key == "SupportsSnapshots"]
        if snapshot_trait:
            return snapshot_trait[0].value == "true"
        return False

    def is_thin(self):
        snapshot_trait = [x for x in self._stor_pool.static_traits if x.key == "Provisioning"]
        if snapshot_trait:
            return snapshot_trait[0].value == "Thin"
        return False

    def is_fat(self):
        snapshot_trait = [x for x in self._stor_pool.static_traits if x.key == "Provisioning"]
        if snapshot_trait:
            return snapshot_trait[0].value == "Fat"
        return False

    def is_diskless(self):
        return self.driver in StoragePoolDriver.diskless_driver()


class StoragePoolListResponse(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(StoragePoolListResponse, self).__init__(protobuf)

    @property
    def storage_pools(self):
        return [StoragePool(x) for x in self._proto_msg.stor_pools]


class KeyValueStoresResponse(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(KeyValueStoresResponse, self).__init__(protobuf)

    def instances(self):
        """
        Returns a list of all known instances
        :return: List with all names of instances
        :rtype: list[str]
        """
        return [x.name for x in self._proto_msg.key_value_store]

    def instance(self, name):
        """
        Returns a KeyValueStore object containing the specified KV instance.

        :param str name: name of the instance wanted
        :return: KeyValueStore object of the instance, if none found an empty is created
        :rtype: KeyValueStore
        """
        kv = [x for x in self._proto_msg.key_value_store if x.name == name]
        kv = kv[0] if kv else {}
        return KeyValueStore(name, {x.key: x.value for x in kv.props})


class KeyValueStore(object):
    def __init__(self, instance_name, props):
        self._instance_name = instance_name
        self._props = props

    @property
    def properties(self):
        """
        Returns the property dictionary.

        :return: dict containing key values
        :rtype: dict[str, str]
        """
        return self._props

    def __str__(self):
        return str({"name": self._instance_name, "properties": self._props})
