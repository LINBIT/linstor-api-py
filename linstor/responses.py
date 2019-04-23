"""
Linstor response module

Contains various classes of linstorapi responses wrappers.
"""
import base64

from datetime import datetime

from linstor.proto.common.ApiCallResponse_pb2 import ApiCallResponse as ApiCallResponseProto
import linstor.proto.common.Node_pb2 as NodeProto
import linstor.proto.common.LayerType_pb2 as LayerType
import linstor.proto.common.ProviderType_pb2 as ProviderType
from linstor.protobuf_to_dict import protobuf_to_dict

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
        Careful this object is not stable and may change.

        :return: A protobuf message object.
        """
        return self._proto_msg

    @property
    def data_v0(self):
        return protobuf_to_dict(self.proto_msg)

    @property
    def data_v1(self):
        return protobuf_to_dict(self.proto_msg)

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
    def cause(self):
        return self._proto_msg.cause

    @property
    def correction(self):
        return self._proto_msg.correction

    @property
    def details(self):
        return self._proto_msg.details

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


class FreeSpace(ProtoMessageResponse):
    def __init__(self, freespace_proto):
        super(FreeSpace, self).__init__(freespace_proto)
        
    @property
    def free_capacity(self):
        return self._proto_msg.free_capacity

    @property
    def total_capacity(self):
        return self._proto_msg.total_capacity

    def __str__(self):
        return "{used}/{total} Kib used".format(used=self.total_capacity-self.free_capacity, total=self.total_capacity)


class StoragePoolDriver(object):
    LVM = ProviderType.LVM
    LVMThin = ProviderType.LVM_THIN
    ZFS = ProviderType.ZFS
    ZFSThin = ProviderType.ZFS_THIN
    Diskless = ProviderType.DISKLESS
    SwordfishTarget = ProviderType.SWORDFISH_TARGET
    SwordfishInitiator = ProviderType.SWORDFISH_INITIATOR

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
        storage_driver_enum = ProviderType.ProviderType.Value(storage_driver)
        if storage_driver_enum == StoragePoolDriver.LVM:
            return props.get(apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_VOLUME_GROUP, '')

        if storage_driver_enum == StoragePoolDriver.LVMThin:
            vg = props.get(apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_VOLUME_GROUP, '')
            lv = props.get(apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_THIN_POOL, '')
            return "{vg}/{lv}".format(vg=vg, lv=lv)

        if storage_driver_enum == StoragePoolDriver.ZFS:
            return props.get(apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_ZPOOL, '')

        if storage_driver_enum == StoragePoolDriver.ZFSThin:
            return props.get(apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_ZPOOLTHIN, '')

        return ''


class StoragePool(ProtoMessageResponse):
    DRIVER_KIND_MAP = {
        ProviderType.DISKLESS: "DisklessDriver",
        ProviderType.LVM: "LvmDriver",
        ProviderType.LVM_THIN: "LvmThinDriver",
        ProviderType.ZFS: "ZfsDriver",
        ProviderType.ZFS_THIN: "ZfsThinDriver",
        ProviderType.SWORDFISH_TARGET: "SwordfishTargetDriver",
        ProviderType.SWORDFISH_INITIATOR: "SwordfishInitiatorDriver"
    }

    def __init__(self, protobuf):
        super(StoragePool, self).__init__(protobuf)

    @property
    def name(self):
        return self._proto_msg.stor_pool_name

    @property
    def node_name(self):
        return self._proto_msg.node_name

    @property
    def driver(self):
        return self.provider_kind

    @property
    def provider_kind(self):
        return ProviderType.ProviderType.Name(self._proto_msg.provider_kind)

    @property
    def properties(self):
        """
        Storage pool properties.

        :return: Property map
        :rtype: dict[str, str]
        """
        return {x.key: x.value for x in self._proto_msg.props}

    @property
    def static_traits(self):
        """
        Static traits.

        :return: Property map
        :rtype: dict[str, str]
        """
        return {x.key: x.value for x in self._proto_msg.static_traits}

    @property
    def free_space(self):
        """
        Returns the free space object of the storage pool
        :return:
        :rtype: FreeSpace
        """
        if self._proto_msg.HasField('free_space'):
            return FreeSpace(self._proto_msg.free_space)
        return None

    def supports_snapshots(self):
        snapshot_trait = [x for x in self._proto_msg.static_traits if x.key == "SupportsSnapshots"]
        if snapshot_trait:
            return snapshot_trait[0].value == "true"
        return False

    def is_thin(self):
        snapshot_trait = [x for x in self._proto_msg.static_traits if x.key == "Provisioning"]
        if snapshot_trait:
            return snapshot_trait[0].value == "Thin"
        return False

    def is_fat(self):
        snapshot_trait = [x for x in self._proto_msg.static_traits if x.key == "Provisioning"]
        if snapshot_trait:
            return snapshot_trait[0].value == "Fat"
        return False

    def is_diskless(self):
        return self._proto_msg.provider_kind in StoragePoolDriver.diskless_driver()

    @property
    def data_v0(self):
        d = protobuf_to_dict(self._proto_msg)
        del d['provider_kind']
        d['driver'] = self.DRIVER_KIND_MAP.get(self._proto_msg.provider_kind, '')
        return d


class StoragePoolListResponse(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(StoragePoolListResponse, self).__init__(protobuf)

    @property
    def storage_pools(self):
        """
        Returns list of storage pool objects.
        :return: list of storage pools
        :rtype: list[StoragePool]
        """
        return [StoragePool(x) for x in self._proto_msg.stor_pools]

    @property
    def data_v0(self):
        return {
            "stor_pools": [x.data_v0 for x in self.storage_pools]
        }


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


class DrbdVolumeDefinitionData(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(DrbdVolumeDefinitionData, self).__init__(protobuf)

    @property
    def resource_name_suffix(self):
        return self._proto_msg.rsc_name_suffix

    @property
    def minor(self):
        return self._proto_msg.minor

    @property
    def number(self):
        return self._proto_msg.number


class VolumeDefinition(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(VolumeDefinition, self).__init__(protobuf)

    @property
    def number(self):
        """
        Volume definition number

        :return: Volume definition number
        :rtype: int
        """
        return int(self._proto_msg.vlm_nr)

    @property
    def size(self):
        """
        Nett volume size in KiB.

        :return: Nett volume size in KiB.
        :rtype: int
        """
        return int(self._proto_msg.vlm_size)

    @property
    def flags(self):
        """
        Resource definition flags as string list.

        :return: Resource definition flags as string list
        :rtype: list[str]
        """
        return [x for x in self._proto_msg.vlm_flags]

    @property
    def properties(self):
        """
        Resource definition properties.

        :return: Property map
        :rtype: dict[str, str]
        """
        return {x.key: x.value for x in self._proto_msg.vlm_props}

    @property
    def drbd_data(self):
        for layer in self._proto_msg.layer_data:
            if layer.layer_type == LayerType.DRBD:
                return DrbdVolumeDefinitionData(layer.drbd)
        return None


class ResourceDefinition(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(ResourceDefinition, self).__init__(protobuf)

    @property
    def name(self):
        """
        Resource definition name.

        :return: Resource definition name
        :rtype: str
        """
        return self._proto_msg.rsc_name

    @property
    def flags(self):
        """
        Resource definition flags as string list.

        :return: Resource definition flags as string list
        :rtype: list[str]
        """
        return [x for x in self._proto_msg.rsc_dfn_flags]

    @property
    def properties(self):
        """
        Resource definition properties.

        :return: Property map
        :rtype: dict[str, str]
        """
        return {x.key: x.value for x in self._proto_msg.rsc_dfn_props}

    @property
    def drbd_data(self):
        for layer in self.proto_msg.layer_data:
            if layer.layer_type == LayerType.DRBD:
                return layer.drbd
        return None

    @property
    def volume_definitions(self):
        """
        List of all volume definitions

        :return:
        :rtype: list[VolumeDefinition]
        """
        return [VolumeDefinition(x) for x in self._proto_msg.vlm_dfns]


class ResourceDefinitionResponse(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(ResourceDefinitionResponse, self).__init__(protobuf)

    @property
    def resource_definitions(self):
        """
        List of resource definitions
        :return: List of resource definitions
        :rtype: list[ResourceDefinition]
        """
        return list(ResourceDefinition(x) for x in self._proto_msg.rsc_dfns)

    @property
    def data_v0(self):
        """
        Returns compatibility output for the first machine readable format.

        :return: Dictionary with old resource definition format
        """
        rsc_dfns = []
        for rsc_dfn in self.resource_definitions:
            vlm_dfns = []
            for vlm_dfn in rsc_dfn.volume_definitions:
                v0_vlm_dfn = {
                    "vlm_dfn_uuid": vlm_dfn.proto_msg.vlm_dfn_uuid,
                    "vlm_nr": vlm_dfn.number,
                    "vlm_size": vlm_dfn.size
                }

                if vlm_dfn.flags:
                    v0_vlm_dfn['vlm_flags'] = vlm_dfn.flags

                if vlm_dfn.properties:
                    v0_vlm_dfn['vlm_props'] = [{"key": x, "value": v} for x, v in vlm_dfn.properties.items()]

                drbd_data = vlm_dfn.drbd_data
                if drbd_data:
                    v0_vlm_dfn['vlm_minor'] = drbd_data.minor

                vlm_dfns.append(v0_vlm_dfn)

            v0_rsc_dfn = {
                "rsc_dfn_uuid": rsc_dfn.proto_msg.rsc_dfn_uuid,
                "rsc_name": rsc_dfn.name,
                "vlm_dfns": vlm_dfns
            }

            if rsc_dfn.flags:
                v0_rsc_dfn['rsc_dfn_flags'] = rsc_dfn.flags
            if rsc_dfn.properties:
                v0_rsc_dfn["rsc_dfn_props"] = [{"key": x, "value": v} for x, v in rsc_dfn.properties.items()]

            drbd_data = rsc_dfn.drbd_data
            if drbd_data:
                v0_rsc_dfn['rsc_dfn_port'] = drbd_data.port
                v0_rsc_dfn['rsc_dfn_secret'] = drbd_data.secret

            rsc_dfns.append(v0_rsc_dfn)
        return {
            "rsc_dfns": rsc_dfns
        }

    @property
    def data_v1(self):
        data = super(ResourceDefinitionResponse, self).data_v1
        for rsc_dfn in data['rsc_dfns']:
            if "external_name" in rsc_dfn:
                rsc_dfn["external_name"] = base64.b64decode(rsc_dfn["external_name"]).decode('utf-8')
        return data


class VolumeState(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(VolumeState, self).__init__(protobuf)

    @property
    def number(self):
        """
        Volume number index
        :return: Volume number index
        :rtype: int
        """
        return self._proto_msg.vlm_nr

    @property
    def disk_state(self):
        """
        :return: String describing the disk state
        :rtype: str
        """
        return self._proto_msg.disk_state


class ResourceState(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(ResourceState, self).__init__(protobuf)

    @property
    def name(self):
        return self._proto_msg.rsc_name

    @property
    def node_name(self):
        return self._proto_msg.node_name

    @property
    def in_use(self):
        """
        Indicates if a resource is in use, for a drbd resource this means primary.
        Other types might be unknown/None
        :return: bool or None
        """
        return self._proto_msg.in_use

    @property
    def volume_states(self):
        """
        Returns volume states
        :return: volume states list
        :rtype: list[VolumeState]
        """
        return [VolumeState(x) for x in self._proto_msg.vlm_states]


class ResourceLayerData(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(ResourceLayerData, self).__init__(protobuf)

    @property
    def id(self):
        return self.proto_msg.id

    @property
    def name_suffix(self):
        return self.proto_msg.rsc_name_suffix

    @property
    def children(self):
        """
        Return resource layer list children.
        :return: List of resource layer data children
        :rtype: list[ResourceLayerData]
        """
        return [ResourceLayerData(x) for x in self.proto_msg.children]

    # TODO payload


class VolumeLayerData(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(VolumeLayerData, self).__init__(protobuf)

    @property
    def layer_type(self):
        """
        Returns the name of the layer type.
        :return: Name of the layer type
        :rtype: str
        """
        return LayerType.LayerType.Name(self.proto_msg.layer_type)


class DrbdVolumeDefinition(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(DrbdVolumeDefinition, self).__init__(protobuf)

    @property
    def number(self):
        return self.proto_msg.vlm_nr

    @property
    def minor(self):
        return self.proto_msg.minor

    @property
    def resource_name_suffix(self):
        return self.proto_msg.rsc_name_suffix


class DrbdVolumeData(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(DrbdVolumeData, self).__init__(protobuf)

    @property
    def drbd_volume_definition(self):
        return DrbdVolumeDefinition(self.proto_msg.drbd_vlm_dfn)

    @property
    def device_path(self):
        return self.proto_msg.device_path

    @property
    def backing_device(self):
        return self.proto_msg.backing_device

    @property
    def meta_disk(self):
        return self.proto_msg.meta_disk

    @property
    def allocated_size(self):
        return self.proto_msg.allocated_size

    @property
    def usable_size(self):
        return self.proto_msg.usable_size


class StorageVolumeData(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(StorageVolumeData, self).__init__(protobuf)


class LUKSVolumeData(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(LUKSVolumeData, self).__init__(protobuf)


class Volume(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(Volume, self).__init__(protobuf)

    @property
    def number(self):
        return self.proto_msg.vlm_nr

    @property
    def storage_pool_name(self):
        return self.proto_msg.stor_pool_name

    @property
    def storage_pool_driver_name(self):
        return self.proto_msg.stor_pool_driver_name

    @property
    def device_path(self):
        return self.proto_msg.device_path

    @property
    def allocated_size(self):
        if self.proto_msg.HasField('allocated_size'):
            return self.proto_msg.allocated_size
        return None

    @property
    def usable_size(self):
        if self.proto_msg.HasField('usable_size'):
            return self.proto_msg.usable_size
        return None

    @property
    def flags(self):
        """
        Volume flags as string list.

        :return: Resource definition flags as string list
        :rtype: list[str]
        """
        return [x for x in self._proto_msg.vlm_flags]

    @property
    def properties(self):
        """
        Volume properties.

        :return: Property map
        :rtype: dict[str, str]
        """
        return {x.key: x.value for x in self._proto_msg.vlm_props}

    @property
    def layer_data(self):
        return [VolumeLayerData(x) for x in self._proto_msg.layer_data]

    @property
    def drbd_data(self):
        for layer in self.layer_data:
            if layer.proto_msg.layer_type == LayerType.DRBD:
                return DrbdVolumeData(layer.proto_msg.drbd)
        return None

    @property
    def storage_data(self):
        for layer in self.layer_data:
            if layer.proto_msg.layer_type == LayerType.STORAGE:
                return StorageVolumeData(layer.proto_msg.storage)
        return None

    @property
    def luks_data(self):
        for layer in self.layer_data:
            if layer.proto_msg.layer_type == LayerType.LUKS:
                return LUKSVolumeData(layer.proto_msg.luks)
        return None

    @property
    def data_v0(self):
        d = {
            "vlm_uuid": self.proto_msg.vlm_uuid,
            "vlm_dfn_uuid": self.proto_msg.vlm_uuid,
            "stor_pool_name": self.storage_pool_name,
            "stor_pool_uuid": self.proto_msg.stor_pool_uuid,
            "vlm_nr": self.number,
            "device_path": self.device_path
        }

        drbd_data = self.drbd_data
        if drbd_data is not None:
            d['vlm_minor_nr'] = drbd_data.drbd_volume_definition.minor
            d['backing_disk'] = drbd_data.backing_device
            d['meta_disk'] = drbd_data.meta_disk
            if drbd_data.allocated_size:
                d['allocated'] = self.proto_msg.allocated_size

        return d


class Resource(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(Resource, self).__init__(protobuf)

    @property
    def name(self):
        return self._proto_msg.name

    @property
    def node_name(self):
        return self._proto_msg.node_name

    @property
    def volumes(self):
        """
        Resource volumes.
        :return: Resource volumes
        :rtype: list[Volume]
        """
        return list([Volume(x) for x in self._proto_msg.vlms])

    @property
    def flags(self):
        """
        Resource flags as string list.

        :return: Resource definition flags as string list
        :rtype: list[str]
        """
        return [x for x in self._proto_msg.rsc_flags]

    @property
    def properties(self):
        """
        Resource properties.

        :return: Property map
        :rtype: dict[str, str]
        """
        return {x.key: x.value for x in self._proto_msg.props}

    @property
    def layer_data(self):
        """
        Return resource layer object
        :return:
        :rtype: ResourceLayerData
        """
        if self.proto_msg.HasField('layer_object'):
            return ResourceLayerData(self.proto_msg.layer_object)
        return None

    @property
    def data_v0(self):
        return {
            "uuid": self.proto_msg.uuid,
            "node_uuid": self.proto_msg.node_uuid,
            "rsc_dfn_uuid": self.proto_msg.rsc_dfn_uuid,
            "name": self.name,
            "node_name": self.node_name,
            "rsc_flags": self.flags,
            "props": [{"key": x, "value": v} for x, v in self.properties.items()],
            "vlms": [x.data_v0 for x in self.volumes]
        }


class ResourceResponse(ProtoMessageResponse):
    def __init__(self, protobuf):
        super(ResourceResponse, self).__init__(protobuf)

    @property
    def resources(self):
        """
        Return resource list from controller.
        :return: List of resources
        :rtype: list[Resource]
        """
        return list(Resource(x) for x in self._proto_msg.resources)

    @property
    def resource_states(self):
        """

        :return:
        :rtype: list[ResourceState]
        """
        return list(ResourceState(x) for x in self._proto_msg.resource_states)

    @property
    def data_v0(self):
        """
        Returns compatibility output for the first machine readable format.

        :return: Dictionary with old resource definition format
        """
        return {
            "resource_states": [x.data_v0 for x in self.resource_states],
            "resources": [x.data_v0 for x in self.resources]
        }
