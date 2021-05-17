"""
Linstor response module

Contains various classes of linstorapi responses wrappers.
"""
from datetime import datetime

import linstor.sharedconsts as apiconsts
from .errors import LinstorError


class RESTMessageResponse(object):
    """
    A base protobuf wrapper class, all api response use.
    """
    def __init__(self, rest_data):
        self._rest_data = rest_data

    def data(self, version):
        """
        Returns a specific version data format.
        :param str version:
        :return:
        """
        if version == "v0":
            return self.data_v0
        return self.data_v1

    @property
    def data_v0(self):
        return self._rest_data

    @property
    def data_v1(self):
        return self._rest_data

    def __nonzero__(self):
        return self.__bool__()

    def __bool__(self):
        return True

    def __str__(self):
        return str(self._rest_data)

    def __repr__(self):
        return "RESTMessageResponse(" + repr(self._rest_data) + ")"


class ApiCallResponse(RESTMessageResponse):
    """
    This is a wrapper class for a proto MsgApiCallResponse.
    It provides some additional methods for easier state checking of the ApiCallResponse.
    """
    def __init__(self, rest_data):
        super(ApiCallResponse, self).__init__(rest_data)

    @classmethod
    def from_json(cls, json_data):
        """
        Creates a ApiCallResponse from a data block.

        :param json_data: Parsed json data with "ret_code", "message" and "details" fields.
        :return: a new ApiCallResponse()
        """
        return ApiCallResponse(json_data)

    def is_error(self, code=None):
        """
        Returns True if the ApiCallResponse is any error and "code" is unset.
        If "code" is set, return True if the given "code" matches the response code.

        :return: True if it is any error and "code" unset.
                 If "code" is set return True if "code" matches
                 response code. In any other cases (e.g., not an error at all), return False.
        """
        if self.ret_code & apiconsts.MASK_ERROR != apiconsts.MASK_ERROR:
            return False  # not an error at all

        return ((code & self.ret_code) == code) if code else True

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
        return self._rest_data["ret_code"]

    @property
    def message(self):
        return self._rest_data.get("message")

    @property
    def cause(self):
        return self._rest_data.get("cause")

    @property
    def correction(self):
        return self._rest_data.get("correction")

    @property
    def details(self):
        return self._rest_data.get("details")

    @property
    def object_refs(self):
        """
        Returns a dict generator with the object_references.

        :return: Dict with object references
        :rtype: dict[str, str]
        """
        return self._rest_data.get("obj_refs", {})

    @property
    def error_report_ids(self):
        return self._rest_data.get("error_report_ids", [])

    @property
    def data_v0(self):
        d = {
            "ret_code": self.ret_code,
            "message": self.message
        }
        if self.cause:
            d["cause"] = self.cause
        if self.correction:
            d["correction"] = self.correction
        if self.details:
            d["details"] = self.details
        if self.object_refs:
            d["object_refs"] = [{"key": x, "value": self.object_refs[x]} for x in self.object_refs]
        if self.error_report_ids:
            d["error_report_ids"] = self.error_report_ids
        return d

    def __eq__(self, other):
        if isinstance(other, ApiCallResponse):
            return self.__hash__() == other.__hash__()
        return False

    def __hash__(self):
        return hash((self.ret_code, self.message))

    def __str__(self):
        st_str = "SUCC"
        if self.is_error():
            st_str = "ERRO"
        elif self.is_info():
            st_str = "INFO"
        elif self.is_warning():
            st_str = "WARN"

        return st_str + ":" + self.message


class ErrorReport(RESTMessageResponse):
    def __init__(self, data):
        super(ErrorReport, self).__init__(data)

    @property
    def datetime(self):
        dt = datetime.fromtimestamp(self._rest_data["error_time"] / 1000)
        return dt.replace(microsecond=(self._rest_data["error_time"] % 1000) * 1000)

    @property
    def id(self):
        return self._rest_data['filename'][len("ErrorReport-"):-len(".log")]

    @property
    def text(self):
        return self._rest_data.get("text")

    @property
    def node_name(self):
        return self._rest_data.get("node_name")

    @property
    def node_names(self):
        return self._rest_data.get("node_name")

    @property
    def module(self):
        return self._rest_data.get("module", "")

    @property
    def version(self):
        return self._rest_data.get("version", "")

    @property
    def peer(self):
        return self._rest_data.get("peer", "")

    @property
    def exception(self):
        return self._rest_data.get("exception", "")

    @property
    def exception_message(self):
        return self._rest_data.get("exception_message", "")

    @property
    def origin_file(self):
        return self._rest_data.get("origin_file", "")

    @property
    def origin_line(self):
        """

        :return: origin line of the exception
        :rtype: Optional[int]
        """
        return int(self._rest_data["origin_line"]) if "origin_line" in self._rest_data else None

    @property
    def data_v0(self):
        d = self._rest_data
        d["node_names"] = d["node_name"]
        del d["node_name"]
        return d


class NodeType(object):
    CONTROLLER = apiconsts.VAL_NODE_TYPE_CTRL
    SATELLITE = apiconsts.VAL_NODE_TYPE_STLT
    COMBINED = apiconsts.VAL_NODE_TYPE_CMBD
    AUXILIARY = apiconsts.VAL_NODE_TYPE_AUX


class NetInterface(RESTMessageResponse):
    def __init__(self, rest_data):
        super(NetInterface, self).__init__(rest_data)

    @property
    def name(self):
        return self._rest_data["name"]

    @property
    def address(self):
        return self._rest_data["address"]

    @property
    def stlt_port(self):
        return self._rest_data.get("satellite_port")

    @property
    def stlt_encryption_type(self):
        return self._rest_data.get("satellite_encryption_type")

    @property
    def is_active(self):
        return self._rest_data.get("is_active")

    @property
    def data_v0(self):
        return {
            "address": self.address,
            "name": self.name,
            "stlt_port": self.stlt_port,
            "stlt_encryption_type": self.stlt_encryption_type
        }


class Node(RESTMessageResponse):
    def __init__(self, rest_data):
        super(Node, self).__init__(rest_data)

    @property
    def name(self):
        return self._rest_data["name"]

    @property
    def type(self):
        return self._rest_data["type"]

    @property
    def connection_status(self):
        return self._rest_data.get(
            "connection_status",
            apiconsts.ConnectionStatus.OFFLINE.name)

    @property
    def net_interfaces(self):
        return [NetInterface(x) for x in self._rest_data.get("net_interfaces", [])]

    @property
    def storage_providers(self):
        return self._rest_data.get("storage_providers", [])

    @property
    def resource_layers(self):
        return self._rest_data.get("resource_layers", [])

    @property
    def unsupported_providers(self):
        return self._rest_data.get("unsupported_providers", {})

    @property
    def unsupported_layers(self):
        return self._rest_data.get("unsupported_layers", {})

    @property
    def props(self):
        return self._rest_data.get("props", {})

    @property
    def properties(self):
        return self._rest_data.get("props", {})

    @property
    def flags(self):
        return self._rest_data.get("flags", [])

    @property
    def data_v0(self):
        d = dict(self._rest_data)
        d["props"] = [{"key": x, "value": self.props[x]} for x in self.props]
        d["connection_status"] = apiconsts.ConnectionStatus[
            self._rest_data.get("connection_status", apiconsts.ConnectionStatus.UNKNOWN.name)].value
        d["net_interfaces"] = [x.data_v0 for x in self.net_interfaces]
        return d

    def __str__(self):
        return "Node({n}, {t}, {con})".format(n=self.name, t=self.type, con=self.connection_status)


class NodeListResponse(RESTMessageResponse):
    def __init__(self, rest_data):
        super(NodeListResponse, self).__init__(rest_data)

    @property
    def nodes(self):
        """
        Returns a list with all nodes.

        :return: The node list.
        :rtype: list[Node]
        """
        return [Node(x) for x in self._rest_data]

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

    @property
    def data_v0(self):
        return {
            "nodes": [n.data_v0 for n in self.nodes]
        }


class FreeSpace(RESTMessageResponse):
    def __init__(self, rest_data):
        super(FreeSpace, self).__init__(rest_data)
        
    @property
    def free_capacity(self):
        return self._rest_data.get("free_capacity")

    @property
    def total_capacity(self):
        return self._rest_data.get("total_capacity")

    def __str__(self):
        return "{used}/{total} Kib used".format(used=self.total_capacity-self.free_capacity, total=self.total_capacity)

    @property
    def data_v0(self):
        return {
            "stor_pool_name": self._rest_data["storage_pool_name"],
            "free_capacity": self.free_capacity,
            "total_capacity": self.total_capacity
        }


class StoragePoolDriver(object):
    LVM = "LVM"
    LVMThin = "LVM_THIN"
    ZFS = "ZFS"
    ZFSThin = "ZFS_THIN"
    Diskless = "DISKLESS"
    FILE = "FILE"
    FILEThin = "FILE_THIN"
    SPDK = "SPDK"
    OPENFLEX_TARGET = "OPENFLEX_TARGET"
    EXOS = "EXOS"

    @staticmethod
    def list():
        return [
            StoragePoolDriver.LVM,
            StoragePoolDriver.LVMThin,
            StoragePoolDriver.ZFS,
            StoragePoolDriver.ZFSThin,
            StoragePoolDriver.Diskless,
            StoragePoolDriver.FILE,
            StoragePoolDriver.FILEThin,
            StoragePoolDriver.SPDK,
            StoragePoolDriver.OPENFLEX_TARGET,
            StoragePoolDriver.EXOS
        ]

    @classmethod
    def diskless_driver(cls):
        return [
            StoragePoolDriver.Diskless
        ]

    @staticmethod
    def storage_driver_pool_to_props(storage_driver, driver_pool_name):
        if storage_driver in [StoragePoolDriver.Diskless]:
            return {}

        if not driver_pool_name:
            raise LinstorError(
                "Driver '{drv}' needs a driver pool name.".format(drv=storage_driver)
            )

        if storage_driver == StoragePoolDriver.LVM:
            return {apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_VOLUME_GROUP: driver_pool_name}

        if storage_driver == StoragePoolDriver.LVMThin:
            driver_pool_parts = driver_pool_name.split('/')
            if not len(driver_pool_parts) == 2:
                raise LinstorError("Pool name '{dp}' does not have format VG/LV".format(dp=driver_pool_name))
            return {
                apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_VOLUME_GROUP: driver_pool_parts[0],
                apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_THIN_POOL: driver_pool_parts[1]
            }

        if storage_driver == StoragePoolDriver.ZFS:
            return {apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_ZPOOL: driver_pool_name}

        if storage_driver == StoragePoolDriver.ZFSThin:
            return {apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_ZPOOLTHIN: driver_pool_name}

        if storage_driver in [
                StoragePoolDriver.FILE,
                StoragePoolDriver.FILEThin]:
            return {apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_FILE_DIRECTORY: driver_pool_name}

        if storage_driver == StoragePoolDriver.SPDK:
            return {apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_VOLUME_GROUP: driver_pool_name}

        if storage_driver == StoragePoolDriver.OPENFLEX_TARGET:
            return {
                apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_OPENFLEX_STOR_POOL: driver_pool_name
            }

        raise LinstorError(
            "Unknown storage driver '{drv}', known drivers: "
            "lvm, lvmthin, zfs, diskless, spdk".format(drv=storage_driver)
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
        if apiconsts.NAMESPC_STORAGE_DRIVER + '/StorPoolName' in props:
            return props[apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_NAME]

        storage_driver_enum = storage_driver
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

        if storage_driver_enum == StoragePoolDriver.SPDK:
            return props.get(apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_VOLUME_GROUP, '')

        if storage_driver_enum == StoragePoolDriver.OPENFLEX_TARGET:
            return props.get(apiconsts.NAMESPC_STORAGE_DRIVER + '/' + apiconsts.KEY_STOR_POOL_OPENFLEX_STOR_POOL, '')

        return ''


class StoragePool(RESTMessageResponse):
    DRIVER_KIND_MAP = {
        "DISKLESS": "DisklessDriver",
        "LVM": "LvmDriver",
        "LVM_THIN": "LvmThinDriver",
        "ZFS": "ZfsDriver",
        "ZFS_THIN": "ZfsThinDriver",
        "SPDK": "SpdkDriver"
    }

    def __init__(self, rest_data):
        super(StoragePool, self).__init__(rest_data)

    @property
    def name(self):
        return self._rest_data["storage_pool_name"]

    @property
    def uuid(self):
        return self._rest_data.get("uuid")

    @property
    def node_name(self):
        """
        Node name where the storage pool is used
        :return: node name
        :rtype: str
        """
        return self._rest_data["node_name"]

    @property
    def driver(self):
        """
        Provider kind string
        :return: provider kind string
        :rtype: str
        """
        return self.provider_kind

    @property
    def provider_kind(self):
        """
        Provider kind string
        :return: provider kind string
        :rtype: str
        """
        return self._rest_data.get("provider_kind")

    @property
    def properties(self):
        """
        Storage pool properties.

        :return: Property map
        :rtype: dict[str, str]
        """
        return self._rest_data.get("props", {})

    @property
    def static_traits(self):
        """
        Static traits.

        :return: Property map
        :rtype: dict[str, str]
        """
        return self._rest_data.get("static_traits", {})

    @property
    def free_space(self):
        """
        Returns the free space object of the storage pool
        :return:
        :rtype: FreeSpace
        """
        if "free_capacity" in self._rest_data:
            return FreeSpace(self._rest_data)
        return None

    @property
    def free_space_mgr_name(self):
        return self._rest_data.get("free_space_mgr_name")

    def supports_snapshots(self):
        sup_snaps = self._rest_data.get("supports_snapshots")
        return self.static_traits.get("SupportsSnapshots", "false") == "true" if sup_snaps is None else sup_snaps

    def is_thin(self):
        """
        Checks if pool is thin
        :return: True if it is a thin pool
        :rtype: bool
        """
        return self.static_traits.get("Provisioning", "") == "Thin"

    def is_fat(self):
        """
        Checks if pool is fat
        :return: True if it is a fat pool
        :rtype: bool
        """
        return self.static_traits.get("Provisioning", "") == "Fat"

    def is_diskless(self):
        """
        Checks if pool is diskless
        :return: True if it is a diskless pool
        :rtype: bool
        """
        return self.provider_kind in StoragePoolDriver.diskless_driver()

    @property
    def reports(self):
        return [ApiCallResponse(x) for x in self._rest_data.get("reports", [])]

    @property
    def data_v0(self):
        d = {
            "stor_pool_uuid": self.uuid,
            "stor_pool_name": self.name,
            "node_name": self.node_name,
            "free_space_mgr_name": self.free_space_mgr_name
        }
        if self.free_space:
            d["free_space"] = self.free_space.data_v0
        d['driver'] = self.DRIVER_KIND_MAP.get(self.provider_kind, '')
        d['static_traits'] = [{"key": x, "value": v} for x, v in self.static_traits.items()]
        if self.properties:
            d["props"] = [{"key": x, "value": v} for x, v in self.properties.items()]
        return d


class StoragePoolListResponse(RESTMessageResponse):
    def __init__(self, rest_data):
        super(StoragePoolListResponse, self).__init__(rest_data)

    @property
    def storage_pools(self):
        """
        Returns list of storage pool objects.
        :return: list of storage pools
        :rtype: list[StoragePool]
        """
        return [StoragePool(x) for x in self._rest_data]

    @property
    def data_v0(self):
        return {
            "stor_pools": [x.data_v0 for x in self.storage_pools]
        }


class KeyValueStoresResponse(RESTMessageResponse):
    def __init__(self, data):
        super(KeyValueStoresResponse, self).__init__(data)

    def instances(self):
        """
        Returns a list of all known instances
        :return: List with all names of instances
        :rtype: list[str]
        """
        return [x['name'] for x in self._rest_data]

    def instance(self, name):
        """
        Returns a KeyValueStore object containing the specified KV instance.

        :param str name: name of the instance wanted
        :return: KeyValueStore object of the instance, if none found an empty is created
        :rtype: KeyValueStore
        """
        kv = [x for x in self._rest_data if x['name'] == name]
        kv = kv[0] if kv else {}
        return KeyValueStore(name, kv.get('props', {}))


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


class DrbdVolumeDefinitionData(RESTMessageResponse):
    def __init__(self, rest_data):
        super(DrbdVolumeDefinitionData, self).__init__(rest_data)

    @property
    def resource_name_suffix(self):
        return self._rest_data["rsc_name_suffix"]

    @property
    def minor(self):
        return self._rest_data["minor_number"]

    @property
    def number(self):
        return self._rest_data["volume_number"]


class VolumeDefinition(RESTMessageResponse):
    def __init__(self, rest_data):
        super(VolumeDefinition, self).__init__(rest_data)

    @property
    def number(self):
        """
        Volume definition number

        :return: Volume definition number
        :rtype: int
        """
        return self._rest_data["volume_number"]

    @property
    def uuid(self):
        return self._rest_data.get("uuid")

    @property
    def size(self):
        """
        Nett volume size in KiB.

        :return: Nett volume size in KiB.
        :rtype: int
        """
        return self._rest_data["size_kib"]

    @property
    def flags(self):
        """
        Resource definition flags as string list.

        :return: Resource definition flags as string list
        :rtype: list[str]
        """
        return self._rest_data.get("flags", [])

    @property
    def properties(self):
        """
        Resource definition properties.

        :return: Property map
        :rtype: dict[str, str]
        """
        return self._rest_data.get("props", {})

    @property
    def drbd_data(self):
        for layer in self._rest_data.get("layer_data", []):
            if layer["type"] == "DRBD" and layer.get("data"):
                return DrbdVolumeDefinitionData(layer["data"])
        return None

    @property
    def data_v0(self):
        """
        Returns compatibility output for the first machine readable format.

        :return: Dictionary with old resource definition format
        """
        v0_vlm_dfn = {
            "vlm_nr": self.number,
            "vlm_size": self.size,
            "vlm_dfn_uuid": self.uuid
        }

        if self.flags:
            v0_vlm_dfn['vlm_flags'] = self.flags

        if self.properties:
            v0_vlm_dfn['vlm_props'] = [{"key": x, "value": v} for x, v in self.properties.items()]

        drbd_data = self.drbd_data
        if drbd_data:
            v0_vlm_dfn['vlm_minor'] = drbd_data.minor

        return v0_vlm_dfn


class VolumeDefinitionResponse(RESTMessageResponse):
    def __init__(self, rest_data):
        super(VolumeDefinitionResponse, self).__init__(rest_data)

    @property
    def volume_definitions(self):
        """

        :return:
        :rtype: list[VolumeDefinition]
        """
        return [VolumeDefinition(x) for x in self._rest_data]

    @property
    def rest_data(self):
        return self._rest_data


class DrbdLayer(RESTMessageResponse):
    def __init__(self, rest_data):
        super(DrbdLayer, self).__init__(rest_data)

    @property
    def port(self):
        return self._rest_data["port"]

    @property
    def secret(self):
        return self._rest_data["secret"]


class ResourceDefinition(RESTMessageResponse):
    def __init__(self, rest_data):
        super(ResourceDefinition, self).__init__(rest_data)

    @property
    def name(self):
        """
        Resource definition name.

        :return: Resource definition name
        :rtype: str
        """
        return self._rest_data["name"]

    @property
    def uuid(self):
        return self._rest_data.get("uuid")

    @property
    def external_name(self):
        """
        Returns the external name of the resource
        :return:
        :rtype: str
        """
        return self._rest_data.get("external_name", "")

    @property
    def flags(self):
        """
        Resource definition flags as string list.

        :return: Resource definition flags as string list
        :rtype: list[str]
        """
        return self._rest_data.get("flags", [])

    @property
    def properties(self):
        """
        Resource definition properties.

        :return: Property map
        :rtype: dict[str, str]
        """
        return self._rest_data.get("props", {})

    @property
    def drbd_data(self):
        for layer in self._rest_data.get("layer_data", []):
            if layer["type"] == "DRBD" and layer.get("data"):
                return DrbdLayer(layer["data"])
        return None

    @property
    def volume_definitions(self):
        """
        List of all volume definitions

        :return:
        :rtype: list[VolumeDefinition]
        """
        return [VolumeDefinition(x) for x in self._rest_data.get("volume_definitions", [])]

    @property
    def resource_group_name(self):
        """
        Returns the resource group name linked to the resource.

        :return: Name of the resource group this resource belongs too.
        :rtype: str
        """
        return self._rest_data.get("resource_group_name", "")


class ResourceDefinitionResponse(RESTMessageResponse):
    def __init__(self, rest_data):
        super(ResourceDefinitionResponse, self).__init__(rest_data)

    @property
    def resource_definitions(self):
        """
        List of resource definitions
        :return: List of resource definitions
        :rtype: list[ResourceDefinition]
        """
        return [ResourceDefinition(x) for x in self._rest_data]

    @property
    def data_v0(self):
        """
        Returns compatibility output for the first machine readable format.

        :return: Dictionary with old resource definition format
        """
        rsc_dfns = []
        for rsc_dfn in self.resource_definitions:
            v0_rsc_dfn = {
                "rsc_name": rsc_dfn.name,
                "rsc_dfn_uuid": rsc_dfn.uuid,
                "vlm_dfns": [x.data_v0 for x in rsc_dfn.volume_definitions]
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


class SelectFilter(RESTMessageResponse):
    def __init__(self, rest_data):
        super(SelectFilter, self).__init__(rest_data)

    @property
    def place_count(self):
        return self._rest_data.get("place_count")

    @property
    def diskless_on_remaining(self):
        return self._rest_data.get("diskless_on_remaining", False)

    @property
    def storage_pool(self):
        return self._rest_data.get("storage_pool")

    @property
    def storage_pool_list(self):
        """
        Returns the list of storage pools used
        :return: storage pool list
        :rtype: List[str]
        """
        return self._rest_data.get("storage_pool_list", [self.storage_pool] if self.storage_pool else [])

    @property
    def not_place_with_rsc(self):
        return self._rest_data.get("not_place_with_rsc")

    @property
    def not_place_with_rsc_regex(self):
        return self._rest_data.get("not_place_with_rsc_regex")

    @property
    def replicas_on_same(self):
        return self._rest_data.get("replicas_on_same")

    @property
    def replicas_on_different(self):
        return self._rest_data.get("replicas_on_different")

    @property
    def layer_stack(self):
        return self._rest_data.get("layer_stack")

    @property
    def provider_list(self):
        return self._rest_data.get("provider_list")

    def __str__(self):
        fields = []
        if self.place_count:
            fields.append("PlaceCount: " + str(self.place_count))

        if self.storage_pool or self.storage_pool_list:
            fields.append("StoragePool(s): " + ", ".join(self.storage_pool_list))

        if "diskless_on_remaining" in self._rest_data:
            fields.append("DisklessOnRemaining: " + str(self.diskless_on_remaining))

        if self.not_place_with_rsc:
            fields.append("NotPlaceWithRsc: " + str(self.not_place_with_rsc))

        if self.not_place_with_rsc_regex:
            fields.append("NotPlaceWithRscRegex: " + str(self.not_place_with_rsc_regex))

        if self.replicas_on_same:
            fields.append("ReplicasOnSame: " + str(self.replicas_on_same))

        if self.replicas_on_different:
            fields.append("ReplicasOnDifferent: " + str(self.replicas_on_different))

        if self.layer_stack:
            fields.append("LayerStack: " + str(self.layer_stack))

        if self.provider_list:
            fields.append("ProviderList: " + str(self.provider_list))
        return "\n".join(fields)


class ResourceGroup(RESTMessageResponse):
    def __init__(self, rest_data):
        super(ResourceGroup, self).__init__(rest_data)

    @property
    def name(self):
        """
        Resource group name.

        :return: Resource group name
        :rtype: str
        """
        return self._rest_data["name"]

    @property
    def description(self):
        """
        Resource group description.

        :return: Group description
        :rtype: str
        """
        return self._rest_data.get("description", "")

    @property
    def properties(self):
        """
        Resource group properties.

        :return: Property map
        :rtype: dict[str, str]
        """
        return self._rest_data.get("props", {})

    @property
    def select_filter(self):
        """
        Returns the select filter for the resource group.

        :return: Select filter class
        :rtype: SelectFilter
        """
        return SelectFilter(self._rest_data.get("select_filter", {}))


class ResourceGroupResponse(RESTMessageResponse):
    def __init__(self, rest_data):
        super(ResourceGroupResponse, self).__init__(rest_data)

    @property
    def resource_groups(self):
        """
        List of resource groups
        :return: List of resource groups
        :rtype: list[ResourceGroup]
        """
        return [ResourceGroup(x) for x in self._rest_data]


class VolumeGroup(RESTMessageResponse):
    def __init__(self, rest_data):
        super(VolumeGroup, self).__init__(rest_data)

    @property
    def number(self):
        """
        Volume number

        :return: volume number
        :rtype: int
        """
        return self._rest_data["volume_number"]

    @property
    def properties(self):
        """
        Volume group properties.

        :return: Property map
        :rtype: dict[str, str]
        """
        return self._rest_data.get("props", {})

    @property
    def flags(self):
        """
        Volume group flags.

        :return: Flags list
        :rtype:  list[str]
        """
        return self._rest_data.get("flags", [])


class VolumeGroupResponse(RESTMessageResponse):
    def __init__(self, rest_data):
        super(VolumeGroupResponse, self).__init__(rest_data)

    @property
    def volume_groups(self):
        """
        List of volume groups
        :return: List of volume groups
        :rtype: list[VolumeGroup]
        """
        return [VolumeGroup(x) for x in self._rest_data]


class VolumeState(RESTMessageResponse):
    def __init__(self, data):
        super(VolumeState, self).__init__(data)

    @property
    def number(self):
        """
        Volume number index
        :return: Volume number index
        :rtype: int
        """
        return self._rest_data["vlm_nr"]

    @property
    def disk_state(self):
        """
        :return: String describing the disk state
        :rtype: str
        """
        return self._rest_data.get("disk_state")

    @property
    def data_v0(self):
        return {
            "vlm_nr": self.number,
            "disk_state": self.disk_state
        }


class ResourceState(RESTMessageResponse):
    def __init__(self, data):
        super(ResourceState, self).__init__(data)

    @property
    def name(self):
        return self._rest_data["rsc_name"]

    @property
    def rsc_name(self):
        return self.name

    @property
    def node_name(self):
        return self._rest_data["node_name"]

    @property
    def in_use(self):
        """
        Indicates if a resource is in use, for a drbd resource this means primary.
        Other types might be unknown/None
        :return: bool or None
        """
        return self._rest_data.get("in_use")

    @property
    def volume_states(self):
        """
        Returns volume states
        :return: volume states list
        :rtype: list[VolumeState]
        """
        return [VolumeState(x) for x in self._rest_data.get("vlm_states", [])]

    @property
    def data_v0(self):
        d = {
            "rsc_name": self.name,
            "node_name": self.node_name
        }

        if self.in_use is not None:
            d["in_use"] = self.in_use

        if self.volume_states:
            d["vlm_states"] = [x.data_v0 for x in self.volume_states]
        return d


class DrbdConnection(RESTMessageResponse):
    def __init__(self, rest_data):
        super(DrbdConnection, self).__init__(rest_data)

    @property
    def connected(self):
        return self._rest_data["connected"]

    @property
    def message(self):
        return self._rest_data.get("message")


class DrbdResource(RESTMessageResponse):
    def __init__(self, data):
        super(DrbdResource, self).__init__(data)

    @property
    def node_id(self):
        """
        Get DRBD node id
        :return: node id
        :rtype: int
        """
        return self._rest_data.get("node_id")

    @property
    def peer_slots(self):
        """
        Get DRBD peer slots
        :return: peer slot count
        :rtype: int
        """
        return self._rest_data.get("peer_slots")

    @property
    def al_stripes(self):
        """
        Get DRBD activity log stripes
        :return: al_stripes
        :rtype: int
        """
        return self._rest_data.get("al_stripes")

    @property
    def al_size(self):
        """
        Get DRBD activity log size
        :return: al size
        :rtype: int
        """
        return self._rest_data.get("al_size")

    @property
    def connections(self):
        """
        Connections dict of this DRBD Resource.

        :return: A node to DrbdConnection dict
        :rtype: dict[str, DrbdConnection]
        """
        return {k: DrbdConnection(v) for k, v in self._rest_data.get("connections", {}).items()}

    # TODO other fields


class ResourceLayerData(RESTMessageResponse):
    def __init__(self, data):
        super(ResourceLayerData, self).__init__(data)

    @property
    def name_suffix(self):
        return self._rest_data["rsc_name_suffix"]

    @property
    def children(self):
        """
        Return resource layer list children.
        :return: List of resource layer data children
        :rtype: list[ResourceLayerData]
        """
        return [ResourceLayerData(x) for x in self._rest_data.children]

    @property
    def type(self):
        return self._rest_data["type"]

    @property
    def drbd_resource(self):
        """
        Gets the DRBD resource layer data if layer data is DRBD, otherwise None.

        :return: None if it isn't a drbd resource, otherwise the DrbdResource object
        :rtype: Optional[DrbdResource]
        """
        if self.type == "DRBD":
            return DrbdResource(self._rest_data["drbd"])
        return None

    # TODO other layer objects


class VolumeLayerData(RESTMessageResponse):
    def __init__(self, data):
        super(VolumeLayerData, self).__init__(data)

    @property
    def layer_type(self):
        """
        Returns the name of the layer type.
        :return: Name of the layer type
        :rtype: str
        """
        return self._rest_data['type']


class DrbdVolumeDefinition(RESTMessageResponse):
    def __init__(self, data):
        super(DrbdVolumeDefinition, self).__init__(data)

    @property
    def number(self):
        return self._rest_data["volume_number"]

    @property
    def minor(self):
        return self._rest_data["minor_number"]

    @property
    def resource_name_suffix(self):
        return self._rest_data["resource_name_suffix"]


class DrbdVolumeData(RESTMessageResponse):
    def __init__(self, data):
        super(DrbdVolumeData, self).__init__(data)

    @property
    def drbd_volume_definition(self):
        return DrbdVolumeDefinition(self._rest_data["drbd_volume_definition"])

    @property
    def device_path(self):
        return self._rest_data["device_path"]

    @property
    def backing_device(self):
        return self._rest_data.get("backing_device")

    @property
    def meta_disk(self):
        return self._rest_data.get('meta_disk', "")

    @property
    def allocated_size(self):
        return self._rest_data["allocated_size_kib"]

    @property
    def usable_size(self):
        return self._rest_data["usable_size_kib"]


class StorageVolumeData(RESTMessageResponse):
    def __init__(self, data):
        super(StorageVolumeData, self).__init__(data)


class LUKSVolumeData(RESTMessageResponse):
    def __init__(self, data):
        super(LUKSVolumeData, self).__init__(data)


class Volume(RESTMessageResponse):
    def __init__(self, data):
        super(Volume, self).__init__(data)

    @property
    def number(self):
        return self._rest_data["volume_number"]

    @property
    def uuid(self):
        return self._rest_data.get("uuid")

    @property
    def storage_pool_name(self):
        return self._rest_data.get("storage_pool_name")

    @property
    def storage_pool_driver_name(self):
        return self._rest_data["provider_kind"]

    @property
    def device_path(self):
        return self._rest_data.get("device_path")

    @property
    def allocated_size(self):
        return self._rest_data.get('allocated_size_kib')

    @property
    def usable_size(self):
        if self.drbd_data:
            return self.drbd_data.usable_size
        return None

    @property
    def flags(self):
        """
        Volume flags as string list.

        :return: Resource definition flags as string list
        :rtype: list[str]
        """
        return self._rest_data.get("flags", [])

    @property
    def properties(self):
        """
        Volume properties.

        :return: Property map
        :rtype: dict[str, str]
        """
        return self._rest_data.get("props", {})

    @property
    def layer_data(self):
        return [VolumeLayerData(x) for x in self._rest_data.get("layer_data", [])]

    @property
    def drbd_data(self):
        for layer in self._rest_data.get("layer_data_list", []):
            if layer["type"] == "DRBD" and layer.get("data"):
                return DrbdVolumeData(layer["data"])
        return None

    @property
    def storage_data(self):
        for layer in self._rest_data.get("layer_data_list", []):
            if layer["type"] == "STORAGE" and layer.get("data"):
                return DrbdVolumeData(layer["data"])
        return None

    @property
    def luks_data(self):
        for layer in self._rest_data.get("layer_data_list", []):
            if layer["type"] == "LUKS" and layer.get("data"):
                return DrbdVolumeData(layer["data"])
        return None

    @property
    def reports(self):
        return [ApiCallResponse(x) for x in self._rest_data.get("reports", [])]

    @property
    def data_v0(self):
        d = {
            "stor_pool_name": self.storage_pool_name,
            "vlm_nr": self.number,
            "vlm_uuid": self.uuid,
            "device_path": self.device_path
        }

        drbd_data = self.drbd_data
        if drbd_data is not None:
            d['vlm_minor_nr'] = drbd_data.drbd_volume_definition.minor
            if drbd_data.backing_device:
                d['backing_disk'] = drbd_data.backing_device
            d['meta_disk'] = drbd_data.meta_disk
            if drbd_data.allocated_size:
                d['allocated'] = self.allocated_size

        return d


class VolumeResponse(RESTMessageResponse):
    def __init__(self, rest_data):
        super(VolumeResponse, self).__init__(rest_data)

    @property
    def volumes(self):
        """
        Resource volumes.
        :return: Resource volumes
        :rtype: list[Volume]
        """
        return list([Volume(x) for x in self._rest_data])


class Resource(RESTMessageResponse):
    def __init__(self, rest_data):
        super(Resource, self).__init__(rest_data)

    @property
    def name(self):
        return self._rest_data["name"]

    @property
    def uuid(self):
        return self._rest_data.get("uuid")

    @property
    def node_name(self):
        return self._rest_data["node_name"]

    @property
    def volumes(self):
        """
        Resource volumes.
        :return: Resource volumes
        :rtype: list[Volume]
        """
        return list([Volume(x) for x in self._rest_data.get("volumes", [])])

    @property
    def flags(self):
        """
        Resource flags as string list.

        :return: Resource definition flags as string list
        :rtype: list[str]
        """
        return self._rest_data.get("flags", [])

    @property
    def properties(self):
        """
        Resource properties.

        :return: Property map
        :rtype: dict[str, str]
        """
        return self._rest_data.get("props", {})

    @property
    def layer_data(self):
        """
        Return resource layer object
        :return:
        :rtype: ResourceLayerData
        """
        if "layer_object" in self._rest_data:
            return ResourceLayerData(self._rest_data["layer_object"])
        return None

    @property
    def create_datetime(self):
        """

        :return: Creation datetime of this resource
        :rtype: Optional[datetime]
        """
        if "create_timestamp" in self._rest_data:
            return datetime.fromtimestamp(self._rest_data["create_timestamp"]/1000)
        return None

    @property
    def data_v0(self):
        return {
            "name": self.name,
            "uuid": self.uuid,
            "node_name": self.node_name,
            "rsc_flags": self.flags,
            "props": [{"key": x, "value": v} for x, v in self.properties.items()],
            "vlms": [x.data_v0 for x in self.volumes]
        }


class ResourceResponse(RESTMessageResponse):
    def __init__(self, rest_data):
        super(ResourceResponse, self).__init__(rest_data)

    @property
    def resources(self):
        """
        Return resource list from controller.
        :return: List of resources
        :rtype: list[Resource]
        """
        return list(Resource(x) for x in self._rest_data)

    @property
    def nodes(self):
        """
        List of node names, the resource is deployed
        :return:
        :rtype: list[str]
        """
        return [x["node_name"] for x in self._rest_data]

    @property
    def resource_states(self):
        """

        :return:
        :rtype: list[ResourceState]
        """
        return [ResourceState({
            "rsc_name": x["name"],
            "node_name": x["node_name"],
            "in_use": x.get("state", {}).get("in_use"),
            "vlm_states": [{
                "vlm_nr": y["volume_number"],
                "disk_state": y.get("state", {}).get("disk_state")
            } for y in x.get("volumes", [])]
        }) for x in self._rest_data]

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


class ResourceConnection(RESTMessageResponse):
    def __init__(self, data):
        super(ResourceConnection, self).__init__(data)

    @property
    def node_a(self):
        return self._rest_data["node_a"]

    @property
    def node_b(self):
        return self._rest_data["node_b"]

    @property
    def flags(self):
        return self._rest_data.get("flags", [])

    @property
    def properties(self):
        return self._rest_data.get("props", {})

    @property
    def port(self):
        return self._rest_data.get("port")

    @property
    def data_v0(self):
        d = {
            "node_name_1": self.node_a,
            "node_name_2": self.node_b
        }
        if self.flags:
            d["flags"] = self.flags
        if self.properties:
            d["props"] = [{"key": x, "value": v} for x, v in self.properties.items()]
        if self.port is not None:
            d["port"] = self.port
        return d


class ResourceConnectionsResponse(RESTMessageResponse):
    def __init__(self, data):
        super(ResourceConnectionsResponse, self).__init__(data)

    @property
    def resource_connections(self):
        return [ResourceConnection(x) for x in self._rest_data]

    @property
    def data_v0(self):
        d = {}
        if self.resource_connections:
            d["rsc_connections"] = [x.data_v0 for x in self.resource_connections]
        return d


class SnapshotVolumeDefinition(RESTMessageResponse):
    def __init__(self, data):
        super(SnapshotVolumeDefinition, self).__init__(data)

    @property
    def number(self):
        return self._rest_data["volume_number"]

    @property
    def size(self):
        return self._rest_data["size_kib"]

    @property
    def data_v0(self):
        return {
            "vlm_nr": self.number,
            "vlm_size": self.size
        }


class Snapshot(RESTMessageResponse):
    def __init__(self, data):
        super(Snapshot, self).__init__(data)

    @property
    def name(self):
        return self._rest_data.get("snapshot_name")

    @property
    def node_name(self):
        return self._rest_data.get("node_name")

    @property
    def flags(self):
        """
        Resource flags as string list.

        :return: Resource definition flags as string list
        :rtype: list[str]
        """
        return self._rest_data.get("flags", [])

    @property
    def create_datetime(self):
        """

        :return: Creation datetime of this resource
        :rtype: Optional[datetime]
        """
        if "create_timestamp" in self._rest_data:
            return datetime.fromtimestamp(self._rest_data["create_timestamp"]/1000)
        return None

    @property
    def uuid(self):
        return self._rest_data.get("uuid")


class SnapshotDefinition(RESTMessageResponse):
    def __init__(self, data):
        super(SnapshotDefinition, self).__init__(data)

    @property
    def name(self):
        return self._rest_data["name"]

    @property
    def uuid(self):
        return self._rest_data.get("uuid")

    @property
    def snapshot_name(self):
        return self.name

    @property
    def resource_name(self):
        return self._rest_data["resource_name"]

    @property
    def rsc_name(self):
        return self.resource_name

    @property
    def nodes(self):
        """
        Node name list this snapshot is deployed.
        :return:
        :rtype: list[str]
        """
        return self._rest_data["nodes"]

    @property
    def flags(self):
        return self._rest_data.get("flags", [])

    @property
    def snapshot_volume_definitions(self):
        return [SnapshotVolumeDefinition(x) for x in self._rest_data.get("volume_definitions", [])]

    @property
    def snapshots(self):
        return [Snapshot(x) for x in self._rest_data.get("snapshots", [])]

    @property
    def data_v0(self):
        return {
            "rsc_name": self.resource_name,
            "snapshot_name": self.snapshot_name,
            "uuid": self.uuid,
            "snapshot_dfn_flags": self.flags,
            "snapshots": [{"node_name": n} for n in self.nodes],
            "snapshot_vlm_dfns": [x.data_v0 for x in self.snapshot_volume_definitions]
        }


class SnapshotResponse(RESTMessageResponse):
    def __init__(self, data):
        super(SnapshotResponse, self).__init__(data)

    @property
    def snapshots(self):
        """
        Returns snapshot list
        :return:
        :rtype: list[SnapshotDefinition]
        """
        return [SnapshotDefinition(x) for x in self._rest_data]

    @property
    def data_v0(self):
        d = {}
        if self.snapshots:
            d["snapshot_dfns"] = [x.data_v0 for x in self.snapshots]
        return d


class Shipping(RESTMessageResponse):
    def __init__(self, data):
        super(Shipping, self).__init__(data)

    @property
    def snapshot_dfn(self):
        """
        Return the SnapshotDefinition object of the shipping
        :return: SnapshotDefinition object of ths shipping
        :rtype: SnapshotDefinition
        """
        return SnapshotDefinition(self._rest_data["snapshot"])

    @property
    def from_node_name(self):
        """
        Source node of the shipping
        :return: source node name
        :rtype: str
        """
        return self._rest_data["from_node_name"]

    @property
    def to_node_name(self):
        """
        Target node of the shipping
        :return: target node name
        :rtype: str
        """
        return self._rest_data["to_node_name"]

    @property
    def status(self):
        """
        Status of the shipping
        :return: status of the shipping
        :rtype: apiconsts.SnapshotShipStatus
        """
        return apiconsts.SnapshotShipStatus(self._rest_data["status"])


class SnapshotShippingResponse(RESTMessageResponse):
    def __init__(self, data):
        super(SnapshotShippingResponse, self).__init__(data)

    @property
    def shippings(self):
        """
        Returns snapshot shipping list
        :return:
        :rtype: list[Shipping]
        """
        return [Shipping(x) for x in self._rest_data]


class ControllerProperties(RESTMessageResponse):
    def __init__(self, data):
        super(ControllerProperties, self).__init__(data)

    @property
    def properties(self):
        return self._rest_data


class StoragePoolDefinition(RESTMessageResponse):
    def __init__(self, data):
        super(StoragePoolDefinition, self).__init__(data)

    @property
    def name(self):
        return self._rest_data["storage_pool_name"]

    @property
    def properties(self):
        return self._rest_data.get("props", {})

    @property
    def data_v0(self):
        d = {
            "stor_pool_name": self.name
        }

        if self.properties:
            d["props"] = [{"key": x, "value": v} for x, v in self.properties.items()]

        return d


class StoragePoolDefinitionResponse(RESTMessageResponse):
    def __init__(self, data):
        super(StoragePoolDefinitionResponse, self).__init__(data)

    @property
    def storage_pool_definitions(self):
        return [StoragePoolDefinition(x) for x in self._rest_data]

    @property
    def data_v0(self):
        d = {}
        if self.storage_pool_definitions:
            d["stor_pool_dfns"] = [x.data_v0 for x in self.storage_pool_definitions]
        return d


class Candidate(RESTMessageResponse):
    def __init__(self, data):
        super(Candidate, self).__init__(data)

    @property
    def max_volume_size(self):
        return self._rest_data["max_volume_size_kib"]

    @property
    def storage_pool(self):
        return self._rest_data["storage_pool"]

    @property
    def node_names(self):
        return self._rest_data.get("node_names", [])

    @property
    def all_thin(self):
        return self._rest_data["all_thin"]


class MaxVolumeSizeResponse(RESTMessageResponse):
    def __init__(self, data):
        super(MaxVolumeSizeResponse, self).__init__(data)

    @property
    def candidates(self):
        """

        :return:
        :rtype: list[Candidates]
        """
        return [Candidate(x) for x in self._rest_data.get("candidates", [])]

    @property
    def default_max_oversubscription_ratio(self):
        return self._rest_data["default_max_oversubscription_ratio"]


class ControllerVersion(RESTMessageResponse):
    def __init__(self, data):
        super(ControllerVersion, self).__init__(data)

    @property
    def version(self):
        return self._rest_data["version"]

    @property
    def git_hash(self):
        return self._rest_data.get("git_hash")

    @property
    def build_time(self):
        return self._rest_data["build_time"]

    @property
    def rest_api_version(self):
        return self._rest_data.get("rest_api_version", "1.0.0")


class NodeStorageEntry(RESTMessageResponse):
    def __init__(self, data):
        super(NodeStorageEntry, self).__init__(data)

    @property
    def device(self):
        return self._rest_data["device"]

    @property
    def model(self):
        return self._rest_data.get("model")

    @property
    def serial(self):
        return self._rest_data.get("serial")

    @property
    def wwn(self):
        return self._rest_data.get("wwn")


class PhysicalDevice(RESTMessageResponse):
    def __init__(self, data):
        super(PhysicalDevice, self).__init__(data)

    @property
    def size(self):
        return self._rest_data["size"]

    @property
    def rotational(self):
        return self._rest_data["rotational"]

    @property
    def nodes(self):
        """
        Returns a node map
        :return:
        :rtype: Dict[str, List[NodeStorageEntry]]
        """
        return {key: [NodeStorageEntry(x) for x in value] for key, value in self._rest_data.get("nodes", {}).items()}


class PhysicalStorageList(RESTMessageResponse):
    def __init__(self, data):
        super(PhysicalStorageList, self).__init__(data)

    @property
    def physical_devices(self):
        return [PhysicalDevice(x) for x in self._rest_data]


class SpaceReport(RESTMessageResponse):
    def __init__(self, data):
        super(SpaceReport, self).__init__(data)

    @property
    def report(self):
        return self._rest_data["reportText"]


class ExosDefaults(RESTMessageResponse):
    def __init__(self, rest_data):
        super(ExosDefaults, self).__init__(rest_data)

    @property
    def username(self):
        return self._rest_data.get("username")

    @property
    def username_env(self):
        return self._rest_data.get("username_env")

    @property
    def password(self):
        return self._rest_data.get("password")

    @property
    def password_env(self):
        return self._rest_data.get("password_env")


class ExosEnclosure(RESTMessageResponse):
    def __init__(self, rest_data):
        super(ExosEnclosure, self).__init__(rest_data)

    @property
    def name(self):
        return self._rest_data["name"]

    @property
    def ctrl_a_ip(self):
        return self._rest_data.get("ctrl_a_ip")

    @property
    def ctrl_b_ip(self):
        return self._rest_data.get("ctrl_b_ip")

    @property
    def health(self):
        return self._rest_data["health"]

    @property
    def health_reason(self):
        return self._rest_data.get("health_reason")


class ExosListResponse(RESTMessageResponse):
    def __init__(self, rest_data):
        super(ExosListResponse, self).__init__(rest_data)

    @property
    def exos_enclosures(self):
        """
        Returns a list with all EXOS enclosures.

        :return: The enclosure list.
        :rtype: list[ExosEnclosure]
        """
        return [ExosEnclosure(x) for x in self._rest_data]

    def exos_enclosure(self, encl_name):
        """
        Returns the specified enclosure from the list of enclosures.

        :param str encl_name: EXOS enclosure name
        :return: ExosEnclosure object of the enclosure, or None
        :rtype: ExosEnclosure
        """
        for encl in self.exos_enclosures:
            if encl.name == encl_name:
                return encl
        return None


class ExosEnclosureEvent(RESTMessageResponse):
    def __init__(self, rest_data):
        super(ExosEnclosureEvent, self).__init__(rest_data)

    @property
    def severity(self):
        return self._rest_data["severity"]

    @property
    def event_id(self):
        return self._rest_data["event_id"]

    @property
    def controller(self):
        return self._rest_data["controller"]

    @property
    def time_stamp(self):
        return self._rest_data["time_stamp"]

    @property
    def time_stamp_numeric(self):
        return self._rest_data["time_stamp_numeric"]

    @property
    def message(self):
        return self._rest_data["message"]

    @property
    def additional_information(self):
        return self._rest_data["additional_information"]

    @property
    def recommended_action(self):
        return self._rest_data["recommended_action"]


class ExosEnclosureEventListResponse(RESTMessageResponse):
    def __init__(self, rest_data):
        super(ExosEnclosureEventListResponse, self).__init__(rest_data)

    @property
    def exos_events(self):
        """
        Returns a list with the most current EXOS events.

        :return: The event list.
        :rtype: list[ExosEnclosureEvent]
        """
        return [ExosEnclosureEvent(x) for x in self._rest_data]


class ExosExecResponse(RESTMessageResponse):
    def __init__(self, rest_data):
        super(ExosExecResponse, self).__init__(rest_data)


class ExosMapResponse(RESTMessageResponse):
    def __init__(self, rest_data):
        super(ExosMapResponse, self).__init__(rest_data)

    @property
    def node_name(self):
        return self._rest_data['node_name']

    @property
    def enclosure_name(self):
        return self._rest_data['enclosure_name']

    @property
    def connections(self):
        return self._rest_data['connections']


class ExosMapListResponse(RESTMessageResponse):
    def __init__(self, rest_data):
        super(ExosMapListResponse, self).__init__(rest_data)

    @property
    def exos_connections(self):
        """
        Returns a list with currently active Linstor node <-> EXOS
        controller connections.

        :return: The map list.
        :rtype: list[ExosMapResponse]
        """
        return [ExosMapResponse(x) for x in self._rest_data]
