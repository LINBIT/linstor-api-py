"""
Resource module
"""

import socket
import sys
from functools import wraps

import linstor.linstorapi
from linstor.sharedconsts import FAIL_EXISTS_RSC, FLAG_DISKLESS
from linstor.responses import ResourceDefinitionResponse, ResourceResponse
from linstor.linstorapi import Linstor

PYTHON2 = True
if sys.version_info > (3, 0):
    PYTHON2 = False
    unicode = str


class _Utils(object):
    @classmethod
    def to_unicode(cls, t):
        if isinstance(t, str):
            if PYTHON2:
                return unicode(t, 'UTF-8')
            else:
                return t
        elif isinstance(t, unicode):
            return t
        else:
            if PYTHON2:
                return unicode(t)
            else:
                return str(t)


class _Client(object):
    def __init__(self, uris, timeout=300, keep_alive=False):
        # external properties
        self._uri_list = linstor.MultiLinstor.controller_uri_list(uris)  # type: list[str]
        self.timeout = timeout
        self.keep_alive = keep_alive

    @property
    def uri_list(self):
        return self._uri_list

    @uri_list.setter
    def uri_list(self, uri_list):
        raise linstor.LinstorReadOnlyAfterSetError()


class _Placement(object):
    def __init__(self, redundancy=None):
        self.redundancy = redundancy
        self.storage_pool = None
        self.diskless_storage_pool = None
        self.diskless_on_remaining = False


class Volume(object):
    """
    Volume class represents a DRBD Volume.

    This object contains important properties of a Volume, including
    e.g: ``size``, and ``device_path``

    :param size: String parsable by linstor.SizeCalc or size in bytes.
    """
    def __init__(self, size):
        # external properties
        self._size = self._size_to_bytes(size)
        self._minor = None
        self._device_path = ''
        self._storage_pool_name = ''

        # internal
        self._volume_id = None
        self._rsc_name = None
        self._client_ref = None  # type: Optional[linstor.Linstor]
        self._assignments = []

    def __repr__(self):
        return "Volume({n}, {nr}, {s}kib, {m})".format(
            n=self._rsc_name, nr=self._volume_id, s=self._size, m=self._minor
        )

    @property
    def storage_pool_name(self):
        return self._storage_pool_name

    @property
    def device_path(self):
        """
        Returns the device path of a Volume (e.g., /dev/drbd1000).

        :return: The device path of a Volume.
        :rtype: str
        """
        return self._device_path

    @device_path.setter
    def device_path(self, device_path):
        raise linstor.LinstorReadOnlyAfterSetError('This is a read-only property')

    @property
    def minor(self):
        """
        Returns the minor number of a Volume (e.g., 1000).

        :return: The minor number of a Volume.
        :rtype: int
        """
        return self._minor

    @minor.setter
    def minor(self, minor):
        if self._rsc_name is not None:
            raise linstor.LinstorReadOnlyAfterSetError()
        self._minor = minor

    @property
    def size(self):
        """
        Returns the size of a Volume (e.g., 1000000).

        Setting tye size of a volume that is deployed triggers a resize operation.

        :return: The size of a Volume in bytes.
        :rtype: int
        """
        return self._size

    @classmethod
    def _size_to_bytes(cls, size):
        if isinstance(size, str):
            return linstor.SizeCalc.auto_convert(size, linstor.SizeCalc.UNIT_B)
        return size

    @size.setter
    def size(self, size):  # this has to be an int, otherwise python complains
        size = self._size_to_bytes(size)
        if self._size is not None \
           and self._rsc_name is not None \
           and self._volume_id is not None:
            r, v = self._rsc_name, self._volume_id
            if self._size > size:
                raise ValueError('shrinking Resource/Volume {}/{} from {} to {} is not allowed'
                                 .format(r, v, self._size, size))

            size_kib = linstor.SizeCalc.convert_round_up(size, linstor.SizeCalc.UNIT_B,
                                                         linstor.SizeCalc.UNIT_KiB)
            with self._client_ref as lin:
                rs = lin.volume_dfn_modify(r, v, size=size_kib)
                if not linstor.Linstor.all_api_responses_no_error(rs):
                    raise linstor.LinstorError('Could not resize Resource/Volume {}/{}: {}'
                                               .format(r, v, Linstor.filter_api_call_response_errors(rs)[0]))

        # if we are here everything is fine
        self._size = size

    # called from VolumeDict
    def _delete(self):
        if self._rsc_name is None:  # this volume was created, but never deployed, no linstor action.
            return
        with self._client_ref as lin:
            r, v = self._rsc_name, self._volume_id
            rs = lin.volume_dfn_delete(r, v)
            if not linstor.Linstor.all_api_responses_no_error(rs):
                raise linstor.LinstorError('Could not delete Resource/Volume {}/{}: {}'.format(
                    r, v, Linstor.filter_api_call_response_errors(rs)[0]))


class _VolumeDict(dict):
    def __init__(self):
        super(_VolumeDict, self).__init__()

    def __setitem__(self, k, v):
        if not isinstance(v, Volume):
            raise ValueError('{} is not of an instance of Volume'.format(v))
        v._volume_id = k
        super(_VolumeDict, self).__setitem__(k, v)

    def __delitem__(self, k):
        self[k]._delete()
        super(_VolumeDict, self).__delitem__(k)


class Resource(object):
    """
    Resource class represents a DRBD Resource.

    This object allows managing existing DRBD Resources as well as creating new ones.

    :param str name: The name of the DRBD resource.
    :param str uri: A list of controller addresses.
     e.g: ``linstor://localhost,10.0.0.2``, ``linstor+ssl://localhost,linstor://192.168.0.1``
    :param linstor.Linstor existing_client: Instead of creating  a new client based on the controller addresses,
     use this pre-configured client object.
    """
    def _update_volumes(f):
        @wraps(f)
        def wrapper(self, *args, **kwargs):
            ret = None
            with self._get_connection() as lin:
                self._lin = lin
                self._maybe_create_rd_and_vd()
                ret = f(self, *args, **kwargs)
                self.__update_volumes()
            self._lin = None
            return ret
        return wrapper

    def __init__(self, name, uri='linstor://localhost', existing_client=None):
        # external properties
        self._name = name  # the user facing name, what linstor calls the "external name"
        self._port = None
        self._resource_group_name = None  # type: Optional[str]
        self.client = _Client(uri)
        self.placement = _Placement()
        self.volumes = _VolumeDict()  # type: dict[int, Volume]
        self.defined = False

        # THINK(rck): maybe a dict, KISS for now
        self._allow_two_primaries = False

        # internal
        self._assignments = {}
        self._linstor_name = None
        self._existing_client = existing_client

        with self._get_connection() as lin:
            self._lin = lin
            self.__update_volumes()

    def __str__(self):
        return '{e}({i})'.format(e=self._name, i=self._linstor_name)

    def __repr__(self):
        return "Resource({n}, {h})".format(n=self, h=self.client.uri_list)

    @classmethod
    def from_resource_group(cls, uri, resource_group_name, resource_name, vlm_sizes,
                            timeout=300, keep_alive=False, definitions_only=False, existing_client=None):
        """
        Spawns a new resource definition from the given resource group.

        :param str uri: A list of controller addresses.
         e.g: ``linstor://localhost,10.0.0.2``, ``linstor+ssl://localhost,linstor://192.168.0.1``
        :param str resource_group_name: Name of the resource group
        :param str resource_name: Name of the new resource definition
        :param list[str] vlm_sizes: String list of volume sizes e.g. ['128Mib', '1G']
        :param int timeout: client library timeout
        :param bool keep_alive: keep client connection alive
        :param bool definitions_only: only spawn definitions
        :param linstor.Linstor existing_client: Client to associate with the resource
        :return: linstor.resource.Resource object of the newly created resource definition
        :rtype: linstor.resource.Resource
        """
        if existing_client:
            client = existing_client
        else:
            c = _Client(uri)
            client = linstor.MultiLinstor(c.uri_list, timeout, keep_alive)

        with client as lin:
            result = lin.resource_group_spawn(
                resource_group_name,
                resource_name,
                vlm_sizes,
                definitions_only=definitions_only
            )
            if not linstor.Linstor.all_api_responses_no_error(result):
                raise linstor.LinstorError(
                    'Could not spawn resource "{}" from resource group "{}": {}'.format(
                        resource_name,
                        resource_group_name,
                        Linstor.filter_api_call_response_errors(result)[0].message
                    )
                )

            return Resource(resource_name, uri=uri, existing_client=existing_client)
        return None

    def _get_connection(self):
        if self._existing_client:
            return self._existing_client
        return linstor.MultiLinstor(self.client.uri_list, self.client.timeout, self.client.keep_alive)

    def _set_properties(self):
        dp = 'yes' if self._allow_two_primaries else 'no'
        props = {'DrbdOptions/Net/allow-two-primaries': dp}
        rs = self._lin.resource_dfn_modify(self._linstor_name, props, delete_props=None)
        if not linstor.Linstor.all_api_responses_no_error(rs):
            raise linstor.LinstorError('Could not set DRBD properties for resource {}: {}'
                                       .format(self, Linstor.filter_api_call_response_errors(rs)[0]))

    def _maybe_create_rd_and_vd(self):
        # resource definition
        if not self.defined:
            rs = self._lin.resource_dfn_create("", self._port, external_name=self._name)
            if not linstor.Linstor.all_api_responses_no_error(rs):
                raise linstor.LinstorError('Could not create resource definition {}: {}'
                                           .format(self, Linstor.filter_api_call_response_errors(rs)[0]))
            ors = rs[0].object_refs
            try:
                self._linstor_name = ors['RscDfn']
            except KeyError:
                raise linstor.LinstorError('Could not get RscDfn for resource definition {}'
                                           .format(self))

            self.defined = True
            self._set_properties()

        # volume definitions
        self._create_volume_definitions()

    def _create_volume_definitions(self):
        for k, v in self.volumes.items():
            if v._rsc_name is None:
                size_kib = linstor.SizeCalc.convert_round_up(v.size, linstor.SizeCalc.UNIT_B,
                                                             linstor.SizeCalc.UNIT_KiB)
                rs = self._lin.volume_dfn_create(self._linstor_name, size_kib, k, v._minor,
                                                 encrypt=False, storage_pool=self.placement.storage_pool)
                if not linstor.Linstor.all_api_responses_no_error(rs):
                    raise linstor.LinstorError('Could not create volume definition {n}/{k}: {e}'
                                               .format(n=self, k=k, e=Linstor.filter_api_call_response_errors(rs)[0]))
                self.volumes[k]._rsc_name = self._linstor_name

    def __update_volumes(self):
        # create fresh volume definitions
        self._create_volume_definitions()

        # update internal state
        rsc_dfn_list_replies = self._lin.resource_dfn_list()
        if not rsc_dfn_list_replies or not rsc_dfn_list_replies[0]:
            return True

        rsc_dfn_list_reply = rsc_dfn_list_replies[0]  # type: ResourceDefinitionResponse
        for rsc_dfn in rsc_dfn_list_reply.resource_definitions:
            # WORKAROUND: linstor-server < 0.9.9 did not set the external_name, so for compat
            # and as these only used non external names, fall back to the name
            to_cmp = rsc_dfn.external_name if rsc_dfn.external_name != "" else rsc_dfn.name
            if _Utils.to_unicode(to_cmp) == _Utils.to_unicode(self._name):
                self._linstor_name = rsc_dfn.name
                self._resource_group_name = rsc_dfn.resource_group_name
                self.defined = True
                for vlm_dfn in rsc_dfn.volume_definitions:
                    vlm_nr = vlm_dfn.number
                    if not self.volumes.get(vlm_nr):
                        self.volumes[vlm_nr] = Volume(None)
                    self.volumes[vlm_nr]._volume_id = vlm_nr
                    self.volumes[vlm_nr]._rsc_name = self._linstor_name
                    self.volumes[vlm_nr]._client_ref = self._get_connection()
                    size_b = linstor.SizeCalc.convert_round_up(vlm_dfn.size, linstor.SizeCalc.UNIT_KiB,
                                                               linstor.SizeCalc.UNIT_B)
                    self.volumes[vlm_nr]._size = size_b
                    if vlm_dfn.drbd_data is not None:
                        self.volumes[vlm_nr]._minor = vlm_dfn.drbd_data.minor
                for key, value in rsc_dfn.properties.items():
                    if key == 'DrbdOptions/Net/allow-two-primaries':
                        self._allow_two_primaries = True if value == 'yes' else False

        if self._linstor_name is None:
            return True

        rsc_list_replies = self._lin.resource_list(filter_by_nodes=None,
                                                   filter_by_resources=[self._linstor_name])
        if not rsc_list_replies or not rsc_list_replies[0]:
            return True

        self._assignments = {}
        rsc_list_reply = rsc_list_replies[0]  # type: ResourceResponse
        for rsc in rsc_list_reply.resources:
            is_diskless = (FLAG_DISKLESS in rsc.flags)
            node_name = rsc.node_name
            self._assignments[node_name] = is_diskless
            for vlm in rsc.volumes:
                vlm_nr = vlm.number
                if vlm.device_path:
                    self.volumes[vlm_nr]._device_path = vlm.device_path
                if vlm.storage_pool_name and not is_diskless:
                    self.volumes[vlm_nr]._storage_pool_name = vlm.storage_pool_name
                if vlm.drbd_data is not None:
                    self.volumes[vlm_nr]._minor = vlm.drbd_data.drbd_volume_definition.minor

        return True

    @property
    def allow_two_primaries(self):
        """
        Returns the value of the DRBD net-option 'allow-two-primaries'.

        :return: The value of the DRBD net-option 'allow-two-primaries'. Raises LinstorError in case of error.
        :rtype: bool
        """
        return self._allow_two_primaries

    @allow_two_primaries.setter
    def allow_two_primaries(self, value):
        if self._allow_two_primaries == value:
            return

        self._allow_two_primaries = value
        if self.defined:
            with self._get_connection() as lin:
                self._lin = lin
                self._set_properties()

    @property
    def name(self):
        """
        Returns the external/user facing name of the Resource.

        :return: The external/user facing name of the Resource.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        if self.defined:
            raise linstor.LinstorReadOnlyAfterSetError()
        self._name = name

    @property
    def linstor_name(self):
        """
        Returns the internal/linstor/DRBD name of the Resource.

        :return: The internal/linstor/DRBD name of the Resource.
        :rtype: str
        """
        return self._linstor_name

    @linstor_name.setter
    def linstor_name(self, name):
        raise linstor.LinstorReadOnlyAfterSetError()

    @property
    def port(self):
        """
        Returns the port of the Resource.

        :return: The port of the Resource.
        :rtype: str
        """
        return self._port

    @port.setter
    def port(self, port_nr):
        if self.defined:
            raise linstor.LinstorReadOnlyAfterSetError()
        self._port = port_nr

    @property
    def resource_group_name(self):
        return self._resource_group_name

    @_update_volumes
    def autoplace(self):
        """
        Automatically place the Resource according to values set in the placement policy.

        Example:
            To autoplace a Resource 'foo' 3 times redundant on the storage pool 'drbdpool' one would::

                $ foo.placement.redundancy = 3
                $ foo.placement.storage_pool = 'drbdpool'
                $ foo.autoplace()

        :return: True if success, else raises LinstorError
        """
        rs = self._lin.resource_auto_place(
            self._linstor_name,
            self.placement.redundancy,
            self.placement.storage_pool,
            do_not_place_with=None,
            do_not_place_with_regex=None,
            replicas_on_same=None,
            replicas_on_different=None,
            diskless_on_remaining=self.placement.diskless_on_remaining)

        if not Linstor.all_api_responses_no_error(rs):
            raise linstor.LinstorError('Could not autoplace resource {}: {}'
                                       .format(self, Linstor.filter_api_call_response_errors(rs)[0]))
        return True

    @_update_volumes
    def activate(self, node_name):
        """
        Makes a resource available at a given host.

        If the host already contains a diskful assignment, this is a NOOP. Otherwise a diskless assignment is
        created.

        :param str node_name: Name of the node
        :return: True if success, else raises LinstorError
        """
        rsc_create_replies = self._lin.resource_create([
            linstor.ResourceData(
                node_name,
                self._linstor_name,
                diskless=True
            )
        ])

        if Linstor.all_api_responses_no_error(rsc_create_replies):
            return True
        else:
            error_replies = Linstor.filter_api_call_response_errors(rsc_create_replies)
            if len(error_replies) == 1 and error_replies[0].is_error(code=FAIL_EXISTS_RSC):
                return True

        raise linstor.LinstorError('Could not activate resource {} on node {}: {}'
                                   .format(self, node_name, ";".join([str(x) for x in rsc_create_replies])))

    # no decorator, calles delete
    def deactivate(self, node_name):
        """
        Deactivates a resource on a host if possible.

        If the assignment is diskless, delete this assignment. If it is diskful and therefore part of the
        given redundany, this is a NOOP (i.e., the redundancy is not decreased).

        :param str node_name: Name of the node
        :return: True if success, else raises LinstorError
        """
        if self.is_diskless(node_name):
            return self.delete(node_name)
        return True

    @_update_volumes
    def _create_or_toggle(self, node_name, diskless):
        is_assigned = self.is_assigned(node_name)
        is_diskless = self.is_diskless(node_name)
        sp = self.placement.diskless_storage_pool
        if is_diskless or (not is_assigned and not diskless):
            sp = self.placement.storage_pool

        if not is_assigned:
            rs = self._lin.resource_create([
                linstor.ResourceData(
                    node_name,
                    self._linstor_name,
                    diskless=diskless,
                    storage_pool=sp
                )
            ])
            if not Linstor.all_api_responses_no_error(rs):
                raise linstor.LinstorError(
                    'Could not create resource {} on node {} as diskless={}: {}'
                    .format(self, node_name, diskless, Linstor.filter_api_call_response_errors(rs)[0]))
        elif is_diskless != diskless:
            rs = self._lin.resource_toggle_disk(node_name, self._linstor_name,
                                                diskless=diskless, storage_pool=sp)
            if not Linstor.all_api_responses_no_error(rs):
                raise linstor.LinstorError(
                    'Could not toggle disk for resource {} on node {} to diskless={}: {}'
                    .format(self, node_name, diskless, Linstor.filter_api_call_response_errors(rs)[0]))
        return True

    def snapshot_create(self, name):
        """
        Creates a new snapshot for the resource.

        :param str name: Name of the snapshot
        :return: True if success, else raises LinstorError
        """
        if self._linstor_name is None:
            raise linstor.LinstorError("Resource '{n}' doesn't exist.".format(n=self.name))

        with self._get_connection() as lin:
            rs = lin.snapshot_create(node_names=[], rsc_name=self._linstor_name, snapshot_name=name, async_msg=False)
            if not Linstor.all_api_responses_no_error(rs):
                raise linstor.LinstorError('Could not create snapshot {}: {}'
                                           .format(name, Linstor.filter_api_call_response_errors(rs)[0].message))
        return True

    def snapshot_delete(self, name):
        """
        Deletes a given snapshot of this resource.

        :param str name: Name of the snapshot
        :return: True if success, else raises LinstorError
        """
        if self._linstor_name is None:
            raise linstor.LinstorError("Resource '{n}' doesn't exist.".format(n=self.name))

        with self._get_connection() as lin:
            rs = lin.snapshot_delete(rsc_name=self._linstor_name, snapshot_name=name)
            if not Linstor.all_api_responses_no_error(rs):
                raise linstor.LinstorError('Could not delete snapshot {}: {}'.format(
                    name,
                    Linstor.filter_api_call_response_errors(rs)[0].message))
        return True

    def snapshot_rollback(self, name):
        """
        Rolls resource data back to snapshot state. The resource must not be in use.
        The snapshot will not be removed and can be used for subsequent rollbacks.
        Only the most recent snapshot may be used; to roll back to an earlier
        snapshot, the intermediate snapshots must first be deleted.

        :param str name: Name of the snapshot
        :return: True if success, else raises LinstorError
        """
        if self._linstor_name is None:
            raise linstor.LinstorError("Resource '{n}' doesn't exist.".format(n=self.name))

        with self._get_connection() as lin:
            rs = lin.snapshot_rollback(rsc_name=self._linstor_name, snapshot_name=name)
            if not Linstor.all_api_responses_no_error(rs):
                raise linstor.LinstorError('Could not rollback to snapshot {}: {}'.format(
                    name,
                    Linstor.filter_api_call_response_errors(rs)[0].message)
                )
        return True

    def restore_from_snapshot(self, snapshot_name, resource_name_to):
        """
        Restores a new resource from a snapshot.

        :param snapshot_name: Snapshot name to use for restoration.
        :param resource_name_to: Name of the new resource.
        :return: A new resource object restored from the snapshot.
        :rtype: linstor.resource.Resource
        """
        if self._linstor_name is None:
            raise linstor.LinstorError("Resource '{n}' doesn't exist.".format(n=self.name))

        with self._get_connection() as lin:
            rs = lin.resource_dfn_create(resource_name_to, resource_group=self.resource_group_name)
            if not Linstor.all_api_responses_no_error(rs):
                raise linstor.LinstorError(
                    "Could not resource definition '{r}' for snapshot restore: {err}"
                    .format(r=resource_name_to, err=Linstor.filter_api_call_response_errors(rs)[0].message))

            rs = lin.snapshot_volume_definition_restore(
                from_resource=self._linstor_name,
                from_snapshot=snapshot_name,
                to_resource=resource_name_to
            )

            if not Linstor.all_api_responses_no_error(rs):
                raise linstor.LinstorError(
                    "Could not restore volume definition '{rd}' from snapshot {sn} to resource definition '{tr}': {err}"
                    .format(
                        rd=self._linstor_name,
                        sn=snapshot_name,
                        tr=resource_name_to,
                        err=Linstor.filter_api_call_response_errors(rs)[0].message
                    )
                )

            rs = lin.snapshot_resource_restore(
                node_names=[],  # to all
                from_resource=self._linstor_name,
                from_snapshot=snapshot_name,
                to_resource=resource_name_to
            )

            if not Linstor.all_api_responses_no_error(rs):
                raise linstor.LinstorError(
                    "Could not restore resource '{rd}' from snapshot {sn} to resource definition '{tr}': {err}"
                    .format(
                        rd=self.name,
                        sn=snapshot_name,
                        tr=resource_name_to,
                        err=Linstor.filter_api_call_response_errors(rs)[0].message
                    )
                )

        return Resource(resource_name_to, ",".join(self.client.uri_list), existing_client=self._existing_client)

    def diskless(self, node_name):
        """
        Assign a resource diskless on a given node.

        If the assignment does not exist, create it diskless. If the assignment is already diskless, this is a
        NOOP. If it exists diskful, convert it to diskless.

        :param str node_name: Name of the node
        :return: True if success, else raises LinstorError
        """
        return self._create_or_toggle(node_name, True)

    def diskful(self, node_name):
        """
        Assign a resource diskful on a given node.

        If the assignment does not exist, create it diskful. If the assignment is already diskful, this is a
        NOOP. If it exists diskless, convert it to diskful.

        :param str node_name: Name of the node
        :return: True if success, else raises LinstorError
        """
        return self._create_or_toggle(node_name, False)

    def is_diskless(self, node_name):
        """
        Returns True if the resource is assigned diskless on the given host.

        :param str node_name: Name of the node
        :return: True if assigned diskless on given host.
        :rtype: bool
        """
        return self._assignments.get(node_name, False)

    def is_diskful(self, node_name):
        """
        Returns True if the resource is assigned diskful on the given host.

        :param str node_name: Name of the node
        :return: True if assigned diskful on given host.
        :rtype: bool
        """
        return not self._assignments.get(node_name, True)

    def is_assigned(self, node_name):
        """
        Returns True if the resource is assigned diskful or diskless on the given host.

        :param str node_name: Name of the node
        :return: True if assigned (diskful or diskless) on given host.
        :rtype: bool
        """
        return self.is_diskful(node_name) or self.is_diskless(node_name)

    def diskless_nodes(self):
        """
        Returns the host names of all diskless nodes.

        :return: Host names of diskless nodes.
        :rtype: list[str]
        """
        return [n for n in self._assignments.keys() if self.is_diskless(n)]

    def diskful_nodes(self):
        """
        Returns the host names of all diskful nodes.

        :return: Host names of diskful nodes.
        :rtype: list[str]
        """
        return [n for n in self._assignments.keys() if self.is_diskful(n)]

    def is_thin(self):
        """
        Returns if the used storage pool of the resource is thin.

        :return: True if storage pool used is thin.
        :rtype: bool
        """
        with self._get_connection() as lin:
            stor_pool_list = lin.storage_pool_list_raise(None, filter_by_stor_pools=[self.volumes[0].storage_pool_name])
            return stor_pool_list.storage_pools[0].is_thin()

    # no decorator! (could recreate)
    def _delete(self, node_name=None):
        reinit = False
        if node_name is None:
            node_name = 'ALL'  # for error msg
            rs = self._lin.resource_dfn_delete(self._linstor_name)
            reinit = True
            self.defined = False
        else:
            if not self.is_assigned(node_name):
                return True
            rs = self._lin.resource_delete(node_name, self._linstor_name)
            if socket.gethostname() == node_name:  # deleted on myself
                reinit = True

        if not Linstor.all_api_responses_no_error(rs):
            raise linstor.LinstorError('Could not delete resource {} on node {}: {}'
                                       .format(self, node_name, Linstor.filter_api_call_response_errors(rs)[0]))
        if reinit:
            self._volumes = _VolumeDict()

        return self.__update_volumes()

    # no decorator! (could recreate)
    def delete(self, node_name=None, snapshots=True):
        """
        Deletes the resource globally or on the given host.

        If the node name is None, deletes the resource globally.

        :param str node_name: Deletes resource only from the specified node.
        :param bool snapshots: If True deletes snapshots prior deleting the resource

        :return: True if success, else raises LinstorError
        """
        if self._linstor_name is None:
            return True  # resource doesn't exist

        with self._get_connection() as lin:
            self._lin = lin

            if snapshots and node_name is None:  # only remove snapshots if resource definition will be deleted
                snapshot_list = lin.snapshot_dfn_list()[0]  # type: linstor.responses.SnapshotResponse
                for snap in [x for x in snapshot_list.snapshots if x.rsc_name.lower() == self._linstor_name.lower()]:
                    lin.snapshot_delete(rsc_name=self._linstor_name, snapshot_name=snap.snapshot_name)

            return self._delete(node_name)

    def drbd_proxy_enable(self, node_name_a, node_name_b):
        if self._linstor_name is None:
            raise linstor.LinstorError("Resource '{n}' doesn't exist.".format(n=self.name))

        proxy_enable_replies = self._lin.drbd_proxy_enable(self._linstor_name, node_name_a, node_name_b)
        if not Linstor.all_api_responses_no_error(proxy_enable_replies):
            raise linstor.LinstorError(
                'Could not enable drbd-proxy for resource {} between {} and {}: {}'.format(
                    self,
                    node_name_a,
                    node_name_b,
                    Linstor.filter_api_call_response_errors(proxy_enable_replies)[0])
            )
        return True

    def drbd_proxy_disable(self, node_name_a, node_name_b):
        if self._linstor_name is None:
            raise linstor.LinstorError("Resource '{n}' doesn't exist.".format(n=self.name))

        proxy_disable_replies = self._lin.drbd_proxy_disable(self._linstor_name, node_name_a, node_name_b)
        if not Linstor.all_api_responses_no_error(proxy_disable_replies):
            raise linstor.LinstorError(
                'Could not disable drbd-proxy for resource {} between {} and {}: {}'.format(
                    self,
                    node_name_a,
                    node_name_b,
                    Linstor.filter_api_call_response_errors(proxy_disable_replies)
                )
            )
        return True
