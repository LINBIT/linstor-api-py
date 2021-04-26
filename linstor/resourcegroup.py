"""
ResourceGroup module
"""

import linstor.errors
from linstor.resource import _Client, Resource


class ResourceGroup(object):
    def __init__(self, name, uri='linstor://localhost', existing_client=None):
        self._name = name
        self._uri = uri
        self.client = _Client(uri)
        self._existing_client = existing_client

        self._description = None
        self._redundancy = None
        self._storage_pool_list = None
        self._do_not_place_with = None
        self._do_not_place_with_regex = None
        self._replicas_on_same = None
        self._replicas_on_different = None
        self._diskless_on_remaining = None
        self._layer_list = None
        self._provider_list = None
        self._property_dict = None

        self._nr_volumes = 0
        self._nr_volumes_default = 1

        self._update_or_create()

    def _get_connection(self):
        if self._existing_client:
            return self._existing_client
        return linstor.MultiLinstor(self.client.uri_list, self.client.timeout, self.client.keep_alive)

    @property
    def name(self):
        """
        Returns the name of the ResourceGroup

        :return: The name of a Resource Group.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        if self._name is not None:
            raise linstor.LinstorReadOnlyAfterSetError('This is a read-only property')
        self._name = name

    @property
    def description(self):
        """
        Returns the description of the ResourceGroup

        :return: The description of a Resource Group.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        self._description = description
        return self._modify_or_create("modify")

    @property
    def redundancy(self):
        """
        Returns the redundancy of the ResourceGroup

        :return: The redundancy of a Resource Group.
        :rtype: int
        """
        return self._redundancy

    @redundancy.setter
    def redundancy(self, redundancy):
        self._redundancy = redundancy
        return self._modify_or_create("modify")

    @property
    def storage_pool(self):
        """
        Returns the storage_pool of the ResourceGroup

        :return: The storage_pool of a Resource Group.
        :rtype: str|list[str]
        """
        return self._storage_pool_list

    @storage_pool.setter
    def storage_pool(self, storage_pool):
        self._storage_pool_list = storage_pool
        return self._modify_or_create("modify")

    @property
    def do_not_place_with(self):
        """
        Returns the do_not_place_with of the ResourceGroup

        :return: The do_not_place_with of a Resource Group.
        :rtype: list[str]
        """
        return self._do_not_place_with

    @do_not_place_with.setter
    def do_not_place_with(self, do_not_place_with):
        self._do_not_place_with = do_not_place_with
        return self._modify_or_create("modify")

    @property
    def do_not_place_with_regex(self):
        """
        Returns the do_not_place_with_regex of the ResourceGroup

        :return: The do_not_place_with_regex of a Resource Group.
        :rtype: str
        """
        return self._do_not_place_with_regex

    @do_not_place_with_regex.setter
    def do_not_place_with_regex(self, do_not_place_with_regex):
        self._do_not_place_with_regex = do_not_place_with_regex
        return self._modify_or_create("modify")

    @property
    def replicas_on_same(self):
        """
        Returns the replicas_on_same of the ResourceGroup

        :return: The replicas_on_same of a Resource Group.
        :rtype: list[str]
        """
        return self._replicas_on_same

    @replicas_on_same.setter
    def replicas_on_same(self, replicas_on_same):
        self._replicas_on_same = replicas_on_same
        return self._modify_or_create("modify")

    @property
    def replicas_on_different(self):
        """
        Returns the replicas_on_different of the ResourceGroup

        :return: The replicas_on_different of a Resource Group.
        :rtype: list[str]
        """
        return self._replicas_on_different

    @replicas_on_different.setter
    def replicas_on_different(self, replicas_on_different):
        self._replicas_on_different = replicas_on_different
        return self._modify_or_create("modify")

    @property
    def diskless_on_remaining(self):
        """
        Returns the diskless_on_remaining of the ResourceGroup

        :return: The diskless_on_remaining of a Resource Group.
        :rtype: bool
        """
        return self._diskless_on_remaining

    @diskless_on_remaining.setter
    def diskless_on_remaining(self, diskless_on_remaining):
        self._diskless_on_remaining = diskless_on_remaining
        return self._modify_or_create("modify")

    def _set_nr_volumes(self, nr_volumes):
        have = self._nr_volumes
        want = nr_volumes
        if have == want:
            return True

        if want < 1:
            raise linstor.LinstorError("A resource group needs at least one volume group")

        with self._get_connection() as lin:
            # inc/dec per interation to keep correct count if we fail in the middle
            if have < want:  # increase
                for v in range(have, want):
                    lin.volume_group_create(self._name, volume_nr=v)
                    self._nr_volumes += 1
            elif have > want:  # decrease
                for v in range(have, want, -1):
                    lin.volume_group_delete(self._name, v-1)
                    self._nr_volumes -= 1
            # else ==, done

        return True

    @property
    def nr_volumes(self):
        """
        Returns the number of volumes of the ResourceGroup

        :return: The number of volumes of a Resource Group.
        :rtype: int
        """
        return self._nr_volumes

    @nr_volumes.setter
    def nr_volumes(self, nr_volumes):
        return self._set_nr_volumes(nr_volumes)

    @property
    def layer_list(self):
        """
        Returns the layer list of the ResourceGroup

        :return: The layer list of a Resource Group.
        :rtype: list[str]
        """
        return self._layer_list

    @layer_list.setter
    def layer_list(self, layer_list):
        self._layer_list = layer_list
        return self._modify_or_create("modify")

    @property
    def provider_list(self):
        """
        Returns the provider list of the ResourceGroup

        :return: The provider list of a Resource Group.
        :rtype: list[str]
        """
        return self._provider_list

    @provider_list.setter
    def provider_list(self, provider_list):
        self._provider_list = provider_list
        return self._modify_or_create("modify")

    @property
    def property_dict(self):
        """
        Returns the property dict of the ResourceGroup

        :return: The property dict of a Resource Group.
        :rtype: dict[str, str]
        """
        return self._property_dict

    @property_dict.setter
    def property_dict(self, property_dict):
        self._property_dict = property_dict
        return self._modify_or_create("modify")

    def delete(self):
        """
        Deletes the ResourceGroup
        """
        with self._get_connection() as lin:
            lin.resource_group_delete(self._name)
        return True

    def create_resource(self, resource_name, vlm_sizes):
        """
        Create resource with values.

        :param str resource_name: Name of the resource to create.
        :param list[str] vlm_sizes: Volume definitions to spawn
        :return: Resource object of the newly created resource definition
        :rtype: linstor.resource.Resource
        """
        r = Resource.from_resource_group(self._uri, self._name, resource_name, vlm_sizes,
                                         timeout=self.client.timeout, keep_alive=self.client.keep_alive,
                                         existing_client=self._existing_client)
        r.client.keep_alive = self.client.keep_alive
        r.client.timeout = self.client.timeout
        return r

    def query_max_volume_size(self):
        """
        Queries maximum volume size from the given resource group and returns all possible candidates
        """
        with self._get_connection() as lin:
            return lin.resource_group_qmvs(self._name)

    def _modify_or_create(self, what="modify"):
        with self._get_connection() as lin:
            fn = None
            if what == "create":
                fn = lin.resource_group_create
            elif what == "modify":
                fn = lin.resource_group_modify

            fn(self._name,
               description=self._description,
               place_count=self._redundancy,
               storage_pool=self._storage_pool_list,
               do_not_place_with=self._do_not_place_with,
               do_not_place_with_regex=self._do_not_place_with_regex,
               replicas_on_same=self._replicas_on_same,
               replicas_on_different=self._replicas_on_different,
               diskless_on_remaining=self._diskless_on_remaining,
               layer_list=self._layer_list,
               provider_list=self._provider_list,
               property_dict=self._property_dict)

        return True

    def _update(self):
        with self._get_connection() as lin:
            rgs = lin.resource_group_list_raise(filter_by_resource_groups=[self._name]).resource_groups
            rg = rgs[0]
            self._name = rg.name
            self._description = rg.description
            sf = rg.select_filter
            self._redundancy = sf.place_count
            self._storage_pool_list = sf.storage_pool_list
            self._do_not_place_with = sf.not_place_with_rsc
            self._do_not_place_with_regex = sf.not_place_with_rsc_regex
            self._replicas_on_same = sf.replicas_on_same
            self._replicas_on_different = sf.replicas_on_different
            self._diskless_on_remaining = sf.diskless_on_remaining
            self._layer_list = sf.layer_stack
            self._provider_list = sf.provider_list
            self._property_dict = rg.properties

            self._nr_volumes = len(lin.volume_group_list_raise(self._name).volume_groups)

        return True

    def _update_or_create(self):
        with self._get_connection() as lin:
            rgs = lin.resource_group_list_raise(filter_by_resource_groups=[self._name]).resource_groups
            if len(rgs) == 0:  # does not exist yet
                self._modify_or_create("create")
                self._set_nr_volumes(self._nr_volumes_default)

        return self._update()
