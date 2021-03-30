#!/usr/bin/env python2

import linstor.linstorapi
from linstor.resource import _Client


class KV(dict):
    """
    KV class represents a Key-Value Store backed by LINSTOR.

    This object provides mainly the same interface as a Python3 dict and acts as a Key-Value store with
    namespaces. A namespace acts like a prefix in a UNIX file system and gets added to the every key that is
    set. The default namespace is '/'.

    Limitations: Keys and values have to be of type str. KV.keys(), KV.items() (as well as KV.values()) are
    implemented as simple generators. So they provide a "view", but not a "set-like" behavior. If you need
    that, convert the generator to a set (i.e. ks = KV.keys(); set(ks) & {'foo'}).

    The __repr__() method is not overridden intentionally and provides the representation of the whole dict,
    basically ignoring the namespace. This is helpful for debugging.

    Example:
        Add a value to a namespace /foo/bar, list it, change the namespace to "/" and list the item::

        $ kv = linstor.KV('myKV', namespace='/foo/bar/')
        $ kv['key'] = 'val'
        $ list(kv.items()) -> [('key', 'val')]
        $ kv.namespace = '/'
        $ list(kv.items()) -> [('/foo/bar/key', 'val')]
        $ kv['foo/baz/key'] = 'valbaz'
        $ kv.namespace = '/foo/bar'
        $ list(kv.items()) -> [('key', 'val')] # keys in /foo/baz not visible

    :param str name: The name of the KV-store. It acts as a unique handle.
    :param str namespace: A UNIX-like file system path.
    :param bool cached: A KV can be backed by a python dict as a caching layer. As of now has to be True.
     This influences whether reads are forwarded to LINSTOR or not. Writes are obviously always forwarded.
    :param str uri: A list of controller addresses.
    :param bool rw_to_linstor: If set to False, entries are not written to LINSTOR. It can be used to use
     the KV as a name spaced dict() only, or for debugging.
    :param linstor.Linstor existing_client: Instead of creating  a new client based on the controller addresses,
     use this pre-configured client object.
    """
    def __init__(self, name, namespace='/', cached=True, uri='linstor://localhost', rw_to_linstor=True,
                 existing_client=None):
        assert cached, 'Currently we only allow "cached" KeyValueStores'
        assert cached or rw_to_linstor, 'KV has to be "cached" and/or "rw_to_linstor"'
        super(KV, self).__init__()
        self._name = name
        self._cached = cached
        self.client = _Client(uri)
        self._existing_client = existing_client
        self._rw_to_linstor = rw_to_linstor
        self._import()
        self._set_ns(namespace)

    def _get_connection(self):
        if self._existing_client:
            return self._existing_client
        return linstor.MultiLinstor(self.client.uri_list, self.client.timeout, self.client.keep_alive)

    # keys are expected to be expanded
    def _set_linstor_kv(self, k, v):
        if not self._rw_to_linstor:
            return
        with self._get_connection() as lin:
            rs = lin.keyvaluestore_modify(self._name, property_dict={k: v}, delete_props=None)
            if not rs[0].is_success():
                raise linstor.LinstorError('Could not set kv({}:{}): {}'.format(k, v, rs[0]))

    # keys are expected to be expanded
    # we could check for an iterable, but a str is also iterable, be explicit, we only have one list-caller
    # still, we want that special case for a list, it is a lot more efficient (see clear()).
    def _del_linstor_kv(self, k, is_list_like=False):
        if not self._rw_to_linstor:
            return

        if is_list_like:
            delete_props = list(k)  # allows e.g., tuples
        else:
            delete_props = [k]
        with self._get_connection() as lin:
            rs = lin.keyvaluestore_modify(self._name, property_dict=None, delete_props=delete_props)
            if not rs[0].is_success():
                raise linstor.LinstorError('Could not delete kv({}): {}'.format(k, rs[0]))

    @classmethod
    def _valid_string(cls, s):
        if isinstance(s, str):
            return True

        # py2 unicode:
        try:
            return isinstance(s, unicode)
        except Exception:
            pass

        return False

    @classmethod
    def _normalize_ns(cls, ns):
        ns = ns.strip()
        while True:
            if ns.startswith('/'):
                ns = ns[1:].lstrip()
            elif ns.endswith('/'):
                ns = ns[:-1].rstrip()
            else:
                break

        return ns

    def _import(self):
        d = {}
        if self._rw_to_linstor:
            with self._get_connection() as lin:
                d = {'/'+k: v for k, v in lin.keyvaluestore_list(self._name).properties.items()}

        super(KV, self).clear()
        super(KV, self).update(d)

    # works for None, '', False, '/', and proper namespaces
    def _set_ns(self, ns):
        if ns:
            ns = KV._normalize_ns(ns)
        ns = '/{}/'.format(ns) if ns else '/'
        self._ns = ns

    def _key_ns_add(self, k):
        return self._ns + self._normalize_ns(k)

    def _key_ns_del(self, k):
        return k[len(self._ns):]

    @property
    def namespace(self):
        """
        Returns the current name space (e.g., /foo/).

        :return: Current name space.
        :rtype: str
        """
        return self._ns

    @namespace.setter
    def namespace(self, ns):
        self._set_ns(ns)

    def __delitem__(self, k):
        if not KV._valid_string(k):
            raise KeyError('key {} has to be a str/unicode, but is {}'.format(k, type(k)))
        k = self._key_ns_add(k)
        self._del_linstor_kv(k)
        super(KV, self).__delitem__(k)

    def __setitem__(self, k, v):
        if not KV._valid_string(k):
            raise KeyError('key {} has to be a str/unicode, but is {}'.format(k, type(k)))
        if not KV._valid_string(v):
            raise ValueError('value {} has to be a str/unicode, but is {}'.format(v, type(v)))

        k = self._key_ns_add(k)
        self._set_linstor_kv(k, v)
        super(KV, self).__setitem__(k, v)

    def __getitem__(self, k):
        return super(KV, self).__getitem__(self._key_ns_add(k))

    def __contains__(self, k):
        return super(KV, self).__contains__(self._key_ns_add(k))

    def __iter__(self):
        for k in super(KV, self).__iter__():
            if k.startswith(self.namespace):
                yield self._key_ns_del(k)

    def clear(self):
        to_delete = [k for k in super(KV, self).keys() if k.startswith(self.namespace)]
        if len(to_delete) > 0:
            self._del_linstor_kv(to_delete, is_list_like=True)
            for k in to_delete:
                super(KV, self).__delitem__(k)

    def get(self, k, d=None):
        return super(KV, self).get(self._key_ns_add(k), d)

    def items(self):
        for k, v in super(KV, self).items():
            if k.startswith(self.namespace):
                yield self._key_ns_del(k), v

    def keys(self):
        return self.__iter__()

    def pop(self, *args):
        k = args[0]
        if self.__contains__(k):
            item = self.__getitem__(k)
            self.__delitem__(k)
            return item

        if len(args) == 2:  # default given
            return args[1]

        raise KeyError

    def popitem(self):
        kv = list(self.items())
        if len(kv) == 0:
            raise KeyError

        k, v = kv[-1]
        self.__delitem__(k)
        return (k, v)

    def setdefault(self, k, d=None):
        if self.__contains__(k):
            return self.__getitem__(k)
        self.__setitem__(k, d)
        return d

    def update(self, *args, **kwargs):
        raise NotImplementedError

    def values(self):
        for _, v in self.items():
            yield v
