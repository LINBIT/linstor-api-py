Linstor Python API Introduction
===============================

Linstor python api is a python library wrapping all tcp client communication
between a python client and the controller REST-API.


Overview
--------

Important classes
~~~~~~~~~~~~~~~~~

The few most important classes the python api currently uses are:

  - :py:class:`~.Linstor`

    Main class that has all methods for manipulating Linstor objects.
    Method names are structured in "object"_"action" e.g.: node_create, resource_list, volume_dfn_delete

  - :py:class:`~.MultiLinstor`

    Wrapper class arount `~.Linstor` that supports connections to multiple controllers.
    It will try to connect to the first controller in the list.

  - :py:class:`~.ApiCallResponse`

    The usual message reply from the controller for actions.

There are 2 error classes that will or can be thrown from a :py:class:`~.Linstor` object.

  - :py:class:`~.LinstorError`

    Common error class, has a message and possible child errors.

  - :py:class:`~.LinstorNetworkError`

    Linstor error indicating a network/connection error.

Code Samples Using the High-Level ResourceGroup API
---------------------------------------------------

In this section we describe methods that are typically used by plugin developers. Using resource groups is the
prefered way.

Create a resource N-times redundant
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A code sample on how to create a resource "foo", with a size of 20MiB. This first creates (or reuses) a
resource group named threeSSD, that uses a fast SSD pool and places resources 3-times redundant.  Usually that
code is executed in a "create" call in a plugin.

.. code-block:: python

  import linstor
  ssd_grp = linstor.ResourceGroup('threeSSD', uri='linstor://192.168.0.42')  # by default uri is localhost
  ssd_grp.redundancy = 3  # only if used for the first time
  ssd_grp.storage_pool = 'myssdpool'  # only if used for the first time
  foo = ssd_grp.create_resource('foo', ['20 MiB'])

Code Samples Using the High-Level Resource API
----------------------------------------------

In this section we describe methods that are typically used by plugin developers after a resource is created
from a resource group, or if a resource already exists.

Resizing an existing resource/volume
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

  import linstor
  foo = linstor.Resource('foo')  # or from a .create_resource() of a resource group
  foo.volumes[0].size = linstor.Volume('30 MiB')
  # resize again
  foo.volumes[0].size += 10 * 1024 * 1024

Create a diskless assignment if there isn't already an assignment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is useful in hyper-converged setups where a local diskless assignment should be created, but only if
there is not already an assignment with a disk.

.. code-block:: python

  import linstor
  foo = linstor.Resource('foo')
  foo.activate('bravo')

Remove diskless assignment (only if diskless)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is usually called in a plugin in a "close" call, where then a diskless assignment should be deleted.
Deletion in such cases is limited to diskless assignments as the redundancy should not be decreased

.. code-block:: python

  import linstor
  foo = linstor.Resource('foo')
  foo.deactivate('bravo')

Setting the assignment state of a resource
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This assigns the resource if it isn't assigned yet and convertes if necessary.

.. code-block:: python

  import linstor
  foo = linstor.Resource('foo')
  foo.placement.storage_pool = 'drbdpool'
  foo.diskful('alpha')  # whatever it was it is now diskful
  foo.diskless('alpha')  # converted to diskless
  foo.delete('alpha')
  foo.diskless('alpha')  # created diskless

Setting and unsetting dual primary
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

  import linstor
  foo = linstor.Resource('foo')
  foo.allow_two_primaries = True
  # do some live migration
  foo.allow_two_primaries = False

Various query and list operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

  import linstor
  foo = linstor.Resource('foo')
  for diskless_node in foo.diskless_nodes():
    print(diskless_node)
  print(foo.is_diskful('alpha'))
  print(foo.is_assigned('bravo'))
  print(foo.volumes[0].backing_disk)
  print(foo.volumes[0].device_path)

Code Samples Using the High-Level Key Value Store API
-----------------------------------------------------

In this section we describe methods that are typically used by plugin developers.

Create a resource N-times redundant
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create or attach to the KV "foo" and manipulate keys in different name spaces.

.. code-block:: python

  import linstor
  kv = linstor.KV('myKV', namespace='/foo/bar/')
  kv['key'] = 'val'
  list(kv.items()) -> [('key', 'val')]
  kv.namespace = '/'
  list(kv.items()) -> [('/foo/bar/key', 'val')]
  kv['foo/baz/key'] = 'valbaz'
  kv.namespace = '/foo/bar'
  list(kv.items()) -> [('key', 'val')] # keys in /foo/baz not visible

Code Samples using the Low-Level API
------------------------------------

List nodes
~~~~~~~~~~

A code sample on how to get the current node list from the Controller.

.. code-block:: python

  import linstor
  with linstor.Linstor("linstor://localhost") as lin:  # may raise exception
   node_list_reply = lin.node_list()  # API calls will always return a list

   assert node_list_reply, "Empty return list"

   node_list = node_list_reply[0]  # NodeListResponse
   print(node_list)

This code sample will print out the current known node list of the controller.
The returned node_list is a NodeListResponse class, a wrapper over a REST-API message,
All rest-messages are declared in the responses module.


Create a node
~~~~~~~~~~~~~

A slightly different connect approach without enter and exit methods, but basically
the same routine.

.. code-block:: python

  import linstor
  lin = linstor.Linstor("linstor://localhost")
  lin.connect()

  node_create_replies = lin.node_create(
    node_name="alpha",
    ip="10.0.0.20",
    node_type=linstor.consts.VAL_NODE_TYPE_STLT
  )

  if linstor.all_api_responses_success(node_create_replies):
    print('SUCCESS', node_create_replies)
  else:
    print('NO SUCCESS', node_create_replies)
  lin.disconnect()

This code snippet connects to the localhost controller and create a satellite node "alpha" with the ip "10.0.0.20".


Create a resource on 2 nodes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Here is a example on how to create a resource "rsc" on 2 nodes (alpha, bravo),
both nodes are already added to the controller with correctly setup default storage pools.

.. code-block:: python

  import linstor

  def check_api_response(api_response):  # check apicallresponses and print messages
    for apiresp in api_response:
      print(apiresp)
    return linstor.Linstor.all_api_responses_success(api_response)

  with linstor.Linstor("linstor://localhost") as lin:
    res_dfn_replies = lin.resource_dfn_create(name="rsc")
    assert check_api_response(res_dfn_replies)

    vlm_dfn_replies = lin.volume_dfn_create(rsc_name="rsc", size=10240)  # size is in KiB
    assert check_api_response(vlm_dfn_replies)

    rsc_create_replies = lin.resource_create(rsc_name="rsc", node_name="alpha")
    assert check_api_response(rsc_create_replies)

    rsc_create_replies = lin.resource_create(rsc_name="rsc", node_name="bravo")
    assert check_api_response(rsc_create_replies)

