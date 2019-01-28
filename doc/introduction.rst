Linstor Python API Introduction
===============================

Linstor python api is a python library wrapping all tcp client communication
between a python client and the controller API.

Linstor uses its own header format combined with Google protobuf messages as payload.


Overview
--------

Important classes
~~~~~~~~~~~~~~~~~

The few most important classes the python api currently uses are:

  - :py:class:`~.Linstor`

    Main class that has all methods for manipulating Linstor objects.
    Method names are structured in "object"_"action" e.g.: node_create, resource_list, volume_dfn_delete

  - :py:class:`~.ApiCallResponse`

    The usual message reply from the controller for actions.

There are 2 error classes that will or can be thrown from a :py:class:`~.Linstor` object.

  - :py:class:`~.LinstorError`

    Common error class, has a message and possible child errors.

  - :py:class:`~.LinstorNetworkError`

    Linstor error indicating a network/connection error.


Watches
~~~~~~~

Watches are used to get notifications of events happing on for example resource objects.
To use them you have to add a watch and provide a callback function that will take decisions
on how long you will want to watch an object.

.. code-block:: python

  with linstor.Linstor("linstor://localhost") as lin:
    rsc_name = "rsc1"

    def vlm_state_handler(event_header, event_data):
        if event_header.event_name in [linstor.consts.EVENT_VOLUME_DISK_STATE]:
            if event_header.event_action == linstor.consts.EVENT_STREAM_CLOSE_NO_CONNECTION:
                print("WARNING: Satellite connection lost")
                sys.exit(20)

            print(event_data.disk_state)
            if event_data.disk_state == "UpToDate":
                return "Done"

    watch_result = lin.watch_events(
        linstor.Linstor.return_if_failure,
        vlm_state_handler,
        linstor.ObjectIdentifier(resource_name=rsc_name)
    )
    # watch_result will contain the result of delete_rscdfn_handler
    print(watch_result)


In this sample a watch is created that waits for the resource to be UpToDate on any satellite.
The callback function used is named ``vlm_state_handler``, a watch callback
function gets 2 parameters, event_header and event_data.
The event_header is the MsgEvent protobuf message, check the protobuf definition
for all attributes. Most important attributes are ``event_name`` and ``event_action``:

  * ``event_name`` is one of

    * :py:data:`linstor.consts.EVENT_RESOURCE_STATE`

      Sent for resource definition events

    * :py:data:`linstor.consts.EVENT_VOLUME_DISK_STATE`

  * ``event_action`` is one of

    * :py:data:`linstor.consts.EVENT_STREAM_OPEN`
    * :py:data:`linstor.consts.EVENT_STREAM_VALUE`
    * :py:data:`linstor.consts.EVENT_STREAM_CLOSE_NO_CONNECTION`

      Satellite dropped connection to the controller

    * :py:data:`linstor.consts.EVENT_STREAM_CLOSE_REMOVED`

      Sent if an object was removed.


Code Samples Using the High-Level Resource API
----------------------------------------------

In this section we describe methods that are typically used by plugin developers.

Create a resource N-times redundant
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A code sample on how to create a resource "foo", with a size of 20MiB 3-times redundant.
Usually that code is executed in a "create" call in a plugin.

.. code-block:: python

  import linstor
  foo = linstor.Resource('foo', uri='linstor://192.168.0.42')  # by default uri is localhost
  foo.volumes[0] = linstor.Volume('20 MiB')
  foo.placement.redundancy = 3
  foo.autoplace()

Resizing an existing resource/volume
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

  import linstor
  foo = linstor.Resource('foo')
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

   node_list = node_list_reply[0]  # First entry is the node list proto msg
   print(node_list)

This code sample will print out the current known node list of the controller.
The returned node_list is a ProtoMessageReply class, a wrapper over protobuf messages,
ProtoMessageReply has a property .proto_msg that allows direct access to the protobuf message.
All protobuf messages are declared in the linstor-common repository.


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
  node_create = node_create_replies[0]
  if node_create.is_success():
    print('SUCCESS', node_create)
  else:
    print('NO SUCCESS', node_create)
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

