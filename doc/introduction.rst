Linstor python api introduction
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

Watches are some kind of events that are sent to everyone who is described for an event or object.
It is used to have realtime notifications of created/deleted resources on satellites.

WIP


Code Samples
------------

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

