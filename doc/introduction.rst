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

Watches are used to get notifications of events happing on for example resource objects.
To use them you have to add a watch and provide a callback function that will take decisions
on how long you will want to watch an object.

.. code-block:: python

  with linstor.Linstor("linstor://localhost") as lin:
    rsc_name = "rsc1"
    def delete_rscdfn_handler(event_header, event_data):
        if event_header.event_name in [linstor.consts.EVENT_RESOURCE_DEPLOYMENT_STATE]:
            if event_header.event_action == linstor.consts.EVENT_STREAM_CLOSE_NO_CONNECTION:
                print("WARNING: Satellite connection lost")
                sys.exit(20)
        elif event_header.event_name in [linstor.consts.EVENT_RESOURCE_DEFINITION_READY]:
            if event_header.event_action == linstor.consts.EVENT_STREAM_CLOSE_REMOVED:
                return []

        return linstor.Linstor.exit_on_error_event_handler(event_header, event_data)


    lin.resource_dfn_delete(rsc_name)
    watch_result = lin.watch_events(
        linstor.Linstor.return_if_failure,
        delete_rscdfn_handler,
        linstor.ObjectIdentifier(resource_name=rsc_name)
    )
    # watch_result will contain the result of delete_rscdfn_handler
    return watch_result


In this sample a resource definition with the name "rsc1" is deleted and a watch
is created that checks if the resource is deleted on all deployed satellites.
The callback function used is named ``delete_rscdfn_handler``, a watch callback
function gets 2 parameters, event_header and event_data.
The event_header is the MsgEvent protobuf message, check the protobuf definition
for all attributes. Most important attributes are ``event_name`` and ``event_action``:

  * ``event_name`` is one of

    * :py:data:`linstor.consts.EVENT_RESOURCE_DEPLOYMENT_STATE`

      Sent for Satellite device handler resource events

    * :py:data:`linstor.consts.EVENT_RESOURCE_DEFINITION_READY`

      Sent for resource definition events

    * :py:data:`linstor.consts.EVENT_SNAPSHOT_DEPLOYMENT`
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

