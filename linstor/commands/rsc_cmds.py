from proto.MsgCrtRsc_pb2 import MsgCrtRsc
from proto.MsgDelRsc_pb2 import MsgDelRsc
from proto.MsgLstRsc_pb2 import MsgLstRsc
from proto.LinStorMapEntry_pb2 import LinStorMapEntry
from linstor.commcontroller import need_communication, completer_communication
from linstor.commands import Commands, NodeCommands, StoragePoolDefinitionCommands
from linstor.utils import namecheck, Table, Output
from linstor.utils import (
    COLOR_DARKGREEN,
    COLOR_RED
)
from linstor.sharedconsts import (
    API_CRT_RSC,
    API_DEL_RSC,
    API_LST_RSC,
    KEY_STOR_POOL_NAME,
    FLAG_DELETE
)

from linstor.consts import BOOL_TRUE, BOOL_FALSE, NODE_NAME, RES_NAME, STORPOOL_NAME


class ResourceCommands(Commands):

    @staticmethod
    def setup_commands(parser):
        # new-resource
        p_new_res = parser.add_parser(
            'create-resource',
            aliases=['crtrsc'],
            description='Defines a DRBD resource for use with linstor. '
            'Unless a specific IP port-number is supplied, the port-number is '
            'automatically selected by the linstor controller on the current node. ')
        p_new_res.add_argument(
            '-s', '--storage-pool',
            type=namecheck(STORPOOL_NAME),
            help="Storage pool name to use.").completer = StoragePoolDefinitionCommands.completer
        p_new_res.add_argument('name', type=namecheck(RES_NAME), help='Name of the new resource')
        p_new_res.add_argument('node_name',
                               type=namecheck(NODE_NAME),
                               help='Name of the new resource').completer = NodeCommands.completer
        p_new_res.set_defaults(func=ResourceCommands.create)

        # modify-resource
        p_mod_res_command = 'modify-resource'
        p_mod_res = parser.add_parser(
            p_mod_res_command,
            aliases=['mr'],
            description='Modifies a DRBD resource.')
        p_mod_res.add_argument('-m', '--managed', choices=(BOOL_TRUE, BOOL_FALSE))
        p_mod_res.add_argument('name', type=namecheck(RES_NAME),
                               help='Name of the resource').completer = ResourceCommands.completer
        p_mod_res.set_defaults(func=Commands.cmd_enoimp)
        p_mod_res.set_defaults(command=p_mod_res_command)

        # remove-resource
        p_rm_res = parser.add_parser(
            'delete-resource',
            aliases=['delrsc'],
            description=' Removes a resource and its associated resource definition '
            'from the linstor cluster. The resource is undeployed from all nodes '
            "and the resource entry is marked for removal from linstor's data "
            'tables. After all nodes have undeployed the resource, the resource '
            "entry is removed from linstor's data tables.")
        p_rm_res.add_argument('-q', '--quiet', action="store_true",
                              help='Unless this option is used, linstor will issue a safety question '
                              'that must be answered with yes, otherwise the operation is canceled.')
        p_rm_res.add_argument('name',
                              help='Name of the resource to delete').completer = ResourceCommands.completer
        p_rm_res.add_argument('node_name',
                              nargs="+",
                              help='Name of the node').completer = NodeCommands.completer
        p_rm_res.set_defaults(func=ResourceCommands.delete)

        resverbose = ('Port',)
        resgroupby = ('Name', 'Port', 'State')
        res_verbose_completer = Commands.show_group_completer(resverbose, "show")
        res_group_completer = Commands.show_group_completer(resgroupby, "groupby")

        p_lreses = parser.add_parser(
            'list-resources',
            aliases=['list-resource', 'ls-rsc', 'display-resources'],
            description='Prints a list of all resource definitions known to '
            'linstor. By default, the list is printed as a human readable table.')
        p_lreses.add_argument('-m', '--machine-readable', choices=['text', 'json'], const='json', nargs='?')
        p_lreses.add_argument('-p', '--pastable', action="store_true", help='Generate pastable output')
        p_lreses.add_argument(
            '-s', '--show',
            nargs='+',
            choices=resverbose).completer = res_verbose_completer
        p_lreses.add_argument(
            '-g', '--groupby',
            nargs='+',
            choices=resgroupby).completer = res_group_completer
        p_lreses.add_argument(
            '-R', '--resources',
            nargs='+',
            type=namecheck(RES_NAME),
            help='Filter by list of resources').completer = ResourceCommands.completer
        p_lreses.add_argument('--separators', action="store_true")
        p_lreses.set_defaults(func=ResourceCommands.list)

        # show properties
        p_sp = parser.add_parser(
            'get-resource-properties',
            aliases=['get-resource-props'],
            description="Prints all properties of the given resource.")
        p_sp.add_argument(
            'resource_name',
            help="Resource for which to print the properties").completer = ResourceCommands.completer
        p_sp.set_defaults(func=ResourceCommands.print_props)

    @staticmethod
    @need_communication
    def create(cc, args):
        p = MsgCrtRsc()
        p.rsc_name = args.name
        p.node_name = args.node_name

        if args.storage_pool:
            prop = LinStorMapEntry()
            prop.key = KEY_STOR_POOL_NAME
            prop.value = args.storage_pool
            p.rsc_props.extend([prop])

        return Commands._create(cc, API_CRT_RSC, p)

    @staticmethod
    @need_communication
    def delete(cc, args):
        del_msgs = []
        for node_name in args.node_name:
            p = MsgDelRsc()
            p.rsc_name = args.name
            p.node_name = node_name

            del_msgs.append(p)

        return Commands._delete_and_output(cc, args, API_DEL_RSC, del_msgs)

    @staticmethod
    @need_communication
    def list(cc, args):
        lstmsg = Commands._get_list_message(cc, API_LST_RSC, MsgLstRsc(), args)

        if lstmsg:
            tbl = Table(utf8=not args.no_utf8, colors=not args.no_color, pastable=args.pastable)
            tbl.add_column("ResourceName")
            tbl.add_column("Node")
            tbl.add_column("State", color=Output.color(COLOR_DARKGREEN, args.no_color))
            for rsc in lstmsg.resources:
                tbl.add_row([
                    rsc.name,
                    rsc.node_name,
                    tbl.color_cell("DELETING", COLOR_RED)
                    if FLAG_DELETE in rsc.rsc_flags else tbl.color_cell("ok", COLOR_DARKGREEN)
                ])
            tbl.show()

            # prntfrm = "{rsc:<20s} {uuid:<40s} {node:<30s}"
            # print(prntfrm.format(rsc="Resource-name", uuid="UUID", node="Node"))
            # for rsc in lstmsg.resources:
            #     print(prntfrm.format(
            #         rsc=rsc.name,
            #         uuid=rsc.uuid,
            #         node=rsc.node_name))

        return None

    @staticmethod
    @need_communication
    def print_props(cc, args):
        lstmsg = Commands._request_list(cc, API_LST_RSC, MsgLstRsc())

        if lstmsg:
            for rsc in lstmsg.resources:
                if rsc.name == args.resource_name:
                    Commands._print_props(rsc.props)
                    break

        return None

    @staticmethod
    @completer_communication
    def completer(cc, prefix, **kwargs):
        possible = set()
        lstmsg = Commands._get_list_message(cc, API_LST_RSC, MsgLstRsc())

        if lstmsg:
            for rsc in lstmsg.resources:
                possible.add(rsc.name)

            if prefix:
                return [res for res in possible if res.startswith(prefix)]

        return possible

    @staticmethod
    @completer_communication
    def completer_volume(cc, prefix, **kwargs):
        possible = set()
        return possible
