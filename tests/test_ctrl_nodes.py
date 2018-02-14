import unittest
from .linstor_testcase import LinstorTestCase
from linstor.commands import NodeCommands
import linstor.sharedconsts as apiconsts


class TestNodeCommands(LinstorTestCase):

    def test_create_node(self):
        retcode = self.execute(['create-node', 'node1', '192.168.100.1'])
        self.assertEqual(0, retcode)

        node_list = self.execute_with_machine_output(['list-nodes'])
        self.assertIsNotNone(node_list)
        self.assertIs(len(node_list), 1)
        node_list = node_list[0]
        self.assertTrue('nodes' in node_list)
        nodes = node_list['nodes']
        self.assertGreater(len(nodes), 0)
        self.assertTrue([n for n in nodes if n['name'] == 'node1'])

        args = self.parse_args(['list-nodes'])  # any valid command, just need the parsed args object
        completer_nodes = NodeCommands.completer('node1', parsed_args=args)
        self.assertTrue('node1' in completer_nodes)

        retcode = self.execute(['delete-node', 'node1'])
        self.assertEqual(0, retcode)

    def find_node(self, nodelist, node_name):
        fnodes = [x for x in nodelist if x['name'] == node_name]
        if fnodes:
            self.assertEqual(1, len(fnodes))
            return fnodes[0]
        return None

    def assert_netinterface(self, netif_data, netif_name, netif_addr):
        self.assertEqual(netif_data['name'], netif_name)
        self.assertEqual(netif_data['address'], netif_addr)

    def assert_netinterfaces(self, node, expected_netifs):
        netifs = self.execute_with_machine_output(['list-netinterfaces', node])
        self.assertEqual(1, len(netifs))
        netifs = netifs[0]
        self.assertIn("nodes", netifs)
        nodes = netifs['nodes']
        node = self.find_node(nodes, 'nodenetif')
        self.assertIsNotNone(node)
        self.assertEqual(len(expected_netifs), len(node['net_interfaces']))
        netifs = node['net_interfaces']

        for i in range(0, len(expected_netifs)):
            self.assert_netinterface(netifs[i], expected_netifs[i][0], expected_netifs[i][1])

    def test_add_netif(self):
        node = self.execute_with_single_resp(['create-node', 'nodenetif', '195.0.0.1'])
        self.assertTrue(node.is_success())
        self.assertEqual(apiconsts.MASK_NODE | apiconsts.MASK_CRT | apiconsts.CREATED, node.ret_code)

        self.assert_netinterfaces('nodenetif', [("default", '195.0.0.1')])

        netif = self.execute_with_single_resp(['create-netinterface', 'nodenetif', 'othernic', '10.0.0.1'])
        self.assertTrue(netif.is_success())
        self.assertEqual(apiconsts.MASK_NET_IF | apiconsts.MASK_CRT | apiconsts.CREATED, netif.ret_code)

        self.assert_netinterfaces('nodenetif', [("default", '195.0.0.1'), ("othernic", '10.0.0.1')])

        # modify netif
        netif = self.execute_with_single_resp(['modify-netinterface', 'nodenetif', 'othernic', '192.168.0.1'])
        self.assertTrue(netif.is_success())
        self.assertEqual(apiconsts.MASK_NET_IF | apiconsts.MASK_MOD | apiconsts.MODIFIED, netif.ret_code)

        self.assert_netinterfaces('nodenetif', [("default", '195.0.0.1'), ("othernic", '192.168.0.1')])

        # delete netif
        netif = self.execute_with_single_resp(['delete-netinterface', 'nodenetif', 'othernic'])
        self.assertTrue(netif.is_success())
        self.assertEqual(apiconsts.MASK_NET_IF | apiconsts.MASK_DEL | apiconsts.DELETED, netif.ret_code)

        self.assert_netinterfaces('nodenetif', [("default", '195.0.0.1')])


if __name__ == '__main__':
    unittest.main()
