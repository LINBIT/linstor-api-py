import unittest
from linstor import ApiCallResponse, sharedconsts


class TestResponses(unittest.TestCase):

    def test_ApiCallResponse(self):
        rc_fail_exists = ApiCallResponse.from_json({
            'ret_code': -4611686018407202314,
            'error_report_ids': ['5CFA0EF9-00000-000001'],
            'obj_refs': {'RscDfn': 'test'},
            'details': "Node(s): 'drbd1', Resource: 'test'",
            'message': "A resource 'test' on node 'drbd1' already exists.",
            'cause': 'The Resource already exists'}
        )

        rc_node_not_exits = ApiCallResponse.from_json({
            'message': "Node 'centos1' not found.",
            'cause': "The specified node 'centos1' could not be found in the database",
            'correction': "Create a node with the name 'centos1' first.",
            'ret_code': -4611686018427387604}
        )

        self.assertTrue(rc_fail_exists.is_error())
        self.assertTrue(rc_fail_exists.is_error(sharedconsts.FAIL_EXISTS_RSC))
        self.assertFalse(rc_fail_exists.is_success())

        self.assertFalse(rc_node_not_exits.is_error(sharedconsts.FAIL_EXISTS_RSC))
        self.assertFalse(rc_node_not_exits.is_error(sharedconsts.FAIL_EXISTS_NODE))
        self.assertTrue(rc_node_not_exits.is_error(sharedconsts.FAIL_NOT_FOUND_NODE))
