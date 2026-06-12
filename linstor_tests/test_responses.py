import unittest
from datetime import datetime, timedelta, timezone
from linstor import ApiCallResponse, sharedconsts
from linstor.responses import AuthToken


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

    def test_auth_token_parse_datetime(self):
        utc = timezone.utc

        nanos = AuthToken({
            "id": 1,
            "description": "nanos",
            "created_at": "2026-06-11T23:52:29.479092777+00:00"})
        self.assertEqual(datetime(2026, 6, 11, 23, 52, 29, 479092, tzinfo=utc),
                         nanos.created_at)

        zulu_nanos = AuthToken({
            "id": 2,
            "description": "zulu-nanos",
            "created_at": "2026-06-11T23:52:29.479092777Z"})
        self.assertEqual(datetime(2026, 6, 11, 23, 52, 29, 479092, tzinfo=utc),
                         zulu_nanos.created_at)

        zulu_millis = AuthToken({
            "id": 3,
            "description": "zulu-millis",
            "created_at": "2026-06-11T23:52:29.479Z"})
        self.assertEqual(datetime(2026, 6, 11, 23, 52, 29, 479000, tzinfo=utc),
                         zulu_millis.created_at)

        no_fraction = AuthToken({
            "id": 4,
            "description": "no-fraction",
            "created_at": "2026-06-11T23:52:29+00:00"})
        self.assertEqual(datetime(2026, 6, 11, 23, 52, 29, tzinfo=utc),
                         no_fraction.created_at)

        # Fractions whose length is neither 3 nor 6 used to break datetime.fromisoformat()
        # on Python < 3.11; the fraction must be zero-padded to microseconds.
        odd_fraction = AuthToken({
            "id": 5,
            "description": "odd-fraction",
            "created_at": "2026-06-11T23:52:29.4791Z"})
        self.assertEqual(datetime(2026, 6, 11, 23, 52, 29, 479100, tzinfo=utc),
                         odd_fraction.created_at)

        # Non-UTC numeric offset.
        offset = AuthToken({
            "id": 6,
            "description": "offset",
            "created_at": "2026-06-11T23:52:29.479-05:30"})
        self.assertEqual(
            datetime(2026, 6, 11, 23, 52, 29, 479000,
                     tzinfo=timezone(timedelta(hours=-5, minutes=-30))),
            offset.created_at)

        self.assertIsNone(AuthToken({
            "id": 7,
            "description": "no-expiry"}).expires_at)
