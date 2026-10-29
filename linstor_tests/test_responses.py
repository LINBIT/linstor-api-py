import unittest
from datetime import datetime, timedelta, timezone
from linstor import ApiCallResponse, sharedconsts
from linstor.responses import AuthToken, CbtExtents, CbtSession, ErrorReportPage, ResourceResponse, SelectFilter


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

    def test_error_report_page(self):
        page = ErrorReportPage({
            "total": 42,
            "limit": 2,
            "offset": 10,
            "sort_by": "exception",
            "sort_order": "asc",
            "items": [
                {
                    "node_name": "lin1",
                    "error_time": 1787713000123,
                    "filename": "ErrorReport-5CFA0EF9-00000-000001.log",
                    "module": "SATELLITE",
                    "exception": "NullPointerException"
                },
                {
                    "node_name": "lin2",
                    "error_time": 1787713400000,
                    "filename": "ErrorReport-5CFA0EFA-00000-000002.log",
                    "module": "CONTROLLER",
                    "exception": "TimeoutException",
                    "exception_message": "timeout",
                    "text": "full report text"
                }
            ]
        })

        self.assertEqual(42, page.total)
        self.assertEqual(2, page.limit)
        self.assertEqual(10, page.offset)
        self.assertEqual("exception", page.sort_by)
        self.assertEqual("asc", page.sort_order)

        reports = page.error_reports
        self.assertEqual(2, len(reports))
        self.assertEqual("5CFA0EF9-00000-000001", reports[0].id)
        self.assertEqual("lin1", reports[0].node_name)
        self.assertEqual("NullPointerException", reports[0].exception)
        self.assertIsNone(reports[0].text)
        self.assertEqual("full report text", reports[1].text)
        self.assertEqual("timeout", reports[1].exception_message)

        empty = ErrorReportPage({"total": 0, "limit": 1000, "offset": 0, "items": []})
        self.assertEqual(0, empty.total)
        self.assertEqual([], empty.error_reports)

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

    def test_resource_state_open(self):
        rsc_resp = ResourceResponse([
            {"name": "r1", "node_name": "n1", "state": {"in_use": False, "open": True}},
            {"name": "r1", "node_name": "n2", "state": {"in_use": False}},
        ])
        open_state, unknown_state = rsc_resp.resource_states

        self.assertTrue(open_state.open)
        self.assertFalse(open_state.in_use)
        self.assertEqual(True, open_state.data_v0["open"])
        self.assertIsNone(unknown_state.open)
        self.assertNotIn("open", unknown_state.data_v0)

    def test_select_filter_diskless_pools_and_nodes(self):
        select_filter = SelectFilter({
            "place_count": 2,
            "storage_pool_list": ["sp0"],
            "storage_pool_diskless_list": ["sp-quorum"],
            "node_name_list": ["n1", "n2"]})

        self.assertEqual(["sp-quorum"], select_filter.storage_pool_diskless_list)
        self.assertEqual(["n1", "n2"], select_filter.node_name_list)
        self.assertIn("DisklessStoragePool(s): sp-quorum", str(select_filter))
        self.assertIn("Nodes: n1, n2", str(select_filter))

        # older controllers never return these fields
        self.assertEqual([], SelectFilter({"place_count": 2}).storage_pool_diskless_list)
        self.assertEqual([], SelectFilter({"place_count": 2}).node_name_list)
        self.assertNotIn("Nodes", str(SelectFilter({"place_count": 2, "node_name_list": []})))

    def test_cbt_session(self):
        session = CbtSession({
            "resource_name": "rsc1_cbt_0a1b2c",
            "node": "node3",
            "cbt_id": "0123456789ABCDEF",
            "volumes": [{"volume_number": 0, "device_path": "/dev/drbd1001", "volume_size": 423493632}]
        })
        self.assertEqual("rsc1_cbt_0a1b2c", session.resource_name)
        self.assertEqual("node3", session.node_name)
        self.assertEqual("0123456789ABCDEF", session.cbt_id)
        self.assertEqual(1, len(session.volumes))
        self.assertEqual(0, session.volumes[0].volume_number)
        self.assertEqual("/dev/drbd1001", session.volumes[0].device_path)
        self.assertEqual(423493632, session.volumes[0].volume_size)

    def test_cbt_extents(self):
        page = CbtExtents({
            "base_cbt_id": "0123456789ABCDEF",
            "since": "2026-10-29T11:49:43Z",
            "volume_size": 423493632,
            "extents": [
                {"start": 0, "length": 4096, "dirty": True, "zero": False},
                {"start": 4096, "length": 1048576, "dirty": False, "zero": True}
            ],
            "next_offset": 1052672
        })
        self.assertEqual("0123456789ABCDEF", page.base_cbt_id)
        self.assertEqual("2026-10-29T11:49:43Z", page.since)
        self.assertEqual(
            [(0, 4096, True, False), (4096, 1048576, False, True)],
            [(x.start, x.length, x.dirty, x.zero) for x in page.extents]
        )
        self.assertEqual(1052672, page.next_offset)

        # zero mode: no tracking interval and no dirty flag
        zero_page = CbtExtents({
            "volume_size": 423493632,
            "extents": [{"start": 0, "length": 423493632, "zero": False}]
        })
        self.assertIsNone(zero_page.base_cbt_id)
        self.assertIsNone(zero_page.since)
        self.assertEqual(
            [(0, 423493632, None, False)], [(x.start, x.length, x.dirty, x.zero) for x in zero_page.extents]
        )

        # the server leaves an empty extent list and a missing next_offset out
        last = CbtExtents({"base_cbt_id": "0123456789ABCDEF", "volume_size": 423493632})
        self.assertEqual([], last.extents)
        self.assertIsNone(last.next_offset)
        self.assertIsNone(last.since)
