import unittest
import linstor.linstorapi as linstorapi
from linstor import SizeCalc, LinstorError


class TestUtils(unittest.TestCase):

    def _check_host_port(self, host_str, excp_host, excp_port=None):
        host, port = linstorapi._LinstorNetClient.parse_host(host_str)
        self.assertEqual(host, excp_host)
        if excp_port is None:
            self.assertIsNone(port)
        else:
            self.assertEqual(port, excp_port)

    def test_parse_host(self):
        self._check_host_port("", "")
        self._check_host_port(None, None)
        self._check_host_port("127.0.0.1", "127.0.0.1")
        self._check_host_port("localhost", "localhost")
        self._check_host_port("localhost:3376", "localhost", "3376")

        self._check_host_port("10.43.8.103:6667", "10.43.8.103", "6667")

        self._check_host_port("4chan.org", "4chan.org")
        self._check_host_port("4chan.org:3376", "4chan.org", "3376")
        self._check_host_port("linbit.com", "linbit.com")
        self._check_host_port("linbit.com:3376", "linbit.com", "3376")
        self._check_host_port("bk.linbit.com", "bk.linbit.com")

        # ipv6
        self._check_host_port("::1", "::1")
        self._check_host_port("[::1]:3376", "::1", "3376")

        self._check_host_port("2001:0db8:85a3:08d3:1319:8a2e:0370:7344", "2001:0db8:85a3:08d3:1319:8a2e:0370:7344")
        self._check_host_port("[2001:0db8:85a3:08d3::0370:7344]", "2001:0db8:85a3:08d3::0370:7344")
        self._check_host_port("[2001:0db8:85a3:08d3::0370:7344]:8080", "2001:0db8:85a3:08d3::0370:7344", "8080")

        with self.assertRaises(ValueError):
            linstorapi._LinstorNetClient.parse_host("[::1")

    def assertSizeUnit(self, val, exp_size, exp_unit):
        size, unit = SizeCalc.parse_unit(val)
        self.assertEqual(exp_size, size)
        self.assertEqual(exp_unit, unit)

    def test_size_calc_units(self):
        self.assertSizeUnit("128k", 128, SizeCalc.UNIT_KiB)
        self.assertSizeUnit("128", 128, SizeCalc.UNIT_B)
        self.assertSizeUnit("248GiB", 248, SizeCalc.UNIT_GiB)
        self.assertSizeUnit("248GB", 248, SizeCalc.UNIT_GB)

        self.assertRaises(LinstorError,  SizeCalc.parse_unit, "nosize")

    def test_size_calc_convert(self):
        self.assertEqual(10485760, SizeCalc.auto_convert("10M", SizeCalc.UNIT_B))
        self.assertEqual(10485760, SizeCalc.auto_convert("10MiB", SizeCalc.UNIT_B))
        self.assertEqual(10000000, SizeCalc.auto_convert("10MB", SizeCalc.UNIT_B))

        self.assertEqual(3221225472, SizeCalc.auto_convert("3Gib", SizeCalc.UNIT_B))
        self.assertEqual(3145728, SizeCalc.auto_convert("3Gib", SizeCalc.UNIT_KiB))
