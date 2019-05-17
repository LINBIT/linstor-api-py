import unittest
from linstor import SizeCalc, LinstorError


class TestUtils(unittest.TestCase):
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
