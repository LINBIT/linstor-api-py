import unittest
from . import test_utils

_std_tests = [
    "linstor_tests.test_utils"
]


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    loaded_tests = loader.loadTestsFromNames(_std_tests)
    suite.addTest(loaded_tests)
    return suite


def load_all():
    suite = unittest.TestSuite()
    loaded_tests = unittest.defaultTestLoader.loadTestsFromNames(_std_tests)
    suite.addTest(loaded_tests)
    return suite


def test_without_controller():
    suite = unittest.TestSuite()
    loaded_tests = unittest.defaultTestLoader.loadTestsFromNames(_std_tests)
    suite.addTest(loaded_tests)
    return suite
