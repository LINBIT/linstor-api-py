import unittest

if __name__ == '__main__':
    import xmlrunner
    unittest.main(module='linstor_tests', testRunner=xmlrunner.XMLTestRunner(output='test-reports'))
