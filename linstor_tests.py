import unittest

if __name__ == '__main__':
    import xmlrunner
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir='linstor_tests')
    runner = xmlrunner.XMLTestRunner(output='test-reports')
    runner.run(suite)
