import unittest
from linstor.linstorapi import _pquote


class TestLinstorApi(unittest.TestCase):

    def test_pquote(self):
        nodepath = _pquote("/v1/nodes")
        self.assertEqual("/v1/nodes", nodepath)
        nodepath = _pquote("/v1/nodes/{}", "lin1")
        self.assertEqual("/v1/nodes/lin1", nodepath)
        nodepath = _pquote("/v1/nodes/{}", '"lin1"')
        self.assertEqual("/v1/nodes/%22lin1%22", nodepath)

        query_params = {"nodes": ["lin1", "lin2"]}
        nodepath = _pquote("/v1/nodes", query_params=query_params)
        self.assertEqual("/v1/nodes?nodes=lin1&nodes=lin2", nodepath)

        vd_path = _pquote("/v1/resource-definitions/{}/volume-definitions/{}/encryption-passphrase", "rsc1", 0)
        self.assertEqual("/v1/resource-definitions/rsc1/volume-definitions/0/encryption-passphrase", vd_path)

        query_params = {"nodes": ['"lin1"', "lin2"]}
        nodepath = _pquote("/v1/nodes", query_params=query_params)
        self.assertEqual("/v1/nodes?nodes=%22lin1%22&nodes=lin2", nodepath)

        query_params = {"nodes": ['lin1', "lin2"], "resources": ["rsc1"]}
        rscs_path = _pquote("/v1/view/resources", query_params=query_params)
        self.assertTrue(rscs_path.startswith("/v1/view/resources?"))
        self.assertTrue("nodes=lin1&nodes=lin2" in rscs_path)
        self.assertTrue("resources=rsc1" in rscs_path)

        query_params = {"nodes": ['"lin1"', "lin2"], "resources": ["rsc1"]}
        rscs_path = _pquote("/v1/view/resources", query_params=query_params)
        self.assertTrue(rscs_path.startswith("/v1/view/resources?"))
        self.assertTrue("nodes=%22lin1%22&nodes=lin2" in rscs_path)
        self.assertTrue("resources=rsc1" in rscs_path)
