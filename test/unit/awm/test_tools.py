import sys

sys.path.append(".")
sys.path.append("..")

import base64
import flask
import unittest
from IM.awm import awm_bp
from pydantic import HttpUrl
from IM.awm.node_registry import EOSCNode
from mock import patch, MagicMock, call


class TestTools(unittest.TestCase):

    def __init__(self, *args):
        unittest.TestCase.__init__(self, *args)

    def setUp(self):
        app = flask.Flask("test_app")
        app.register_blueprint(awm_bp, url_prefix='/awm')
        self.client = app.test_client()

    @patch('IM.awm.authorization.check_OIDC')
    @patch('IM.awm.routers.tools.Repository')
    def test_list_tools(self, mock_repo, mock_check_oidc):
        mock_check_oidc.return_value = {'sub': 'test-user', 'name': 'username'}
        headers = {"Authorization": "Bearer you-very-secret-token"}

        repo = MagicMock()
        mock_repo.create.return_value = repo
        repo.list.return_value = {"elem": {"path": "path", "sha": "version"}}
        repo.get.return_value = "description: DESC\nmetadata:\n  template_name: NAME"

        response = self.client.get("/awm/tools", headers=headers)
        self.assertEqual(response.status_code, 200)
        expexted_res = {'count': 1,
                        'elements': [{'blueprint': 'description: DESC\n'
                                                   'metadata:\n'
                                                   '  template_name: NAME',
                                      'blueprintType': 'tosca',
                                      'description': 'DESC',
                                      'id': 'path',
                                      'name': 'NAME',
                                      'self': 'http://localhost/awm/tool/path?version=version',
                                      'type': 'vm',
                                      'version': 'version'}],
                        'from': 0,
                        'limit': 100}

        self.assertEqual(response.json, expexted_res)

    @patch('IM.awm.authorization.check_OIDC')
    @patch('IM.awm.routers.tools.Repository')
    @patch('IM.awm.routers.tools.EOSCNodeRegistry')
    @patch('requests.get')
    def test_list_tools_remote(self, mock_get, mock_reg, mock_repo, mock_check_oidc):
        mock_check_oidc.return_value = {'sub': 'test-user', 'name': 'username', 'token': 'at'}
        headers = {"Authorization": "Bearer you-very-secret-token"}

        blueprint = "description: DESC\nmetadata:\n  template_name: NAME"
        repo = MagicMock()
        mock_repo.create.return_value = repo
        repo.list.return_value = {"elem": {"path": "path", "sha": "version"}}
        repo.get.return_value = blueprint

        node1 = EOSCNode(awmAPI=HttpUrl("http://server1.com"), nodeId="n1")
        node2 = EOSCNode(awmAPI=HttpUrl("http://server2.com"), nodeId="n2")
        mock_reg.list_nodes.return_value = [node1, node2]

        resp1 = MagicMock()
        resp1.status_code = 200
        resp1.json.return_value = {'count': 1,
                                   'elements': [{'blueprint': blueprint,
                                                 'blueprintType': 'tosca',
                                                 'id': 'tool1',
                                                 'type': 'vm'}],
                                   'from': 0,
                                   'limit': 100}
        resp2 = MagicMock()
        resp2.status_code = 200
        resp2.json.return_value = {'count': 2,
                                   'elements': [{'blueprint': blueprint,
                                                 'blueprintType': 'tosca',
                                                 'id': 'tool2',
                                                 'type': 'vm'},
                                                {'blueprint': blueprint,
                                                 'blueprintType': 'tosca',
                                                 'id': 'tool3',
                                                 'type': 'vm'}],
                                   'from': 0,
                                   'limit': 100}
        mock_get.side_effect = [resp1, resp2, resp1, resp1, resp1, resp2]

        response = self.client.get("/awm/tools?allNodes=true", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["count"], 4)
        self.assertEqual(len(response.json["elements"]), 4)
        mock_get.assert_any_call('http://server1.com/tools?from0&limit=99',
                                 headers={'Authorization': 'Bearer at'}, timeout=30)
        mock_get.assert_any_call('http://server2.com/tools?from0&limit=98',
                                 headers={'Authorization': 'Bearer at'}, timeout=30)

        response = self.client.get("/awm/tools?allNodes=true&from=1&limit=2", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["count"], 3)
        self.assertEqual(len(response.json["elements"]), 2)
        mock_get.assert_any_call('http://server1.com/tools?from0&limit=2',
                                 headers={'Authorization': 'Bearer at'}, timeout=30)
        mock_get.assert_any_call('http://server2.com/tools?from0&limit=1',
                                 headers={'Authorization': 'Bearer at'}, timeout=30)

        response = self.client.get("/awm/tools?allNodes=true&from=3&limit=2", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["count"], 4)
        self.assertEqual(len(response.json["elements"]), 1)


    @patch('IM.awm.authorization.check_OIDC')
    @patch('IM.awm.routers.tools.Repository')
    def test_get_tool(self, mock_repo, mock_check_oidc):
        mock_check_oidc.return_value = {'sub': 'test-user', 'name': 'username'}
        headers = {"Authorization": "Bearer you-very-secret-token"}

        repo = MagicMock()
        mock_repo.create.return_value = repo
        repo_response = MagicMock()
        repo.get_by_path.return_value = repo_response
        repo_response.status_code = 200
        repo_response.json.return_value = {
            "sha": "version",
            "content": base64.b64encode(b"description: DESC\nmetadata:\n  template_name: NAME").decode()
        }

        response = self.client.get("/awm/tool/toolid", headers=headers)
        self.assertEqual(response.status_code, 200)
        expexted_res = {'blueprint': 'description: DESC\n'
                                     'metadata:\n'
                                     '  template_name: NAME',
                        'blueprintType': 'tosca',
                        'description': 'DESC',
                        'id': 'toolid',
                        'name': 'NAME',
                        'self': 'http://localhost/awm/tool/toolid?version=version',
                        'type': 'vm',
                        'version': 'version'}
        self.assertEqual(response.json, expexted_res)

        repo.get_by_sha.return_value = repo_response
        response = self.client.get("/awm/tool/toolid?version=version", headers=headers)
        self.assertEqual(response.status_code, 200)
        expexted_res = {'blueprint': 'description: DESC\n'
                                     'metadata:\n'
                                     '  template_name: NAME',
                        'blueprintType': 'tosca',
                        'description': 'DESC',
                        'id': 'toolid',
                        'name': 'NAME',
                        'self': 'http://localhost/awm/tool/toolid?version=version',
                        'type': 'vm',
                        'version': 'version'}
        self.assertEqual(response.json, expexted_res)
