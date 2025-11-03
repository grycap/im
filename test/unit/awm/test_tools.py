import sys

sys.path.append(".")
sys.path.append("..")

import flask
import unittest
from IM.awm import awm_bp
from mock import patch, MagicMock


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
                                      'self': 'http://localhost/awm/tools/path?version=version',
                                      'type': 'vm',
                                      'version': 'version'}],
                        'from': 0,
                        'limit': 100}

        self.assertEqual(response.json, expexted_res)
