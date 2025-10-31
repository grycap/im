import sys

sys.path.append(".")
sys.path.append("..")

import flask
import unittest
from IM.awm import awm_bp
from mock import patch


class TestUser(unittest.TestCase):

    def __init__(self, *args):
        unittest.TestCase.__init__(self, *args)

    def setUp(self):
        app = flask.Flask("test_app")
        app.register_blueprint(awm_bp, url_prefix='/awm')
        self.client = app.test_client()

    @patch('IM.awm.authorization.check_OIDC')
    def test_get_user(self, mock_check_oidc):
        mock_check_oidc.return_value = {'sub': 'test-user', 'name': 'username'}
        headers = {"Authorization": "Bearer you-very-secret-token"}
        response = self.client.get("/awm/user/info", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'base_id': 'test-user', 'user_dn': 'username', 'vos': []})
