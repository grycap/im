import sys

sys.path.append(".")
sys.path.append("..")

import flask
import unittest
from IM.rest.awm import awm_bp
from IM import __version__


class TestService(unittest.TestCase):

    def __init__(self, *args):
        unittest.TestCase.__init__(self, *args)

    def setUp(self):
        app = flask.Flask("test_app")
        app.register_blueprint(awm_bp, url_prefix='/awm')
        self.client = app.test_client()

    def test_get_version(self):
        response = self.client.get("/awm/version")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"message": f"{__version__}"})
