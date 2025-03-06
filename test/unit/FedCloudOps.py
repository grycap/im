import unittest
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

import sys

sys.path.append("..")
sys.path.append(".")

from IM.FedCloudOps import FedCloudOps
from mock import patch, MagicMock


class TestFedCloudOps(unittest.TestCase):

    def get_response(self, url, *args, **kwargs):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]

        resp.status_code = 404
        resp.text = "Not Found"

        if url == "/EGI-Federation/fedcloud-catchall-operations/main/sites/BIFI.yaml":
            resp.status_code = 200
            resp.text = """---
gocdb: BIFI
endpoint: https://colossus.cesar.unizar.es:5000/v3
images:
  sync: true
  formats:
    - qcow2
    - raw
vos:
  - name: ops
    auth:
      project_id: 038db3eeca5c4960a443a89b92373cd2"""

        return resp

    @patch('requests.get')
    def test_get_project_ids(self, requests):
        requests.side_effect = self.get_response
        projects = FedCloudOps.get_project_ids('BIFI')
        self.assertEqual(projects, {'ops': '038db3eeca5c4960a443a89b92373cd2'})
