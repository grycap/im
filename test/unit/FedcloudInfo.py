import unittest

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

import sys

sys.path.append("..")
sys.path.append(".")

from IM.FedcloudInfo import FedcloudInfo
from mock import patch, MagicMock


class TestFedcloudInfo(unittest.TestCase):

    def get_response(self, method, url, **kwargs):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]

        resp.status_code = 404

        if method == "GET":
            if url == "/sites/":
                resp.status_code = 200
                resp.json.return_value = [
                    {
                        "id": "15522G0",
                        "name": "INFN-CLOUD-BARI",
                        "url": "https://keystone.recas.ba.infn.it/v3",
                        "state": "",
                        "hostname": "nova.recas.ba.infn.it",
                    }
                ]
            if url == "/site/INFN-CLOUD-BARI/":
                resp.status_code = 200
                resp.json.return_value = {
                    "id": "15522G0",
                    "name": "INFN-CLOUD-BARI",
                    "url": "https://keystone.recas.ba.infn.it/v3",
                    "state": "",
                    "hostname": "nova.recas.ba.infn.it",
                }
            elif url == "/site/INFN-CLOUD-BARI/projects":
                resp.status_code = 200
                resp.json.return_value = [
                    {"id": "projectid1", "name": "ops"},
                    {"id": "projectid2", "name": "vo.access.egi.eu"},
                ]
            elif url in [
                "/site/INFN-CLOUD-BARI/fedcloud.egi.eu/images",
                "/site/INFN-CLOUD-BARI/images",
                "/images",
            ]:
                resp.status_code = 200
                resp.json.return_value = [
                    {
                        "egi_id": "egi.docker",
                        "id": "image_id2",
                        "endpoint": "https://keystone.recas.ba.infn.it/v3",
                        "mpuri": "https://appdb.egi.eu/store/vo/image/0c0a1ffc-b936-5efd-920c-b648a02cccf4:13976/",
                        "name": "EGI Docker",
                        "version": "2023.09.19",
                        "vo": "fedcloud.egi.eu",
                    },
                    {
                        "egi_id": "egi.docker",
                        "id": "image_id3",
                        "endpoint": "https://keystone.recas.ba.infn.it/v3",
                        "mpuri": "https://appdb.egi.eu/store/vo/image/0c0a1ffc-b936-5e66-920c-b648a02cccf4:13976/",
                        "name": "EGI Docker",
                        "version": "2023.09.01",
                        "vo": "fedcloud.egi.eu",
                    },
                ]
        return resp

    @patch("requests.request")
    def test_get_site_url(self, requests):
        requests.side_effect = self.get_response
        res = FedcloudInfo.get_site_url("INFN-CLOUD-BARI")
        self.assertEqual(res, "https://keystone.recas.ba.infn.it")

    @patch("requests.request")
    def test_get_image_id(self, requests):
        requests.side_effect = self.get_response
        res = FedcloudInfo.get_image_id(
            "INFN-CLOUD-BARI", "egi.docker", "fedcloud.egi.eu"
        )
        self.assertEqual(res, "image_id2")

    @patch("requests.request")
    def test_get_image_data(self, requests):
        requests.side_effect = self.get_response
        str_url = "egi://INFN-CLOUD-BARI/egi.docker?fedcloud.egi.eu"
        site_url, image_id, _ = FedcloudInfo.get_image_data(str_url)
        self.assertEqual(site_url, "https://keystone.recas.ba.infn.it")
        self.assertEqual(image_id, "image_id2")

    @patch("requests.request")
    def test_get_project_ids(self, requests):
        requests.side_effect = self.get_response
        projects = FedcloudInfo.get_project_ids("INFN-CLOUD-BARI")
        self.assertEqual(
            projects, {"ops": "projectid1", "vo.access.egi.eu": "projectid2"}
        )
