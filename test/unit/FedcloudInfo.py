import unittest

from urllib.parse import urlparse

import sys

sys.path.append("..")
sys.path.append(".")

from radl.radl import system, Feature
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
                        "egi_id": "egi_vm_images/docker:22.04",
                        "id": "93759c63-b998-4222-84eb-5fa10af1113b",
                        "endpoint": "https://keystone.recas.ba.infn.it/v3",
                        "mpuri": ("registry.egi.eu/egi_vm_images/docker:22.04-sha256:"
                                  "09ef8b577905758d51bc2515f8bef89a9ee11202b64878bb59a02417b55c95ce"),
                        "name": "registry.egi.eu egi_vm_images/docker:22.04",
                        "version": "2025-10-07-fc45d0d3",
                        "vo": "fedcloud.egi.eu",
                    },
                    {
                        "egi_id": "egi_vm_images/ubuntu:24.04",
                        "id": "8d4755c8-6157-4dd0-a60e-3f8cfbfcbc60",
                        "endpoint": "https://keystone.recas.ba.infn.it/v3",
                        "mpuri": ("registry.egi.eu/egi_vm_images/ubuntu:24.04-sha256:"
                                  "4bcb811d1fa2f53e794d9be240c36f004e45308128b2cba9e3a51a7975bd2359"),
                        "name": "registry.egi.eu egi_vm_images/ubuntu:24.04",
                        "version": "2025-10-07-fc45d0d3",
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
            "INFN-CLOUD-BARI", "egi_vm_images/ubuntu:24.04", "fedcloud.egi.eu"
        )
        self.assertEqual(res, "8d4755c8-6157-4dd0-a60e-3f8cfbfcbc60")

    @patch("requests.request")
    def test_get_image_data(self, requests):
        requests.side_effect = self.get_response
        str_url = "egi://INFN-CLOUD-BARI/egi_vm_images/ubuntu:24.04?fedcloud.egi.eu"
        site_url, image_id, _ = FedcloudInfo.get_image_data(str_url)
        self.assertEqual(site_url, "https://keystone.recas.ba.infn.it")
        self.assertEqual(image_id, "8d4755c8-6157-4dd0-a60e-3f8cfbfcbc60")

    @patch("requests.request")
    def test_get_project_ids(self, requests):
        requests.side_effect = self.get_response
        projects = FedcloudInfo.get_project_ids("INFN-CLOUD-BARI")
        self.assertEqual(
            projects, {"ops": "projectid1", "vo.access.egi.eu": "projectid2"}
        )

    @patch("requests.request")
    def test_search_vm(self, requests):
        radl_system = system("s0", [Feature("disk.0.os.name", "=", "linux"),
                                    Feature("disk.0.os.flavour", "=", "ubuntu"),
                                    Feature("disk.0.os.version", "=", "24.04")])
        requests.side_effect = self.get_response
        res = FedcloudInfo.search_vm(radl_system)

        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].getValue("disk.0.image.url"),
                         "ost://keystone.recas.ba.infn.it/8d4755c8-6157-4dd0-a60e-3f8cfbfcbc60")
        self.assertEqual(res[0].getValue("disk.0.image.vo"), "fedcloud.egi.eu")
