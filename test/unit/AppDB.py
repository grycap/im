import unittest
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

import sys

sys.path.append("..")
sys.path.append(".")

from IM.AppDB import AppDB
from mock import patch, MagicMock


class TestAppDB(unittest.TestCase):

    def get_response(self, method, url, verify, cert=None, headers=None, data=None):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]

        resp.status_code = 404

        if method == "GET":
            if url == "/rest/1.0/sites":
                resp.status_code = 200
                resp.text = """<appdb:appdb>
                                <appdb:site id="83757G0" name="RECAS-BARI" infrastructure="Production">
                                <site:url type="home">http://www.recas-bari.it/index.php/en/</site:url>
                                    <site:service type="openstack" id="8016G0" host="cloud.recas.ba.infn.it">
                                    </site:service>
                                    <site:service type="occi" id="8015G0" host="cloud.recas.ba.infn.it">
                                    </site:service>
                                </appdb:site>
                                <appdb:site id="194G0" name="RAL-LCG2" infrastructure="Production">
                                </appdb:site>
                                </appdb:appdb>"""
            elif url == "/rest/1.0/va_providers/8015G0":
                resp.status_code = 200
                resp.text = """<appdb:appdb>
                                <virtualization:provider id="8015G0" in_production="true">
                                <provider:shares>
                                  <vo:vo id="1" projectid="projectid1">ops</vo:vo>
                                  <vo:vo id="2" projectid="projectid2">vo.access.egi.eu</vo:vo>
                                </provider:shares>
                                <provider:url>
                                http://cloud.recas.ba.infn.it:8787/occi/?image=303d8324-69a7-4372-be24-1d68703affd7
                                </provider:url>
                                <provider:endpoint_url>
                                http://cloud.recas.ba.infn.it:8787/occi/
                                </provider:endpoint_url>
                                </virtualization:provider>
                                </appdb:appdb>"""
            elif url == "/rest/1.0/va_providers/8016G0":
                resp.status_code = 200
                resp.text = """<appdb:appdb>
                                <virtualization:provider id="8016G0" in_production="true">
                                <provider:url>https://cloud.recas.ba.infn.it:5000/v3</provider:url>
                                <provider:endpoint_url>
                                http://cloud.recas.ba.infn.it:8774/v2.1/f41187320a504846b132582e172fa268
                                </provider:endpoint_url>
                                <provider:image
                                mp_uri="https://appdb.egi.eu/store/vo/image/6c43f8b5-2e26-5e42-82d5-79bb738fa8e2:8187/"
                                archived="false"
                                vmiversion="2019.01.21"
                                va_provider_image_id="http://url/os_tpl#image_id"
                                appcname="egi.docker.ubuntu.16.04"
                                voname="fedcloud.egi.eu"/>
                                <provider:image
                                mp_uri="https://appdb.egi.eu/store/vo/image/60c0ed25-fea5-5e63-b443-034df484b502:7661/"
                                archived="false"
                                vmiversion="2019.01.21"
                                va_provider_image_id="http://url/os_tpl#image_id2"
                                appcname="egi.ubuntu.16.04"
                                voname="fedcloud.egi.eu"/>
                                <provider:image
                                mp_uri="https://appdb.egi.eu/store/vo/image/83d5e854-a128-5b1f-9457-d32e10a720a6:8135/"
                                archived="true"
                                vmiversion="2018.01.21"
                                va_provider_image_id="http://url/os_tpl#image_id3"
                                appcname="egi.ubuntu.16.04"
                                voname="fedcloud.egi.eu"/>
                                </virtualization:provider>
                                </appdb:appdb>"""

        return resp

    @patch('requests.request')
    def test_get_site_id(self, requests):
        requests.side_effect = self.get_response
        res = AppDB.get_site_id("RECAS-BARI", "openstack")
        self.assertEqual(res, "8016G0")
        res = AppDB.get_site_id("RECAS-BARI", "occi")
        self.assertEqual(res, "8015G0")

    @patch('requests.request')
    def test_get_site_url(self, requests):
        requests.side_effect = self.get_response
        res = AppDB.get_site_url("8016G0", "openstack")
        self.assertEqual(res, "https://cloud.recas.ba.infn.it:5000")

    @patch('requests.request')
    def test_get_image_id(self, requests):
        requests.side_effect = self.get_response
        res = AppDB.get_image_id("8016G0", "egi.ubuntu.16.04", "fedcloud.egi.eu")
        self.assertEqual(res, "image_id2")

    @patch('requests.request')
    def test_get_image_id_from_uri(self, requests):
        requests.side_effect = self.get_response
        res = AppDB.get_image_id_from_uri("8016G0", "83d5e854-a128-5b1f-9457-d32e10a720a6:8135")
        self.assertEqual(res, "image_id3")

    @patch('requests.request')
    def test_get_image_data(self, requests):
        requests.side_effect = self.get_response
        str_url = "appdb://RECAS-BARI/egi.ubuntu.16.04?fedcloud.egi.eu"
        site_url, image_id, _ = AppDB.get_image_data(str_url, "openstack")
        self.assertEqual(site_url, "https://cloud.recas.ba.infn.it:5000")
        self.assertEqual(image_id, "image_id2")

        str_url = "appdb://RECAS-BARI/60c0ed25-fea5-5e63-b443-034df484b502:7661"
        site_url, image_id, _ = AppDB.get_image_data(str_url, "openstack")
        self.assertEqual(site_url, "https://cloud.recas.ba.infn.it:5000")
        self.assertEqual(image_id, "image_id2")

        str_url = "appdb://egi.ubuntu.16.04?fedcloud.egi.eu"
        site_url, image_id, _ = AppDB.get_image_data(str_url, "openstack", site='cloud.recas.ba.infn.it')
        self.assertEqual(site_url, "https://cloud.recas.ba.infn.it:5000")
        self.assertEqual(image_id, "image_id2")

        str_url = "appdb://egi.ubuntu.16.04"
        site_url, image_id, _ = AppDB.get_image_data(str_url, "openstack", vo="fedcloud.egi.eu",
                                                     site='cloud.recas.ba.infn.it')
        self.assertEqual(site_url, "https://cloud.recas.ba.infn.it:5000")
        self.assertEqual(image_id, "image_id2")

    @patch('requests.request')
    def test_get_project_ids(self, requests):
        requests.side_effect = self.get_response
        projects = AppDB.get_project_ids('8015G0')
        self.assertEqual(projects, {'ops': 'projectid1', 'vo.access.egi.eu': 'projectid2'})
