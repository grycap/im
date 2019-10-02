import unittest
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
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
                                    archived="false"
                                    vmiversion="2019.01.21"
                                    va_provider_image_id="http://url/os_tpl#image_id"
                                    appcname="egi.docker.ubuntu.16.04"
                                    voname="fedcloud.egi.eu"/>
                                <provider:image
                                    archived="false"
                                    vmiversion="2019.01.21"
                                    va_provider_image_id="http://url/os_tpl#image_id2"
                                    appcname="egi.ubuntu.16.04"
                                    voname="fedcloud.egi.eu"/>
                                <provider:image
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
        res = AppDB.get_site_url("8015G0", "occi")
        self.assertEqual(res, "http://cloud.recas.ba.infn.it:8787/occi/")

    @patch('requests.request')
    def test_get_image_id(self, requests):
        requests.side_effect = self.get_response
        res = AppDB.get_image_id("8016G0", "egi.ubuntu.16.04", "fedcloud.egi.eu")
        self.assertEqual(res, "image_id2")

    @patch('requests.request')
    def test_get_image_data(self, requests):
        requests.side_effect = self.get_response
        str_url = "appdb://RECAS-BARI/egi.ubuntu.16.04?fedcloud.egi.eu"
        site_url, image_id, msg = AppDB.get_image_data(str_url, "openstack")
        self.assertEqual(site_url, "https://cloud.recas.ba.infn.it:5000")
        self.assertEqual(image_id, "image_id2")
