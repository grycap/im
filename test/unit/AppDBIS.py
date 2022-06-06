import unittest
import json
import os
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.AppDBIS import AppDBIS
from radl.radl import system, Feature
from mock import patch, MagicMock


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestAppDBIS(unittest.TestCase):

    def get_response(self, method, url, verify, cert=None, headers=None, data=None):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]
        query = parts[4]

        resp.status_code = 404
        if method == "GET":
            if url == "/rest/cloud/computing/images" and query == "limit=10&skip=0":
                resp.status_code = 200
                resp.json.return_value = json.loads(read_file_as_string('../files/appdbis_images.json'))
            elif url == "/rest/cloud/computing/images" and query == "limit=10&skip=10":
                resp.status_code = 200
                resp.json.return_value = json.loads(read_file_as_string('../files/appdbis_images_p2.json'))
            elif url == ("/rest/cloud/computing/images/egi.top.vaproviders."
                         "images.00716434466174a6823f0224254aa7c91acff60d"):
                resp.status_code = 200
                resp.json.return_value = json.loads(read_file_as_string('../files/appdbis_image.json'))
        elif method == "POST":
            if url == "/graphql":
                graph_ql_req = """
                {
                  siteCloudComputingEndpoints(filter: {
                    templates: {
                      CPU: {gt: 2},
                      RAM: {gt: 1024}
                    },
                    images: {
                      entityName: {
                        ilike: "*Name* [Ubuntu/16.04/*]"
                      },
                      shareVO:{
                        ilike: "fedcloud.egi.eu"
                      }
                    },
                    isInProduction:true,
                    beta:false,
                    endpointServiceType: {
                      eq: "org.openstack.nova"
                    }
                  }) {
                    items {
                      gocEndpointUrl,
                      shares(filter: {
                        VO:{
                          ilike: "fedcloud.egi.eu"
                        }
                      }) {
                        items {
                          totalVM,
                          maxVM,
                          runningVM,
                          suspendedVM,
                          VO
                        }
                      }
                      serviceStatus{
                        value,
                        timestamp
                      },
                      serviceDowntimes {
                        outcome,
                        severity,
                        endDate
                      },
                      site {
                        name
                      },
                      images(filter: {
                        entityName:{
                          ilike: "*Name* [Ubuntu/16.04/*]"
                        },
                        shareVO:{
                          ilike: "fedcloud.egi.eu"
                        }
                      }) {
                        totalCount,
                        items {
                          share {
                            projectID,
                            VO
                          },
                          OSFamily,
                          OSName,
                          OSVersion,
                          OSPlatform,
                          entityName,
                        }
                      }
                    }
                  }
                }
                """
                self.maxDiff = None
                expected = '{"query": "%s"}' % graph_ql_req.replace(' ', '').replace('"', '\\"').replace('\n', '')
                self.assertEqual(data, expected)

                resp.status_code = 200
                resp.json.return_value = json.loads(read_file_as_string('../files/appdbis_res.json'))

        return resp

    @patch('requests.request')
    def test_get_image_list(self, requests):
        requests.side_effect = self.get_response
        app = AppDBIS()
        code, res = app.get_image_list(10)
        self.assertEqual(code, 200)
        self.assertEqual(len(res), 20)
        self.assertEqual(res[0]["applicationEnvironmentAppName"],
                         "VO VO.NEXTGEOSS.EU Image for EGI CentOS 7 [CentOS/7/VirtualBox]")

    @patch('requests.request')
    def test_get_image(self, requests):
        requests.side_effect = self.get_response
        app = AppDBIS()
        code, res = app.get_image('egi.top.vaproviders.images.00716434466174a6823f0224254aa7c91acff60d')
        self.assertEqual(code, 200)
        self.assertEqual(res["imageBaseMpUri"],
                         "https://appdb.egi.eu/store/vm/image/b3008f58-8a15-4480-9c03-c0770eafbb3b:7751")

    @patch('requests.request')
    def test_get_endpoints_and_images(self, requests):
        requests.side_effect = self.get_response
        app = AppDBIS()
        code, res = app.get_endpoints_and_images("fedcloud.egi.eu", "*Name* [Ubuntu/16.04/*]", 2, 1024)
        self.assertEqual(code, 200)
        self.assertEqual(len(res), 8)
        self.assertEqual(res[0]["site"]["name"], "CESGA")

    @patch('IM.AppDBIS.AppDBIS.get_endpoints_and_images')
    def test_search_vm(self, get_endpoints_and_images):
        end_res = json.loads(read_file_as_string('../files/appdbis_res.json'))["data"]["siteServices"]["items"]
        get_endpoints_and_images.return_value = 200, end_res
        app = AppDBIS()
        sys = system("s0", [Feature("disk.0.os.flavour", "=", "Ubuntu"),
                            Feature("disk.0.os.version", "=", "16.04"),
                            Feature("disk.0.os.image.name", "=", "Name"),
                            Feature("cpu.count", "=", 2),
                            Feature("memory.size", "=", 1024, "m")])
        res = app.search_vm(sys)
        self.assertEqual(len(res), 26)
        self.assertEqual(get_endpoints_and_images.call_args_list[0][0],
                         ('*', "*Name* [Ubuntu/16.04/*]", 2, 1024))

        self.assertEqual(res[0].name, "s0")
        self.assertEqual(res[0].getValue('disk.0.image.vo'), "fedcloud.egi.eu")
        self.assertEqual(res[0].getValue('disk.0.image.url'), ("https://fedcloud-osservices.egi.cesga.es:5000/"
                                                               "7e59923c-3932-4a4f-a67d-06f412800f5b"))
