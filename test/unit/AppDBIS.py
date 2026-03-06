import unittest
import json
import os
from urllib.parse import urlparse
from IM.AppDBIS import AppDBIS
from radl.radl import system, Feature
from mock import patch, MagicMock


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    with open(abs_file_path, 'r') as f:
        return f.read()


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
                         "images.008b85eaa022d50fb385e3fcae018d34ff48abdb"):
                resp.status_code = 200
                resp.json.return_value = json.loads(read_file_as_string('../files/appdbis_image.json'))
        elif method == "POST":
            if url == "/graphql":
                graph_ql_req1 = """
                {
                  siteCloudComputingEndpoints(filter: {
                    templates: {
                      CPU: {gt: 2},
                      RAM: {gt: 1024}
                    },
                    serviceStatus: {
                      value: {ne: CRITICAL}
                    },
                    images: {
                      entityName: {
                        ilike: "*Name* [Ubuntu/20.04/*]"
                      },
                      shareVO:{
                        ilike: "vo.access.egi.eu"
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
                          ilike: "vo.access.egi.eu"
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
                          ilike: "*Name* [Ubuntu/20.04/*]"
                        },
                        shareVO:{
                          ilike: "vo.access.egi.eu"
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
                          imageID
                        }
                      }
                    }
                  }
                }
                """
                self.maxDiff = None
                expected1 = '{"query": "%s"}' % graph_ql_req1.replace(' ', '').replace('"', '\\"').replace('\n', '')

                graph_ql_req2 = """
                {
                  siteCloudComputingEndpoints(filter: {
                    serviceStatus: {
                      value: {ne: CRITICAL}
                    },
                    images: {
                      shareVO:{
                        eq: "vo.access.egi.eu"
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
                          eq: "vo.access.egi.eu"
                        }
                      }) {
                        items {
                          totalVM,
                          maxVM,
                          projectID
                        }
                      }
                      site {
                        name
                      }
                    }
                  }
                }
                """
                expected2 = '{"query": "%s"}' % graph_ql_req2.replace(' ', '').replace('"', '\\"').replace('\n', '')
                self.assertIn(data, [expected1, expected2])

                resp.status_code = 200
                if data == expected1:
                    resp.json.return_value = json.loads(read_file_as_string('../files/appdbis_res.json'))
                else:
                    resp.json.return_value = json.loads(read_file_as_string('../files/appdbis_sites.json'))

        return resp

    @patch('requests.request')
    def test_get_image_list(self, requests):
        requests.side_effect = self.get_response
        app = AppDBIS()
        code, res = app.get_image_list(10)
        self.assertEqual(code, 200)
        self.assertEqual(len(res), 20)
        self.assertEqual(res[0]["entityName"],
                         "Image for EGI Ubuntu 18.04 [Ubuntu/18.04/VirtualBox]")

    @patch('requests.request')
    def test_get_image(self, requests):
        requests.side_effect = self.get_response
        app = AppDBIS()
        code, res = app.get_image('egi.top.vaproviders.images.008b85eaa022d50fb385e3fcae018d34ff48abdb')
        self.assertEqual(code, 200)
        self.assertEqual(res["imageBaseMpUri"],
                         "https://appdb.egi.eu/store/vm/image/9117c171-8ca5-41ad-bd36-4b71e4e5dc85:7949")

    @patch('requests.request')
    def test_get_endpoints_and_images(self, requests):
        requests.side_effect = self.get_response
        app = AppDBIS()
        code, res = app.get_endpoints_and_images("vo.access.egi.eu", "*Name* [Ubuntu/20.04/*]", 2, 1024)
        self.assertEqual(code, 200)
        self.assertEqual(len(res), 8)
        self.assertEqual(res[0]["site"]["name"], "CESGA")

    @patch('IM.AppDBIS.AppDBIS.get_image_list')
    def test_search_vm(self, get_image_list):
        images = json.loads(read_file_as_string('../files/appdbis_images.json'))
        get_image_list.return_value = 200, images["data"]
        app = AppDBIS()
        sys = system("s0", [Feature("disk.0.os.flavour", "=", "Ubuntu"),
                            Feature("disk.0.os.version", "=", "20.04"),
                            Feature("disk.0.os.image.name", "=", "EGI"),
                            Feature("cpu.count", "=", 2),
                            Feature("memory.size", "=", 1024, "m")])
        res = app.search_vm(sys)
        self.assertEqual(len(res), 1)

        self.assertEqual(res[0].name, "s0")
        self.assertEqual(res[0].getValue('disk.0.image.vo'), "vo.access.egi.eu")
        self.assertEqual(res[0].getValue('disk.0.image.url'), ("ost://thor.univ-lille.fr:5000/"
                                                               "d57482d1-9253-4ee7-b3d0-a64d92682591"))

    @patch('requests.request')
    def test_get_sites_supporting_vo(self, requests):
        requests.side_effect = self.get_response
        app = AppDBIS()
        code, res = app.get_sites_supporting_vo("vo.access.egi.eu")
        self.assertEqual(code, 200)
        self.assertEqual(len(res), 9)
        self.assertEqual(res[0][0], "INFN-PADOVA-STACK")

    @patch('IM.AppDBIS.AppDBIS.get_image_list')
    @patch('IM.AppDBIS.AppDBIS.get_sites_supporting_vo')
    def test_list_images(self, get_sites_supporting_vo, get_image_list):
        images = json.loads(read_file_as_string('../files/appdbis_images.json'))
        get_image_list.return_value = 200, images["data"]
        get_sites_supporting_vo.return_value = 200, [("NAME", "https://thor.univ-lille.fr:5000", "projectid")]
        app = AppDBIS()
        filters = {"distribution": "Ubuntu",
                   "version": "20.04",
                   "vo": "voname",
                   "app": "EGI"}

        res = app.list_images(filters)
        self.assertEqual(res, [{'name': 'NAME - Image for EGI Ubuntu 20.04 [Ubuntu/20.04/VirtualBox]',
                                'uri': 'ost://thor.univ-lille.fr:5000/d57482d1-9253-4ee7-b3d0-a64d92682591'}])
