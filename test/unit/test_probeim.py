import unittest
import mock
import sys
import json

sys.path.append(".")
sys.path.append("../monitoring")
sys.path.append("./monitoring")

import probeim


class MockResponse:

    def __init__(self, json_data, status_code):
        self.info = json_data
        self.statuscode = status_code


class TestProbeIMZabbix(unittest.TestCase):

    @mock.patch('probeim.IM.requestIM')
    def test_list_infrastructure(self, request_get_mock):
        """ Testing IM.list_infrastructure """
        request_get_mock.return_value = MockResponse({"key2": "value2"}, 200)
        im = probeim.IM("http://server.com:8800")
        rl = im.list_infrastructure()
        self.assertEqual(rl.statuscode, 200)
        self.assertEqual(rl.info, 'list method OK')

    @mock.patch('probeim.IM.requestIM')
    def test_create_infrastructure(self, request_post_mock):
        """ Testing IM.create_infrastructure """
        request_post_mock.return_value = MockResponse('{"uri": "any/url"}', 200)
        im = probeim.IM("http://server.com:8800")
        rc = im.create_infrastructure()
        jsonuri = json.loads(str(request_post_mock.return_value.info))
        self.assertEqual(rc.statuscode, 200)
        self.assertEqual(jsonuri['uri'], 'any/url')

    @mock.patch('probeim.IM.requestIM')
    def test_start_infrastructure(self, request_put_mock):
        """ Testing IM.start_infrastructure """
        request_put_mock.return_value = MockResponse({}, 200)
        im = probeim.IM("http://server.com:8800")
        rc = im.start_infrastructure('any/url')
        self.assertEqual(rc.statuscode, 200)
        self.assertEqual(rc.info, 'start method OK')

    @mock.patch('probeim.IM.requestIM')
    def test_create_vm(self, request_vmpost_mock):
        """ Testing IM.create_vm """
        request_vmpost_mock.return_value = MockResponse({"uri-list": []}, 200)
        im = probeim.IM("http://server.com:8800")
        cv = im.create_vm('any/url')
        self.assertEqual(cv.statuscode, 200)
        self.assertEqual(cv.info, 'Creation of VM is OK')

    @mock.patch('probeim.IM.requestIM')
    def test_delete_vm(self, request_delete_mock):
        """ Testing IM.delete_infrastructure """
        request_delete_mock.return_value = MockResponse({}, 200)
        im = probeim.IM("http://server.com:8800")
        dv = im.delete_infrastructure('any/url')
        self.assertEqual(dv.statuscode, 200)
        self.assertEqual(dv.info, 'delete_infrastructure is OK')

    @mock.patch('probeim.IM.requestIM')
    def test_get_infrastructure_vms(self, get_infrastructure_vms):
        """ Testing IM.get_infrastructure_vms """
        get_infrastructure_vms.return_value = MockResponse('{"uri-list": [{"uri": "uri1"}]}', 200)
        im = probeim.IM("http://server.com:8800")
        dv = im.get_infrastructure_vms('any/url')
        self.assertEqual(dv.statuscode, 200)
        self.assertEqual(dv.info, [{"uri": "uri1"}])

    @mock.patch('probeim.IM.requestIM')
    def test_get_im_version(self, get_im_version):
        """ Testing IM.get_im_version """
        get_im_version.return_value = MockResponse('{"version": "1.10.0"}', 200)
        im = probeim.IM("http://server.com:8800")
        dv = im.get_im_version()
        self.assertEqual(dv.statuscode, 200)
        self.assertEqual(dv.info, 'get version method OK')

    @mock.patch('probeim.IM.create_infrastructure')
    @mock.patch('probeim.IM.start_infrastructure')
    @mock.patch('probeim.IM.list_infrastructure')
    @mock.patch('probeim.IM.create_vm')
    @mock.patch('probeim.IM.delete_infrastructure')
    @mock.patch('probeim.IM.get_infrastructure_vms')
    @mock.patch('probeim.IM.get_im_version')
    @mock.patch('time.sleep')
    def test_main(self, _, get_im_version, get_infrastructure_vms, delete, create_vm, list_i, start, create):
        """ Testing main function """
        delete.return_value = MockResponse({}, 200)
        create_vm.return_value = MockResponse({"uri-list": []}, 200)
        list_i.return_value = MockResponse({"key2": "value2"}, 200)
        start.return_value = MockResponse({}, 200)
        create.return_value = MockResponse("any/url", 200)
        get_im_version.return_value = MockResponse('{"version": "1.10.0"}', 200)
        get_infrastructure_vms.side_effect = [MockResponse(["vm"], 200), MockResponse(["vm", "vm2"], 200)]
        rc, _, _ = probeim.main("", None, "user", "pass")
        self.assertEqual(rc, 0)


if __name__ == '__main__':
    unittest.main()
