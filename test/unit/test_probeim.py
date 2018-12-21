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
    @mock.patch('time.sleep')
    def test_list_infrastructure(self, _, request_get_mock):
        """ Testing IM.list_infrastructure """
        request_get_mock.return_value = MockResponse({"key2": "value2"}, 200)
        anyheader = {"headerkey": "headervalue"}
        rl = probeim.IM.list_infrastructure("http://server.com:8800", anyheader)
        self.assertEqual(rl.statuscode, 200)
        self.assertEqual(rl.info, 'list method OK')

    @mock.patch('probeim.IM.requestIM')
    @mock.patch('time.sleep')
    def test_create_infrastructure(self, _, request_post_mock):
        """ Testing IM.create_infrastructure """
        request_post_mock.return_value = MockResponse('{"uri": "any/url"}', 200)
        anyheader = {"headerkey": "headervalue"}
        rc = probeim.IM.create_infrastructure("http://server.com:8800", anyheader)
        jsonuri = json.loads(str(request_post_mock.return_value.info))
        self.assertEqual(rc.statuscode, 200)
        self.assertEqual(jsonuri['uri'], 'any/url')

    @mock.patch('probeim.IM.requestIM')
    @mock.patch('time.sleep')
    def test_start_infrastructure(self, _, request_put_mock):
        """ Testing IM.start_infrastructure """
        request_put_mock.return_value = MockResponse({}, 200)
        anyheader = {"headerkey": "headervalue"}
        anyurl = 'any/url'
        rc = probeim.IM.start_infrastructure(anyheader, anyurl)
        self.assertEqual(rc.statuscode, 200)
        self.assertEqual(rc.info, 'start method OK')

    @mock.patch('probeim.IM.requestIM')
    @mock.patch('time.sleep')
    def test_create_vm(self, _, request_vmpost_mock):
        """ Testing IM.create_vm """
        request_vmpost_mock.return_value = MockResponse({"uri-list": []}, 200)
        anyheader = {"headerkey": "headervalue"}
        anyurl = 'any/url'
        cv = probeim.IM.create_vm(anyheader, anyurl)
        self.assertEqual(cv.statuscode, 200)
        self.assertEqual(cv.info, 'Creation of VM is OK')

    @mock.patch('probeim.IM.requestIM')
    @mock.patch('time.sleep')
    def test_delete_vm(self, _, request_delete_mock):
        """ Testing IM.delete_infrastructure """
        request_delete_mock.return_value = MockResponse({}, 200)
        anyheader = {"headerkey": "headervalue"}
        anyurl = 'any/url'
        dv = probeim.IM.delete_infrastructure(anyheader, anyurl)
        self.assertEqual(dv.statuscode, 200)
        self.assertEqual(dv.info, 'delete_infrastructure is OK')

    def test_update_imheaders(self):
        """ Testing IM.update_imheaders """
        headers = probeim.IM.update_imheaders()
        expected_res = ("id = os; type = OpenNebula; host = http://onehost.com:2633; "
                        "username = mon_user; password = mon_test_1X;\\n"
                        "id = im; type = InfrastructureManager; "
                        "username = mon_user; password = mon_test_1X;\\n")
        self.assertEqual(headers['Authorization'], expected_res)

        headers = probeim.IM.update_imheaders("sometoken")
        expected_res = ("id = os; type = OpenNebula; host = http://onehost.com:2633; "
                        "token = sometoken;\\n"
                        "id = im; type = InfrastructureManager; "
                        "token = sometoken;\\n")
        self.assertEqual(headers['Authorization'], expected_res)

    @mock.patch('probeim.IM.create_infrastructure')
    @mock.patch('probeim.IM.start_infrastructure')
    @mock.patch('probeim.IM.list_infrastructure')
    @mock.patch('probeim.IM.create_vm')
    @mock.patch('probeim.IM.delete_infrastructure')
    @mock.patch('time.sleep')
    def test_main(self, _, delete, create_vm, list_i, start, create):
        """ Testing main function """
        delete.return_value = MockResponse({}, 200)
        create_vm.return_value = MockResponse({"uri-list": []}, 200)
        list_i.return_value = MockResponse({"key2": "value2"}, 200)
        start.return_value = MockResponse({}, 200)
        create.return_value = MockResponse('{"uri": "any/url"}', 200)
        success, msg = probeim.main("", None)
        self.assertTrue(success, msg)


if __name__ == '__main__':
    unittest.main()
