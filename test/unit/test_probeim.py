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
        """ Testing IMinfrastructureOper.list_infrastructure """
        request_get_mock.return_value = MockResponse({"key2": "value2"}, 200)
        anyheader = {"headerkey": "headervalue"}
        rl = probeim.IM.list_infrastructure("http://server.com:8800", anyheader)
        assert rl.statuscode == 200
        assert rl.info == 'list method OK'

    @mock.patch('probeim.IM.requestIM')
    @mock.patch('time.sleep')
    def test_create_infrastructure(self, _, request_post_mock):
        """ Testing IMinfrastructureOper.create_infrastructure """
        request_post_mock.return_value = MockResponse('{"uri": "any/url"}', 200)
        anyheader = {"headerkey": "headervalue"}
        rc = probeim.IM.create_infrastructure("http://server.com:8800", anyheader)
        jsonuri = json.loads(str(request_post_mock.return_value.info))
        assert rc.statuscode == 200
        assert str(jsonuri['uri']) == 'any/url'

    @mock.patch('probeim.IM.requestIM')
    @mock.patch('time.sleep')
    def test_start_infrastructure(self, _, request_put_mock):
        """ Testing IMinfrastructureOper.start_infrastructure """
        request_put_mock.return_value = MockResponse({}, 200)
        anyheader = {"headerkey": "headervalue"}
        anyurl = 'any/url'
        rc = probeim.IM.start_infrastructure(anyheader, anyurl)
        assert rc.statuscode == 200
        assert rc.info == 'start method OK'

    @mock.patch('probeim.IM.requestIM')
    @mock.patch('time.sleep')
    def test_create_vm(self, _, request_vmpost_mock):
        """ Testing IMinfrastructureOper.create_vm """
        request_vmpost_mock.return_value = MockResponse({"uri-list": []}, 200)
        anyheader = {"headerkey": "headervalue"}
        anyurl = 'any/url'
        cv = probeim.IM.create_vm(anyheader, anyurl)
        assert cv.statuscode == 200
        assert cv.info == 'Creation of VM is OK'

    @mock.patch('probeim.IM.requestIM')
    @mock.patch('time.sleep')
    def test_delete_vm(self, _, request_delete_mock):
        """ Testing IMinfrastructureOper.delete_infrastructure """
        request_delete_mock.return_value = MockResponse({}, 200)
        anyheader = {"headerkey": "headervalue"}
        anyurl = 'any/url'
        dv = probeim.IM.delete_infrastructure(anyheader, anyurl)
        assert dv.statuscode == 200
        assert dv.info == 'delete_infrastructure is OK'


if __name__ == '__main__':
    unittest.main()
