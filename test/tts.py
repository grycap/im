#! /usr/bin/env python
#
# IM - Infrastructure Manager
# Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import unittest
import os

from IM.tts.tts import TTSClient
from radl import radl_parse
from mock import patch, MagicMock


class TestTTSClient(unittest.TestCase):
    """
    Class to test the TTCLient class
    """
    @classmethod
    def setUpClass(cls):
        cls.last_op = None, None

    def get_response(self):
        method, url = self.__class__.last_op

        resp = MagicMock()

        if method == "GET":
            if "/api/credential/somecred" == url:
                resp.status = 200
                resp.read.return_value = ('[{"name": "Username", "type": "text", "value": "username"},'
                                          '{"name": "Password", "type": "text", "value": "password"}]')
            if "/api/service" == url:
                resp.status = 200
                resp.read.return_value = ('{"service_list": [{"id":"sid", "type":"stype", "host": "shost"}]}')
        elif method == "POST":
            if url == "/api/credential/":
                resp.status = 303
                resp.msg = {'location': "/api/credential/somecred"}

        return resp
    
    def request(self, method, url, body=None, headers={}):
        self.__class__.last_op = method, url

    @patch('httplib.HTTPConnection')
    def test_list_endservices(self, connection):
        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.putrequest.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        token = "eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkYzVkNWFiNy02ZGI5LTQwNzktOTg1Yy04MGFjMDUwMTcwNjYiLCJpc3MiOiJodHRwczpcL1wvaWFtLXRlc3QuaW5kaWdvLWRhdGFjbG91ZC5ldVwvIiwiZXhwIjoxNDY2MDkzOTE3LCJpYXQiOjE0NjYwOTAzMTcsImp0aSI6IjE1OTU2N2U2LTdiYzItNDUzOC1hYzNhLWJjNGU5MmE1NjlhMCJ9.eINKxJa2J--xdGAZWIOKtx9Wi0Vz3xHzaSJWWY-UHWy044TQ5xYtt0VTvmY5Af-ngwAMGfyaqAAvNn1VEP-_fMYQZdwMqcXLsND4KkDi1ygiCIwQ3JBz9azBT1o_oAHE5BsPsE2BjfDoVRasZxxW5UoXCmBslonYd8HK2tUVjz0"
        iss = "https://iam-test.indigo-datacloud.eu/"
        ttsc = TTSClient(token, iss, "localhost")
        success, services = ttsc.list_endservices()

        expected_services = {"service_list": [{"id":"sid", "type":"stype", "host": "shost"}]}

        self.assertTrue(success, msg="ERROR: getting services: %s." % services)
        self.assertEqual(services, expected_services, msg="ERROR: getting services: Unexpected services.")

    @patch('httplib.HTTPConnection')
    def test_find_service(self, connection):
        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.putrequest.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        token = "eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkYzVkNWFiNy02ZGI5LTQwNzktOTg1Yy04MGFjMDUwMTcwNjYiLCJpc3MiOiJodHRwczpcL1wvaWFtLXRlc3QuaW5kaWdvLWRhdGFjbG91ZC5ldVwvIiwiZXhwIjoxNDY2MDkzOTE3LCJpYXQiOjE0NjYwOTAzMTcsImp0aSI6IjE1OTU2N2U2LTdiYzItNDUzOC1hYzNhLWJjNGU5MmE1NjlhMCJ9.eINKxJa2J--xdGAZWIOKtx9Wi0Vz3xHzaSJWWY-UHWy044TQ5xYtt0VTvmY5Af-ngwAMGfyaqAAvNn1VEP-_fMYQZdwMqcXLsND4KkDi1ygiCIwQ3JBz9azBT1o_oAHE5BsPsE2BjfDoVRasZxxW5UoXCmBslonYd8HK2tUVjz0"
        iss = "https://iam-test.indigo-datacloud.eu/"
        ttsc = TTSClient(token, iss, "localhost")
        service = ttsc.find_service("stype", "shost")

        expected_service = {"id":"sid", "type":"stype", "host": "shost"}

        self.assertEqual(service, expected_service, msg="ERROR: finding service: Unexpected service.")

    @patch('httplib.HTTPConnection')
    def test_request_credential(self, connection):
        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.putrequest.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        token = "eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkYzVkNWFiNy02ZGI5LTQwNzktOTg1Yy04MGFjMDUwMTcwNjYiLCJpc3MiOiJodHRwczpcL1wvaWFtLXRlc3QuaW5kaWdvLWRhdGFjbG91ZC5ldVwvIiwiZXhwIjoxNDY2MDkzOTE3LCJpYXQiOjE0NjYwOTAzMTcsImp0aSI6IjE1OTU2N2U2LTdiYzItNDUzOC1hYzNhLWJjNGU5MmE1NjlhMCJ9.eINKxJa2J--xdGAZWIOKtx9Wi0Vz3xHzaSJWWY-UHWy044TQ5xYtt0VTvmY5Af-ngwAMGfyaqAAvNn1VEP-_fMYQZdwMqcXLsND4KkDi1ygiCIwQ3JBz9azBT1o_oAHE5BsPsE2BjfDoVRasZxxW5UoXCmBslonYd8HK2tUVjz0"
        iss = "https://iam-test.indigo-datacloud.eu/"
        ttsc = TTSClient(token, iss, "localhost")
        success, cred = ttsc.request_credential("sid")
        
        expected_cred = [{'name': 'Username', 'type': 'text', 'value': 'username'},
                         {'name': 'Password', 'type': 'text', 'value': 'password'}]

        self.assertTrue(success, msg="ERROR: getting credentials: %s." % cred)
        self.assertEqual(cred, expected_cred, msg="ERROR: getting credentials: Unexpected credetials.")
if __name__ == '__main__':
    unittest.main()
