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

from IM.uriparse import uriparse
from IM.tts.tts import TTSClient
from mock import patch, MagicMock


class TestTTSClient(unittest.TestCase):
    """
    Class to test the TTCLient class
    """
    @classmethod
    def setUpClass(cls):
        token = ("eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkYzVkNWFiNy02ZGI5LTQwNzktOTg1Yy04MGFjMDUwMTcwNjYi"
                 "LCJpc3MiOiJodHRwczpcL1wvaWFtLXRlc3QuaW5kaWdvLWRhdGFjbG91ZC5ldVwvIiwiZXhwIjoxNDY2MDkzOTE3LCJpYXQiOjE"
                 "0NjYwOTAzMTcsImp0aSI6IjE1OTU2N2U2LTdiYzItNDUzOC1hYzNhLWJjNGU5MmE1NjlhMCJ9.eINKxJa2J--xdGAZWIOKtx9Wi"
                 "0Vz3xHzaSJWWY-UHWy044TQ5xYtt0VTvmY5Af-ngwAMGfyaqAAvNn1VEP-_fMYQZdwMqcXLsND4KkDi1ygiCIwQ3JBz9azBT1o_"
                 "oAHE5BsPsE2BjfDoVRasZxxW5UoXCmBslonYd8HK2tUVjz0")
        cls.ttsc = TTSClient(token, "localhost")

    def get_response(self, method, url, verify=False, cert=None, headers={}, data=None):
        resp = MagicMock()
        parts = uriparse(url)
        url = parts[2]

        if method == "GET":
            if "/api/v2/oidcp" == url:
                resp.status_code = 200
                resp.text = '{"openid_provider_list": [{"id": "iam"}]}'
            elif "/api/v2/iam/service" == url:
                resp.status_code = 200
                resp.text = ('{"service_list": [{"id":"sid", "description": "shost"}]}')
            else:
                resp.status_code = 400
        elif method == "POST":
            if url == "/api/v2/iam/credential":
                resp.status_code = 200
                resp.text = ('{ "credential": { "entries": [{"name": "Username", "type": "text", "value": "username"},'
                             '{"name": "Password", "type": "text", "value": "password"}]}}')
            else:
                resp.status_code = 401
        else:
            resp.status_code = 402

        return resp

    @patch('requests.request')
    def test_list_providers(self, requests):
        requests.side_effect = self.get_response

        success, providers = self.ttsc.list_providers()

        expected_providers = {"openid_provider_list": [{"id": "iam"}]}

        self.assertTrue(success, msg="ERROR: getting providers: %s." % providers)
        self.assertEqual(providers, expected_providers, msg="ERROR: getting providers: Unexpected providers.")

    @patch('requests.request')
    def test_list_endservices(self, requests):
        requests.side_effect = self.get_response

        _, provider = self.ttsc.get_provider()
        success, services = self.ttsc.list_endservices(provider["id"])

        expected_services = {"service_list": [{"id": "sid", "description": "shost"}]}

        self.assertTrue(success, msg="ERROR: getting services: %s." % services)
        self.assertEqual(services, expected_services, msg="ERROR: getting services: Unexpected services.")

    @patch('requests.request')
    def test_find_service(self, requests):
        requests.side_effect = self.get_response

        success, service = self.ttsc.find_service("shost")

        expected_service = {"id": "sid", "description": "shost"}

        self.assertTrue(success)
        self.assertEqual(service, expected_service)

    @patch('requests.request')
    def test_request_credential(self, requests):
        requests.side_effect = self.get_response

        success, cred = self.ttsc.request_credential("sid")

        expected_cred = {"credential": {"entries": [
            {'name': 'Username', 'type': 'text', 'value': 'username'},
            {'name': 'Password', 'type': 'text', 'value': 'password'}]}}

        self.assertTrue(success, msg="ERROR: getting credentials: %s." % cred)
        self.assertEqual(cred, expected_cred, msg="ERROR: getting credentials: Unexpected credetials.")
if __name__ == '__main__':
    unittest.main()
