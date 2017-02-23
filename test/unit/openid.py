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
import json

from IM.openid.OpenIDClient import OpenIDClient
from mock import patch, MagicMock


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestOpenIDClient(unittest.TestCase):
    """
    Class to test the TTCLient class
    """
    @classmethod
    def setUpClass(cls):
        cls.token = ("eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkYzVkNWFiNy02ZGI5LTQwNzktOTg1Yy04MGFjMDUwMTcw"
                     "NjYiLCJpc3MiOiJodHRwczpcL1wvaWFtLXRlc3QuaW5kaWdvLWRhdGFjbG91ZC5ldVwvIiwiZXhwIjoxNDY2MDkzOTE3LCJ"
                     "pYXQiOjE0NjYwOTAzMTcsImp0aSI6IjE1OTU2N2U2LTdiYzItNDUzOC1hYzNhLWJjNGU5MmE1NjlhMCJ9.eINKxJa2J--xd"
                     "GAZWIOKtx9Wi0Vz3xHzaSJWWY-UHWy044TQ5xYtt0VTvmY5Af-ngwAMGfyaqAAvNn1VEP-_fMYQZdwMqcXLsND4KkDi1ygiC"
                     "IwQ3JBz9azBT1o_oAHE5BsPsE2BjfDoVRasZxxW5UoXCmBslonYd8HK2tUVjz0")

    def test_is_access_token_expired(self):
        expired, msg = OpenIDClient.is_access_token_expired(self.token)

        self.assertTrue(expired)
        self.assertEqual(msg, "Token expired")

    @patch('requests.request')
    def test_get_user_info_request(self, requests):
        mock_response = MagicMock()
        mock_response.status_code = 200
        user_info = read_file_as_string('../files/iam_user_info.json')
        mock_response.text = user_info
        requests.return_value = mock_response

        success, user_info_resp = OpenIDClient.get_user_info_request(self.token)

        self.assertTrue(success)
        self.assertEqual(json.loads(user_info), user_info_resp)

    @patch('requests.request')
    def test_get_token_introspection(self, requests):
        mock_response = MagicMock()
        mock_response.status_code = 200
        token_info = read_file_as_string('../files/iam_token_info.json')
        mock_response.text = token_info
        requests.return_value = mock_response

        success, token_info_resp = OpenIDClient.get_token_introspection(self.token, "cid", "csec")

        self.assertTrue(success)
        self.assertEqual(json.loads(token_info), token_info_resp)

if __name__ == '__main__':
    unittest.main()
