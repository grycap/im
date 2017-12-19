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
from IM.tts.onetts import ONETTSClient
from mock import patch, MagicMock


class TestONETTSClient(unittest.TestCase):
    """
    Class to test the OneTTSClient class
    """
    @patch('IM.tts.onetts.TTSClient')
    def test_list_providers(self, ttscli):
        tts = MagicMock()
        ttscli.return_value = tts
        tts.get_provider.return_value = True, {"id": "iam"}
        tts.find_service.return_value = True, {"id": "sid"}
        tts.request_credential.return_value = True, {"credential": {"entries": [
            {'name': 'Username', 'type': 'text', 'value': 'username'},
            {'name': 'Password', 'type': 'text', 'value': 'password'}]}}

        token = ("eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkYzVkNWFiNy02ZGI5LTQwNzktOTg1Yy04MGFjMDUwMTcwNjYi"
                 "LCJpc3MiOiJodHRwczpcL1wvaWFtLXRlc3QuaW5kaWdvLWRhdGFjbG91ZC5ldVwvIiwiZXhwIjoxNDY2MDkzOTE3LCJpYXQiOjE"
                 "0NjYwOTAzMTcsImp0aSI6IjE1OTU2N2U2LTdiYzItNDUzOC1hYzNhLWJjNGU5MmE1NjlhMCJ9.eINKxJa2J--xdGAZWIOKtx9Wi"
                 "0Vz3xHzaSJWWY-UHWy044TQ5xYtt0VTvmY5Af-ngwAMGfyaqAAvNn1VEP-_fMYQZdwMqcXLsND4KkDi1ygiCIwQ3JBz9azBT1o_"
                 "oAHE5BsPsE2BjfDoVRasZxxW5UoXCmBslonYd8HK2tUVjz0")
        username, password = ONETTSClient.get_auth_from_tts("https://localhost:8443", "oneserver", token)

        self.assertEqual(username, "username", msg="ERROR: getting one auth from TTS, incorrect username.")
        self.assertEqual(password, "password", msg="ERROR: getting one auth from TTS, incorrect password.")

if __name__ == '__main__':
    unittest.main()
