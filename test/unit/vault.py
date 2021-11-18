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
import json

from IM.vault import VaultCredentials
from mock import patch, MagicMock


class TestVaultCredentials(unittest.TestCase):
    """
    Class to test the VaultCredentials class
    """
    @patch("hvac.Client")
    @patch('requests.post')
    def test_get_creds(self, post, hvac):
        client = MagicMock()
        cred1 = {"id": "credid", "type": "type", "username": "user", "password": "pass", "enabled": 1}
        cred2 = {"id": "fed", "type": "fedcloud", "host": "server", "vo": "vo", "project_id": "prj", "enabled": 1}
        client.secrets.kv.v1.read_secret.return_value = {"data": {"credid": json.dumps(cred1),
                                                                  "fed": json.dumps(cred2)}}

        hvac.return_value = client

        v = VaultCredentials("http://host:8200")
        creds = v.get_creds("atoken")
        self.assertIn({"id": "credid", "type": "type", "username": "user", "password": "pass"}, creds)
        self.assertIn({'auth_version': '3.x_oidc_access_token', 'domain': 'prj', 'host': 'server',
                       'id': 'fed', 'password': 'atoken', 'tenant': 'openid', 'type': 'OpenStack',
                       'username': 'egi.eu'}, creds)


if __name__ == '__main__':
    unittest.main()
