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
import sys
import unittest

sys.path.append(".")
sys.path.append("..")
from IM.auth import Authentication
from IM.connectors.EGI import EGICloudConnector
from mock import patch, MagicMock, call


class TestEGIConnector(unittest.TestCase):
    """
    Class to test the EGI connector
    """

    @patch('requests.get')
    @patch('IM.connectors.EGI.EGICloudConnector._get_host')
    def test_add_dns(self, mock_get_host, mock_get):
        mock_get_host.return_value = None, ""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"status": "ok",
                                                                         "host": {"update_secret": "123"}})
        auth_data = Authentication([{'type': 'InfrastructureManager', 'token': 'access_token'}])
        cloud = EGICloudConnector(None, None)
        success = EGICloudConnector.add_dns_entry(cloud, "hostname", "domain", "ip", auth_data)
        self.assertTrue(success)
        self.assertEqual(mock_get.call_count, 2)
        eurl1 = f"{EGICloudConnector.DYDNS_URL}/nic/register?fqdn=hostname.domain&comment=IM created DNS entry"
        eurl2 = f"{EGICloudConnector.DYDNS_URL}/nic/update?hostname=hostname.domain&myip=ip"
        calls = [call(eurl1, headers={'Authorization': 'Bearer access_token'}, timeout=10),
                 call(eurl2, headers={'Authorization': 'Bearer access_token'}, timeout=10)]
        mock_get.assert_has_calls(calls)

        success = EGICloudConnector.add_dns_entry(cloud, "*", "hostname.domain", "ip", auth_data)
        self.assertTrue(success)
        self.assertEqual(mock_get.call_count, 4)
        eurl1 = f"{eurl1}&wildcard=true"
        self.assertEqual(mock_get.call_args_list[2], call(eurl1, headers={'Authorization': 'Bearer access_token'},
                                                          timeout=10))
        self.assertEqual(mock_get.call_args_list[3], call(eurl2, headers={'Authorization': 'Bearer access_token'},
                                                          timeout=10))

    @patch('requests.get')
    @patch('IM.connectors.EGI.EGICloudConnector._get_host')
    def test_add_dydns(self, mock_get_host, mock_get):
        mock_get_host.return_value = None, ""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"status": "ok",
                                                                         "host": {"update_secret": "123"}})
        cloud = EGICloudConnector(None, None)
        auth_data = Authentication([{'type': 'InfrastructureManager', 'username': 'user', 'password': 'pass'}])
        success = EGICloudConnector.add_dns_entry(cloud, "dydns:123@hostname", "domain.", "ip", auth_data)
        self.assertTrue(success)
        eurl = f"{EGICloudConnector.DYDNS_URL}/nic/update?hostname=hostname.domain&myip=ip"
        self.assertEqual(mock_get.call_count, 1)
        mock_get.assert_any_call(eurl, headers={'Authorization': 'Basic aG9zdG5hbWUuZG9tYWluOjEyMw=='}, timeout=10)

    @patch('requests.get')
    @patch('IM.connectors.EGI.EGICloudConnector._get_host')
    @patch('IM.connectors.EGI.EGICloudConnector._get_domains')
    def test_del_dns(self, mock_get_domains, mock_get_host, mock_get):
        mock_get_host.return_value = {"name": "hostname"}, ""
        mock_get_domains.return_value = ["domain"], ""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"status": "ok"})
        auth_data = Authentication([{'type': 'InfrastructureManager', 'token': 'access_token'}])
        cloud = EGICloudConnector(None, None)
        success = EGICloudConnector.del_dns_entry(cloud, "hostname", "domain.", "ip", auth_data)
        self.assertTrue(success)
        eurl = f"{EGICloudConnector.DYDNS_URL}/nic/unregister?fqdn=hostname.domain"
        mock_get.assert_called_with(eurl, headers={'Authorization': 'Bearer access_token'}, timeout=10)

        success = EGICloudConnector.del_dns_entry(cloud, "*", "whostname.domain", "ip", auth_data)
        self.assertTrue(success)
        eurl = f"{EGICloudConnector.DYDNS_URL}/nic/unregister?fqdn=whostname.domain"
        mock_get.assert_called_with(eurl, headers={'Authorization': 'Bearer access_token'}, timeout=10)

    @patch('requests.get')
    def test_get_host(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"status": "ok",
                                                                         "hosts": [{"name": "hostname"}]})
        host, error = EGICloudConnector._get_host("hostname", "domain", "access_token")
        self.assertEqual(host["name"], "hostname")
        self.assertEqual(error, "")
        self.assertEqual(mock_get.call_count, 1)
        eurl = f"{EGICloudConnector.DYDNS_URL}/nic/hosts?domain=domain"
        mock_get.assert_called_with(eurl, headers={'Authorization': 'Bearer access_token'}, timeout=10)

    @patch('requests.get')
    def test_get_domains(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"status": "ok",
                                                                         "private": [{"name": "domain1",
                                                                                      "available": True}],
                                                                         "public": [{"name": "domain2",
                                                                                     "available": True}]})
        domains, error = EGICloudConnector._get_domains("access_token")
        self.assertEqual(error, "")
        self.assertEqual(domains, ["domain1", "domain2"])
        self.assertEqual(mock_get.call_count, 1)
        eurl = f"{EGICloudConnector.DYDNS_URL}/nic/domains"
        mock_get.assert_called_with(eurl, headers={'Authorization': 'Bearer access_token'}, timeout=10)


if __name__ == '__main__':
    unittest.main()
