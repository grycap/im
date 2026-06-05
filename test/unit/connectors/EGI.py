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
from IM.VirtualMachine import VirtualMachine
from radl import radl_parse
from mock import patch, MagicMock, call


class TestEGIConnector(unittest.TestCase):
    """
    Class to test the EGI connector
    """

    @patch('requests.get')
    @patch('IM.connectors.EGI.EGICloudConnector._get_host')
    @patch('IM.connectors.EGI.EGICloudConnector._get_domains')
    def test_add_dns(self, mock_get_domains, mock_get_host, mock_get):
        mock_get_host.return_value = None, ""
        mock_get_domains.return_value = "domain", ""
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
        mock_get_domains.return_value = "domain", ""
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

        domain, error = EGICloudConnector._get_domains("access_token", "domain1")
        self.assertEqual(error, "")
        self.assertEqual(domain, "domain1")

        domain, error = EGICloudConnector._get_domains("access_token", "domain3")
        self.assertEqual(error, "Domain domain3 not found in DyDNS service")
        self.assertEqual(domain, None)

    @patch('requests.get')
    @patch('requests.post')
    @patch('IM.connectors.EGI.EGICloudConnector._get_host')
    def test_create_tls_certificate(self, mock_get_host, mock_post, mock_get):
        mock_get_host.return_value = {"name": "hostname"}, ""
        mock_post.return_value = MagicMock(status_code=200, text="issued-cert")
        mock_get.return_value = MagicMock(status_code=200)

        auth_data = Authentication([{'type': 'InfrastructureManager', 'token': 'access_token'}])
        cloud = EGICloudConnector(None, None)
        vm = MagicMock()

        success = cloud.create_tls_certificate(vm, "hostname", "domain", "8.8.8.8", auth_data)
        self.assertTrue(success)

        post_url = f"{EGICloudConnector.DYDNS_URL}/api/hosts/hostname.domain/certificate"
        self.assertEqual(mock_post.call_count, 1)
        self.assertEqual(mock_get.call_count, 0)

        post_call = mock_post.call_args
        self.assertEqual(post_call.args[0], post_url)
        self.assertEqual(post_call.kwargs['headers'], {'Authorization': 'Bearer access_token'})
        self.assertEqual(post_call.kwargs['timeout'], 60)
        self.assertIn('csr', post_call.kwargs['json'])
        self.assertTrue(post_call.kwargs['json']['csr'].startswith('-----BEGIN CERTIFICATE REQUEST-----'))

        vm.set_tls_certificate.assert_called_once()
        set_cert_call = vm.set_tls_certificate.call_args
        self.assertEqual(set_cert_call.args[0:2], ('hostname', 'domain'))
        self.assertTrue(set_cert_call.args[2].startswith('-----BEGIN RSA PRIVATE KEY-----'))
        self.assertEqual(set_cert_call.args[3], 'issued-cert')

    def test_generate_csr_returns_private_key(self):
        csr_pem, private_key_pem = EGICloudConnector._generate_csr("hostname.domain")
        self.assertTrue(csr_pem.startswith('-----BEGIN CERTIFICATE REQUEST-----'))
        self.assertTrue(private_key_pem.startswith('-----BEGIN RSA PRIVATE KEY-----'))

    @patch('IM.connectors.EGI.EGICloudConnector.create_tls_certificate')
    @patch('IM.connectors.EGI.EGICloudConnector.add_dns_entry')
    def test_manage_dns_entries_with_tls(self, mock_add_dns, mock_create_tls):
        mock_add_dns.return_value = True
        mock_create_tls.return_value = True

        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.ip = '158.42.1.1' and
            net_interface.0.dns.0.name = 'hostname.domain.com' and
            net_interface.0.dns.0.tls = 'true' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'ost://server.com/1' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        auth_data = Authentication([{'type': 'InfrastructureManager', 'token': 'access_token'}])
        cloud = EGICloudConnector(None, None)

        inf = MagicMock()
        vm = VirtualMachine(inf, "vmid", cloud.cloud, radl, radl, cloud, 1)

        success = cloud.manage_dns_entries("add", vm, auth_data)
        self.assertTrue(success)

        mock_add_dns.assert_called_once_with('hostname', 'domain.com.', '158.42.1.1', auth_data, None)
        mock_create_tls.assert_called_once_with(vm, 'hostname', 'domain.com.', '158.42.1.1', auth_data)


if __name__ == '__main__':
    unittest.main()
