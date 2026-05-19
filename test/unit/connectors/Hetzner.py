#! /usr/bin/env python
#
# IM - Infrastructure Manager
# Copyright (C) 2024 - GRyCAP - Universitat Politecnica de Valencia
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
import json

sys.path.append(".")
sys.path.append("..")
from .CloudConn import TestCloudConnectorBase
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
from IM.VirtualMachine import VirtualMachine
from IM.InfrastructureInfo import InfrastructureInfo
from IM.connectors.Hetzner import HetznerCloudConnector
from mock import patch, MagicMock



class TestHetznerConnector(TestCloudConnectorBase):
    @patch('IM.connectors.Hetzner.HetznerCloudConnector._make_request')
    def test_list_images(self, make_request_mock):
        """
        Test list_images returns filtered images in standard format
        """
        auth = Authentication([{'id': 'hetzner', 'type': 'Hetzner', 'token': 'api_token'}])
        hetzner_cloud = self.get_hetzner_cloud()

        # Mock /images endpoint
        make_request_mock.side_effect = lambda method, endpoint, auth_data, data=None: self.get_response_mock(method, endpoint, None, data)

        # No filters
        images = hetzner_cloud.list_images(auth)
        self.assertIsInstance(images, list)
        self.assertGreaterEqual(len(images), 2)
        self.assertIn({'uri': 'htz://ubuntu-22.04', 'name': 'Ubuntu 22.04'}, images)

        # Filter by distribution
        images_ubuntu = hetzner_cloud.list_images(auth, filters={"distribution": "ubuntu"})
        self.assertTrue(any('ubuntu' in img['uri'] for img in images_ubuntu))
        images_debian = hetzner_cloud.list_images(auth, filters={"distribution": "debian"})
        self.assertTrue(any('debian' in img['uri'] for img in images_debian))

    @staticmethod
    def get_hetzner_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "Hetzner"
        inf = MagicMock()
        inf.id = "1"
        cloud = HetznerCloudConnector(cloud_info, inf)
        return cloud

    @patch('IM.connectors.Hetzner.HetznerCloudConnector._make_request')
    def test_10_concrete(self, make_request_mock):
        """
        Test that concrete system is properly resolved
        """
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=2 and
            memory.size>=4096m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'htz://ubuntu-22.04' and
            disk.0.os.credentials.username = 'root'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'hetzner', 'type': 'Hetzner', 'token': 'api_token'}])
        hetzner_cloud = self.get_hetzner_cloud()

        def make_request_side_effect(method, endpoint, auth_data, data=None):
            return self.get_response_mock(method, endpoint, None, data)

        make_request_mock.side_effect = make_request_side_effect

        concrete = hetzner_cloud.concreteSystem(radl_system, auth)
        self.assertIsNotNone(concrete, msg="concrete system should not be None")
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.Hetzner.HetznerCloudConnector._make_request')
    def test_10_concrete_wrong_protocol(self, make_request_mock):
        """
        Test that concrete system returns None for wrong protocol
        """
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=2 and
            memory.size>=4096m and
            disk.0.image.url = 'aws://ami-12345' and
            disk.0.os.credentials.username = 'root'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'hetzner', 'type': 'Hetzner', 'token': 'api_token'}])
        hetzner_cloud = self.get_hetzner_cloud()

        def make_request_side_effect(method, endpoint, auth_data, data=None):
            return self.get_response_mock(method, endpoint, None, data)

        make_request_mock.side_effect = make_request_side_effect

        concrete = hetzner_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(concrete, [], msg="concrete system should return empty list for wrong protocol")

    def get_response_mock(self, method, url, headers, json_data=None, verify=True):
        """
        Mock response generator for Hetzner API calls
        """
        resp = MagicMock()
        resp.status_code = 200

        if '/server_types' in url and method == 'GET':
            resp.status_code = 200
            resp.json.return_value = {
                'server_types': [
                    {
                        'id': 1,
                        'name': 'cx11',
                        'description': '1 vCPU, 1 GB RAM',
                        'cores': 1,
                        'memory': 1.0,
                        'disk': 25,
                        'prices': [{'monthly': 5.90}]
                    },
                    {
                        'id': 2,
                        'name': 'cx21',
                        'description': '2 vCPU, 4 GB RAM',
                        'cores': 2,
                        'memory': 4.0,
                        'disk': 40,
                        'prices': [{'monthly': 10.90}]
                    },
                    {
                        'id': 3,
                        'name': 'cx31',
                        'description': '2 vCPU, 8 GB RAM',
                        'cores': 2,
                        'memory': 8.0,
                        'disk': 80,
                        'prices': [{'monthly': 21.90}]
                    }
                ]
            }
        elif '/images' in url and method == 'GET':
            resp.status_code = 200
            resp.json.return_value = {
                'images': [
                    {
                        'id': 1,
                        'type': 'system',
                        'status': 'available',
                        'name': 'ubuntu-22.04',
                        'description': 'Ubuntu 22.04'
                    },
                    {
                        'id': 2,
                        'type': 'system',
                        'status': 'available',
                        'name': 'debian-12',
                        'description': 'Debian 12'
                    }
                ]
            }
        elif '/locations' in url and method == 'GET':
            resp.status_code = 200
            resp.json.return_value = {
                'locations': [
                    {
                        'id': 'fsn1',
                        'name': 'Falkenstein DC Park 1',
                        'description': 'Falkenstein 1 DC',
                        'country': 'DE',
                        'city': 'Falkenstein',
                        'latitude': 50.47612,
                        'longitude': 12.370071
                    },
                    {
                        'id': 'nbg1',
                        'name': 'Nuremberg DC Park 1',
                        'description': 'Nuremberg 1 DC',
                        'country': 'DE',
                        'city': 'Nuremberg',
                        'latitude': 49.452102,
                        'longitude': 11.076734
                    }
                ]
            }
        elif '/ssh_keys' in url and method == 'GET':
            resp.status_code = 200
            resp.json.return_value = {'ssh_keys': []}
        elif '/ssh_keys' in url and method == 'POST':
            resp.status_code = 201
            resp.json.return_value = {
                'ssh_key': {
                    'id': 123,
                    'name': 'test-key',
                    'public_key': 'ssh-rsa AAAA...'
                }
            }
        elif '/servers' in url and method == 'POST':
            resp.status_code = 201
            resp.json.return_value = {
                'server': {
                    'id': 42,
                    'name': 'test-server',
                    'status': 'initializing',
                    'public_net': {
                        'ipv4': {
                            'ip': '192.0.2.1',
                            'blocked': False
                        },
                        'ipv6': {
                            'ip': '2001:db8::/64',
                            'blocked': False
                        }
                    },
                    'server_type': {
                        'id': 1,
                        'name': 'cx11',
                        'description': '1 vCPU, 1 GB RAM'
                    },
                    'datacenter': {
                        'id': 1,
                        'name': 'fsn1-dc14',
                        'description': 'Falkenstein 1 DC14',
                        'location': {
                            'id': 'fsn1',
                            'name': 'Falkenstein DC Park 1'
                        }
                    }
                }
            }
        elif '/servers/' in url and method == 'GET':
            resp.status_code = 200
            resp.json.return_value = {
                'server': {
                    'id': 42,
                    'name': 'test-server',
                    'status': 'running',
                    'public_net': {
                        'ipv4': {
                            'ip': '192.0.2.1',
                            'blocked': False
                        },
                        'ipv6': {
                            'ip': '2001:db8::/64',
                            'blocked': False
                        }
                    }
                }
            }
        elif '/servers/' in url and method == 'DELETE':
            resp.status_code = 200
        elif '/servers/' in url and '/actions/power_on' in url:
            resp.status_code = 201
            resp.json.return_value = {'action': {'id': 1, 'command': 'power_on'}}
        elif '/servers/' in url and '/actions/power_off' in url:
            resp.status_code = 201
            resp.json.return_value = {'action': {'id': 2, 'command': 'power_off'}}
        elif '/servers/' in url and '/actions/reboot' in url:
            resp.status_code = 201
            resp.json.return_value = {'action': {'id': 3, 'command': 'reboot'}}

        return resp

    @patch('IM.connectors.Hetzner.HetznerCloudConnector._make_request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, make_request_mock):
        """
        Test launching VMs in Hetzner
        """
        radl_data = """
            network net1 (outbound = 'yes')
            network net2 ()
            system test (
            cpu.count>=2 and
            memory.size>=4096m and
            disk.0.size>=20g and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            availability_zone = 'fsn1' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'htz://ubuntu-22.04' and
            disk.0.os.credentials.username = 'root'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'hetzner', 'type': 'Hetzner', 'token': 'test_token'}])
        hetzner_cloud = self.get_hetzner_cloud()

        def make_request_side_effect(method, endpoint, auth_data, data=None):
            return self.get_response_mock(method, endpoint, None, data)

        make_request_mock.side_effect = make_request_side_effect

        inf = InfrastructureInfo()
        res = hetzner_cloud.launch(inf, radl, radl, 1, auth)
        success, vm = res[0]

        self.assertTrue(success, msg="ERROR: launching a VM. Error: %s" % (vm if not success else ""))
        self.assertEqual(vm.id, "42")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.Hetzner.HetznerCloudConnector.manage_dns_entries')
    @patch('IM.connectors.Hetzner.HetznerCloudConnector._make_request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_30_updateVMInfo(self, save_data, make_request_mock, manage_dns_mock):
        """
        Test updating VM information
        """
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.count>=2 and
            memory.size>=4096m and
            disk.0.size>=20g and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'htz://ubuntu-22.04' and
            disk.0.os.credentials.username = 'root'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'hetzner', 'type': 'Hetzner', 'token': 'test_token'}])
        hetzner_cloud = self.get_hetzner_cloud()

        inf = MagicMock()
        inf.id = "1"
        vm = VirtualMachine(inf, "42", hetzner_cloud.cloud, radl, radl, hetzner_cloud, 1)

        def make_request_side_effect(method, endpoint, auth_data, data=None):
            return self.get_response_mock(method, endpoint, None, data)

        make_request_mock.side_effect = make_request_side_effect
        manage_dns_mock.return_value = True

        success, vm = hetzner_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertEqual(vm.state, VirtualMachine.RUNNING)
        self.assertEqual(manage_dns_mock.call_args_list[0][0][0], "add")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.Hetzner.HetznerCloudConnector.manage_dns_entries')
    @patch('IM.connectors.Hetzner.HetznerCloudConnector._make_request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_40_finalize(self, save_data, make_request_mock, manage_dns_mock):
        """
        Test destroying a VM
        """
        radl_data = """
            network net ()
            system test (
            cpu.count>=2 and
            memory.size>=4096m and
            disk.0.size>=20g and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'htz://ubuntu-22.04' and
            disk.0.os.credentials.username = 'root'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        auth = Authentication([{'id': 'hetzner', 'type': 'Hetzner', 'token': 'test_token'}])
        hetzner_cloud = self.get_hetzner_cloud()

        inf = MagicMock()
        inf.id = "1"
        vm = VirtualMachine(inf, "42", hetzner_cloud.cloud, radl, radl, hetzner_cloud, 1)

        def make_request_side_effect(method, endpoint, auth_data, data=None):
            return self.get_response_mock(method, endpoint, None, data)

        make_request_mock.side_effect = make_request_side_effect
        manage_dns_mock.return_value = True

        success, msg = hetzner_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM. Error: %s" % msg)
        self.assertEqual(manage_dns_mock.call_args_list[0][0][0], "del")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.Hetzner.HetznerCloudConnector._make_request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_50_start(self, save_data, make_request_mock):
        """
        Test starting a stopped VM
        """
        radl_data = """
            network net ()
            system test (
            disk.0.image.url = 'htz://ubuntu-22.04'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        auth = Authentication([{'id': 'hetzner', 'type': 'Hetzner', 'token': 'test_token'}])
        hetzner_cloud = self.get_hetzner_cloud()

        inf = MagicMock()
        inf.id = "1"
        vm = VirtualMachine(inf, "42", hetzner_cloud.cloud, radl, radl, hetzner_cloud, 1)

        def make_request_side_effect(method, endpoint, auth_data, data=None):
            return self.get_response_mock(method, endpoint, None, data)

        make_request_mock.side_effect = make_request_side_effect

        success, msg = hetzner_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: starting VM. Error: %s" % msg)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.Hetzner.HetznerCloudConnector._make_request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_60_stop(self, save_data, make_request_mock):
        """
        Test stopping a running VM
        """
        radl_data = """
            network net ()
            system test (
            disk.0.image.url = 'htz://ubuntu-22.04'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        auth = Authentication([{'id': 'hetzner', 'type': 'Hetzner', 'token': 'test_token'}])
        hetzner_cloud = self.get_hetzner_cloud()

        inf = MagicMock()
        inf.id = "1"
        vm = VirtualMachine(inf, "42", hetzner_cloud.cloud, radl, radl, hetzner_cloud, 1)

        def make_request_side_effect(method, endpoint, auth_data, data=None):
            return self.get_response_mock(method, endpoint, None, data)

        make_request_mock.side_effect = make_request_side_effect

        success, msg = hetzner_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM. Error: %s" % msg)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.Hetzner.HetznerCloudConnector._make_request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_70_reboot(self, save_data, make_request_mock):
        """
        Test rebooting a VM
        """
        radl_data = """
            network net ()
            system test (
            disk.0.image.url = 'htz://ubuntu-22.04'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        auth = Authentication([{'id': 'hetzner', 'type': 'Hetzner', 'token': 'test_token'}])
        hetzner_cloud = self.get_hetzner_cloud()

        inf = MagicMock()
        inf.id = "1"
        vm = VirtualMachine(inf, "42", hetzner_cloud.cloud, radl, radl, hetzner_cloud, 1)

        def make_request_side_effect(method, endpoint, auth_data, data=None):
            return self.get_response_mock(method, endpoint, None, data)

        make_request_mock.side_effect = make_request_side_effect

        success, msg = hetzner_cloud.reboot(vm, auth)

        self.assertTrue(success, msg="ERROR: rebooting VM. Error: %s" % msg)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.Hetzner.HetznerCloudConnector._make_request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_80_alterVM(self, save_data, make_request_mock):
        """
        Test altering VM configuration (currently not supported)
        """
        radl_data = """
            network net ()
            system test (
            cpu.count>=2 and
            memory.size>=4096m and
            disk.0.size>=20g and
            disk.0.image.url = 'htz://ubuntu-22.04'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        auth = Authentication([{'id': 'hetzner', 'type': 'Hetzner', 'token': 'test_token'}])
        hetzner_cloud = self.get_hetzner_cloud()

        inf = MagicMock()
        inf.id = "1"
        vm = VirtualMachine(inf, "42", hetzner_cloud.cloud, radl, radl, hetzner_cloud, 1)

        def make_request_side_effect(method, endpoint, auth_data, data=None):
            return self.get_response_mock(method, endpoint, None, data)

        make_request_mock.side_effect = make_request_side_effect

        success, msg = hetzner_cloud.alterVM(vm, radl, auth)

        # alterVM is not fully supported
        self.assertFalse(success, msg="alterVM should not be fully supported")

    def test_90_get_image_id(self):
        """
        Test extracting image ID from URL
        """
        hetzner_cloud = self.get_hetzner_cloud()

        image_id = hetzner_cloud.get_image_id('htz://ubuntu-22.04')
        self.assertEqual(image_id, 'ubuntu-22.04')

        image_id = hetzner_cloud.get_image_id('htz://debian-12')
        self.assertEqual(image_id, 'debian-12')

    @patch('IM.connectors.Hetzner.HetznerCloudConnector._make_dns_request')
    def test_95_add_dns_entry(self, make_dns_request_mock):
        """
        Test adding DNS entry in Hetzner DNS
        """
        auth = Authentication([{'id': 'hetzner', 'type': 'Hetzner', 'token': 'dns_token'}])
        hetzner_cloud = self.get_hetzner_cloud()

        zones_resp = MagicMock()
        zones_resp.json.return_value = {
            'zones': [
                {'id': 'zone1', 'name': 'example.org'}
            ]
        }
        records_resp = MagicMock()
        records_resp.json.return_value = {'records': []}
        create_resp = MagicMock()
        create_resp.json.return_value = {'record': {'id': 'rec1'}}
        make_dns_request_mock.side_effect = [zones_resp, records_resp, create_resp]

        success = hetzner_cloud.add_dns_entry('test', 'example.org.', '192.0.2.1', auth)

        self.assertTrue(success)
        self.assertEqual(make_dns_request_mock.call_args_list[0][0][0], 'GET')
        self.assertEqual(make_dns_request_mock.call_args_list[1][0][0], 'GET')
        self.assertEqual(make_dns_request_mock.call_args_list[2][0][0], 'POST')

    @patch('IM.connectors.Hetzner.HetznerCloudConnector._make_dns_request')
    def test_96_del_dns_entry(self, make_dns_request_mock):
        """
        Test deleting DNS entry in Hetzner DNS
        """
        auth = Authentication([{'id': 'hetzner', 'type': 'Hetzner', 'token': 'dns_token'}])
        hetzner_cloud = self.get_hetzner_cloud()

        zones_resp = MagicMock()
        zones_resp.json.return_value = {
            'zones': [
                {'id': 'zone1', 'name': 'example.org'}
            ]
        }
        records_resp = MagicMock()
        records_resp.json.return_value = {
            'records': [
                {'id': 'rec1', 'type': 'A', 'name': 'test', 'value': '192.0.2.1'}
            ]
        }
        delete_resp = MagicMock()
        make_dns_request_mock.side_effect = [zones_resp, records_resp, delete_resp]

        success = hetzner_cloud.del_dns_entry('test', 'example.org.', '192.0.2.1', auth)

        self.assertTrue(success)
        self.assertEqual(make_dns_request_mock.call_args_list[0][0][0], 'GET')
        self.assertEqual(make_dns_request_mock.call_args_list[1][0][0], 'GET')
        self.assertEqual(make_dns_request_mock.call_args_list[2][0][0], 'DELETE')


if __name__ == '__main__':
    unittest.main()
