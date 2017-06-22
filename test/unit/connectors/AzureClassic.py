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
import os
import logging
import logging.config
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

sys.path.append(".")
sys.path.append("..")
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
from IM.VirtualMachine import VirtualMachine
from IM.InfrastructureInfo import InfrastructureInfo
from IM.connectors.AzureClassic import AzureClassicCloudConnector
from IM.uriparse import uriparse
from mock import patch, MagicMock


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestAzureClassicConnector(unittest.TestCase):
    """
    Class to test the IM connectors
    """

    def setUp(self):
        self.last_op = None, None
        self.log = StringIO()
        self.handler = logging.StreamHandler(self.log)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.handler.setFormatter(formatter)

        logging.RootLogger.propagate = 0
        logging.root.setLevel(logging.ERROR)

        logger = logging.getLogger('CloudConnector')
        logger.setLevel(logging.DEBUG)
        logger.propagate = 0
        for handler in logger.handlers:
            logger.removeHandler(handler)
        logger.addHandler(self.handler)

    def tearDown(self):
        self.handler.flush()
        self.log.close()
        self.log = StringIO()
        self.handler.close()

    @staticmethod
    def get_azure_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "AzureClassic"
        inf = MagicMock()
        inf.id = "1"
        cloud = AzureClassicCloudConnector(cloud_info, inf)
        return cloud

    @patch('requests.request')
    def test_10_concrete(self, requests):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'azr://image-id' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'azure', 'type': 'AzureClassic', 'subscription_id': 'user',
                                'public_key': 'public_key', 'private_key': 'private_key'}])
        azure_cloud = self.get_azure_cloud()

        requests.side_effect = self.get_response

        concrete = azure_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    def get_response(self, method, url, verify, cert, headers, data):
        resp = MagicMock()
        parts = uriparse(url)
        url = parts[2]
        params = parts[4]

        resp = MagicMock()

        if method == "GET":
            if "/deployments/" in url:
                resp.status_code = 200
                resp.text = ("<Deployment><Status>Running</Status><RoleInstanceList><RoleInstance>"
                             "<InstanceSize>RoleSizeName</InstanceSize><PowerState>Started</PowerState>"
                             "<IpAddress>10.0.0.1</IpAddress><InstanceEndpoints><InstanceEndpoint>"
                             "<Vip>158.42.1.1</Vip></InstanceEndpoint></InstanceEndpoints></RoleInstance>"
                             "</RoleInstanceList></Deployment>")
            if "/operations/" in url:
                resp.status_code = 200
                resp.text = ("<Operation><Status>Succeeded"
                             "</Status></Operation>")
            elif "/storageservices/" in url:
                resp.status_code = 200
                resp.text = ("<StorageService><StorageServiceProperties><GeoPrimaryRegion>North Europe"
                             "</GeoPrimaryRegion></StorageServiceProperties></StorageService>")
            elif url.endswith("/rolesizes"):
                resp.status_code = 200
                resp.text = ("<RoleSizes><RoleSize><SupportedByVirtualMachines>true"
                             "</SupportedByVirtualMachines><Name>RoleSizeName</Name>"
                             "<MemoryInMb>512</MemoryInMb><Cores>1</Cores>"
                             "<VirtualMachineResourceDiskSizeInMb>2014"
                             "</VirtualMachineResourceDiskSizeInMb>"
                             "</RoleSize>"
                             "<RoleSize><SupportedByVirtualMachines>true"
                             "</SupportedByVirtualMachines><Name>RoleSizeName</Name>"
                             "<MemoryInMb>2048</MemoryInMb><Cores>2</Cores>"
                             "<VirtualMachineResourceDiskSizeInMb>2014"
                             "</VirtualMachineResourceDiskSizeInMb>"
                             "</RoleSize>"
                             "</RoleSizes>")

        elif method == "POST":
            if url.endswith("/Operations"):
                resp.status_code = 202
                resp.headers = {'x-ms-request-id': 'id'}
            elif url.endswith("/services/hostedservices"):
                resp.status_code = 201
                resp.text = ""
            elif url.endswith("/deployments"):
                resp.status_code = 202
                resp.headers = {'x-ms-request-id': 'id'}
        elif method == "DELETE":
            if params == "comp=media":
                resp.status_code = 202
                resp.headers = {'x-ms-request-id': 'id'}
        elif method == "PUT":
            if "roles" in url:
                resp.status_code = 202
                resp.headers = {'x-ms-request-id': 'id'}

        return resp

    @patch('requests.request')
    @patch('time.sleep')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, sleep, requests):
        radl_data = """
            network net1 (outbound = 'yes' and outports = '8080,9000:9100')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'azr://image-id' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'azure', 'type': 'AzureClassic', 'subscription_id': 'user',
                                'public_key': 'public_key', 'private_key': 'private_key'}])
        azure_cloud = self.get_azure_cloud()

        requests.side_effect = self.get_response

        res = azure_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    def test_30_updateVMInfo(self, requests):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'azr://image-id' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'azure', 'type': 'AzureClassic', 'subscription_id': 'user',
                                'public_key': 'public_key', 'private_key': 'private_key'}])
        azure_cloud = self.get_azure_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", azure_cloud.cloud, radl, radl, azure_cloud, 1)

        requests.side_effect = self.get_response

        success, vm = azure_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    @patch('time.sleep')
    def test_40_stop(self, sleep, requests):
        auth = Authentication([{'id': 'azure', 'type': 'AzureClassic', 'subscription_id': 'user',
                                'public_key': 'public_key', 'private_key': 'private_key'}])
        azure_cloud = self.get_azure_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", azure_cloud.cloud, "", "", azure_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = azure_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    @patch('time.sleep')
    def test_50_start(self, sleep, requests):
        auth = Authentication([{'id': 'azure', 'type': 'AzureClassic', 'subscription_id': 'user',
                                'public_key': 'public_key', 'private_key': 'private_key'}])
        azure_cloud = self.get_azure_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", azure_cloud.cloud, "", "", azure_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = azure_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    @patch('time.sleep')
    def test_55_alter(self, sleep, requests):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'azr://image-id' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        new_radl_data = """
            system test (
            cpu.count>=2 and
            memory.size>=2048m
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        auth = Authentication([{'id': 'azure', 'type': 'AzureClassic', 'subscription_id': 'user',
                                'public_key': 'public_key', 'private_key': 'private_key'}])
        azure_cloud = self.get_azure_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", azure_cloud.cloud, radl, radl, azure_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = azure_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    @patch('time.sleep')
    def test_60_finalize(self, sleep, requests):
        auth = Authentication([{'id': 'azure', 'type': 'AzureClassic', 'subscription_id': 'user',
                                'public_key': 'public_key', 'private_key': 'private_key'}])
        azure_cloud = self.get_azure_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", azure_cloud.cloud, "", "", azure_cloud, 1)

        sleep.return_value = True
        requests.side_effect = self.get_response

        success, _ = azure_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
