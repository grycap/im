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
from IM.connectors.Azure import AzureCloudConnector
from mock import patch, MagicMock, call


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestAzureConnector(unittest.TestCase):
    """
    Class to test the IM connectors
    """

    def setUp(self):
        self.error_in_wait = True
        self.error_in_create = True
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
        cloud_info.type = "Azure"
        inf = MagicMock()
        inf.id = "1"
        cloud = AzureCloudConnector(cloud_info, inf)
        return cloud

    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.UserPassCredentials')
    def test_10_concrete(self, credentials, compute_client):
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

        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'username': 'user', 'password': 'password'}])
        azure_cloud = self.get_azure_cloud()

        instace_type = MagicMock()
        instace_type.name = "instance_type1"
        instace_type.number_of_cores = 1
        instace_type.memory_in_mb = 1024
        instace_type.resource_disk_size_in_mb = 102400
        instace_types = [instace_type]
        client = MagicMock()
        compute_client.return_value = client
        client.virtual_machine_sizes.list.return_value = instace_types

        concrete = azure_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    def wait(self):
        """
        Wait VMs returning error only first time
        """
        if self.error_in_wait:
            self.error_in_wait = False
            raise Exception("Error waiting VM")

    def create_vm(self, group_name, vm_name, vm_parameters):
        """
        Create VMs returning error only first time
        """
        if self.error_in_create:
            self.error_in_create = False
            raise Exception("Error creating VM")
        else:
            async_vm_creation = MagicMock()
            async_vm_creation.wait.side_effect = self.wait
            return async_vm_creation

    @patch('IM.connectors.Azure.ResourceManagementClient')
    @patch('IM.connectors.Azure.StorageManagementClient')
    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.NetworkManagementClient')
    @patch('IM.connectors.Azure.UserPassCredentials')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, credentials, network_client, compute_client, storage_client, resource_client):
        radl_data = """
            network net1 (outbound = 'yes' and outports = '8080,9000:9100' and sg_name = 'nsgname')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'azr://Canonical/UbuntuServer/16.04.0-LTS/latest' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'username': 'user', 'password': 'password'}])
        azure_cloud = self.get_azure_cloud()

        cclient = MagicMock()
        compute_client.return_value = cclient
        nclient = MagicMock()
        network_client.return_value = nclient
        rclient = MagicMock()
        resource_client.return_value = rclient

        nclient.virtual_networks.get.side_effect = Exception()

        subnet_create = MagicMock()
        subnet_create_res = MagicMock()
        subnet_create_res.id = "subnet-0"
        subnet_create.result.return_value = subnet_create_res
        nclient.subnets.create_or_update.return_value = subnet_create

        public_ip_create = MagicMock()
        public_ip_create_res = MagicMock()
        public_ip_create_res.id = "ip-0"
        public_ip_create.result.return_value = public_ip_create_res
        nclient.public_ip_addresses.create_or_update.return_value = public_ip_create

        instace_type = MagicMock()
        instace_type.name = "instance_type1"
        instace_type.number_of_cores = 1
        instace_type.memory_in_mb = 1024
        instace_type.resource_disk_size_in_mb = 102400
        instace_types = [instace_type]
        cclient.virtual_machine_sizes.list.return_value = instace_types

        cclient.virtual_machines.create_or_update.side_effect = self.create_vm

        res = azure_cloud.launch_with_retry(InfrastructureInfo(), radl, radl, 3, auth, 2, 0)
        self.assertEqual(len(res), 3)
        self.assertTrue(res[0][0])
        self.assertTrue(res[1][0])
        self.assertTrue(res[2][0])
        self.assertEquals(rclient.resource_groups.delete.call_count, 2)
        self.assertIn("rg-userimage-", rclient.resource_groups.delete.call_args_list[0][0][0])
        self.assertIn("rg-userimage-", rclient.resource_groups.delete.call_args_list[1][0][0])

    @patch('IM.connectors.Azure.NetworkManagementClient')
    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.DnsManagementClient')
    @patch('IM.connectors.Azure.UserPassCredentials')
    def test_30_updateVMInfo(self, credentials, dns_client, compute_client, network_client):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test.domain.com' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'azr://Canonical/UbuntuServer/16.04.0-LTS/latest' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'username': 'user', 'password': 'password'}])
        azure_cloud = self.get_azure_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "rg0/im0", azure_cloud.cloud, radl, radl, azure_cloud, 1)

        instace_type = MagicMock()
        instace_type.name = "instance_type1"
        instace_type.number_of_cores = 1
        instace_type.memory_in_mb = 1024
        instace_type.resource_disk_size_in_mb = 102400
        instace_types = [instace_type]
        cclient = MagicMock()
        compute_client.return_value = cclient
        cclient.virtual_machine_sizes.list.return_value = instace_types

        avm = MagicMock()
        avm.provisioning_state = "Succeeded"
        avm.hardware_profile.vm_size = "instance_type1"
        avm.location = "northeurope"
        ni = MagicMock()
        ni.id = "/subscriptions/subscription-id/resourceGroups/rg0/providers/Microsoft.Network/networkInterfaces/ni-0"
        avm.network_profile.network_interfaces = [ni]
        cclient.virtual_machines.get.return_value = avm

        nclient = MagicMock()
        network_client.return_value = nclient
        ni_res = MagicMock()
        ip_conf = MagicMock()
        ip_conf.private_ip_address = "10.0.0.1"
        ip_conf.public_ip_address.id = ("/subscriptions/subscription-id/resourceGroups/rg0/"
                                        "providers/Microsoft.Network/networkInterfaces/ip-0")
        ni_res.ip_configurations = [ip_conf]
        nclient.network_interfaces.get.return_value = ni_res

        pub_ip_res = MagicMock()
        pub_ip_res.ip_address = "13.0.0.1"
        nclient.public_ip_addresses.get.return_value = pub_ip_res

        dclient = MagicMock()
        dns_client.return_value = dclient
        dclient.zones.get.return_value = None
        dclient.record_sets.get.return_value = None

        success, vm = azure_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertEquals(dclient.zones.create_or_update.call_args_list,
                          [call('rg0', 'domain.com', {'location': 'global'})])
        self.assertEquals(dclient.record_sets.create_or_update.call_args_list,
                          [call('rg0', 'domain.com', 'test', 'A',
                                {'arecords': [{'ipv4_address': '13.0.0.1'}], 'ttl': 300})])
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.UserPassCredentials')
    def test_40_stop(self, credentials, compute_client):
        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'username': 'user', 'password': 'password'}])
        azure_cloud = self.get_azure_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "rg0/vm0", azure_cloud.cloud, "", "", azure_cloud, 1)

        success, _ = azure_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.UserPassCredentials')
    def test_50_start(self, credentials, compute_client):
        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'username': 'user', 'password': 'password'}])
        azure_cloud = self.get_azure_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "rg0/vm0", azure_cloud.cloud, "", "", azure_cloud, 1)

        success, _ = azure_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.Azure.ResourceManagementClient')
    @patch('IM.connectors.Azure.StorageManagementClient')
    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.NetworkManagementClient')
    @patch('IM.connectors.Azure.UserPassCredentials')
    def test_55_alter(self, credentials, network_client, compute_client, storage_client, resource_client):
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

        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'username': 'user', 'password': 'password'}])
        azure_cloud = self.get_azure_cloud()

        instace_type = MagicMock()
        instace_type.name = "instance_type2"
        instace_type.number_of_cores = 2
        instace_type.memory_in_mb = 2048
        instace_type.resource_disk_size_in_mb = 102400
        instace_types = [instace_type]
        cclient = MagicMock()
        compute_client.return_value = cclient
        cclient.virtual_machine_sizes.list.return_value = instace_types

        vm = MagicMock()
        vm.provisioning_state = "Succeeded"
        vm.hardware_profile.vm_size = "instance_type2"
        vm.location = "northeurope"
        ni = MagicMock()
        ni.id = "/subscriptions/subscription-id/resourceGroups/rg0/providers/Microsoft.Network/networkInterfaces/ni-0"
        vm.network_profile.network_interfaces = [ni]
        cclient.virtual_machines.get.return_value = vm

        nclient = MagicMock()
        network_client.return_value = nclient
        ni_res = MagicMock()
        ip_conf = MagicMock()
        ip_conf.private_ip_address = "10.0.0.1"
        ip_conf.public_ip_address.id = ("/subscriptions/subscription-id/resourceGroups/rg0/"
                                        "providers/Microsoft.Network/networkInterfaces/ip-0")
        ni_res.ip_configurations = [ip_conf]
        nclient.network_interfaces.get.return_value = ni_res

        pub_ip_res = MagicMock()
        pub_ip_res.ip_address = "13.0.0.1"
        nclient.public_ip_addresses.get.return_value = pub_ip_res

        inf = MagicMock()
        vm = VirtualMachine(inf, "rg0/vm0", azure_cloud.cloud, radl, radl, azure_cloud, 1)

        success, _ = azure_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.Azure.ResourceManagementClient')
    @patch('IM.connectors.Azure.UserPassCredentials')
    def test_60_finalize(self, credentials, resource_client):
        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'username': 'user', 'password': 'password'}])
        azure_cloud = self.get_azure_cloud()
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.ip = '158.42.1.1' and
            net_interface.0.dns_name = 'test.domain.com'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        inf = MagicMock()
        vm = VirtualMachine(inf, "rg0/vm0", azure_cloud.cloud, radl, radl, azure_cloud, 1)

        success, _ = azure_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
