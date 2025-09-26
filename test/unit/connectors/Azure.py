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
from .CloudConn import TestCloudConnectorBase
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
from IM.VirtualMachine import VirtualMachine
from IM.InfrastructureInfo import InfrastructureInfo
from IM.connectors.Azure import AzureCloudConnector
from azure.core.exceptions import ResourceNotFoundError
from mock import patch, MagicMock, call
from IM.config import Config


class TestAzureConnector(TestCloudConnectorBase):
    """
    Class to test the IM connectors
    """

    def setUp(self):
        self.error_in_wait = True
        self.error_in_create = True
        TestCloudConnectorBase.setUp(self)

    @staticmethod
    def get_azure_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "Azure"
        inf = MagicMock()
        inf.id = "1"
        cloud = AzureCloudConnector(cloud_info, inf)
        return cloud

    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.ClientSecretCredential')
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
                                'client_id': 'client', 'secret': 'password', 'tenant': 'tenant'}])
        azure_cloud = self.get_azure_cloud()

        sku = MagicMock()
        sku.resource_type = "virtualMachines"
        sku.name = "Standard_A1"
        cpu_cap = MagicMock()
        cpu_cap.name = "vCPUs"
        cpu_cap.value = "1"
        mem_cap = MagicMock()
        mem_cap.name = "MemoryGB"
        mem_cap.value = "1"
        res_cap = MagicMock()
        res_cap.name = "MaxResourceVolumeMB"
        res_cap.value = "102400"
        os_cap = MagicMock()
        os_cap.name = "OSVhdSizeMB"
        os_cap.value = "102400"
        sku.capabilities = [cpu_cap, mem_cap, res_cap, os_cap]
        client = MagicMock()
        compute_client.return_value = client
        client.resource_skus.list.return_value = [sku]

        concrete = azure_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            instance_type = 'Standard_*' and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'azr://image-id' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

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
    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.NetworkManagementClient')
    @patch('IM.connectors.Azure.ClientSecretCredential')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, credentials, network_client, compute_client, resource_client):
        radl_data = """
            network net1 (outbound = 'yes' and outports = '8080,9000:9100' and sg_name = 'nsgname')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            instance_tags = 'key=value,key1=value2' and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.size = 20g and
            disk.0.image.url = 'azr://Canonical/UbuntuServer/16.04.0-LTS/latest' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path' and
            disk.2.image.url='RGname/DiskName' and
            disk.2.device='hdb' and
            disk.2.mount_path='/mnt/path2'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'client_id': 'client', 'secret': 'password', 'tenant': 'tenant'},
                               {'type': 'InfrastructureManager', 'username': 'user', 'password': 'pass'}])
        azure_cloud = self.get_azure_cloud()

        cclient = MagicMock()
        compute_client.return_value = cclient
        nclient = MagicMock()
        network_client.return_value = nclient
        rclient = MagicMock()
        resource_client.return_value = rclient

        nclient.virtual_networks.get.side_effect = ResourceNotFoundError()

        subnet_create = MagicMock()
        subnet_create_res = MagicMock()
        subnet_create_res.id = "subnet-0"
        subnet_create_res.address_prefix = "10.0.1.0/24"
        subnet_create.result.return_value = subnet_create_res
        nclient.subnets.begin_create_or_update.return_value = subnet_create
        nclient.subnets.get.side_effect = ResourceNotFoundError()

        nic_create = MagicMock()
        nic_create_res = MagicMock()
        nic_create_res.id = "nic-0"
        nic_create_res.name = "nic_name"
        nic_create.result.return_value = nic_create_res
        nclient.network_interfaces.begin_create_or_update.return_value = nic_create

        public_ip_create = MagicMock()
        public_ip_create_res = MagicMock()
        public_ip_create_res.id = "ip-0"
        public_ip_create.result.return_value = public_ip_create_res
        nclient.public_ip_addresses.begin_create_or_update.return_value = public_ip_create

        sku = MagicMock()
        sku.resource_type = "virtualMachines"
        sku.name = "Standard_A1"
        cpu_cap = MagicMock()
        cpu_cap.name = "vCPUs"
        cpu_cap.value = "1"
        mem_cap = MagicMock()
        mem_cap.name = "MemoryGB"
        mem_cap.value = "1"
        res_cap = MagicMock()
        res_cap.name = "MaxResourceVolumeMB"
        res_cap.value = "102400"
        os_cap = MagicMock()
        os_cap.name = "OSVhdSizeMB"
        os_cap.value = "102400"
        sku.capabilities = [cpu_cap, mem_cap, res_cap, os_cap]
        cclient.resource_skus.list.return_value = [sku]

        cclient.virtual_machines.begin_create_or_update.side_effect = self.create_vm

        cclient.virtual_machine_images.list.return_value = ["image"]

        disk = MagicMock()
        disk.name = "dname"
        disk.id = "did"
        cclient.disks.get.return_value = disk

        inf = InfrastructureInfo()
        inf.auth = auth
        inf.radl = radl
        res = azure_cloud.launch_with_retry(inf, radl, radl, 3, auth, 2, 0)
        self.assertEqual(len(res), 3)
        self.assertTrue(res[0][0])
        self.assertTrue(res[1][0])
        self.assertTrue(res[2][0])
        self.assertEqual(nclient.network_interfaces.begin_delete.call_count, 1)
        self.assertIn("nic_name", nclient.network_interfaces.begin_delete.call_args_list[0][0][1])

        json_vm_req = cclient.virtual_machines.begin_create_or_update.call_args_list[0][0][2]
        self.assertEqual(json_vm_req['storage_profile']['data_disks'][0]['disk_size_gb'], 1)
        self.assertEqual(json_vm_req['storage_profile']['data_disks'][1]['managed_disk']['id'], "did")
        image_res = {'sku': '16.04.0-LTS', 'publisher': 'Canonical', 'version': 'latest', 'offer': 'UbuntuServer'}
        self.assertEqual(json_vm_req['storage_profile']['image_reference'], image_res)
        self.assertEqual(json_vm_req['hardware_profile']['vm_size'], 'Standard_A1')
        self.assertEqual(json_vm_req['os_profile']['admin_username'], 'user')
        self.assertEqual(json_vm_req['os_profile']['admin_password'], 'pass')
        self.assertEqual(json_vm_req['os_profile']['admin_password'], 'pass')
        self.assertEqual(nclient.subnets.begin_create_or_update.call_args_list[0][0][3]['address_prefix'],
                         '10.0.1.0/24')

        radl_data = """
            network net1 (outbound = 'yes')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            instance_tags = 'key=value,key1=value2' and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'azr://error/rgname/diskname' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()
        with self.assertRaises(Exception) as ex:
            azure_cloud.launch(inf, radl, radl, 1, auth)
        self.assertEqual(str(ex.exception), "Incorrect image url: it must be snapshot or disk.")

        radl_data = """
            network net1 (outbound = 'yes')
            network net2 (cidr = '192.168.*.0/24')
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            instance_tags = 'key=value,key1=value2' and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'azr://snapshot/rgname/diskname' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()
        res = azure_cloud.launch(inf, radl, radl, 1, auth)
        json_vm_req = cclient.virtual_machines.begin_create_or_update.call_args_list[5][0][2]
        self.assertEqual(json_vm_req['storage_profile']['os_disk']['os_type'], 'linux')
        self.assertEqual(nclient.subnets.begin_create_or_update.call_args_list[2][0][3]['address_prefix'],
                         '192.168.1.0/24')

        radl_data = """
            network net1 (outbound = 'yes')
            network net2 (provider_id = 'vnet.subnet1')
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            instance_tags = 'key=value,key1=value2' and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'azr://snapshot/rgname/diskname' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        vnet = MagicMock()
        vnet.id = "vnetid"
        nclient.virtual_networks.get.side_effect = None
        nclient.virtual_networks.get.return_value = vnet
        nclient.subnets.get.side_effect = None
        subnet_create.address_prefix = "10.0.1.0/24"
        nclient.subnets.get.return_value = subnet_create
        res = azure_cloud.launch(inf, radl, radl, 1, auth)
        self.assertEqual(nclient.subnets.get.call_args_list[3][0][1], 'vnet')
        self.assertEqual(nclient.subnets.get.call_args_list[3][0][2], 'subnet1')
        self.assertEqual(nclient.subnets.begin_create_or_update.call_count, 3)
        self.assertEqual(nclient.virtual_networks.begin_create_or_update.call_count, 3)
        self.assertEqual(nclient.public_ip_addresses.begin_create_or_update.call_count, 7)

        old_priv = Config.PRIVATE_NET_MASKS
        Config.PRIVATE_NET_MASKS = ["172.16.0.0/12", "192.168.0.0/16"]
        res = azure_cloud.launch(inf, radl, radl, 1, auth)
        Config.PRIVATE_NET_MASKS = old_priv
        # Check that public ip is not created
        self.assertEqual(nclient.public_ip_addresses.begin_create_or_update.call_count, 7)

    @patch('IM.connectors.Azure.NetworkManagementClient')
    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.DnsManagementClient')
    @patch('IM.connectors.Azure.ClientSecretCredential')
    def test_30_updateVMInfo(self, credentials, dns_client, compute_client, network_client):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test.domain.com' and
            net_interface.0.additional_dns_names = ['some.test@domain.com'] and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'azr://Canonical/UbuntuServer/16.04.0-LTS/latest' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'client_id': 'client', 'secret': 'password', 'tenant': 'tenant'}])
        azure_cloud = self.get_azure_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "rg0/im0", azure_cloud.cloud, radl, radl, azure_cloud, 1)

        sku = MagicMock()
        sku.resource_type = "virtualMachines"
        sku.name = "Standard_A1"
        cpu_cap = MagicMock()
        cpu_cap.name = "vCPUs"
        cpu_cap.value = "1"
        mem_cap = MagicMock()
        mem_cap.name = "MemoryGB"
        mem_cap.value = "1"
        res_cap = MagicMock()
        res_cap.name = "MaxResourceVolumeMB"
        res_cap.value = "102400"
        os_cap = MagicMock()
        os_cap.name = "OSVhdSizeMB"
        os_cap.value = "102400"
        sku.capabilities = [cpu_cap, mem_cap, res_cap, os_cap]
        cclient = MagicMock()
        compute_client.return_value = cclient
        cclient.resource_skus.list.return_value = [sku]

        avm = MagicMock()
        avm.provisioning_state = "Succeeded"
        avm.hardware_profile.vm_size = "Standard_A1"
        avm.location = "northeurope"
        status1 = MagicMock()
        status1.code = "ProvisioningState/succeeded"
        status2 = MagicMock()
        status2.code = "PowerState/running"
        avm.instance_view.statuses = [status1, status2]
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
        self.assertEqual(dclient.zones.create_or_update.call_args_list[0],
                         call('rg0', 'domain.com', {'location': 'global'}))
        self.assertEqual(dclient.record_sets.create_or_update.call_args_list[0],
                         call('rg0', 'domain.com', 'test', 'A',
                              {'arecords': [{'ipv4_address': '13.0.0.1'}], 'ttl': 300}))
        self.assertEqual(dclient.record_sets.create_or_update.call_args_list[1],
                         call('rg0', 'domain.com', 'some.test', 'A',
                              {'arecords': [{'ipv4_address': '13.0.0.1'}], 'ttl': 300}))
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        # Test using PRIVATE_NET_MASKS setting 10.0.0.0/8 as public net
        old_priv = Config.PRIVATE_NET_MASKS
        Config.PRIVATE_NET_MASKS = ["172.16.0.0/12", "192.168.0.0/16"]
        ip_conf.public_ip_address = None
        success, vm = azure_cloud.updateVMInfo(vm, auth)
        Config.PRIVATE_NET_MASKS = old_priv
        self.assertEqual(vm.getPublicIP(), "10.0.0.1")
        self.assertEqual(vm.getPrivateIP(), None)

    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.ClientSecretCredential')
    def test_40_stop(self, credentials, compute_client):
        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'client_id': 'client', 'secret': 'password', 'tenant': 'tenant'}])
        azure_cloud = self.get_azure_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "rg0/vm0", azure_cloud.cloud, "", "", azure_cloud, 1)

        success, _ = azure_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.ClientSecretCredential')
    def test_50_start(self, credentials, compute_client):
        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'client_id': 'client', 'secret': 'password', 'tenant': 'tenant'}])
        azure_cloud = self.get_azure_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "rg0/vm0", azure_cloud.cloud, "", "", azure_cloud, 1)

        success, _ = azure_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.ClientSecretCredential')
    def test_52_reboot(self, credentials, compute_client):
        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'client_id': 'client', 'secret': 'password', 'tenant': 'tenant'}])
        azure_cloud = self.get_azure_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "rg0/vm0", azure_cloud.cloud, "", "", azure_cloud, 1)

        success, _ = azure_cloud.reboot(vm, auth)

        self.assertTrue(success, msg="ERROR: rebooting VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.Azure.ResourceManagementClient')
    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.NetworkManagementClient')
    @patch('IM.connectors.Azure.ClientSecretCredential')
    def test_55_alter(self, credentials, network_client, compute_client, resource_client):
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
                                'client_id': 'client', 'secret': 'password', 'tenant': 'tenant'}])
        azure_cloud = self.get_azure_cloud()

        sku = MagicMock()
        sku.resource_type = "virtualMachines"
        sku.name = "Standard_A2"
        cpu_cap = MagicMock()
        cpu_cap.name = "vCPUs"
        cpu_cap.value = "2"
        mem_cap = MagicMock()
        mem_cap.name = "MemoryGB"
        mem_cap.value = "2"
        res_cap = MagicMock()
        res_cap.name = "MaxResourceVolumeMB"
        res_cap.value = "102400"
        os_cap = MagicMock()
        os_cap.name = "OSVhdSizeMB"
        os_cap.value = "102400"
        sku.capabilities = [cpu_cap, mem_cap, res_cap, os_cap]
        cclient = MagicMock()
        compute_client.return_value = cclient
        cclient.resource_skus.list.return_value = [sku]

        vm = MagicMock()
        vm.provisioning_state = "Succeeded"
        vm.hardware_profile.vm_size = "Standard_A2"
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

    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.ResourceManagementClient')
    @patch('IM.connectors.Azure.ClientSecretCredential')
    def test_60_finalize(self, credentials, resource_client, compute_client):
        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'client_id': 'client', 'secret': 'password', 'tenant': 'tenant'}])
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
        inf.id = "1"
        vm = VirtualMachine(inf, "rg0/vm0", azure_cloud.cloud, radl, radl, azure_cloud, 1)
        vm.disks = ["disk1"]
        vm.dns_entries = [('test', 'domain.com.', '158.42.1.1')]

        cclient = MagicMock()
        compute_client.return_value = cclient
        rclient = MagicMock()
        resource_client.return_value = rclient
        rg = MagicMock()
        rg.tags = {'InfID': "1"}
        rclient.resource_groups.get.return_value = rg

        success, _ = azure_cloud.finalize(vm, False, auth)
        success, _ = azure_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        self.assertEqual(cclient.virtual_machines.begin_delete.call_count, 2)
        self.assertEqual(cclient.virtual_machines.begin_delete.call_args_list[0][0], ('rg0', 'vm0'))
        self.assertEqual(rclient.resource_groups.begin_delete.call_count, 1)
        self.assertEqual(rclient.resource_groups.begin_delete.call_args_list[0][0], ('rg0',))

    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.ClientSecretCredential')
    def test_list_images(self, credentials, compute_client):
        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'client_id': 'client', 'secret': 'password', 'tenant': 'tenant'}])
        azure_cloud = self.get_azure_cloud()

        cclient = MagicMock()
        compute_client.return_value = cclient
        offer = MagicMock()
        offer.name = "offer1"
        offer2 = MagicMock()
        offer2.name = "offer2"
        cclient.virtual_machine_images.list_offers.return_value = [offer, offer2]
        sku = MagicMock()
        sku.name = "sku1"
        cclient.virtual_machine_images.list_skus.return_value = [sku]
        pub = MagicMock()
        pub.name = "pub1"
        cclient.virtual_machine_images.list_publishers.return_value = [pub]

        images = azure_cloud.list_images(auth)

        self.assertEqual(len(images), 18)
        self.assertEqual(images[0], {'uri': 'azr://Canonical/offer1/sku1/latest', 'name': 'Canonical offer1 sku1'})

        images = azure_cloud.list_images(auth, filters={"publisher": "*"})
        self.assertEqual(images, [{'uri': 'azr://pub1/offer1/sku1/latest', 'name': 'pub1 offer1 sku1'},
                                  {'uri': 'azr://pub1/offer2/sku1/latest', 'name': 'pub1 offer2 sku1'}])

        images = azure_cloud.list_images(auth, filters={"publisher": "*", "offer": "offer1"})
        self.assertEqual(images, [{'uri': 'azr://pub1/offer1/sku1/latest', 'name': 'pub1 offer1 sku1'}])

        images = azure_cloud.list_images(auth, filters={"publisher": "*", "offer": "*"})
        self.assertEqual(images, [{'uri': 'azr://pub1/offer1/sku1/latest', 'name': 'pub1 offer1 sku1'},
                                  {'uri': 'azr://pub1/offer2/sku1/latest', 'name': 'pub1 offer2 sku1'}])

    @patch('IM.connectors.Azure.ResourceManagementClient')
    @patch('IM.connectors.Azure.ComputeManagementClient')
    @patch('IM.connectors.Azure.ClientSecretCredential')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_invalid_rg_name_launch(self, save_data, credentials, compute_client, resource_client):
        radl_data = """
            network net1 (outbound = 'yes')
            network net2 ()
            system test (
            rg_name='rg1' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net1' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'azr://Canonical/UbuntuServer/16.04.0-LTS/latest'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'azure', 'type': 'Azure', 'subscription_id': 'subscription_id',
                                'client_id': 'client', 'secret': 'password', 'tenant': 'tenant'},
                               {'type': 'InfrastructureManager', 'username': 'user', 'password': 'pass'}])
        azure_cloud = self.get_azure_cloud()

        inf = InfrastructureInfo()
        inf.auth = auth
        inf.radl = radl
        res = azure_cloud.launch_with_retry(inf, radl, radl, 1, auth, 1, 0)

        radl_data = """
            network net1 (outbound = 'yes')
            network net2 ()
            system test2 (
            rg_name='rg2' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net1' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'azr://Canonical/UbuntuServer/16.04.0-LTS/latest'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        res = azure_cloud.launch_with_retry(inf, radl, radl, 1, auth, 1, 0)
        self.assertEqual(res, [(False, 'Attempt 1: Error: Invalid rg_name. It must be unique per infrastructure.\n')])


if __name__ == '__main__':
    unittest.main()
