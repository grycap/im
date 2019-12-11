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
from IM.connectors.LibCloud import LibCloudCloudConnector
from mock import patch, MagicMock


class TestOSTConnector(TestCloudConnectorBase):
    """
    Class to test the IM connectors
    """

    @staticmethod
    def get_lib_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "LibCloud"
        inf = MagicMock()
        inf.id = "1"
        cloud = LibCloudCloudConnector(cloud_info, inf)
        return cloud

    @patch('libcloud.compute.drivers.ec2.EC2NodeDriver')
    def test_10_concrete(self, get_driver):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'aws://ami-id' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'libcloud', 'type': 'LibCloud', 'username': 'user',
                                'password': 'pass', 'driver': 'EC2'}])
        lib_cloud = self.get_lib_cloud()

        driver = MagicMock()
        driver.name = "Amazon EC2"
        get_driver.return_value = driver

        node_size = MagicMock()
        node_size.ram = 512
        node_size.price = 1
        node_size.disk = 1
        node_size.vcpus = 1
        node_size.name = "small"
        driver.list_sizes.return_value = [node_size]

        concrete = lib_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.ec2.EC2NodeDriver')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, get_driver):
        radl_data = """
            network net1 (outbound = 'yes')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'aws://ami-id' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'libcloud', 'type': 'LibCloud', 'username': 'user',
                                'password': 'pass', 'driver': 'EC2'}])
        lib_cloud = self.get_lib_cloud()

        driver = MagicMock()
        driver.name = "Amazon EC2"
        driver.features = {"create_node": ["ssh_key"]}
        get_driver.return_value = driver

        node_size = MagicMock()
        node_size.ram = 512
        node_size.price = 1
        node_size.disk = 1
        node_size.vcpus = 1
        node_size.name = "small"
        driver.list_sizes.return_value = [node_size]

        driver.get_key_pair.return_value = ""

        keypair = MagicMock()
        keypair.public_key = "public"
        driver.create_key_pair.return_value = keypair
        driver.features = {'create_node': ['ssh_key']}

        node = MagicMock()
        node.id = "1"
        node.name = "name"
        driver.create_node.return_value = node

        res = lib_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.ec2.EC2NodeDriver')
    def test_30_updateVMInfo(self, get_driver):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.ip = '158.42.1.1' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'aws://ami-id' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'libcloud', 'type': 'LibCloud', 'username': 'user',
                                'password': 'pass', 'driver': 'EC2'}])
        lib_cloud = self.get_lib_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", lib_cloud.cloud, radl, radl, lib_cloud, 1)

        driver = MagicMock()
        driver.name = "Amazon EC2"
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.extra = {'availability': 'use-east-1'}
        node.public_ips = []
        node.private_ips = ['10.0.0.1']
        node.driver = driver
        node.size = MagicMock()
        node.size.ram = 512
        node.size.price = 1
        node.size.disk = 1
        node.size.vcpus = 1
        node.size.name = "small"
        driver.list_nodes.return_value = [node]

        volume = MagicMock()
        volume.id = "vol1"
        volume.extra = {"state": "available"}
        volume.attach.return_value = True
        driver.create_volume.return_value = volume

        driver.ex_allocate_address.return_value = "10.0.0.1"

        success, vm = lib_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.ec2.EC2NodeDriver')
    def test_40_stop(self, get_driver):
        auth = Authentication([{'id': 'libcloud', 'type': 'LibCloud', 'username': 'user',
                                'password': 'pass', 'driver': 'EC2'}])
        lib_cloud = self.get_lib_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", lib_cloud.cloud, "", "", lib_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.driver = driver
        driver.list_nodes.return_value = [node]

        driver.ex_stop_node.return_value = True

        success, _ = lib_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.ec2.EC2NodeDriver')
    def test_50_start(self, get_driver):
        auth = Authentication([{'id': 'libcloud', 'type': 'LibCloud', 'username': 'user',
                                'password': 'pass', 'driver': 'EC2'}])
        lib_cloud = self.get_lib_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", lib_cloud.cloud, "", "", lib_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.driver = driver
        driver.list_nodes.return_value = [node]

        driver.ex_stop_node.return_value = True

        success, _ = lib_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: starting VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.ec2.EC2NodeDriver')
    def test_60_reboot(self, get_driver):
        auth = Authentication([{'id': 'libcloud', 'type': 'LibCloud', 'username': 'user',
                                'password': 'pass', 'driver': 'EC2'}])
        lib_cloud = self.get_lib_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", lib_cloud.cloud, "", "", lib_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.driver = driver
        node.reboot.return_value = True
        driver.list_nodes.return_value = [node]

        success, _ = lib_cloud.reboot(vm, auth)

        self.assertTrue(success, msg="ERROR: rebooting VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.ec2.EC2NodeDriver')
    def test_70_finalize(self, get_driver):
        auth = Authentication([{'id': 'libcloud', 'type': 'LibCloud', 'username': 'user',
                                'password': 'pass', 'driver': 'EC2'}])
        lib_cloud = self.get_lib_cloud()

        radl_data = """
            system test (
            cpu.count>=2 and
            memory.size>=2048m
            )"""
        radl = radl_parse.parse_radl(radl_data)

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", lib_cloud.cloud, radl, radl, lib_cloud, 1)
        vm.keypair = ""

        driver = MagicMock()
        driver.name = "Amazon EC2"
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.driver = driver
        node.destroy.return_value = True
        driver.list_nodes.return_value = [node]

        sg = MagicMock()
        sg.id = sg.name = "sg1"
        driver.ex_get_node_security_groups.return_value = [sg]

        keypair = MagicMock()
        driver.get_key_pair.return_value = keypair
        vm.keypair = keypair
        volume = MagicMock()
        volume.id = "id"
        vm.volumes = [volume]

        driver.delete_key_pair.return_value = True

        driver.ex_describe_addresses_for_node.return_value = ["ip"]
        driver.ex_disassociate_address.return_value = True

        success, _ = lib_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
