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
from IM.connectors.Linode import LinodeCloudConnector
from IM.connectors.Linode import NodeState
from mock import patch, MagicMock


class TestLinodeConnector(TestCloudConnectorBase):
    """
    Class to test the IM connectors
    """

    @staticmethod
    def get_lib_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "Linode"
        inf = MagicMock()
        inf.id = "1"
        cloud = LinodeCloudConnector(cloud_info, inf)
        return cloud

    @patch('libcloud.compute.drivers.linode.LinodeNodeDriver')
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
            disk.0.image.url = 'lin://linode/ubuntu' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'linode', 'type': 'Linode', 'username': 'apiKey'}])
        linode_cloud = self.get_lib_cloud()

        driver = MagicMock(['list_sizes'])
        get_driver.return_value = driver

        node_size = MagicMock(['ram', 'name', 'id', 'price', 'disk', 'extra'])
        node_size.ram = 512
        node_size.price = 1
        node_size.disk = 1
        node_size.extra = {'vcpus': 1}
        node_size.name = "Linude 512M"
        node_size.id = "small"
        node_size2 = MagicMock(['ram', 'name', 'id', 'price', 'disk', 'extra'])
        node_size2.ram = 1024
        node_size2.price = 2
        node_size2.disk = 1
        node_size2.extra = {'vcpus': 2}
        node_size2.name = "Linude 1G"
        node_size2.id = "medium"
        driver.list_sizes.return_value = [node_size, node_size2]

        concrete = linode_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertEqual(concrete[0].getValue('instance_type'), "small")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            instance_type = 'me*' and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'lin://linode/ubuntu' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]
        concrete = linode_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertEqual(concrete[0].getValue('instance_type'), "medium")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.linode.LinodeNodeDriver')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, get_driver):
        radl_data = """
            network net1 (outbound = 'yes')
            network net2 ()
            system test (
            cpu.count=1 and
            gpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            availability_zone = 'us-east' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'lin://linode/ubuntu' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'linode', 'type': 'Linode', 'username': 'apiKey'}])
        linode_cloud = self.get_lib_cloud()

        driver = MagicMock(['list_sizes', 'create_node', 'list_locations'])
        get_driver.return_value = driver

        node_size = MagicMock(['ram', 'price', 'disk', 'extra'])
        node_size.ram = 512
        node_size.price = 1
        node_size.disk = 1
        node_size.extra = {'vcpus': 1, 'gpus': None}
        node_size.name = "small"

        node_sizeg = MagicMock(['ram', 'price', 'disk', 'extra'])
        node_sizeg.ram = 512
        node_sizeg.price = 2
        node_sizeg.disk = 1
        node_sizeg.extra = {'vcpus': 1, 'gpus': 1}
        node_sizeg.name = "gsmall"
        driver.list_sizes.return_value = [node_size, node_sizeg]

        node = MagicMock(['id', 'name', 'driver'])
        node.id = "1"
        node.name = "name"
        node.driver = driver
        driver.create_node.return_value = node

        location = MagicMock(['id', 'name'])
        location.id = 'us-east'
        location.name = 'us-east'
        driver.list_locations.return_value = [location]

        res = linode_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertEqual(driver.create_node.call_args_list[0][1]['size'], node_sizeg)
        self.assertEqual(driver.create_node.call_args_list[0][1]['image'].id, 'linode/ubuntu')
        self.assertEqual(driver.create_node.call_args_list[0][1]['location'], location)
        self.assertEqual(len(driver.create_node.call_args_list[0][1]['root_pass']), 8)
        self.assertLess(len(driver.create_node.call_args_list[0][1]['name']), 32)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.linode.LinodeNodeDriver')
    @patch('libcloud.dns.drivers.linode.LinodeDNSDriver')
    def test_30_updateVMInfo(self, get_dns_driver, get_driver):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test.domain.com' and
            net_interface.0.additional_dns_names = ['other-test.domain.com'] and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'lin://linode/ubuntu' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass' and
            disk.1.size=1GB and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'linode', 'type': 'Linode', 'username': 'apiKey'}])
        linode_cloud = self.get_lib_cloud()

        inf = MagicMock(['id'])
        vm = VirtualMachine(inf, "1", linode_cloud.cloud, radl, radl, linode_cloud, 1)

        driver = MagicMock(['name', 'ex_get_node', 'list_sizes', 'create_volume', 'list_volumes'])
        get_driver.return_value = driver
        driver.name = 'Linode'
        dns_driver = MagicMock()
        get_dns_driver.return_value = dns_driver

        node = MagicMock(['id', 'state', 'public_ips', 'private_ips', 'driver', 'size'])
        node.id = "1"
        node.state = NodeState.RUNNING
        node.public_ips = ['8.8.8.8']
        node.private_ips = ['10.0.0.1']
        node.driver = driver
        node.size = "small"
        driver.ex_get_node.return_value = node

        node_size = MagicMock(['id', 'ram', 'price', 'disk', 'extra'])
        node_size.id = 'small'
        node_size.ram = 512
        node_size.price = 1
        node_size.disk = 1
        node_size.extra = {'vcpus': 1}
        node_size.name = "small"
        driver.list_sizes.return_value = [node_size]

        volume = MagicMock(['id', 'extra'])
        volume.id = "vol1"
        volume.extra = {"filesystem_path": "/dev/algo", "linode_id": "1"}
        driver.create_volume.return_value = volume
        driver.list_volumes.return_value = []

        dns_driver.list_zones.return_value = []
        dns_driver.list_records.return_value = []

        success, vm = linode_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertEqual(driver.create_volume.call_args_list[0][0][1], 10)
        self.assertEqual(driver.create_volume.call_args_list[0][1]['node'], node)

        self.assertEqual(dns_driver.create_zone.call_count, 2)
        self.assertEqual(dns_driver.create_record.call_count, 2)
        self.assertEqual(dns_driver.create_zone.call_args_list[0][0][0], 'domain.com')
        self.assertEqual(dns_driver.create_record.call_args_list[0][0][0], 'test')
        self.assertEqual(dns_driver.create_record.call_args_list[0][0][2], 'A')
        self.assertEqual(dns_driver.create_record.call_args_list[0][0][3], '8.8.8.8')
        self.assertEqual(dns_driver.create_record.call_args_list[1][0][0], 'other-test')

        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.linode.LinodeNodeDriver')
    def test_40_stop(self, get_driver):
        auth = Authentication([{'id': 'linode', 'type': 'Linode', 'username': 'apiKey'}])
        linode_cloud = self.get_lib_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", linode_cloud.cloud, "", "", linode_cloud, 1)

        driver = MagicMock(['ex_get_node'])
        get_driver.return_value = driver

        node = MagicMock(['id', 'state', 'driver', 'stop_node'])
        node.id = "1"
        node.state = NodeState.RUNNING
        node.driver = driver
        driver.ex_get_node.return_value = node

        node.stop_node.return_value = True

        success, _ = linode_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.linode.LinodeNodeDriver')
    def test_50_start(self, get_driver):
        auth = Authentication([{'id': 'linode', 'type': 'Linode', 'username': 'apiKey'}])
        linode_cloud = self.get_lib_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", linode_cloud.cloud, "", "", linode_cloud, 1)

        driver = MagicMock(['ex_get_node'])
        get_driver.return_value = driver

        node = MagicMock(['id', 'state', 'driver', 'start'])
        node.id = "1"
        node.state = NodeState.RUNNING
        node.driver = driver
        node.start.return_value = True
        driver.ex_get_node.return_value = node

        success, _ = linode_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: starting VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.linode.LinodeNodeDriver')
    def test_55_alter(self, get_driver):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'one://server.com/1' and
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

        auth = Authentication([{'id': 'linode', 'type': 'Linode', 'username': 'apiKey'}])
        linode_cloud = self.get_lib_cloud()

        inf = MagicMock(['id'])
        vm = VirtualMachine(inf, "1", linode_cloud.cloud, radl, radl, linode_cloud, 1)

        driver = MagicMock(['ex_get_node', 'list_sizes', 'ex_resize_node', 'create_volume'])
        get_driver.return_value = driver

        node = MagicMock(['id', 'state', 'driver', 'size', 'public_ips', 'private_ips'])
        node.id = "1"
        node.state = NodeState.RUNNING
        node.size = "small"
        node.public_ips = []
        node.private_ips = ['10.0.0.1']
        node.driver = driver
        driver.ex_get_node.return_value = node

        node_size = MagicMock(['id', 'ram', 'price', 'disk', 'extra', 'name'])
        node_size.ram = 2048
        node_size.price = 1
        node_size.disk = 1
        node_size.extra = {'vcpus': 2}
        node_size.name = "big"
        node_size.id = "big"
        driver.list_sizes.return_value = [node_size]

        driver.ex_resize_node.return_value = True

        success, _ = linode_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertEqual(driver.ex_resize_node.call_args_list[0][0], (node, node_size))

        new_radl_data = """
            system test (
            disk.1.size = 10G
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        volume = MagicMock(['id', 'extra'])
        volume.id = 'volid'
        volume.extra = {"filesystem_path": "/dev/deviceid"}

        driver.create_volume.return_value = volume

        success, _ = linode_cloud.alterVM(vm, new_radl, auth)
        self.assertEqual(vm.info.systems[0].getValue("disk.1.device"), 'deviceid')
        self.assertTrue(success, msg="ERROR: modifying VM info.")

    @patch('libcloud.compute.drivers.linode.LinodeNodeDriver')
    def test_60_reboot(self, get_driver):
        auth = Authentication([{'id': 'linode', 'type': 'Linode', 'username': 'apiKey'}])
        linode_cloud = self.get_lib_cloud()

        inf = MagicMock(['id'])
        vm = VirtualMachine(inf, "1", linode_cloud.cloud, "", "", linode_cloud, 1)

        driver = MagicMock(['ex_get_node'])
        get_driver.return_value = driver

        node = MagicMock(['id', 'state', 'driver', 'reboot'])
        node.id = "1"
        node.state = "running"
        node.driver = driver
        node.reboot.return_value = True
        driver.ex_get_node.return_value = node

        success, _ = linode_cloud.reboot(vm, auth)

        self.assertTrue(success, msg="ERROR: rebooting VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.linode.LinodeNodeDriver')
    @patch('libcloud.dns.drivers.linode.LinodeDNSDriver')
    def test_70_finalize(self, get_dns_driver, get_driver):
        auth = Authentication([{'id': 'linode', 'type': 'Linode', 'username': 'apiKey'}])
        lib_cloud = self.get_lib_cloud()

        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.count>=2 and
            memory.size>=2048m and
            net_interface.0.connection = 'net' and
            net_interface.0.ip = '158.42.1.1' and
            net_interface.0.dns_name = 'test.domain.com'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        inf = MagicMock(['id'])
        vm = VirtualMachine(inf, "1", lib_cloud.cloud, radl, radl, lib_cloud, 1)
        vm.dns_entries = [('test', 'domain.com.', '158.42.1.1')]

        driver = MagicMock(['ex_get_node', 'list_volumes'])
        get_driver.return_value = driver
        dns_driver = MagicMock()
        get_dns_driver.return_value = dns_driver

        node = MagicMock(['id', 'state', 'driver', 'destroy'])
        node.id = "1"
        node.state = NodeState.RUNNING
        node.driver = driver
        node.destroy.return_value = True
        driver.ex_get_node.return_value = node

        volume = MagicMock(['id', 'extra', 'detach', 'destroy'])
        volume.id = "id"
        volume.extra = {'linode_id': '1'}
        volume.detach.return_value = True
        volume.destroy.return_value = True
        driver.list_volumes.return_value = [volume]

        zone = MagicMock()
        zone.domain = 'domain.com'
        record = MagicMock()
        record.data = '158.42.1.1'
        record.name = 'test'
        dns_driver.list_zones.return_value = [zone]
        dns_driver.list_records.return_value = [record]
        dns_driver.delete_record.return_value = True

        success, _ = lib_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertEqual(node.destroy.call_count, 1)
        self.assertEqual(volume.detach.call_count, 1)
        self.assertEqual(volume.destroy.call_count, 1)
        self.assertEqual(dns_driver.delete_record.call_count, 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.linode.LinodeNodeDriver')
    def test_get_cloud_info(self, get_driver):
        auth = Authentication([{'id': 'linode', 'type': 'Linode', 'username': 'apiKey'}])
        lib_cloud = self.get_lib_cloud()

        driver = MagicMock()
        get_driver.return_value = driver

        image = MagicMock(['id', 'name'])
        image.id = "image_id"
        image.name = "image_name"
        driver.list_images.return_value = [image]

        res = lib_cloud.list_images(auth)

        self.assertEqual(res, [{"uri": "lin://image_id", "name": "image_name"}])


if __name__ == '__main__':
    unittest.main()
