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
from IM.connectors.CloudStack import CloudStackCloudConnector
from mock import patch, MagicMock


class TestOSCConnector(TestCloudConnectorBase):
    """
    Class to test the IM connectors
    """

    def setUp(self):
        self.error_in_create = True
        TestCloudConnectorBase.setUp(self)

    @staticmethod
    def get_osc_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "CloudStack"
        cloud_info.protocol = "http"
        cloud_info.server = "server.com"
        inf = MagicMock()
        inf.id = "1"
        cloud = CloudStackCloudConnector(cloud_info, inf)
        return cloud

    @patch('libcloud.compute.drivers.cloudstack.CloudStackNodeDriver')
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
            disk.0.image.url = 'cst://server.com/image-id' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'ost', 'type': 'CloudStack', 'username': 'apikey',
                                'password': 'secretkey', 'host': 'http://server.com'}])
        osc_cloud = self.get_osc_cloud()

        driver = MagicMock()
        get_driver.return_value = driver

        node_size = MagicMock()
        node_size.ram = 512
        node_size.price = 1
        node_size.disk = 1
        node_size.vcpus = 1
        node_size.name = "small"
        driver.list_sizes.return_value = [node_size]

        concrete = osc_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    def create_node(self, **kwargs):
        """
        Create VMs returning error only first time
        """
        if self.error_in_create:
            self.error_in_create = False
            raise Exception("Error creating VM")
        else:
            node = MagicMock()
            node.id = "osc1"
            node.name = "osc1name"
            return node

    @patch('libcloud.compute.drivers.cloudstack.CloudStackNodeDriver')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, get_driver):
        radl_data = """
            network net1 (outbound = 'yes' and outports = '8080,9000:9100' and sg_name= 'test')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            instance_tags='key=value,key1=value2' and
            net_interface.0.connection = 'net1' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'cst://server.com/image-id' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'ost', 'type': 'CloudStack', 'username': 'apikey',
                                'password': 'secretkey', 'host': 'http://server.com'},
                               {'type': 'InfrastructureManager', 'username': 'user', 'password': 'pass'}])
        osc_cloud = self.get_osc_cloud()

        driver = MagicMock()
        get_driver.return_value = driver

        node_size = MagicMock()
        node_size.ram = 512
        node_size.price = 1
        node_size.disk = 1
        node_size.vcpus = 1
        node_size.name = "small"
        driver.list_sizes.return_value = [node_size]

        driver.ex_create_security_group.return_value = {"name": "sgname", "id": "sgid"}
        driver.ex_list_security_groups.return_value = []
        driver.ex_create_security_group_rule.return_value = True

        driver.create_node.side_effect = self.create_node

        inf = InfrastructureInfo()
        inf.auth = auth
        res = osc_cloud.launch_with_retry(inf, radl, radl, 1, auth, 2, 1)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")

    @patch('libcloud.compute.drivers.cloudstack.CloudStackNodeDriver')
    def test_30_updateVMInfo(self, get_driver):
        radl_data = """
            network net (outbound = 'yes')
            network net1 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.1.connection = 'net1' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'cst://server.com/ami-id' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass' and
            disk.1.size=1GB and
            disk.1.device='hdc' and
            disk.1.fstype='ext4' and
            disk.1.mount_path='/mnt/disk1'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'ost', 'type': 'CloudStack', 'username': 'apikey',
                                'password': 'secretkey', 'host': 'http://server.com'}])
        osc_cloud = self.get_osc_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", osc_cloud.cloud, radl, radl, osc_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.extra = {'size_name': 'small', 'zone_name': 'zname', 'zone_id': 'zid'}
        node.public_ips = ['8.8.8.8']
        node.private_ips = []
        node.driver = driver
        driver.list_nodes.return_value = [node]

        node_size = MagicMock()
        node_size.ram = 512
        node_size.price = 1
        node_size.disk = 1
        node_size.vcpus = 1
        node_size.name = "small"
        driver.ex_get_size.return_value = node_size

        volume = MagicMock()
        volume.id = "vol1"
        volume.attach.return_value = True
        driver.create_volume.return_value = volume

        success, vm = osc_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertEquals(vm.info.systems[0].getValue("net_interface.0.ip"), "8.8.8.8")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.cloudstack.CloudStackNodeDriver')
    def test_40_stop(self, get_driver):
        auth = Authentication([{'id': 'ost', 'type': 'CloudStack', 'username': 'apikey',
                                'password': 'secretkey', 'host': 'http://server.com'}])
        osc_cloud = self.get_osc_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", osc_cloud.cloud, "", "", osc_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.driver = driver
        driver.list_nodes.return_value = [node]
        node.ex_stop.return_value = u"Stopped"

        success, _ = osc_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.cloudstack.CloudStackNodeDriver')
    def test_50_start(self, get_driver):
        auth = Authentication([{'id': 'ost', 'type': 'CloudStack', 'username': 'apikey',
                                'password': 'secretkey', 'host': 'http://server.com'}])
        osc_cloud = self.get_osc_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", osc_cloud.cloud, "", "", osc_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.driver = driver
        driver.list_nodes.return_value = [node]
        node.ex_start.return_value = u"Running"

        success, _ = osc_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.cloudstack.CloudStackNodeDriver')
    def test_52_reboot(self, get_driver):
        auth = Authentication([{'id': 'ost', 'type': 'CloudStack', 'username': 'apikey',
                                'password': 'secretkey', 'host': 'http://server.com'}])
        osc_cloud = self.get_osc_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", osc_cloud.cloud, "", "", osc_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.driver = driver
        driver.list_nodes.return_value = [node]
        node.reboot_node.return_value = True

        success, _ = osc_cloud.reboot(vm, auth)

        self.assertTrue(success, msg="ERROR: rebooting VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.cloudstack.CloudStackNodeDriver')
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

        auth = Authentication([{'id': 'ost', 'type': 'CloudStack', 'username': 'apikey',
                                'password': 'secretkey', 'host': 'http://server.com'}])
        osc_cloud = self.get_osc_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", osc_cloud.cloud, radl, radl, osc_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.extra = {'size_name': 'small'}
        node.public_ips = ['8.8.8.8']
        node.private_ips = []
        node.driver = driver
        driver.list_nodes.return_value = [node]

        node.ex_stop.return_value = u"Stopped"
        node.ex_start.return_value = u"Running"

        node_size = MagicMock()
        node_size.ram = 2048
        node_size.price = 1
        node_size.disk = 1
        node_size.vcpus = 2
        node_size.name = "small"
        driver.list_sizes.return_value = [node_size]

        driver.ex_resize.return_value = True

        success, _ = osc_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.cloudstack.CloudStackNodeDriver')
    @patch('time.sleep')
    def test_60_finalize(self, sleep, get_driver):
        auth = Authentication([{'id': 'ost', 'type': 'CloudStack', 'username': 'apikey',
                                'password': 'secretkey', 'host': 'http://server.com'}])
        osc_cloud = self.get_osc_cloud()

        radl_data = """
            network public (outboud = 'yes')
            system test (
            cpu.count>=2 and
            memory.size>=2048m
            )"""
        radl = radl_parse.parse_radl(radl_data)

        inf = MagicMock()
        inf.id = "infid"
        inf.radl = radl
        vm = VirtualMachine(inf, "1", osc_cloud.cloud, radl, radl, osc_cloud, 1)
        vm.volumes = ["volid"]

        driver = MagicMock()
        driver.name = "CloudStack"
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.driver = driver
        node.destroy.return_value = True
        driver.list_nodes.return_value = [node]

        driver.delete_security_group.return_value = True

        success, _ = osc_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
