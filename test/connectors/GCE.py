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
from StringIO import StringIO

sys.path.append(".")
sys.path.append("..")
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
from IM.VirtualMachine import VirtualMachine
from IM.InfrastructureInfo import InfrastructureInfo
from IM.connectors.GCE import GCECloudConnector
from mock import patch, MagicMock


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestGCEConnector(unittest.TestCase):
    """
    Class to test the IM connectors
    """

    @classmethod
    def setUpClass(cls):
        cls.log = StringIO()
        ch = logging.StreamHandler(cls.log)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)

        logging.RootLogger.propagate = 0
        logging.root.setLevel(logging.ERROR)

        logger = logging.getLogger('CloudConnector')
        logger.setLevel(logging.DEBUG)
        logger.propagate = 0
        logger.addHandler(ch)

    @classmethod
    def clean_log(cls):
        cls.log = StringIO()

    @staticmethod
    def get_gce_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "GCE"
        one_cloud = GCECloudConnector(cloud_info)
        return one_cloud

    @patch('libcloud.compute.drivers.gce.GCENodeDriver')
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
            disk.0.image.url = 'gce://us-central1-a/centos-6' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'one', 'type': 'GCE', 'username': 'user',
                                'password': 'pass\npass', 'project': 'proj'}])

        driver = MagicMock()
        get_driver.return_value = driver

        node_size = MagicMock()
        node_size.ram = 512
        node_size.price = 1
        node_size.disk = 1
        node_size.name = "small"
        driver.list_sizes.return_value = [node_size]

        gce_cloud = self.get_gce_cloud()
        concrete = gce_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('libcloud.compute.drivers.gce.GCENodeDriver')
    def test_20_launch(self, get_driver):
        radl_data = """
            network net1 (outbound = 'yes')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.ip = '10.0.0.1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'gce://us-central1-a/centos-6' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'one', 'type': 'GCE', 'username': 'user',
                                'password': 'pass\npass', 'project': 'proj'}])
        gce_cloud = self.get_gce_cloud()

        driver = MagicMock()
        get_driver.return_value = driver

        node_size = MagicMock()
        node_size.ram = 512
        node_size.price = 1
        node_size.disk = 1
        node_size.vcpus = 1
        node_size.name = "small"
        driver.list_sizes.return_value = [node_size]

        driver.ex_get_image.return_value = "image"
        driver.ex_create_address.return_value = "ip"
        net = MagicMock()
        net.name = "default"
        driver.ex_list_networks.return_value = [net]

        node = MagicMock()
        node.id = "gce1"
        node.name = "gce1name"
        driver.create_node.return_value = node

        res = gce_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('libcloud.compute.drivers.gce.GCENodeDriver')
    def test_30_updateVMInfo(self, get_driver):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'gce://us-central1-a/centos-6' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'one', 'type': 'GCE', 'username': 'user',
                                'password': 'pass\npass', 'project': 'proj'}])
        gce_cloud = self.get_gce_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", gce_cloud.cloud, radl, radl, gce_cloud)

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        zone = MagicMock()
        node.id = "1"
        node.state = "running"
        node.extra = {'flavorId': 'small'}
        node.public_ips = []
        node.public_ips = ['158.42.1.1']
        node.private_ips = ['10.0.0.1']
        node.driver = driver
        zone.name = 'us-central1-a'
        node.extra = {'zone': zone}
        driver.ex_get_node.return_value = node

        volume = MagicMock()
        volume.id = "vol1"
        volume.attach.return_value = True
        volume.extra = {'status': 'READY'}
        driver.create_volume.return_value = volume

        success, vm = gce_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('libcloud.compute.drivers.gce.GCENodeDriver')
    def test_40_stop(self, get_driver):
        auth = Authentication([{'id': 'one', 'type': 'GCE', 'username': 'user',
                                'password': 'pass\npass', 'project': 'proj'}])
        gce_cloud = self.get_gce_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", gce_cloud.cloud, "", "", gce_cloud)

        driver = MagicMock()
        get_driver.return_value = driver

        driver.ex_get_node.return_value = MagicMock()
        driver.ex_stop_node.return_value = True

        success, _ = gce_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('libcloud.compute.drivers.gce.GCENodeDriver')
    def test_50_start(self, get_driver):
        auth = Authentication([{'id': 'one', 'type': 'GCE', 'username': 'user',
                                'password': 'pass\npass', 'project': 'proj'}])
        gce_cloud = self.get_gce_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", gce_cloud.cloud, "", "", gce_cloud)

        driver = MagicMock()
        get_driver.return_value = driver

        driver.ex_get_node.return_value = MagicMock()
        driver.ex_start_node.return_value = True

        success, _ = gce_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('libcloud.compute.drivers.gce.GCENodeDriver')
    @patch('time.sleep')
    def test_60_finalize(self, sleep, get_driver):
        auth = Authentication([{'id': 'one', 'type': 'GCE', 'username': 'user',
                                'password': 'pass\npass', 'project': 'proj'}])
        gce_cloud = self.get_gce_cloud()

        radl_data = """
            system test (
            cpu.count>=2 and
            memory.size>=2048m
            )"""
        radl = radl_parse.parse_radl(radl_data)

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", gce_cloud.cloud, radl, radl, gce_cloud)

        driver = MagicMock()
        driver.name = "OpenStack"
        get_driver.return_value = driver

        node = MagicMock()
        node.destroy.return_value = True
        node.extra = {'disks': [{'source': 'vol'}]}
        node.driver = driver
        driver.ex_get_node.return_value = node

        volume = MagicMock()
        volume.detach.return_value = True
        volume.destroy.return_value = True
        driver.ex_get_volume.return_value = volume

        success, _ = gce_cloud.finalize(vm, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()


if __name__ == '__main__':
    unittest.main()
