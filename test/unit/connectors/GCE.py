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
from IM.connectors.GCE import GCECloudConnector
from mock import patch, MagicMock, call
from libcloud.compute.base import NodeSize


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestGCEConnector(unittest.TestCase):
    """
    Class to test the IM connectors
    """

    def setUp(self):
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
    def get_gce_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "GCE"
        inf = MagicMock()
        inf.id = "1"
        gce_cloud = GCECloudConnector(cloud_info, inf)
        return gce_cloud

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
        node_size.price = 1.0
        node_size.disk = 1
        node_size.name = "small"
        node_size.extra = {'guestCpus': 1}
        node_size2 = MagicMock()
        node_size2.ram = 1024
        node_size2.price = None
        node_size2.disk = 2
        node_size2.name = "medium"
        node_size2.extra = {'guestCpus': 2}
        driver.list_sizes.return_value = [node_size, node_size2]

        gce_cloud = self.get_gce_cloud()
        concrete = gce_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.gce.GCENodeDriver')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, get_driver):
        radl_data = """
            network net1 (outbound = 'yes' and outports = '8080,9000:9100' and sg_name = 'fwname')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net1' and
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
        node_size.extra = {'guestCpus': 1}
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

        node2 = MagicMock()
        node2.id = "gce2"
        node2.name = "gce2name"
        node3 = MagicMock()
        node3.id = "gce3"
        node3.name = "gce3name"
        driver.ex_create_multiple_nodes.return_value = [node, node2, node3]

        res = gce_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a single VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        res = gce_cloud.launch(InfrastructureInfo(), radl, radl, 3, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching 3 VMs.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        radl_data = """
            network net1 (outbound = 'yes' and outports = '8080,9000:9100' and sg_name = 'fwname')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.0.ip = '10.0.0.1' and
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
        driver.create_node.side_effect = Exception("Error msg")
        res = gce_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, msg = res[0]
        self.assertFalse(success)
        self.assertEqual(msg, "ERROR: Error msg")
        self.assertEqual(driver.ex_destroy_address.call_count, 1)
        self.assertEqual(driver.ex_destroy_address.call_args_list, [call('ip')])

    @patch('libcloud.compute.drivers.gce.GCENodeDriver')
    @patch('libcloud.dns.drivers.google.GoogleDNSDriver')
    def test_30_updateVMInfo(self, get_dns_driver, get_driver):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test.domain.com' and
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
        vm = VirtualMachine(inf, "1", gce_cloud.cloud, radl, radl, gce_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver
        dns_driver = MagicMock()
        get_dns_driver.return_value = dns_driver

        node = MagicMock()
        zone = MagicMock()
        node.id = "1"
        node.state = "running"
        node.extra = {'flavorId': 'small'}
        node.public_ips = ['158.42.1.1']
        node.private_ips = ['10.0.0.1']
        node.driver = driver
        zone.name = 'us-central1-a'
        node.extra = {'zone': zone}
        node.size = NodeSize("1", "name1", 512, 1, None, None, driver)
        driver.ex_get_node.return_value = node

        volume = MagicMock()
        volume.id = "vol1"
        volume.attach.return_value = True
        volume.extra = {'status': 'READY'}
        driver.create_volume.return_value = volume

        dns_driver.iterate_zones.return_value = []
        dns_driver.iterate_records.return_value = []

        success, vm = gce_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")

        self.assertEquals(dns_driver.create_zone.call_count, 1)
        self.assertEquals(dns_driver.create_record.call_count, 1)
        self.assertEquals(dns_driver.create_zone.call_args_list[0], call('domain.com.'))
        self.assertEquals(dns_driver.create_record.call_args_list[0][0][0], 'test.domain.com.')
        self.assertEquals(dns_driver.create_record.call_args_list[0][0][2], 'A')
        self.assertEquals(dns_driver.create_record.call_args_list[0][0][3], {'rrdatas': ['158.42.1.1'], 'ttl': 300})

        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.gce.GCENodeDriver')
    def test_40_stop(self, get_driver):
        auth = Authentication([{'id': 'one', 'type': 'GCE', 'username': 'user',
                                'password': 'pass\npass', 'project': 'proj'}])
        gce_cloud = self.get_gce_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", gce_cloud.cloud, "", "", gce_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver

        driver.ex_get_node.return_value = MagicMock()
        driver.ex_stop_node.return_value = True

        success, _ = gce_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.gce.GCENodeDriver')
    def test_50_start(self, get_driver):
        auth = Authentication([{'id': 'one', 'type': 'GCE', 'username': 'user',
                                'password': 'pass\npass', 'project': 'proj'}])
        gce_cloud = self.get_gce_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", gce_cloud.cloud, "", "", gce_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver

        driver.ex_get_node.return_value = MagicMock()
        driver.ex_start_node.return_value = True

        success, _ = gce_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.gce.GCENodeDriver')
    @patch('libcloud.dns.drivers.google.GoogleDNSDriver')
    @patch('time.sleep')
    def test_60_finalize(self, sleep, get_dns_driver, get_driver):
        auth = Authentication([{'id': 'one', 'type': 'GCE', 'username': 'user',
                                'password': 'pass\npass', 'project': 'proj'}])
        gce_cloud = self.get_gce_cloud()

        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.count=2 and
            memory.size=2048m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test.domain.com' and
            net_interface.0.ip = '158.42.1.1'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", gce_cloud.cloud, radl, radl, gce_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver
        dns_driver = MagicMock()
        get_dns_driver.return_value = dns_driver

        node = MagicMock()
        node.destroy.return_value = True
        node.extra = {'disks': [{'source': 'vol'}]}
        node.driver = driver
        driver.ex_get_node.return_value = node

        volume = MagicMock()
        volume.detach.return_value = True
        volume.destroy.return_value = True
        driver.ex_get_volume.return_value = volume

        zone = MagicMock()
        zone.domain = "domain.com."
        dns_driver.iterate_zones.return_value = [zone]
        record = MagicMock()
        record.name = 'test.domain.com.'
        record.data = {'rrdatas': ['158.42.1.1'], 'ttl': 300}
        dns_driver.iterate_records.return_value = [record]

        success, _ = gce_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertEquals(dns_driver.delete_record.call_count, 1)
        self.assertEquals(dns_driver.delete_record.call_args_list[0][0][0].name, 'test.domain.com.')
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    def test_70_get_custom_instance(self):
        radl_data = """
            system test (
            cpu.count=2 and
            memory.size=2048m
            )"""
        radl = radl_parse.parse_radl(radl_data)

        gce_cloud = self.get_gce_cloud()
        size = MagicMock()
        size.extra = {"selfLink": "/some/path/sizenamne", "guestCpus": 1}
        size.ram = 1024
        size.name = "sizenamne"
        sizes = [size]
        instance = gce_cloud.get_instance_type(sizes, radl.systems[0])
        self.assertEquals(instance.name, "custom-2-2048")
        self.assertEquals(instance.extra['selfLink'], "/some/path/custom-2-2048")

        size2 = MagicMock()
        size2.extra = {"selfLink": "/some/path/sizenamne", "guestCpus": 2}
        size2.ram = 2048
        size2.name = "sizenamne"
        sizes.append(size2)
        instance = gce_cloud.get_instance_type(sizes, radl.systems[0])
        self.assertEquals(instance.name, "sizenamne")

if __name__ == '__main__':
    unittest.main()
