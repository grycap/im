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
from IM.connectors.OpenStack import OpenStackCloudConnector
from IM.config import Config
from mock import patch, MagicMock, call


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestOSTConnector(unittest.TestCase):
    """
    Class to test the IM connectors
    """

    def setUp(self):
        self.error_in_create = True
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
    def get_ost_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "OpenStack"
        cloud_info.protocol = "https"
        cloud_info.server = "server.com"
        cloud_info.port = 5000
        inf = MagicMock()
        inf.id = "1"
        one_cloud = OpenStackCloudConnector(cloud_info, inf)
        return one_cloud

    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
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
            disk.0.image.url = 'ost://server.com/ami-id' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        driver = MagicMock()
        get_driver.return_value = driver

        node_size = MagicMock()
        node_size.ram = 512
        node_size.price = 1
        node_size.disk = 1
        node_size.vcpus = 1
        node_size.name = "small"
        driver.list_sizes.return_value = [node_size]

        concrete = ost_cloud.concreteSystem(radl_system, auth)
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
            node.id = "ost1"
            node.name = "ost1name"
            return node

    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, get_driver):
        radl_data = """
            network net1 (outbound = 'yes' and provider_id = 'public' and
                          outports = '8080,9000:9100' and sg_name= 'test')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            instance_tags='key=value,key1=value2' and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'ost://server.com/ami-id' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        driver = MagicMock()
        get_driver.return_value = driver

        node_size = MagicMock()
        node_size.ram = 512
        node_size.price = 1
        node_size.disk = 1
        node_size.vcpus = 1
        node_size.name = "small"
        driver.list_sizes.return_value = [node_size]

        net = MagicMock()
        net.name = "public"
        driver.ex_list_networks.return_value = [net]

        sg = MagicMock()
        sg.name = "sg"
        driver.ex_create_security_group.return_value = sg
        driver.ex_list_security_groups.return_value = []
        driver.ex_create_security_group_rule.return_value = True

        keypair = MagicMock()
        keypair.public_key = "public"
        keypair.private_key = "private"
        driver.create_key_pair.return_value = keypair
        driver.features = {'create_node': ['ssh_key']}

        driver.create_node.side_effect = self.create_node

        res = ost_cloud.launch_with_retry(InfrastructureInfo(), radl, radl, 1, auth, 2, 1)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        # test with proxy auth data
        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'proxy': 'proxy',
                                'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        res = ost_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")

    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
    def test_30_updateVMInfo(self, get_driver):
        radl_data = """
            network net (outbound = 'yes' and provider_id = 'os-lan.pool1')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'ost://server.com/ami-id' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", ost_cloud.cloud, radl, radl, ost_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.extra = {'flavorId': 'small',
                      'addresses': {'os-lan': [{'addr': '10.0.0.1', 'OS-EXT-IPS:type': 'fixed'}]}}
        node.public_ips = []
        node.private_ips = ['10.0.0.1']
        node.driver = driver
        driver.ex_get_node_details.return_value = node

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

        pool = MagicMock()
        pool.name = "pool1"
        floating_ip = MagicMock()
        floating_ip.ip_address = "8.8.8.8"
        pool.list_floating_ips.return_value = []
        pool.create_floating_ip.return_value = floating_ip
        driver.ex_list_floating_ip_pools.return_value = [pool]

        success, vm = ost_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertEquals(vm.info.systems[0].getValue("net_interface.1.ip"), "10.0.0.1")

        # In this case the Node has the float ip assigned
        # node.public_ips = ['8.8.8.8']
        floating_ip.node_id = node.id
        pool.list_floating_ips.return_value = [floating_ip]
        driver.ex_list_floating_ip_pools.return_value = [pool]

        success, vm = ost_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertEquals(vm.info.systems[0].getValue("net_interface.1.ip"), "10.0.0.1")
        self.assertEquals(vm.info.systems[0].getValue("net_interface.0.ip"), "8.8.8.8")

        # In this case the Node addresses are not available and it uses the old method
        node.extra = {'flavorId': 'small'}
        success, vm = ost_cloud.updateVMInfo(vm, auth)
        self.assertEquals(vm.info.systems[0].getValue("net_interface.1.ip"), "10.0.0.1")
        self.assertEquals(vm.info.systems[0].getValue("net_interface.0.ip"), "8.8.8.8")

        self.assertTrue(success, msg="ERROR: updating VM info.")

        # the node has a IPv6 IP
        node = MagicMock()
        node.id = "2"
        node.state = "running"
        node.extra = {'flavorId': 'small'}
        node.public_ips = ['8.8.8.8', '2001:630:12:581:f816:3eff:fe92:2146']
        node.private_ips = ['10.0.0.1']
        node.driver = driver
        driver.ex_get_node_details.return_value = node

        success, vm = ost_cloud.updateVMInfo(vm, auth)
        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertEquals(vm.info.systems[0].getValue("net_interface.0.ip"), "8.8.8.8")
        self.assertEquals(vm.info.systems[0].getValue("net_interface.0.ipv6"), "2001:630:12:581:f816:3eff:fe92:2146")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
    def test_40_stop(self, get_driver):
        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", ost_cloud.cloud, "", "", ost_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.extra = {'flavorId': 'small'}
        node.public_ips = ['158.42.1.1']
        node.private_ips = ['10.0.0.1']
        node.driver = driver
        driver.ex_get_node_details.return_value = node

        driver.ex_stop_node.return_value = True

        success, _ = ost_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
    def test_50_start(self, get_driver):
        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", ost_cloud.cloud, "", "", ost_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.extra = {'flavorId': 'small'}
        node.public_ips = ['158.42.1.1']
        node.private_ips = ['10.0.0.1']
        node.driver = driver
        driver.ex_get_node_details.return_value = node

        driver.ex_start_node.return_value = True

        success, _ = ost_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
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

        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", ost_cloud.cloud, radl, radl, ost_cloud, 1)

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.extra = {'flavorId': 'small'}
        node.public_ips = ['158.42.1.1']
        node.private_ips = ['10.0.0.1']
        node.driver = driver
        driver.ex_get_node_details.return_value = node

        node_size = MagicMock()
        node_size.ram = 2048
        node_size.price = 1
        node_size.disk = 1
        node_size.vcpus = 2
        node_size.name = "small"
        driver.list_sizes.return_value = [node_size]

        driver.ex_resize.return_value = True

        success, _ = ost_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
    @patch('time.sleep')
    def test_60_finalize(self, sleep, get_driver):
        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

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
        vm = VirtualMachine(inf, "1", ost_cloud.cloud, radl, radl, ost_cloud, 1)

        driver = MagicMock()
        driver.name = "OpenStack"
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.extra = {'flavorId': 'small'}
        node.public_ips = ['158.42.1.1']
        node.private_ips = ['10.0.0.1']
        node.driver = driver
        node.destroy.return_value = True
        driver.ex_get_node_details.return_value = node

        keypair = MagicMock()
        driver.get_key_pair.return_value = keypair
        vm.keypair = keypair

        driver.delete_key_pair.return_value = True

        driver.delete_security_group.return_value = True

        driver.ex_list_floating_ips.return_value = []

        success, _ = ost_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
    def test_70_create_snapshot(self, get_driver):
        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", ost_cloud.cloud, "", "", ost_cloud, 1)

        driver = MagicMock()
        driver.name = "OpenStack"
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.driver = driver
        driver.ex_get_node_details.return_value = node
        image = MagicMock()
        image.id = "newimage"
        driver.create_image.return_value = image

        success, new_image = ost_cloud.create_snapshot(vm, 0, "image_name", True, auth)

        self.assertTrue(success, msg="ERROR: creating snapshot: %s" % new_image)
        self.assertEqual(new_image, "ost://server.com/newimage")
        self.assertEqual(driver.create_image.call_args_list, [call(node, "image_name")])
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
    def test_80_delete_image(self, get_driver):
        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        driver = MagicMock()
        driver.name = "OpenStack"
        get_driver.return_value = driver

        image = MagicMock()
        image.id = "image"
        driver.get_image.return_value = image

        success, msg = ost_cloud.delete_image('ost://server.com/image', auth)

        self.assertTrue(success, msg="ERROR: deleting image. %s" % msg)
        self.assertEqual(driver.delete_image.call_args_list, [call(image)])
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
