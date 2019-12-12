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
from IM.connectors.OpenStack import OpenStackCloudConnector
from mock import patch, MagicMock, call


class TestOSTConnector(TestCloudConnectorBase):
    """
    Class to test the IM connectors
    """

    def setUp(self):
        self.error_in_create = True
        TestCloudConnectorBase.setUp(self)

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

    @patch('IM.AppDB.AppDB.get_site_id')
    @patch('IM.AppDB.AppDB.get_site_url')
    @patch('IM.AppDB.AppDB.get_image_id')
    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
    def test_15_concrete_appdb(self, get_driver, get_image_id, get_site_url, get_site_id):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'appdb://CESNET-MetaCloud/egi.ubuntu.16.04?fedcloud.egi.eu' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()
        ost_cloud.cloud.server = "server.com"

        driver = MagicMock()
        get_driver.return_value = driver

        node_size = MagicMock()
        node_size.ram = 512
        node_size.price = 1
        node_size.disk = 1
        node_size.vcpus = 1
        node_size.name = "small"
        driver.list_sizes.return_value = [node_size]

        get_site_url.return_value = "https://server.com:5000"
        get_site_id.return_value = "8016G0"
        get_image_id.return_value = "imageid1"
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
    @patch('IM.AppDB.AppDB.get_image_data')
    def test_20_launch(self, get_image_data, save_data, get_driver):
        radl_data = """
            network net1 (outbound = 'yes' and provider_id = 'public' and
                          outports = '8080,9000:9100' and sg_name= 'test')
            network net2 (dnsserver='1.1.1.1' and create = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            instance_tags='key=value,key1=value2' and
            net_interface.1.connection = 'net1' and
            net_interface.0.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'ost://server.com/ami-id' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.2.image.url = 'ost://server.com/vol-id' and
            disk.2.device='hdc'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'},
                               {'type': 'InfrastructureManager', 'username': 'user',
                                'password': 'pass'}])
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

        net1 = MagicMock()
        net1.name = "public"
        net1.id = "net1id"
        net1.extra = {'router:external': True}
        net1.cidr = None
        net2 = MagicMock()
        net2.name = "private"
        net2.id = "net2id"
        net2.cidr = "10.0.0.0/24"
        driver.ex_list_networks.return_value = [net2, net1]

        sg = MagicMock()
        sg.name = "sg"
        driver.ex_create_security_group.return_value = sg
        driver.ex_list_security_groups.return_value = []
        driver.ex_create_security_group_rule.return_value = True

        driver.features = {'create_node': ['ssh_key']}

        driver.create_node.side_effect = self.create_node

        driver.ex_create_network.return_value = net2
        subnet1 = MagicMock()
        driver.ex_create_subnet.return_value = subnet1

        router = MagicMock()
        router.id = "id"
        router.name = "name"
        router.extra = {'external_gateway_info': {'network_id': net1.id}}
        driver.ex_list_routers.return_value = [router]
        driver.ex_add_router_subnet.return_value = True

        image = MagicMock()
        image.id = 'imageid'
        driver.get_image.return_value = image
        vol = MagicMock()
        vol.id = 'volid'
        driver.ex_get_volume.return_value = vol

        inf = InfrastructureInfo()
        inf.auth = auth
        res = ost_cloud.launch_with_retry(inf, radl, radl, 1, auth, 2, 1)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertEqual(driver.create_node.call_args_list[0][1]['networks'], [net1])
        mappings = [
            {'source_type': 'image',
             'uuid': 'imageid',
             'boot_index': 0,
             'delete_on_termination': False,
             'device_name': 'vda'},
            {'guest_format': 'ext3',
             'boot_index': 1,
             'volume_size': 1,
             'device_name': 'vdb',
             'source_type': 'blank',
             'destination_type': 'volume',
             'delete_on_termination': True},
            {'boot_index': 2,
             'delete_on_termination': False,
             'destination_type': 'volume',
             'device_name': 'vdc',
             'source_type': 'volume',
             'uuid': 'volid'}
        ]
        self.assertEqual(driver.create_node.call_args_list[0][1]['ex_blockdevicemappings'], mappings)
        self.assertEqual(driver.ex_create_subnet.call_args_list[0][0][2], "10.0.1.0/24")

        # test with proxy auth data
        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'proxy': 'proxy',
                                'tenant': 'tenant', 'host': 'https://server.com:5000'},
                               {'type': 'InfrastructureManager', 'username': 'user',
                                'password': 'pass'}])
        inf = InfrastructureInfo()
        inf.auth = auth
        res = ost_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")

        get_image_data.return_value = "https://cloud.recas.ba.infn.it:5000", "image_id2", ""
        radl.systems[0].setValue('disk.0.image.url', 'appdb://CESNET-MetaCloud/egi.ubuntu.16.04?fedcloud.egi.eu')
        res = ost_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertEqual(driver.get_image.call_args_list[3][0][0], "image_id2")

    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
    def test_30_updateVMInfo(self, get_driver):
        radl_data = """
            network net (outbound = 'yes' and provider_id = 'pool1')
            network net1 (provider_id = 'os-lan' and router='10.0.0.0/16,vrouter1')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net1' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'ost://server.com/ami-id' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path' and
            disk.2.image.url='ost://server.com/ami-id1' and
            disk.2.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", ost_cloud.cloud, radl, radl, ost_cloud, 1)

        vm2 = MagicMock()
        syst = MagicMock()
        syst.name = "vrouter1"
        vm2.info.systems = [syst]
        vm2.getIfaceIP.return_value = "10.0.0.1"
        inf.vm_list = [vm2, vm]

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.extra = {'flavorId': 'small', 'volumes_attached': [{'id': 'vol1'}],
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
        volume.size = 1
        volume.extra = {'attachments': [{'device': 'vdb'}]}
        volume.attach.return_value = True
        driver.create_volume.return_value = volume
        driver.ex_get_volume.return_value = volume

        pool = MagicMock()
        pool.name = "pool1"
        floating_ip = MagicMock()
        floating_ip.ip_address = "8.8.8.8"
        pool.list_floating_ips.return_value = []
        pool.create_floating_ip.return_value = floating_ip
        driver.ex_list_floating_ip_pools.return_value = [pool]

        net1 = MagicMock()
        net1.id = 'net1id'
        net1.name = "os-lan"
        net1.cidr = None
        net1.extra = {'subnets': ["subnet1"]}
        net2 = MagicMock()
        net2.id = 'net2id'
        net2.name = "public"
        net2.cidr = None
        net2.extra = {'subnets': [], 'router:external': True}
        driver.ex_list_networks.return_value = [net1, net2]

        port = MagicMock()
        port.extra = {'device_id': node.id, 'device_owner': 'compute:nova'}
        driver.ex_list_ports.return_value = [port]

        success, vm = ost_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertEquals(vm.info.systems[0].getValue("net_interface.1.ip"), "10.0.0.1")
        self.assertEquals(driver.ex_update_subnet.call_args_list[0][0][0].id, "subnet1")
        self.assertEquals(driver.ex_update_subnet.call_args_list[0][1],
                          {'host_routes': [{'nexthop': '10.0.0.1', 'destination': '10.0.0.0/16'}]})
        self.assertEquals(vm.info.systems[0].getValue("disk.1.device"), "vdb")
        self.assertEquals(vm.info.systems[0].getValue("disk.1.image.url"), "ost://server.com/vol1")

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
    def test_52_reboot(self, get_driver):
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

        driver.ex_hard_reboot_node.return_value = True

        success, _ = ost_cloud.reboot(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
    @patch('IM.connectors.OpenStack.OpenStackCloudConnector.add_elastic_ip_from_pool')
    def test_55_alter(self, add_elastic_ip_from_pool, get_driver):
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
        vm.volumes = []

        driver = MagicMock()
        get_driver.return_value = driver

        node = MagicMock()
        node.id = "1"
        node.state = "running"
        node.extra = {'flavorId': 'small', 'vm_state': 'resized'}
        node.public_ips = []
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
        driver.ex_get_size.return_value = node_size

        driver.ex_resize.return_value = True
        driver.ex_confirm_resize.return_value = True

        success, _ = ost_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertEqual(driver.ex_resize.call_args_list[0][0], (node, node_size))
        self.assertEqual(driver.ex_confirm_resize.call_args_list[0][0], (node,))

        new_radl_data = """
            system test (
            disk.1.size = 10G
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        volume = MagicMock()
        volume.id = 'volid'
        volume.extra = {'state': 'available'}
        volume.attach.return_value = True
        volumeused = MagicMock()
        volumeused.extra = {'state': 'in-use', 'attachments': [{'device': 'hdc'}]}
        volumeused.id = 'volid'
        volume.driver.ex_get_volume.return_value = volumeused
        driver.create_volume.return_value = volume

        success, _ = ost_cloud.alterVM(vm, new_radl, auth)
        self.assertEqual(vm.info.systems[0].getValue("disk.1.device"), 'hdc')
        self.assertTrue(success, msg="ERROR: modifying VM info.")

        new_radl_data = """
            network net1 (outbound = 'yes' and provider_id = 'pool1')
            system test (
            net_interface.0.connection = 'net1'
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        add_elastic_ip_from_pool.return_value = True, ""

        success, _ = ost_cloud.alterVM(vm, new_radl, auth)
        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertEqual(add_elastic_ip_from_pool.call_args_list[0][0], (vm, node, None, 'pool1'))

        radl_data = """
            network net (outbound = 'yes' and provider_id = 'pool1')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.ip = '8.8.8.8' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'one://server.com/1' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        vm = VirtualMachine(inf, "1", ost_cloud.cloud, radl, radl, ost_cloud, 1)

        new_radl_data = """
            network net ()
            system test (
            net_interface.0.connection = 'net'
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        fip = MagicMock()
        fip.delete.return_value = True
        driver.ex_get_floating_ip.return_value = fip
        driver.ex_detach_floating_ip_from_node.return_value = True
        node.public_ips = ['158.42.1.1']

        success, _ = ost_cloud.alterVM(vm, new_radl, auth)
        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertEqual(driver.ex_detach_floating_ip_from_node.call_args_list[0][0], (node, fip))
        self.assertIsNone(vm.requested_radl.systems[0].getValue('net_interface.0.ip'))

        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
    @patch('time.sleep')
    def test_60_finalize(self, sleep, get_driver):
        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        radl_data = """
            network public (outboud = 'yes')
            network private (create = 'yes' and provider_id = ' im-infid-private')
            system test (
            cpu.count>=2 and
            memory.size>=2048m and
            net_interface.0.connection = 'public' and
            net_interface.1.connection = 'private'
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

        driver.delete_security_group.return_value = True

        fip = MagicMock()
        fip.node_id = node.id
        fip.ip_address = '158.42.1.1'
        fip.delete.return_value = True
        driver.ex_list_floating_ips.return_value = [fip]
        driver.ex_detach_floating_ip_from_node.return_value = True

        sg1 = MagicMock()
        sg1.name = "im-infid-private"
        sg1.description = "Security group created by the IM"
        sg2 = MagicMock()
        sg2.name = "im-infid-public"
        sg2.description = "Security group created by the IM"
        sg3 = MagicMock()
        sg3.name = "im-infid"
        sg3.description = ""
        driver.ex_list_security_groups.return_value = [sg1, sg2, sg3]

        net1 = MagicMock()
        net1.name = "im-infid-private"
        net1.cidr = None
        net1.extra = {'subnets': ["subnet1"]}
        net2 = MagicMock()
        net2.name = "public"
        net2.cidr = None
        net2.extra = {'subnets': [], 'router:external': True}
        driver.ex_list_networks.return_value = [net1, net2]

        router = MagicMock()
        router.id = "id"
        router.name = "name"
        router.extra = {'external_gateway_info': {'network_id': net2.id}}
        driver.ex_list_routers.return_value = [router]
        driver.ex_add_router_subnet.return_value = True

        vm.volumes = ['volid']
        success, _ = ost_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        self.assertEqual(node.destroy.call_args_list, [call()])
        self.assertEqual(driver.ex_del_router_subnet.call_args_list[0][0][0], router)
        self.assertEqual(driver.ex_del_router_subnet.call_args_list[0][0][1].id, "subnet1")
        self.assertEqual(driver.ex_delete_network.call_args_list[0][0][0], net1)
        self.assertEqual(driver.ex_delete_security_group.call_args_list[0][0][0], sg2)
        self.assertEqual(driver.ex_delete_security_group.call_args_list[1][0][0], sg1)
        self.assertEqual(fip.delete.call_args_list, [call()])
        self.assertEqual(driver.ex_detach_floating_ip_from_node.call_args_list[0][0], (node, fip))

        vm.floating_ips = ['158.42.1.1']
        success, _ = ost_cloud.finalize(vm, True, auth)
        self.assertEqual(fip.delete.call_args_list, [call()])
        self.assertEqual(node.destroy.call_args_list, [call(), call()])

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

    def test_get_networks(self):
        radl_data = """
            network net1 (outbound = 'yes')
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
            disk.1.device='hdb'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        driver = MagicMock()

        pool = MagicMock()
        pool.name = "public"
        driver.ex_list_floating_ip_pools.return_value = [pool]

        net1 = MagicMock()
        net1.name = "private"
        net1.cidr = None
        net1.extra = {'subnets': ["subnet1"]}
        net2 = MagicMock()
        net2.name = "public"
        net2.cidr = None
        net2.extra = {'subnets': [], 'router:external': True}
        driver.ex_list_networks.return_value = [net1, net2]

        subnet = MagicMock()
        subnet.cidr = "10.0.0.0/24"
        subnet.id = "subnet1"
        driver.ex_list_subnets.return_value = [subnet]

        ost_cloud = self.get_ost_cloud()
        nets = ost_cloud.get_networks(driver, radl)
        self.assertEqual(nets, [net1])


if __name__ == '__main__':
    unittest.main()
