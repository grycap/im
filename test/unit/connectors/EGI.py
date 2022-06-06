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
from IM.InfrastructureInfo import InfrastructureInfo
from IM.connectors.EGI import EGICloudConnector
from mock import patch, MagicMock


class TestEGIConnector(TestCloudConnectorBase):
    """
    Class to test the IM connectors
    """

    def setUp(self):
        self.error_in_create = True
        TestCloudConnectorBase.setUp(self)

    @staticmethod
    def get_egi_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "EGI"
        cloud_info.server = "CESGA"
        cloud_info.extra['vo'] = "vo.access.egi.eu"
        inf = MagicMock()
        inf.id = "1"
        one_cloud = EGICloudConnector(cloud_info, inf)
        return one_cloud

    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
    @patch('IM.connectors.EGI.AppDB')
    def test_10_concrete(self, appdb, get_driver):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'ost://site.com/image-id' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'egi1', 'type': 'EGI', 'host': 'CESGA',
                                'vo': 'vo.access.egi.eu', 'token': 'access_token'}])
        egi_cloud = self.get_egi_cloud()

        driver = MagicMock()
        get_driver.return_value = driver

        appdb.get_image_data.return_value = "", "imageid", ""
        appdb.get_site_id.return_value = "site1"
        appdb.get_site_url.return_value = "https://site.com:5000/v3"
        appdb.get_project_ids.return_value = {"vo.access.egi.eu": "projectid"}

        node_size = MagicMock()
        node_size.id = '1'
        node_size.ram = 512
        node_size.price = 1
        node_size.disk = 1
        node_size.vcpus = 1
        node_size.name = "g.small"
        node_size.extra = {'pci_passthrough:alias': 'GPU:2,FPGA:1'}
        node_size2 = MagicMock()
        node_size.id = '2'
        node_size2.ram = 512
        node_size2.price = 1
        node_size2.disk = 1
        node_size2.vcpus = 1
        node_size2.name = "small"
        node_size2.extra = {}
        driver.list_sizes.return_value = [node_size, node_size2]
        driver.ex_get_size_extra_specs.return_value = {}

        concrete = egi_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertEqual(concrete[0].getValue("instance_type"), "small")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        radl_system.setValue('disk.0.image.url', 'appdb://image_apc_name')
        concrete = egi_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertEqual(concrete[0].getValue("instance_type"), "small")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        radl_system.setValue('disk.0.image.url', 'appdb://CESGA/image_apc_name?vo_name')
        concrete = egi_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 0)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        radl_system.setValue('disk.0.image.url', 'appdb://CESGA/image_apc_name?vo.access.egi.eu')
        concrete = egi_cloud.concreteSystem(radl_system, auth)
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
    @patch('IM.connectors.EGI.AppDB')
    def test_20_launch(self, appdb, get_image_data, save_data, get_driver):
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
            disk.0.image.url = 'appdb://apc_image_name' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.2.image.url = 'ost://server.com/vol-id' and
            disk.2.device='hdc'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'egi1', 'type': 'EGI', 'host': 'CESGA',
                                'vo': 'vo.access.egi.eu', 'token': 'access_token'},
                               {'type': 'InfrastructureManager', 'username': 'user',
                                'password': 'pass'}])
        egi_cloud = self.get_egi_cloud()

        driver = MagicMock()
        get_driver.return_value = driver

        get_image_data.return_value = "", "imageid", ""
        appdb.get_site_id.return_value = "site1"
        appdb.get_site_url.return_value = "https://site.com:5000/v3"
        appdb.get_project_ids.return_value = {"vo.access.egi.eu": "projectid"}

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
        inf.radl = radl
        inf.auth = auth
        res = egi_cloud.launch_with_retry(inf, radl, radl, 1, auth, 2, 1)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertEqual(driver.create_node.call_args_list[0][1]['networks'], [net1])
        mappings = [
            {'source_type': 'image',
             'uuid': 'imageid',
             'boot_index': 0,
             'delete_on_termination': False},
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

    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
    @patch('IM.connectors.EGI.AppDB')
    def test_get_driver(self, appdb, get_driver):
        auth = Authentication([{'id': 'egi1', 'type': 'EGI', 'host': 'CESGA',
                                'vo': 'vo.access.egi.eu', 'token': 'access_token'},
                               {'type': 'InfrastructureManager', 'username': 'user',
                                'password': 'pass'}])
        egi_cloud = self.get_egi_cloud()

        appdb.get_site_id.return_value = "site1"
        appdb.get_site_url.return_value = "https://site.com:5000/v3"
        appdb.get_project_ids.return_value = {"vo.access.egi.eu": "projectid"}

        egi_cloud.get_driver(auth)

        egi_cloud.cloud.extra['vo'] = 'other_vo'
        with self.assertRaises(Exception) as ex:
            egi_cloud.get_driver(auth)
        self.assertEqual('No compatible EGI auth data has been specified (check VO).',
                         str(ex.exception))

        egi_cloud.driver = None
        auth = Authentication([{'id': 'egi1', 'type': 'EGI', 'host': 'CESGA',
                                'vo': 'vo.access.egi.eu', 'token': 'access_token'},
                               {'id': 'egi2', 'type': 'EGI', 'host': 'CESGA',
                                'vo': 'other_vo', 'token': 'access_token'},
                               {'type': 'InfrastructureManager', 'username': 'user',
                                'password': 'pass'}])
        egi_cloud.get_driver(auth)


if __name__ == '__main__':
    unittest.main()
