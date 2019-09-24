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
from IM.connectors.OpenNebula import OpenNebulaCloudConnector
from mock import patch, MagicMock, call


class TestONEConnector(TestCloudConnectorBase):
    """
    Class to test the IM connectors
    """

    @staticmethod
    def get_one_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "OpenNebula"
        cloud_info.server = "server.com"
        cloud_info.port = 2633
        inf = MagicMock()
        inf.id = "1"
        one_cloud = OpenNebulaCloudConnector(cloud_info, inf)
        return one_cloud

    @patch('IM.connectors.OpenNebula.ServerProxy')
    def test_05_getONEVersion(self, server_proxy):
        one_server = MagicMock()
        one_server.system.listMethods.return_value = ["one.system.version"]
        one_server.one.system.version.return_value = (True, "5.2.1", "")
        server_proxy.return_value = one_server

        auth = Authentication([{'id': 'one', 'type': 'OpenNebula', 'username': 'user',
                                'password': 'pass', 'host': 'server.com:2633'}])

        one_cloud = self.get_one_cloud()
        one_cloud.getONEVersion(auth)

    def test_10_concrete(self):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'one://server.com/1' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'one', 'type': 'OpenNebula', 'username': 'user',
                                'password': 'pass', 'host': 'server.com:2633'}])
        one_cloud = self.get_one_cloud()
        concrete = one_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.OpenNebula.ServerProxy')
    @patch('IM.connectors.OpenNebula.OpenNebulaCloudConnector.getONEVersion')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, getONEVersion, server_proxy):
        radl_data = """
            network net1 (provider_id = 'publica' and outbound = 'yes' and
                          outports = '8080,9000:9100' and sg_name= 'test')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            availability_zone='0' and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            instance_tags = 'key=value,key1=value2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'one://server.com/1' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'one', 'type': 'OpenNebula', 'username': 'user',
                                'password': 'pass', 'host': 'server.com:2633'},
                               {'type': 'InfrastructureManager', 'username': 'user',
                                'password': 'pass'}])
        one_cloud = self.get_one_cloud()

        getONEVersion.return_value = "4.14.0"

        one_server = MagicMock()
        one_server.one.vm.allocate.return_value = (True, "1", 0)
        one_server.one.vnpool.info.return_value = (True, self.read_file_as_string("files/nets.xml"), 0)
        one_server.one.secgrouppool.info.return_value = (True, self.read_file_as_string("files/sgs.xml"), 0)
        one_server.one.secgroup.allocate.return_value = (True, 1, 0)
        server_proxy.return_value = one_server

        inf = InfrastructureInfo()
        inf.auth = auth
        res = one_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        sg_template = ('NAME = test\nRULE = [ PROTOCOL = TCP, RULE_TYPE = inbound, RANGE = 22:22 ]\n'
                       'RULE = [ PROTOCOL = TCP, RULE_TYPE = inbound, RANGE = 8080:8080 ]\n'
                       'RULE = [ PROTOCOL = TCP, RULE_TYPE = inbound, RANGE = 9000:9100 ]\n')
        self.assertEqual(one_server.one.secgroup.allocate.call_args_list, [call('user:pass', sg_template)])
        vm_template = """
            NAME = userimage

            CPU = 1
            VCPU = 1
            MEMORY = 512
            OS = [ ARCH = "x86_64" ]

            DISK = [ IMAGE_ID = "1" ]
 DISK = [ SAVE = no, TYPE = fs , FORMAT = ext3, SIZE = 1024, TARGET = hdb ]


            SCHED_REQUIREMENTS = "CLUSTER_ID=\\"0\\""\n"""
        self.assertIn(vm_template, one_server.one.vm.allocate.call_args_list[0][0][1])
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        # Now test an error in allocate
        one_server.one.vm.allocate.return_value = (False, "Error msg", 0)
        res = one_cloud.launch(inf, radl, radl, 1, auth)
        success, msg = res[0]
        self.assertFalse(success)
        self.assertEqual(msg, "ERROR: Error msg")

    @patch('IM.connectors.OpenNebula.ServerProxy')
    def test_30_updateVMInfo(self, server_proxy):
        radl_data = """
            network net (outbound = 'yes' and provider_id = 'publica')
            network net1 (provider_id = 'privada')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net1' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'one://server.com/1' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'one', 'type': 'OpenNebula', 'username': 'user',
                                'password': 'pass', 'host': 'server.com:2633'}])
        one_cloud = self.get_one_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", one_cloud.cloud, radl, radl, one_cloud, 1)

        one_server = MagicMock()
        one_server.one.vm.info.return_value = (True, self.read_file_as_string("files/vm_info.xml"), 0)
        server_proxy.return_value = one_server

        success, vm = one_cloud.updateVMInfo(vm, auth)
        self.assertEquals(vm.info.systems[0].getValue("net_interface.1.ip"), "10.0.0.01")
        self.assertEquals(vm.info.systems[0].getValue("net_interface.0.ip"), "158.42.1.1")

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.OpenNebula.ServerProxy')
    def test_40_stop(self, server_proxy):
        auth = Authentication([{'id': 'one', 'type': 'OpenNebula', 'username': 'user',
                                'password': 'pass', 'host': 'server.com:2633'}])
        one_cloud = self.get_one_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", one_cloud.cloud, "", "", one_cloud, 1)

        one_server = MagicMock()
        one_server.one.vm.action.return_value = (True, "", 0)
        server_proxy.return_value = one_server

        success, _ = one_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.OpenNebula.ServerProxy')
    def test_50_start(self, server_proxy):
        auth = Authentication([{'id': 'one', 'type': 'OpenNebula', 'username': 'user',
                                'password': 'pass', 'host': 'server.com:2633'}])
        one_cloud = self.get_one_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", one_cloud.cloud, "", "", one_cloud, 1)

        one_server = MagicMock()
        one_server.one.vm.action.return_value = (True, "", 0)
        server_proxy.return_value = one_server

        success, _ = one_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.OpenNebula.ServerProxy')
    def test_52_reboot(self, server_proxy):
        auth = Authentication([{'id': 'one', 'type': 'OpenNebula', 'username': 'user',
                                'password': 'pass', 'host': 'server.com:2633'}])
        one_cloud = self.get_one_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", one_cloud.cloud, "", "", one_cloud, 1)

        one_server = MagicMock()
        one_server.one.vm.action.return_value = (True, "", 0)
        server_proxy.return_value = one_server

        success, _ = one_cloud.reboot(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.OpenNebula.ServerProxy')
    def test_55_alter(self, server_proxy):
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
            memory.size>=2048m and
            disk.1.size=1GB and
            disk.1.device='hdc' and
            disk.1.fstype='ext4' and
            disk.1.mount_path='/mnt/disk'
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        auth = Authentication([{'id': 'one', 'type': 'OpenNebula', 'username': 'user',
                                'password': 'pass', 'host': 'server.com:2633'}])
        one_cloud = self.get_one_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", one_cloud.cloud, radl, radl, one_cloud, 1)

        one_server = MagicMock()
        one_server.one.vm.action.return_value = (True, "", 0)
        one_server.one.vm.resize.return_value = (True, "", 0)
        one_server.one.vm.info.return_value = (True, self.read_file_as_string("files/vm_info_off.xml"), 0)
        one_server.one.vm.attach.return_value = (True, "", 0)

        one_server.system.listMethods.return_value = ["one.vm.resize"]

        server_proxy.return_value = one_server

        success, _ = one_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.OpenNebula.ServerProxy')
    @patch('IM.connectors.OpenNebula.OpenNebulaCloudConnector._get_security_group')
    def test_60_finalize(self, get_security_group, server_proxy):
        auth = Authentication([{'id': 'one', 'type': 'OpenNebula', 'username': 'user',
                                'password': 'pass', 'host': 'server.com:2633'}])
        one_cloud = self.get_one_cloud()
        radl_data = """
            network net1 (provider_id = 'publica' and outbound = 'yes' and outports = '8080,9000:9100')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'one://server.com/1' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        inf = MagicMock()
        inf.radl = radl
        vm = VirtualMachine(inf, "1", one_cloud.cloud, radl, radl, one_cloud, 1)

        one_server = MagicMock()
        one_server.one.vm.action.return_value = (True, "", 0)
        server_proxy.return_value = one_server
        get_security_group.return_value = 101
        one_server.one.secgroup.delete.return_value = (True, "", 0)

        success, _ = one_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.OpenNebula.ServerProxy')
    @patch('IM.connectors.OpenNebula.OpenNebulaCloudConnector.getONEVersion')
    @patch('time.sleep')
    def test_70_create_snapshot(self, sleep, getONEVersion, server_proxy):
        auth = Authentication([{'id': 'one', 'type': 'OpenNebula', 'username': 'user',
                                'password': 'pass', 'host': 'server.com:2633'}])
        one_cloud = self.get_one_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", one_cloud.cloud, "", "", one_cloud, 1)

        getONEVersion.return_value = "5.2.1"
        one_server = MagicMock()
        one_server.one.vm.disksaveas.return_value = (True, 1, 0)
        one_server.one.image.info.return_value = (True, "<IMAGE><STATE>1</STATE></IMAGE>", 0)
        server_proxy.return_value = one_server

        success, new_image = one_cloud.create_snapshot(vm, 0, "image_name", True, auth)

        self.assertTrue(success, msg="ERROR: creating snapshot: %s" % new_image)
        self.assertEqual(new_image, 'one://server.com/1')
        self.assertEqual(one_server.one.vm.disksaveas.call_args_list, [call('user:pass', 1, 0, 'image_name', '', -1)])
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.OpenNebula.ServerProxy')
    @patch('IM.connectors.OpenNebula.OpenNebulaCloudConnector.getONEVersion')
    @patch('time.sleep')
    def test_80_delete_image(self, sleep, getONEVersion, server_proxy):
        auth = Authentication([{'id': 'one', 'type': 'OpenNebula', 'username': 'user',
                                'password': 'pass', 'host': 'server.com:2633'}])
        one_cloud = self.get_one_cloud()

        getONEVersion.return_value = "4.12"
        one_server = MagicMock()
        one_server.one.image.delete.return_value = (True, "", 0)
        one_server.one.imagepool.info.return_value = (True, "<IMAGE_POOL><IMAGE><ID>1</ID>"
                                                      "<NAME>imagename</NAME></IMAGE></IMAGE_POOL>", 0)
        one_server.one.image.info.return_value = (True, "<IMAGE><STATE>1</STATE></IMAGE>", 0)
        server_proxy.return_value = one_server

        success, msg = one_cloud.delete_image('one://server.com/1', auth)

        self.assertTrue(success, msg="ERROR: deleting image. %s" % msg)
        self.assertEqual(one_server.one.image.delete.call_args_list, [call('user:pass', 1)])
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        success, msg = one_cloud.delete_image('one://server.com/imagename', auth)

        self.assertTrue(success, msg="ERROR: deleting image. %s" % msg)
        self.assertEqual(one_server.one.image.delete.call_args_list[1], call('user:pass', 1))
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
