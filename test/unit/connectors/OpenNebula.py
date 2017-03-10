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
from IM.connectors.OpenNebula import OpenNebulaCloudConnector
from mock import patch, MagicMock


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestONEConnector(unittest.TestCase):
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
    def get_one_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "OpenNebula"
        cloud_info.server = "server.com"
        cloud_info.port = 2633
        inf = MagicMock()
        inf.id = "1"
        one_cloud = OpenNebulaCloudConnector(cloud_info, inf)
        return one_cloud

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
    def test_20_launch(self, getONEVersion, server_proxy):
        radl_data = """
            network net1 (provider_id = 'publica' and outbound = 'yes')
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

        auth = Authentication([{'id': 'one', 'type': 'OpenNebula', 'username': 'user',
                                'password': 'pass', 'host': 'server.com:2633'}])
        one_cloud = self.get_one_cloud()

        getONEVersion.return_value = "4.12"

        one_server = MagicMock()
        one_server.one.vm.allocate.return_value = (True, "1", 0)
        one_server.one.vnpool.info.return_value = (True, read_file_as_string("files/nets.xml"), 0)
        server_proxy.return_value = one_server

        res = one_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.OpenNebula.ServerProxy')
    def test_30_updateVMInfo(self, server_proxy):
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
        radl.check()

        auth = Authentication([{'id': 'one', 'type': 'OpenNebula', 'username': 'user',
                                'password': 'pass', 'host': 'server.com:2633'}])
        one_cloud = self.get_one_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", one_cloud.cloud, radl, radl, one_cloud, 1)

        one_server = MagicMock()
        one_server.one.vm.info.return_value = (True, read_file_as_string("files/vm_info.xml"), 0)
        server_proxy.return_value = one_server

        success, vm = one_cloud.updateVMInfo(vm, auth)

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
    @patch('IM.connectors.OpenNebula.OpenNebulaCloudConnector.checkResize')
    def test_55_alter(self, checkResize, server_proxy):
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

        checkResize.return_value = True
        one_server = MagicMock()
        one_server.one.vm.action.return_value = (True, "", 0)
        one_server.one.vm.resize.return_value = (True, "", 0)
        one_server.one.vm.info.return_value = (True, read_file_as_string("files/vm_info_off.xml"), 0)
        one_server.one.vm.attach.return_value = (True, "", 0)
        server_proxy.return_value = one_server

        success, _ = one_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.OpenNebula.ServerProxy')
    def test_60_finalize(self, server_proxy):
        auth = Authentication([{'id': 'one', 'type': 'OpenNebula', 'username': 'user',
                                'password': 'pass', 'host': 'server.com:2633'}])
        one_cloud = self.get_one_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", one_cloud.cloud, "", "", one_cloud, 1)

        one_server = MagicMock()
        one_server.one.vm.action.return_value = (True, "", 0)
        server_proxy.return_value = one_server

        success, _ = one_cloud.finalize(vm, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
