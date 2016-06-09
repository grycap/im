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

sys.path.append("..")
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
from IM.VirtualMachine import VirtualMachine
from IM.InfrastructureInfo import InfrastructureInfo
from IM.connectors.OCCI import OCCICloudConnector
from mock import patch, MagicMock


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestOCCIConnector(unittest.TestCase):
    """
    Class to test the IM connectors
    """

    @classmethod
    def setUpClass(cls):
        cls.last_op = None, None
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
    def get_occi_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "OCCI"
        cloud_info.protocol = "https"
        cloud_info.server = "server.com"
        cloud_info.port = 11443
        cloud = OCCICloudConnector(cloud_info)
        return cloud

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
            disk.0.image.url = 'https://server.com:11443/image' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'}])
        occi_cloud = self.get_occi_cloud()

        concrete = occi_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    def get_response(self):
        method, url = self.__class__.last_op

        resp = MagicMock()

        if method == "GET":
            if url == "/-/":
                resp.status = 200
                resp.read.return_value = read_file_as_string("files/occi.txt")
            elif url == "/compute/1":
                resp.status = 200
                resp.read.return_value = read_file_as_string("files/occi_vm_info.txt")
        elif method == "POST":
            if url == "/compute/":
                resp.status = 201
                resp.read.return_value = 'https://server.com/compute/1'
            elif url.endswith("action=suspend"):
                resp.status = 200
            elif url.endswith("action=start"):
                resp.status = 200
        elif method == "DELETE":
            if url.endswith("/compute/1"):
                resp.status = 200
            elif url.endswith("/storage/1"):
                resp.status = 200

        return resp

    def request(self, method, url, body=None, headers={}):
        self.__class__.last_op = method, url

    @patch('httplib.HTTPSConnection')
    @patch('IM.connectors.OCCI.KeyStoneAuth.get_keystone_uri')
    @patch('IM.connectors.OCCI.OCCICloudConnector.delete_proxy')
    def test_20_launch(self, delete_proxy, get_keystone_uri, connection):
        radl_data = """
            network net1 (outbound = 'yes' and outports = '8080')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'http://server.com/666956cb-9d15-475e-9f19-a3732c82a327' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'}])
        occi_cloud = self.get_occi_cloud()

        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.putrequest.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        get_keystone_uri.return_value = None

        res = occi_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('httplib.HTTPSConnection')
    @patch('IM.connectors.OCCI.KeyStoneAuth.get_keystone_uri')
    @patch('IM.connectors.OCCI.OCCICloudConnector.delete_proxy')
    def test_30_updateVMInfo(self, delete_proxy, get_keystone_uri, connection):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'https://server.com/666956cb-9d15-475e-9f19-a3732c82a327' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'}])
        occi_cloud = self.get_occi_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", occi_cloud.cloud, radl, radl, occi_cloud)

        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        get_keystone_uri.return_value = None

        success, vm = occi_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('httplib.HTTPSConnection')
    @patch('IM.connectors.OCCI.KeyStoneAuth.get_keystone_uri')
    @patch('IM.connectors.OCCI.OCCICloudConnector.delete_proxy')
    def test_40_stop(self, delete_proxy, get_keystone_uri, connection):
        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'}])
        occi_cloud = self.get_occi_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", occi_cloud.cloud, "", "", occi_cloud)

        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        get_keystone_uri.return_value = None

        success, _ = occi_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('httplib.HTTPSConnection')
    @patch('IM.connectors.OCCI.KeyStoneAuth.get_keystone_uri')
    @patch('IM.connectors.OCCI.OCCICloudConnector.delete_proxy')
    def test_50_start(self, delete_proxy, get_keystone_uri, connection):
        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'}])
        occi_cloud = self.get_occi_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", occi_cloud.cloud, "", "", occi_cloud)

        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        get_keystone_uri.return_value = None

        success, _ = occi_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('httplib.HTTPSConnection')
    @patch('IM.connectors.OCCI.KeyStoneAuth.get_keystone_uri')
    @patch('IM.connectors.OCCI.OCCICloudConnector.delete_proxy')
    def test_60_finalize(self, delete_proxy, get_keystone_uri, connection):
        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'}])
        occi_cloud = self.get_occi_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", occi_cloud.cloud, "", "", occi_cloud)

        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        get_keystone_uri.return_value = None

        success, _ = occi_cloud.finalize(vm, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()


if __name__ == '__main__':
    unittest.main()
