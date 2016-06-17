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
from IM.connectors.Kubernetes import KubernetesCloudConnector
from mock import patch, MagicMock


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestKubernetesConnector(unittest.TestCase):
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
    def get_kube_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "Kubernetes"
        cloud_info.protocol = "http"
        cloud_info.server = "server.com"
        cloud_info.port = 8080
        cloud = KubernetesCloudConnector(cloud_info)
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
            disk.0.image.url = 'docker://someimage' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'fogbow', 'type': 'Kubernetes', 'host': 'http://server.com:8080'}])
        kube_cloud = self.get_kube_cloud()

        concrete = kube_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    def get_response(self):
        method, url = self.__class__.last_op

        resp = MagicMock()

        if method == "GET":
            if url == "/api/":
                resp.status = 200
                resp.read.return_value = '{"versions": "v1"}'
            elif url.endswith("/pods/1"):
                resp.status = 200
                resp.read.return_value = ('{"metadata": {"namespace":"namespace", "name": "name"}, "status": '
                                          '{"phase":"Running", "hostIP": "158.42.1.1", "podIP": "10.0.0.1"}, '
                                          '"spec": {"volumes": [{"persistentVolumeClaim": {"claimName" : "cname"}}]}}')
        elif method == "POST":
            if url.endswith("/pods"):
                resp.status = 201
                resp.read.return_value = '{"metadata": {"namespace":"namespace", "name": "name"}}'
        elif method == "DELETE":
            if url.endswith("/pods/1"):
                resp.status = 200
            elif "persistentvolumeclaims" in url:
                resp.status = 200
        elif method == "PATCH":
            if url.endswith("/pods/1"):
                resp.status = 201

        return resp

    def request(self, method, url, body=None, headers={}):
        self.__class__.last_op = method, url

    @patch('httplib.HTTPConnection')
    def test_20_launch(self, connection):
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
            disk.0.image.url = 'docker://someimage' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'fogbow', 'type': 'Kubernetes', 'host': 'http://server.com:8080'}])
        kube_cloud = self.get_kube_cloud()

        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.putrequest.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        res = kube_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('httplib.HTTPConnection')
    def test_30_updateVMInfo(self, connection):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'docker://someimage' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'fogbow', 'type': 'Kubernetes', 'host': 'http://server.com:8080'}])
        kube_cloud = self.get_kube_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "namespace/1", kube_cloud.cloud, radl, radl, kube_cloud)

        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        success, vm = kube_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('httplib.HTTPConnection')
    def test_55_alter(self, connection):
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

        auth = Authentication([{'id': 'fogbow', 'type': 'Kubernetes', 'host': 'http://server.com:8080'}])
        kube_cloud = self.get_kube_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "namespace/1", kube_cloud.cloud, radl, radl, kube_cloud)

        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.putrequest.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        success, _ = kube_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('httplib.HTTPConnection')
    def test_60_finalize(self, connection):
        auth = Authentication([{'id': 'fogbow', 'type': 'Kubernetes', 'host': 'http://server.com:8080'}])
        kube_cloud = self.get_kube_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "namespace/1", kube_cloud.cloud, "", "", kube_cloud)

        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        success, _ = kube_cloud.finalize(vm, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()


if __name__ == '__main__':
    unittest.main()
