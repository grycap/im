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
from IM.connectors.Kubernetes import KubernetesCloudConnector
from IM.uriparse import uriparse
from mock import patch, MagicMock


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestKubernetesConnector(unittest.TestCase):
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
    def get_kube_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "Kubernetes"
        cloud_info.protocol = "http"
        cloud_info.server = "server.com"
        cloud_info.port = 8080
        inf = MagicMock()
        inf.id = "1"
        cloud = KubernetesCloudConnector(cloud_info, inf)
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

    def get_response(self, method, url, verify, headers, data):
        resp = MagicMock()
        parts = uriparse(url)
        url = parts[2]

        if method == "GET":
            if url == "/api/":
                resp.status_code = 200
                resp.text = '{"versions": "v1"}'
            elif url.endswith("/pods/1"):
                resp.status_code = 200
                resp.text = ('{"metadata": {"namespace":"namespace", "name": "name"}, "status": '
                             '{"phase":"Running", "hostIP": "158.42.1.1", "podIP": "10.0.0.1"}, '
                             '"spec": {"volumes": [{"persistentVolumeClaim": {"claimName" : "cname"}}]}}')
        elif method == "POST":
            if url.endswith("/pods"):
                resp.status_code = 201
                resp.text = '{"metadata": {"namespace":"namespace", "name": "name"}}'
            if url.endswith("/namespaces"):
                resp.status_code = 201
        elif method == "DELETE":
            if url.endswith("/pods/1"):
                resp.status_code = 200
            if url.endswith("/namespaces/namespace"):
                resp.status_code = 200
            elif "persistentvolumeclaims" in url:
                resp.status_code = 200
        elif method == "PATCH":
            if url.endswith("/pods/1"):
                resp.status_code = 201

        return resp

    @patch('requests.request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, requests):
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

        requests.side_effect = self.get_response

        res = kube_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    def test_30_updateVMInfo(self, requests):
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
        inf.id = "namespace"
        vm = VirtualMachine(inf, "1", kube_cloud.cloud, radl, radl, kube_cloud, 1)

        requests.side_effect = self.get_response

        success, vm = kube_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    def test_55_alter(self, requests):
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
        inf.id = "namespace"
        vm = VirtualMachine(inf, "1", kube_cloud.cloud, radl, radl, kube_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = kube_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    def test_60_finalize(self, requests):
        auth = Authentication([{'id': 'fogbow', 'type': 'Kubernetes', 'host': 'http://server.com:8080'}])
        kube_cloud = self.get_kube_cloud()

        inf = MagicMock()
        inf.id = "namespace"
        vm = VirtualMachine(inf, "1", kube_cloud.cloud, "", "", kube_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = kube_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
