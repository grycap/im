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
import json
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
from IM.connectors.Docker import DockerCloudConnector
from IM.uriparse import uriparse
from mock import patch, MagicMock


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestDockerConnector(unittest.TestCase):
    """
    Class to test the IM connectors
    """

    def setUp(self):
        TestDockerConnector.swarm = False
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
    def activate_swarm(activate=True):
        TestDockerConnector.swarm = activate

    @staticmethod
    def get_docker_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "Docker"
        cloud_info.protocol = "http"
        cloud_info.server = "server.com"
        cloud_info.port = 2375
        inf = MagicMock()
        inf.id = "1"
        cloud = DockerCloudConnector(cloud_info, inf)
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

        auth = Authentication([{'id': 'docker', 'type': 'Docker', 'host': 'http://server.com:2375'}])
        docker_cloud = self.get_docker_cloud()

        concrete = docker_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    def get_response(self, method, url, verify, cert, headers, data):
        resp = MagicMock()
        parts = uriparse(url)
        url = parts[2]
        params = parts[4]

        if method == "GET":
            if url == '/info':
                resp.status_code = 200
                if TestDockerConnector.swarm:
                    resp.text = '{"Swarm": {"LocalNodeState": "active"}}'
                else:
                    resp.text = '{"Swarm": {"LocalNodeState": "inactive"}}'
            elif url == "/api/":
                resp.status_code = 200
                resp.text = '{"versions": "v1"}'
            elif url == "/containers/1/json":
                resp.status_code = 200
                resp.text = '{"State": {"Running": 1}, "NetworkSettings": {"IPAddress": "10.0.0.1"}}'
            elif url == "/services/1":
                resp.status_code = 200
                resp.text = ('{"Spec": {"Name": "sname"},"UpdateStatus": {"CompletedAt": '
                             '"2016-06-07T21:10:20.269723157Z"},"Endpoint": {"VirtualIPs":'
                             ' [{"Addr": "10.0.0.1/16"}]}}')
            elif url.startswith("/tasks"):
                resp.status_code = 200
                resp.text = ('[{"Status": {"State": "rejected", "Err": "Err"}}, {"Status": {"State": "running"}}]')
            elif url.startswith("/networks"):
                resp.status_code = 200
                data = json.loads(params.split("=")[1])
                netname = list(data['name'].keys())[0]
                resp.text = '[{"Name": "%s", "Id": "netid"}]' % netname
        elif method == "POST":
            if url == "/containers/create":
                resp.status_code = 201
                resp.text = '{"Id": "id"}'
            elif url == "/services/create":
                resp.status_code = 201
                resp.text = '{"ID": "id"}'
            elif url == "/images/create":
                resp.status_code = 200
            elif url.endswith("/start"):
                resp.status_code = 204
            elif url.endswith("/stop"):
                resp.status_code = 204
            elif url == "/volumes/create":
                resp.status_code = 201
            elif url == "/networks/create":
                resp.status_code = 201
            elif url == "/networks/netid/connect":
                resp.status_code = 200
        elif method == "DELETE":
            if url == "/containers/1":
                resp.status_code = 204
            if url == "/services/1":
                resp.status_code = 200
            if url == "/volumes/hdb":
                resp.status_code = 204
            if url == "/networks/netid":
                resp.status_code = 204

        return resp

    @patch('requests.request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, requests):
        radl_data = """
            network net1 (outbound = 'yes' and outports = '8080')
            network net2 ()
            network net3 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            net_interface.2.connection = 'net3' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'docker://someimage' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'docker', 'type': 'Docker', 'host': 'http://server.com:2375'}])
        docker_cloud = self.get_docker_cloud()

        requests.side_effect = self.get_response

        res = docker_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        self.activate_swarm()
        docker_cloud._swarm = None
        res = docker_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        self.activate_swarm(False)
        docker_cloud._swarm = None
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

        auth = Authentication([{'id': 'docker', 'type': 'Docker', 'host': 'http://server.com:2375'}])
        docker_cloud = self.get_docker_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", docker_cloud.cloud, radl, radl, docker_cloud, 1)

        requests.side_effect = self.get_response

        success, vm = docker_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertEquals(vm.info.systems[0].getValue("net_interface.1.ip"), "10.0.0.1")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        self.activate_swarm()
        docker_cloud._swarm = None
        success, vm = docker_cloud.updateVMInfo(vm, auth)
        self.activate_swarm(False)
        docker_cloud._swarm = None

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertEquals(vm.info.systems[0].getValue("net_interface.1.ip"), "10.0.0.1")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    def test_40_stop(self, requests):
        auth = Authentication([{'id': 'docker', 'type': 'Docker', 'host': 'http://server.com:2375'}])
        docker_cloud = self.get_docker_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", docker_cloud.cloud, "", "", docker_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = docker_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    def test_50_start(self, requests):
        auth = Authentication([{'id': 'docker', 'type': 'Docker', 'host': 'http://server.com:2375'}])
        docker_cloud = self.get_docker_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", docker_cloud.cloud, "", "", docker_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = docker_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    def test_60_finalize(self, requests):
        radl_data = """
            network net (outbound = 'yes')
            network net1 ()
            system test (
            cpu.count=1 and
            memory.size=512m and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path' and
            disk.1.created='yes'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        auth = Authentication([{'id': 'docker', 'type': 'Docker', 'host': 'http://server.com:2375'}])
        docker_cloud = self.get_docker_cloud()

        inf = MagicMock()
        inf.id = "infid"
        vm = VirtualMachine(inf, "1", docker_cloud.cloud, radl, radl, docker_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = docker_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        self.activate_swarm()
        docker_cloud._swarm = None
        success, _ = docker_cloud.finalize(vm, True, auth)
        self.activate_swarm(False)
        docker_cloud._swarm = None

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
