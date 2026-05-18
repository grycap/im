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

import json
import sys
import unittest

sys.path.append(".")
sys.path.append("..")
from .CloudConn import TestCloudConnectorBase
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
from IM.VirtualMachine import VirtualMachine
from IM.connectors.OSCAR import OSCARCloudConnector
from urllib.parse import urlparse
from mock import patch, MagicMock


class TestOSCARConnector(TestCloudConnectorBase):
    """
    Class to test the IM connectors
    """

    @staticmethod
    def get_oscar_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "OSCAR"
        cloud_info.protocol = "http"
        cloud_info.server = "oscar.com"
        cloud_info.port = -1
        inf = MagicMock()
        inf.id = "1"
        cloud = OSCARCloudConnector(cloud_info, inf)
        return cloud

    def test_10_concrete(self):
        radl_data = """
            network net ()
            system test (
            name = 'plants' and
            script = '#!/bin/bash
                      echo "HOLA"' and
            cpu.count>=1 and
            memory.size>=512m and
            disk.0.image.url = 'oscar://oscar.com/some/image:tag'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'osc', 'type': 'OSCAR', 'host': 'http://oscar.com', 'token': 'token'}])
        oscar_cloud = self.get_oscar_cloud()

        concrete = oscar_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)

        radl_system.setValue('disk.0.image.url', 'docker:///some/image:tag')
        concrete = oscar_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)

        radl_system.setValue('disk.0.image.url', 'some/image:tag')
        concrete = oscar_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @staticmethod
    def get_response(method, url, verify=False, headers=None, data=None):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]

        if method == "GET":
            if url == "/system/services/fname":
                resp.status_code = 200
                resp.json.return_value = {
                    "name": "plants", "memory": "2048M",
                    "cpu": "1.0", "script": "plants.sh",
                    "image": "grycap/oscar-theano-plants",
                    "environment": {"Variables": {"a": "b"}},
                    "token": "service_token",
                    "input": [{"storage_provider": "minio_id",
                               "path": "/input", "suffix": ["*.txt"]}],
                    "output": [{"storage_provider": "minio_id",
                               "path": "/output"}],
                    "storage_providers": {"minio": {"minio_id": {"access_key": "AK",
                                                                 "secret_key": "SK",
                                                                 "endpoint": "https://minio.com",
                                                                 "region": "mregion",
                                                                 "verify": False}}}}
        elif method == "POST":
            if url == "/system/services":
                resp.status_code = 201
                resp.text = ''
        elif method == "DELETE":
            if url == "/system/services/fname":
                resp.status_code = 204
        elif method == "PUT":
            if url == "/system/services/fname":
                resp.status_code = 204

        return resp

    @patch('requests.request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, requests):
        radl_data = """
            system test (
                name = 'plants' and
                memory.size = 2GI and
                cpu.count = 1.0 and
                cpu.sgx = 1 and
                gpu.count = 1 and
                disk.0.image.url = 'grycap/oscar-theano-plants' and
                script = 'plants.sh' and
                environment.variables = ['a:b', 'VAR:https://server'] and
                input.0.provider = 'minio_id' and
                input.0.path = '/input' and
                input.0.suffix = ['*.txt'] and
                output.0.provider = 'minio_id' and
                output.0.path = '/output' and
                minio.0.id = 'minio_id' and
                minio.0.endpoint = 'https://minio.com' and
                minio.0.region = 'mregion' and
                minio.0.access_key = 'AK' and
                minio.0.secret_key = 'SK' and
                expose.min_scale = 1 and
                expose.max_scale = 2 and
                expose.port = 8080 and
                expose.cpu_threshold = 70
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'osc', 'type': 'OSCAR', 'host': 'http://oscar.com',
                                'username': 'user', 'password': 'pass'}])
        oscar_cloud = self.get_oscar_cloud()

        requests.side_effect = self.get_response

        inf = MagicMock(["id", "_lock", "add_vm"])
        inf.id = "infid"
        res = oscar_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.maxDiff = None
        expected_res = {"name": "plants", "memory": "2048Mi",
                        "cpu": "1", "script": "plants.sh",
                        "enable_gpu": True,
                        "enable_sgx": True,
                        "expose": {"cpu_threshold": 70, "max_scale": 2, "min_scale": 1, "port": 8080},
                        "image": "grycap/oscar-theano-plants",
                        "environment": {"Variables": {"a": "b", "VAR": "https://server"}},
                        "input": [{"storage_provider": "minio_id",
                                  "path": "/input", "suffix": ["*.txt"]}],
                        "output": [{"storage_provider": "minio_id",
                                   "path": "/output"}],
                        "storage_providers": {"minio": {"minio_id": {"access_key": "AK",
                                                                     "secret_key": "SK",
                                                                     "endpoint": "https://minio.com",
                                                                     "region": "mregion"}}}}
        self.assertEqual(json.loads(requests.call_args_list[0][1]['data']), expected_res)
        self.assertEqual(requests.call_args_list[0][1]['headers']['Authorization'], "Basic dXNlcjpwYXNz")

        radl.systems[0].setValue("dependencies", ["other_func"])
        inf2 = MagicMock(["id", "_lock", "add_vm", "get_vm_list"])
        inf2.id = "infid"
        vm1 = MagicMock(["info"])
        vm1.info = radl.clone()
        vm2 = MagicMock(["info", "is_configured"])
        vm2.info = radl.clone()
        vm2.info.systems[0].name = "other_func"
        vm2.is_configured.return_value = False
        inf2.get_vm_list.return_value = [vm1, vm2]
        res = oscar_cloud.launch(inf2, radl, radl, 1, auth)
        self.assertEqual(res[0][1].state, VirtualMachine.PENDING)
        self.assertEqual(requests.call_count, 1)

    @patch('requests.request')
    def test_30_updateVMInfo(self, requests):
        radl_data = """
            system test (
                memory.size = 4G and
                cpu.count = 2.0
            )"""
        radl = radl_parse.parse_radl(radl_data)

        auth = Authentication([{'id': 'osc', 'type': 'OSCAR', 'host': 'http://oscar.com', 'token': 'token'}])
        oscar_cloud = self.get_oscar_cloud()

        inf = MagicMock()
        inf.id = "infid"
        vm = VirtualMachine(inf, "fname", oscar_cloud.cloud, radl, radl, oscar_cloud, 1)
        vm.state = VirtualMachine.RUNNING

        requests.side_effect = self.get_response

        success, vm = oscar_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.assertEqual(requests.call_args_list[0][0][0], "GET")
        self.assertEqual(requests.call_args_list[0][0][1], "http://oscar.com:80/system/services/fname")
        self.assertEqual(vm.info.systems[0].getValue("token"), "service_token")

        radl_data2 = """
            system test (
                name = 'plants' and
                memory.size = 2G and
                cpu.count = 1.0 and
                disk.0.image.url = 'grycap/oscar-theano-plants' and
                script = 'plants.sh' and
                environment.variables = ['a:b'] and
                input.0.provider = 'minio_id' and
                input.0.path = '/input' and
                input.0.suffix = ['*.txt'] and
                output.0.provider = 'minio_id' and
                output.0.path = '/output' and
                minio.0.id = 'minio_id' and
                minio.0.endpoint = 'https://minio.com' and
                minio.0.region = 'mregion' and
                minio.0.access_key = 'AK' and
                minio.0.secret_key = 'SK' and
                dependencies = ['other_func']
            )"""
        radl2 = radl_parse.parse_radl(radl_data2)

        inf2 = MagicMock(["id", "_lock", "add_vm", "get_vm_list"])
        inf2.id = "infid"
        vm1 = VirtualMachine(inf2, "fname", oscar_cloud.cloud, radl2, radl2, oscar_cloud, 1)
        vm1.state = VirtualMachine.PENDING
        vm2 = MagicMock(["info", "is_configured"])
        vm2.info = radl2.clone()
        vm2.info.systems[0].name = "other_func"
        vm2.is_configured.return_value = False
        inf2.get_vm_list.return_value = [vm1, vm2]
        success, vm = oscar_cloud.updateVMInfo(vm1, auth)
        self.assertEqual(vm.state, VirtualMachine.PENDING)
        self.assertEqual(requests.call_count, 1)

        vm2.is_configured.return_value = True
        success, vm = oscar_cloud.updateVMInfo(vm1, auth)
        self.assertEqual(vm.state, VirtualMachine.RUNNING)
        self.assertEqual(requests.call_args_list[1][0][0], "POST")
        self.assertEqual(requests.call_args_list[1][0][1], "http://oscar.com:80/system/services")

    @patch('requests.request')
    def test_55_alter(self, requests):
        radl_data = """
            system test (
                name = 'plants' and
                memory.size = 2G and
                cpu.count = 1.0 and
                disk.0.image.url = 'oscar://oscar.com/grycap/oscar-theano-plants' and
                script = 'plants.sh' and
                environment.variables = ['a:b'] and
                input.provider = 'minio_id' and
                input.path = '/input' and
                input.suffix = ['*.txt'] and
                output.provider = 'minio_id' and
                output.path = '/output' and
                minio.0.id = 'minio_id' and
                minio.0.endpoint = 'https://minio.com' and
                minio.0.region = 'mregion' and
                minio.0.access_key = 'AK' and
                minio.0.secret_key = 'SK'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        new_radl_data = """
            system test (
            cpu.count>=2 and
            memory.size>=4GI
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        auth = Authentication([{'id': 'osc', 'type': 'OSCAR', 'host': 'http://oscar.com', 'token': 'token'}])
        oscar_cloud = self.get_oscar_cloud()

        inf = MagicMock()
        inf.id = "infid"
        vm = VirtualMachine(inf, "fname", oscar_cloud.cloud, radl, radl, oscar_cloud, 1)

        requests.side_effect = self.get_response

        success, new_vm = oscar_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.assertEqual(new_vm.info.systems[0].getValue("cpu.count"), 2)
        self.assertEqual(new_vm.info.systems[0].getFeature("memory.size").getValue("M"), 4295)
        self.assertEqual(requests.call_args_list[0][0][0], "PUT")
        self.assertEqual(requests.call_args_list[0][0][1], "http://oscar.com:80/system/services/fname")
        self.assertEqual(json.loads(requests.call_args_list[0][1]['data']), {'memory': '4096Mi', 'cpu': '2'})

    @patch('requests.request')
    def test_60_finalize(self, requests):
        auth = Authentication([{'id': 'osc', 'type': 'OSCAR', 'host': 'http://oscar.com', 'token': 'token'}])
        oscar_cloud = self.get_oscar_cloud()

        inf = MagicMock()
        inf.id = "infid"
        vm = VirtualMachine(inf, "fname", oscar_cloud.cloud, "", "", oscar_cloud, 1)
        vm.state = VirtualMachine.RUNNING

        requests.side_effect = self.get_response

        success, _ = oscar_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.assertEqual(requests.call_args_list[0][0][0], "DELETE")
        self.assertEqual(requests.call_args_list[0][0][1], "http://oscar.com:80/system/services/fname")


if __name__ == '__main__':
    unittest.main()
