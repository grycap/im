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
import json

sys.path.append(".")
sys.path.append("..")
from .CloudConn import TestCloudConnectorBase
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
from IM.VirtualMachine import VirtualMachine
from IM.connectors.OSCAR import OSCARCloudConnector
try:
    from urlparse import urlparse
except ImportError:
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
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    def get_response(self, method, url, verify=False, headers={}, data=None):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]

        if method == "GET":
            if url == "/system/services/fname":
                resp.status_code = 200
                resp.json.return_value = {
                    "name": "plants", "memory": "2048Mi",
                    "cpu": 1.0, "script": "plants.sh",
                    "image": "grycap/oscar-theano-plants",
                    "environment": {"Variables": {"a": "b"}},
                    "input": {"storage_provider": "minio_id", 
                                "path": "/input", "suffix": ["*.txt"]},
                    "output": {"storage_provider": "minio_id",
                                "path": "/output"},
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
                resp.status_code = 201

        return resp

    @patch('requests.request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, requests):
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
        radl.check()

        auth = Authentication([{'id': 'osc', 'type': 'OSCAR', 'host': 'http://oscar.com', 'token': 'token'}])
        oscar_cloud = self.get_oscar_cloud()

        requests.side_effect = self.get_response

        inf = MagicMock(["id", "_lock", "add_vm"])
        inf.id = "infid"
        res = oscar_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        print(requests.call_args_list[0][1]['data'])
        self.maxDiff = None
        expected_res = {"name": "plants", "memory": "2048Mi",
                        "cpu": 1.0, "script": "plants.sh",
                        "image": "grycap/oscar-theano-plants",
                        "environment": {"Variables": {"a": "b"}},
                        "input": {"storage_provider": "minio_id", 
                                  "path": "/input", "suffix": ["*.txt"]},
                        "output": {"storage_provider": "minio_id",
                                  "path": "/output"},
                        "storage_providers": {"minio": {"minio_id": {"access_key": "AK",
                                                                    "secret_key": "SK",
                                                                    "endpoint": "https://minio.com",
                                                                    "region": "mregion",
                                                                    "verify": False}}}}
        self.assertEqual(json.loads(requests.call_args_list[0][1]['data']), expected_res)

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

        requests.side_effect = self.get_response

        success, vm = oscar_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

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
            memory.size>=4G
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        auth = Authentication([{'id': 'osc', 'type': 'OSCAR', 'host': 'http://oscar.com', 'token': 'token'}])
        oscar_cloud = self.get_oscar_cloud()

        inf = MagicMock()
        inf.id = "infid"
        vm = VirtualMachine(inf, "fname", oscar_cloud.cloud, radl, radl, oscar_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = oscar_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    def test_60_finalize(self, requests):
        auth = Authentication([{'id': 'osc', 'type': 'OSCAR', 'host': 'http://oscar.com', 'token': 'token'}])
        oscar_cloud = self.get_oscar_cloud()

        inf = MagicMock()
        inf.id = "namespace"
        vm = VirtualMachine(inf, "fname", oscar_cloud.cloud, "", "", oscar_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = oscar_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
