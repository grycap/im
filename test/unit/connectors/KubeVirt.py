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
from IM.connectors.KubeVirt import KubeVirtCloudConnector
from urllib.parse import urlparse
from mock import patch, MagicMock


class TestKubeVirtConnector(TestCloudConnectorBase):
    """
    Class to test the KubVirt connectors
    """

    @staticmethod
    def get_kube_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "KubeVirt"
        cloud_info.protocol = "http"
        cloud_info.server = "server.com"
        cloud_info.port = 6443
        inf = MagicMock()
        inf.id = "1"
        cloud = KubeVirtCloudConnector(cloud_info, inf)
        return cloud

    def test_10_concrete(self):
        radl_data = """
            network net ()
            system test (
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'kvr://someimage' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'kube', 'type': 'KubeVirt',
                                'host': 'http://server.com:6443', 'token': 'token'}])
        kube_cloud = self.get_kube_cloud()

        concrete = kube_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    def get_response(self, method, url, verify, headers, data, timeout):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]

        resp.status_code = 404

        if method == "GET":
            if url == '/apis/kubevirt.io/v1/namespaces/namespace/virtualmachines/1':
                resp.status_code = 200
            elif url == '/apis/kubevirt.io/v1/namespaces/namespace/virtualmachineinstances/1':
                resp.status_code = 200
                resp.text = ('{"metadata": {"namespace":"namespace", "name": "name"}, "status": '
                             '{"printableStatus":"Running", "currentCPUTopology": {"cores": 1}, '
                             '"interfaces": [{"ipAddress": "10.0.0.1"}] },'
                             '"spec": {"volumes": [{"persistentVolumeClaim": {"claimName" : "cname"}}]}}')
            elif url == "/api/v1/namespaces/infid":
                resp.status_code = 200
            elif url == "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/datavolumes.cdi.kubevirt.io":
                resp.status_code = 200
            elif url == "/api/v1/namespaces/namespace/services/1":
                resp.status_code = 200
                resp.json.return_value = {"metadata": {"name": "1", "namespace": "infid"},
                                          "status": {"loadBalancer": {"ingress": [{"ip": "8.8.8.8"}]}}}
        elif method == "POST":
            if url == '/apis/kubevirt.io/v1/namespaces/infid/virtualmachines':
                resp.status_code = 201
                resp.text = '{"metadata": {"name": "vm1", "namespace": "infid"}}'
            elif url.endswith("/services"):
                resp.status_code = 201
            elif url.endswith("/namespaces/"):
                resp.status_code = 201
            elif url.endswith("/persistentvolumeclaims"):
                resp.status_code = 201
        elif method == "DELETE":
            if url == "/apis/kubevirt.io/v1/namespaces/namespace/virtualmachines/1":
                resp.status_code = 200
            if url.endswith("/services/1"):
                resp.status_code = 200
            elif url.endswith("/namespaces/namespace"):
                resp.status_code = 200
            elif "persistentvolumeclaims" in url:
                resp.status_code = 200
        elif method == "PATCH":
            if url == '/apis/kubevirt.io/v1/namespaces/namespace/virtualmachines/1':
                resp.status_code = 201

        return resp

    @patch('requests.request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, requests):
        radl_data = """
            network net1 (outbound = 'yes' and outports = '8080')
            network net2 ()
            system test (
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'kvr://someimage' and
            disk.1.size=1GB and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'kube', 'type': 'KubeVirt',
                                'host': 'http://server.com:8080', 'token': 'token'}])
        kube_cloud = self.get_kube_cloud()

        requests.side_effect = self.get_response

        inf = MagicMock(["id", "_lock", "add_vm", "radl"])
        inf.id = "infid"
        inf.radl = radl
        res = kube_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        self.assertEqual(requests.call_count, 5)
        urls_called = [
            "http://server.com:6443/apis/apiextensions.k8s.io/v1/customresourcedefinitions/datavolumes.cdi.kubevirt.io",
            "http://server.com:6443/api/v1/namespaces/infid",
            "http://server.com:6443/api/v1/namespaces/infid/persistentvolumeclaims",
            "http://server.com:6443/apis/kubevirt.io/v1/namespaces/infid/virtualmachines",
            "http://server.com:6443/api/v1/namespaces/infid/services"
        ]

        for i, url in enumerate(urls_called):
            self.assertEqual(requests.call_args_list[i][0][1], url)

    @patch('requests.request')
    def test_30_updateVMInfo(self, requests):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'kvr://someimage'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'kube', 'type': 'KubeVirt', 'namespace': 'namespace',
                                'host': 'http://server.com:8080', 'token': 'token'}])
        kube_cloud = self.get_kube_cloud()

        inf = MagicMock()
        inf.id = "infid"
        vm = VirtualMachine(inf, "1", kube_cloud.cloud, radl, radl, kube_cloud, 1)

        requests.side_effect = self.get_response

        success, vm = kube_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertEqual(vm.info.systems[0].getValue("net_interface.0.ip"), "8.8.8.8")
        self.assertEqual(vm.info.systems[0].getValue("net_interface.1.ip"), "10.0.0.1")
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
            disk.0.image.url = 'kvr://image'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        new_radl_data = """
            system test (
            cpu.count>=2 and
            memory.size>=2048m
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        auth = Authentication([{'id': 'kube', 'type': 'KubeVirt',
                                'host': 'http://server.com:8080', 'token': 'token'}])
        kube_cloud = self.get_kube_cloud()

        inf = MagicMock()
        inf.id = "namespace"
        inf.radl = MagicMock()
        inf.radl.description = None
        vm = VirtualMachine(inf, "1", kube_cloud.cloud, radl, radl, kube_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = kube_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    def test_60_finalize(self, requests):
        auth = Authentication([{'id': 'kube', 'type': 'KubeVirt',
                                'host': 'http://server.com:8080', 'token': 'token'}])
        kube_cloud = self.get_kube_cloud()

        inf = MagicMock()
        inf.id = "namespace"
        inf.radl = MagicMock()
        inf.radl.description = None
        vm = VirtualMachine(inf, "1", kube_cloud.cloud, "", "", kube_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = kube_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        self.assertEqual(requests.call_count, 6)
        urls_called = [
            ("GET", "http://server.com:6443/apis/kubevirt.io/v1/namespaces/namespace/virtualmachines/1"),
            ("GET", "http://server.com:6443/apis/kubevirt.io/v1/namespaces/namespace/virtualmachineinstances/1"),
            ("DELETE", "http://server.com:6443/api/v1/namespaces/namespace/persistentvolumeclaims/cname"),
            ("DELETE", "http://server.com:6443/apis/kubevirt.io/v1/namespaces/namespace/virtualmachines/1"),
            ("DELETE", "http://server.com:6443/api/v1/namespaces/namespace/services/1"),
            ("GET", "http://server.com:6443/api/v1/namespaces/namespace"),
        ]

        for i, url in enumerate(urls_called):
            self.assertEqual(requests.call_args_list[i][0][0], url[0])
            self.assertEqual(requests.call_args_list[i][0][1], url[1])

    @patch('requests.request')
    def test_70_vm_op(self, requests):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'kvr://image'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'kube', 'type': 'KubeVirt',
                                'host': 'http://server.com:8080', 'token': 'token'}])
        kube_cloud = self.get_kube_cloud()

        requests.side_effect = self.get_response
        inf = MagicMock()
        inf.id = "namespace"
        inf.radl = MagicMock()
        inf.radl.description = None
        vm = VirtualMachine(inf, "1", kube_cloud.cloud, radl, radl, kube_cloud, 1)

        success, _ = kube_cloud.stop(vm, auth)
        self.assertTrue(success, msg="ERROR: stopping VM.")

        success, _ = kube_cloud.start(vm, auth)
        self.assertTrue(success, msg="ERROR: start VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
