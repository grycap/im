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
from IM.connectors.Kubernetes import KubernetesCloudConnector
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from mock import patch, MagicMock


class TestKubernetesConnector(TestCloudConnectorBase):
    """
    Class to test the IM connectors
    """

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
            system test (
            cpu.count>=1 and
            memory.size>=512m and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'docker://someimage'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'kube', 'type': 'Kubernetes',
                                'host': 'http://server.com:8080', 'token': 'token'}])
        kube_cloud = self.get_kube_cloud()

        concrete = kube_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    def get_response(self, method, url, verify, headers, data):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]

        if method == "GET":
            if url == "/api/":
                resp.status_code = 200
                resp.text = '{"versions": "v1"}'
            elif url.endswith("/pods/1"):
                resp.status_code = 200
                resp.text = ('{"metadata": {"namespace":"some_namespace", "name": "name"}, "status": '
                             '{"phase":"Running", "hostIP": "158.42.1.1", "podIP": "10.0.0.1"}, '
                             '"spec": {"containers": [{"image": "image:1.0"}], '
                             '"volumes": [{"persistentVolumeClaim": {"claimName" : "cname"}}]}}')
            if url == "/api/v1/namespaces/some_namespace":
                resp.status_code = 200
        elif method == "POST":
            if url.endswith("/pods"):
                resp.status_code = 201
                resp.text = '{"metadata": {"namespace":"some_namespace", "name": "name"}}'
            elif url.endswith("/services"):
                resp.status_code = 201
            elif url.endswith("/namespaces/"):
                resp.status_code = 201
            elif url.endswith("/persistentvolumeclaims"):
                resp.status_code = 201
            elif url.endswith("/apis/networking.k8s.io/v1/namespaces/some_namespace/ingresses"):
                resp.status_code = 201
        elif method == "DELETE":
            if url.endswith("/pods/1"):
                resp.status_code = 200
            elif url.endswith("/services/1"):
                resp.status_code = 200
            elif url.endswith("/namespaces/some_namespace"):
                resp.status_code = 200
            elif "persistentvolumeclaims" in url:
                resp.status_code = 200
            elif "ingresses" in url:
                resp.status_code = 200
        elif method == "PATCH":
            if url.endswith("/pods/1"):
                resp.status_code = 200

        return resp

    def add_vm(self, vm):
        vm.im_id = 0

    @patch('requests.request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, requests):
        radl_data = """
            description desc (
                name = 'Infrastructure Name' and
                namespace = 'some_namespace'
            )
            network net (outbound = 'yes' and outports = '38080-8080')
            system test (
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'ingress.domain.com' and
            environment.variables = 'var=some_val' and
            instance_tags = 'key=_inva:lid_' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'docker://someimage' and
            disk.1.size = 10G and
            disk.1.mount_path = '/mnt'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'kube', 'type': 'Kubernetes',
                                'host': 'http://server.com:8080', 'token': 'token'}])
        kube_cloud = self.get_kube_cloud()

        requests.side_effect = self.get_response

        inf = MagicMock(["id", "_lock", "add_vm", "description"])
        inf.id = "infid"
        inf.description = MagicMock(["getValue"])
        inf.description.getValue.return_value = "some_namespace"
        inf.add_vm.side_effect = self.add_vm
        res = kube_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")

        exp_pvc = {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {"name": "test-1", "namespace": "some_namespace"},
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": {"requests": {"storage": 10737418240}},
            },
        }
        self.assertEqual(requests.call_args_list[1][0][1],
                         'http://server.com:8080/api/v1/namespaces/some_namespace/persistentvolumeclaims')
        self.assertEqual(json.loads(requests.call_args_list[1][1]['data']), exp_pvc)

        exp_pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "test",
                "namespace": "some_namespace",
                "labels": {"name": "test", "IM_INFRA_ID": "infid", "key": "invalid_"},
            },
            "spec": {
                "containers": [
                    {
                        "name": "test",
                        "image": "someimage",
                        "imagePullPolicy": "Always",
                        "ports": [{"containerPort": 8080, "protocol": "TCP"}],
                        "resources": {
                            "limits": {"cpu": "1", "memory": "536870912"},
                            "requests": {"cpu": "1", "memory": "536870912"},
                        },
                        "env": [{"name": "var", "value": "some_val"}],
                        "volumeMounts": [{"name": "test-1", "mountPath": "/mnt"}],
                    }
                ],
                "restartPolicy": "OnFailure",
                "volumes": [
                    {"name": "test-1", "persistentVolumeClaim": {"claimName": "test-1"}}
                ],
            },
        }
        self.assertEqual(requests.call_args_list[2][0][1],
                         'http://server.com:8080/api/v1/namespaces/some_namespace/pods')
        self.assertEqual(json.loads(requests.call_args_list[2][1]['data']), exp_pod)

        exp_svc = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "test",
                "namespace": "some_namespace",
                "labels": {"name": "test"},
            },
            "spec": {
                "type": "NodePort",
                "ports": [
                    {
                        "port": 8080,
                        "protocol": "TCP",
                        "targetPort": 8080,
                        "name": "port8080",
                        "nodePort": 38080,
                    }
                ],
                "selector": {"name": "test"},
            },
        }
        self.assertEqual(requests.call_args_list[3][0][1],
                         'http://server.com:8080/api/v1/namespaces/some_namespace/services')
        self.assertEqual(json.loads(requests.call_args_list[3][1]['data']), exp_svc)

        exp_ing = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {
                "labels": {"name": "test"},
                "name": "test",
                "namespace": "some_namespace",
            },
            "spec": {
                "rules": [
                    {
                        "host": "ingress.domain.com",
                        "http": {
                            "paths": [
                                {
                                    "backend": {
                                        "service": {
                                            "name": "test",
                                            "port": {"number": 8080},
                                        }
                                    },
                                    "path": "/",
                                    "pathType": "Prefix",
                                }
                            ]
                        },
                    }
                ]
            },
        }

        self.assertEqual(requests.call_args_list[5][0][1],
                         'http://server.com:8080/apis/networking.k8s.io/v1/namespaces/some_namespace/ingresses')
        self.assertEqual(json.loads(requests.call_args_list[5][1]['data']), exp_ing)

        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    def test_30_updateVMInfo(self, requests):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.image.url = 'docker://someimage'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'kube', 'type': 'Kubernetes',
                                'host': 'http://server.com:8080', 'token': 'token'}])
        kube_cloud = self.get_kube_cloud()

        inf = MagicMock()
        inf.id = "namespace"
        vm = VirtualMachine(inf, "1", kube_cloud.cloud, radl, radl, kube_cloud, 1)

        requests.side_effect = self.get_response

        success, vm = kube_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertEqual(vm.info.systems[0].getValue("net_interface.0.ip"), "158.42.1.1")
        self.assertEqual(vm.info.systems[0].getValue("net_interface.1.ip"), "10.0.0.1")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    def test_55_alter(self, requests):
        radl_data = """
            network net ()
            system test (
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.image.url = 'docker://image:1.0'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        new_radl_data = """
            system test (
            disk.0.image.url = 'docker://image:2.0'
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        auth = Authentication([{'id': 'kube', 'type': 'Kubernetes',
                                'host': 'http://server.com:8080', 'token': 'token'}])
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
        auth = Authentication([{'id': 'kube', 'type': 'Kubernetes',
                                'host': 'http://server.com:8080', 'token': 'token'}])
        kube_cloud = self.get_kube_cloud()

        inf = MagicMock()
        inf.id = "infid"
        inf.description = MagicMock(["getValue"])
        inf.description.getValue.return_value = "some_namespace"
        vm = VirtualMachine(inf, "1", kube_cloud.cloud, "", "", kube_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = kube_cloud.finalize(vm, True, auth)

        self.assertEqual(requests.call_args_list[1][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/some_namespace/persistentvolumeclaims/cname'))
        self.assertEqual(requests.call_args_list[2][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/some_namespace/pods/1'))
        self.assertEqual(requests.call_args_list[3][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/some_namespace/services/1'))
        self.assertEqual(requests.call_args_list[4][0],
                         ('DELETE',
                          'http://server.com:8080/apis/networking.k8s.io/v1/namespaces/some_namespace/ingresses/1'))
        self.assertEqual(requests.call_args_list[5][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/some_namespace'))
        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
