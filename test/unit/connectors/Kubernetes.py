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
        query = parts[4]

        pod_data = {
            "metadata": {"namespace": "somenamespace", "name": "name"},
            "status": {
                "phase": "Running",
                "hostIP": "158.42.1.1",
                "podIP": "10.0.0.1"
            },
            "spec": {
                "containers": [
                    {"image": "image:1.0"}
                ],
                "volumes": [
                    {"persistentVolumeClaim": {"claimName": "cname"}},
                    {"configMap": {"name": "configmap"}},
                    {"secret": {"secretName": "secret"}}
                ]
            }
        }

        if method == "GET":
            if url == "/api/":
                resp.status_code = 200
                resp.text = '{"versions": "v1"}'
            elif url.endswith("/pods") and query == "labelSelector=name=1":
                resp.status_code = 200
                resp.json.return_value = {"items": [pod_data]}
            elif url == "/api/v1/namespaces/somenamespace":
                resp.status_code = 200
                resp.json.return_value = {'apiVersion': 'v1', 'kind': 'Namespace',
                                          'metadata': {'name': 'somenamespace', 'labels': {'inf_id': 'infid'}}}
            elif url == "/api/v1/namespaces/somenamespace/deployments/1":
                resp.status_code = 200
                resp.json.return_value = {'apiVersion': 'v1', 'kind': 'Deployment',
                                          "metadata": {"namespace": "somenamespace", "name": "name"},
                                          'spec': {'template': pod_data}}
        elif method == "POST":
            if url.endswith("/deployments"):
                resp.status_code = 201
                resp.text = '{"metadata": {"namespace":"somenamespace", "name": "name"}}'
            elif url.endswith("/services"):
                resp.status_code = 201
            elif url.endswith("/namespaces/"):
                resp.status_code = 201
            elif url.endswith("/persistentvolumeclaims"):
                resp.status_code = 201
            elif url.endswith("/apis/networking.k8s.io/v1/namespaces/somenamespace/ingresses"):
                resp.status_code = 201
            elif url.endswith("/configmaps"):
                resp.status_code = 201
            elif url.endswith("/secrets"):
                resp.status_code = 201
        elif method == "DELETE":
            if url.endswith("/deployments/1"):
                resp.status_code = 200
            elif url.endswith("/services/1"):
                resp.status_code = 200
            elif url.endswith("/namespaces/somenamespace"):
                resp.status_code = 200
            elif "persistentvolumeclaims" in url:
                resp.status_code = 200
            elif "ingresses" in url:
                resp.status_code = 200
            elif "configmaps" in url:
                resp.status_code = 200
            elif "secrets" in url:
                resp.status_code = 200
        elif method == "PATCH":
            if url.endswith("/deployments/1"):
                resp.status_code = 200

        return resp

    def add_vm(self, vm):
        vm.im_id = 0

    @patch('requests.request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    @patch('IM.connectors.Kubernetes.KubernetesCloudConnector._random_string', return_value='aaaa')
    def test_20_launch(self, random_string, save_data, requests):
        radl_data = """
            description desc (
                name = 'Infrastructure Name' and
                namespace = 'somenamespace2'
            )
            network net (outbound = 'yes' and outports = '38080-8080')
            system test (
            cpu.count>=1 and
            gpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'https://ingress.domain.com/path' and
            environment.variables = 'var=some_val,var2="some,val2"' and
            instance_tags = 'key=_inva:lid_' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'docker://someimage' and
            command = ['/bin/bash', '-c', 'sleep 100'] and
            disk.1.size = 10G and
            disk.1.mount_path = '/mnt' and
            disk.2.mount_path = '/etc/config' and
            disk.2.content = '
            some content
            ' and
            disk.3.mount_path = '/etc/secret' and
            disk.3.content = 'dmFsdWUtMg0KDQo='
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'kube', 'type': 'Kubernetes', 'namespace': 'somenamespace',
                                'host': 'http://server.com:8080', 'token': 'token'}])
        kube_cloud = self.get_kube_cloud()

        requests.side_effect = self.get_response

        inf = MagicMock(["id", "_lock", "add_vm", "description"])
        inf.id = "infid"
        inf.radl = radl
        inf.description.getValue.return_value = "somenamespace"
        inf.add_vm.side_effect = self.add_vm
        res = kube_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")

        self.assertEqual(requests.call_args_list[0][0][1],
                         'http://server.com:8080/api/v1/namespaces/somenamespace')

        exp_pvc = {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {"name": "test-aaaa-1",
                         "namespace": "somenamespace",
                         'labels': {'name': 'test-aaaa-1'}},
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": {"requests": {"storage": 10000000000}},
            },
        }
        self.assertEqual(requests.call_args_list[1][0][1],
                         'http://server.com:8080/api/v1/namespaces/somenamespace/persistentvolumeclaims')
        self.assertEqual(json.loads(requests.call_args_list[1][1]['data']), exp_pvc)

        exp_cm = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "test-aaaa-cm-2",
                         "namespace": "somenamespace",
                         'labels': {'name': 'test-aaaa-cm-2'}},
            "data": {"config": "\n            some content\n            "},
        }
        self.assertEqual(requests.call_args_list[2][0][1],
                         'http://server.com:8080/api/v1/namespaces/somenamespace/configmaps')
        self.assertEqual(json.loads(requests.call_args_list[2][1]['data']), exp_cm)

        exp_cm = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "test-aaaa-cm-3",
                         "namespace": "somenamespace",
                         'labels': {'name': 'test-aaaa-cm-3'}},
            "data": {"secret": "dmFsdWUtMg0KDQo="},
        }
        self.assertEqual(requests.call_args_list[3][0][1],
                         'http://server.com:8080/api/v1/namespaces/somenamespace/secrets')
        self.assertEqual(json.loads(requests.call_args_list[3][1]['data']), exp_cm)

        exp_dep = {
            "apiVersion": "v1",
            "kind": "Deployment",
            "metadata": {
                "name": "test-aaaa",
                "namespace": "somenamespace",
                "labels": {"name": "test-aaaa", "IM_INFRA_ID": "infid", "key": "invalid_"},
            },
            "spec": {
                "replicas": 1,
                "selector": {
                    "matchLabels": {"name": "test-aaaa"},
                },
                "template": {
                    "metadata": {
                        "labels": {"name": "test-aaaa"},
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "test-aaaa",
                                "command": ["/bin/bash"],
                                "args": ["-c", "sleep 100"],
                                "image": "someimage",
                                "imagePullPolicy": "Always",
                                "ports": [{"containerPort": 8080, "protocol": "TCP"}],
                                "resources": {
                                    "limits": {"cpu": "1", "memory": "512000000", "nvidia.com/gpu": "1"},
                                    "requests": {"cpu": "1", "memory": "512000000", "nvidia.com/gpu": "1"},
                                },
                                "env": [{"name": "var", "value": "some_val"},
                                        {"name": "var2", "value": "some,val2"}],
                                "volumeMounts": [{"name": "test-aaaa-1", "mountPath": "/mnt"},
                                                {'mountPath': '/etc/config', 'name': 'test-aaaa-cm-2',
                                                'readOnly': True, 'subPath': 'config'},
                                                {'mountPath': '/etc/secret', 'name': 'test-aaaa-cm-3',
                                                'readOnly': True, 'subPath': 'secret'}],
                            }
                        ],
                        "restartPolicy": "OnFailure",
                        "volumes": [
                            {"name": "test-aaaa-1", "persistentVolumeClaim": {"claimName": "test-aaaa-1"}},
                            {"name": "test-aaaa-cm-2", "configMap": {"name": "test-aaaa-cm-2"}},
                            {"name": "test-aaaa-cm-3", "secret": {"secretName": "test-aaaa-cm-3"}},
                        ]
                    }
                }
            }
        }
        self.maxDiff = None
        self.assertEqual(requests.call_args_list[4][0][1],
                         'http://server.com:8080/api/v1/namespaces/somenamespace/deployments')
        self.assertEqual(json.loads(requests.call_args_list[4][1]['data']), exp_dep)

        exp_svc = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "test-aaaa",
                "namespace": "somenamespace",
                "labels": {"name": "test-aaaa"},
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
                "selector": {"name": "test-aaaa"},
            },
        }
        self.assertEqual(requests.call_args_list[5][0][1],
                         'http://server.com:8080/api/v1/namespaces/somenamespace/services')
        self.assertEqual(json.loads(requests.call_args_list[5][1]['data']), exp_svc)

        self.maxDiff = None
        exp_ing = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {
                "labels": {"name": "test-aaaa"},
                "name": "test-aaaa",
                "namespace": "somenamespace",
                "annotations": {
                    "cert-manager.io/cluster-issuer": "letsencrypt-prod",
                    "haproxy.router.openshift.io/ip_whitelist": "0.0.0.0/0",
                    "haproxy.router.openshift.io/redirect-to-https": "True",
                    "route.openshift.io/termination": "edge"
                },
            },
            "spec": {
                "tls": [
                    {
                        "hosts": ["ingress.domain.com"],
                        "secretName": "test-aaaa-tls"
                    }
                ],
                "rules": [
                    {
                        "host": "ingress.domain.com",
                        "http": {
                            "paths": [
                                {
                                    "backend": {
                                        "service": {
                                            "name": "test-aaaa",
                                            "port": {"number": 8080},
                                        }
                                    },
                                    "path": "/path",
                                    "pathType": "Prefix",
                                }
                            ]
                        },
                    }
                ]
            },
        }

        self.assertEqual(requests.call_args_list[7][0][1],
                         'http://server.com:8080/apis/networking.k8s.io/v1/namespaces/somenamespace/ingresses')
        self.assertEqual(json.loads(requests.call_args_list[7][1]['data']), exp_ing)

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
        vm = VirtualMachine(inf, "namespace/1", kube_cloud.cloud, radl, radl, kube_cloud, 1)

        requests.side_effect = self.get_response

        success, vm = kube_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertEqual(vm.info.systems[0].getValue("net_interface.0.ip"), "158.42.1.1")
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
            disk.0.image.url = 'docker://image:2.0' and
            cpu.count=2 and
            memory.size=1g
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        auth = Authentication([{'id': 'kube', 'type': 'Kubernetes',
                                'host': 'http://server.com:8080', 'token': 'token'}])
        kube_cloud = self.get_kube_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "namespace/1", kube_cloud.cloud, radl, radl, kube_cloud, 1)

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
        vm = VirtualMachine(inf, "somenamespace/1", kube_cloud.cloud, "", "", kube_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = kube_cloud.finalize(vm, True, auth)

        self.assertEqual(requests.call_args_list[1][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/somenamespace/persistentvolumeclaims/cname'))
        self.assertEqual(requests.call_args_list[2][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/somenamespace/configmaps/configmap'))
        self.assertEqual(requests.call_args_list[3][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/somenamespace/secrets/secret'))
        self.assertEqual(requests.call_args_list[4][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/somenamespace/deployments/1'))
        self.assertEqual(requests.call_args_list[5][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/somenamespace/services/1'))
        self.assertEqual(requests.call_args_list[6][0],
                         ('DELETE',
                          'http://server.com:8080/apis/networking.k8s.io/v1/namespaces/somenamespace/ingresses/1'))
        self.assertEqual(requests.call_args_list[7][0],
                         ('GET',
                          'http://server.com:8080/api/v1/namespaces/somenamespace'))
        self.assertEqual(requests.call_args_list[8][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/somenamespace'))
        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
