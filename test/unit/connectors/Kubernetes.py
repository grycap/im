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
        resp.status_code = 404
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
            elif url.endswith("/pods") and query in ["labelSelector=name=1", "labelSelector=name=2"]:
                resp.status_code = 200
                resp.json.return_value = {"items": [pod_data]}
            elif url == "/api/v1/namespaces/somenamespace":
                resp.status_code = 200
                resp.json.return_value = {'apiVersion': 'v1', 'kind': 'Namespace',
                                          'metadata': {'name': 'somenamespace', 'labels': {'inf_id': 'infid'}}}
            elif url == "/apis/apps/v1/namespaces/somenamespace/deployments/1":
                resp.status_code = 200
                resp.json.return_value = {'apiVersion': 'v1', 'kind': 'Deployment',
                                          "metadata": {"namespace": "somenamespace", "name": "name"},
                                          'spec': {'template': pod_data}}
            elif url == "/api/v1/namespaces/somenamespace/resourcequotas":
                resp.status_code = 200
                resp.json.return_value = {
                    'items': [
                        {
                            'spec': {
                                'hard': {
                                    'limits.cpu': '10',
                                    'limits.memory': '10Gi',
                                    'pods': '10',
                                    'requests.nvidia.com/gpu': '1',
                                    'requests.storage': '20Gi',
                                    'persistentvolumeclaims': '10',
                                    'sc1.storageclass.storage.k8s.io/requests.storage': '20Gi',
                                    'sc1.storageclass.storage.k8s.io/persistentvolumeclaims': '10'
                                }
                            },
                            'status': {
                                'used': {
                                    'limits.cpu': '1',
                                    'limits.memory': '1Gi',
                                    'pods': '1',
                                    'requests.nvidia.com/gpu': '0',
                                    'requests.storage': '1Gi',
                                    'persistentvolumeclaims': '1',
                                    'sc1.storageclass.storage.k8s.io/requests.storage': '1Gi',
                                    'sc1.storageclass.storage.k8s.io/persistentvolumeclaims': '1'
                                }
                            }
                        }
                    ]
                }
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
    def test_20_launch(self, save_data, requests):
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
            "metadata": {"name": "test-1",
                         "namespace": "somenamespace",
                         'labels': {'name': 'test-1'}},
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
            "metadata": {"name": "test-cm-2",
                         "namespace": "somenamespace",
                         'labels': {'name': 'test-cm-2'}},
            "data": {"config": "\n            some content\n            "},
        }
        self.assertEqual(requests.call_args_list[2][0][1],
                         'http://server.com:8080/api/v1/namespaces/somenamespace/configmaps')
        self.assertEqual(json.loads(requests.call_args_list[2][1]['data']), exp_cm)

        exp_cm = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "test-cm-3",
                         "namespace": "somenamespace",
                         'labels': {'name': 'test-cm-3'}},
            "data": {"secret": "dmFsdWUtMg0KDQo="},
        }
        self.assertEqual(requests.call_args_list[3][0][1],
                         'http://server.com:8080/api/v1/namespaces/somenamespace/secrets')
        self.assertEqual(json.loads(requests.call_args_list[3][1]['data']), exp_cm)

        exp_dep = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "test",
                "namespace": "somenamespace",
                "labels": {"name": "test", "IM_INFRA_ID": "infid", "key": "invalid_"},
            },
            "spec": {
                "replicas": 1,
                "selector": {
                    "matchLabels": {"name": "test"},
                },
                "template": {
                    "metadata": {
                        "labels": {"name": "test"},
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "test",
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
                                "volumeMounts": [{"name": "test-1", "mountPath": "/mnt"},
                                                 {'mountPath': '/etc/config', 'name': 'test-cm-2',
                                                  'readOnly': True, 'subPath': 'config'},
                                                 {'mountPath': '/etc/secret', 'name': 'test-cm-3',
                                                  'readOnly': True, 'subPath': 'secret'}],
                            }
                        ],
                        "volumes": [
                            {"name": "test-1", "persistentVolumeClaim": {"claimName": "test-1"}},
                            {"name": "test-cm-2", "configMap": {"name": "test-cm-2"}},
                            {"name": "test-cm-3", "secret": {"secretName": "test-cm-3"}},
                        ]
                    }
                }
            }
        }
        self.maxDiff = None
        self.assertEqual(requests.call_args_list[4][0][1],
                         'http://server.com:8080/apis/apps/v1/namespaces/somenamespace/deployments')
        self.assertEqual(json.loads(requests.call_args_list[4][1]['data']), exp_dep)

        exp_svc = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "test",
                "namespace": "somenamespace",
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
        self.assertEqual(requests.call_args_list[5][0][1],
                         'http://server.com:8080/api/v1/namespaces/somenamespace/services')
        self.assertEqual(json.loads(requests.call_args_list[5][1]['data']), exp_svc)

        self.maxDiff = None
        exp_ing = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {
                "labels": {"name": "test"},
                "name": "test",
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
                        "secretName": "test-tls"
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
                                            "name": "test",
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

        exp_data = [{"op": "replace", "path": "/spec/template/spec/containers/0/image",
                     "value": "image:2.0"},
                    {"op": "replace", "path": "/spec/template/spec/containers/0/resources/limits/cpu",
                     "value": "2"},
                    {"op": "replace", "path": "/spec/template/spec/containers/0/resources/requests/cpu",
                     "value": "2"},
                    {"op": "replace", "path": "/spec/template/spec/containers/0/resources/limits/memory",
                     "value": "1000000000"},
                    {"op": "replace", "path": "/spec/template/spec/containers/0/resources/requests/memory",
                     "value": "1000000000"}]
        self.assertEqual(json.loads(requests.call_args_list[0][1]['data']), exp_data)

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
                          'http://server.com:8080/apis/apps/v1/namespaces/somenamespace/deployments/1'))
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

    @patch('requests.request')
    def test_60_finalize_pod(self, requests):
        auth = Authentication([{'id': 'kube', 'type': 'Kubernetes',
                                'host': 'http://server.com:8080', 'token': 'token'}])
        kube_cloud = self.get_kube_cloud()

        inf = MagicMock()
        inf.id = "infid"
        vm = VirtualMachine(inf, "somenamespace/2", kube_cloud.cloud, "", "", kube_cloud, 1)

        requests.side_effect = self.get_response

        success, _ = kube_cloud.finalize(vm, True, auth)

        self.assertEqual(requests.call_args_list[2][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/somenamespace/persistentvolumeclaims/cname'))
        self.assertEqual(requests.call_args_list[3][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/somenamespace/configmaps/configmap'))
        self.assertEqual(requests.call_args_list[4][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/somenamespace/secrets/secret'))
        self.assertEqual(requests.call_args_list[5][0],
                         ('DELETE',
                          'http://server.com:8080/apis/apps/v1/namespaces/somenamespace/pods/2'))
        self.assertEqual(requests.call_args_list[6][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/somenamespace/services/2'))
        self.assertEqual(requests.call_args_list[7][0],
                         ('DELETE',
                          'http://server.com:8080/apis/networking.k8s.io/v1/namespaces/somenamespace/ingresses/2'))
        self.assertEqual(requests.call_args_list[8][0],
                         ('GET',
                          'http://server.com:8080/api/v1/namespaces/somenamespace'))
        self.assertEqual(requests.call_args_list[9][0],
                         ('DELETE',
                          'http://server.com:8080/api/v1/namespaces/somenamespace'))
        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    def test_70_quotas(self, requests):
        auth = Authentication([{'id': 'kube', 'type': 'Kubernetes', 'namespace': 'somenamespace',
                                'host': 'http://server.com:8080', 'token': 'token'}])
        kube_cloud = self.get_kube_cloud()

        requests.side_effect = self.get_response

        quotas = kube_cloud.get_quotas(auth)
        expected_quotas = {
            'cores': {'limit': 10, 'used': 1},
            'ram': {'limit': 10, 'used': 1},
            'instances': {'limit': 10, 'used': 1},
            'gpus': {'limit': 1, 'used': 0},
            'volume_storage': {'limit': 20, 'used': 1},
            'volume_storage_sc1': {'limit': 20, 'used': 1},
            'volumes': {'limit': 10, 'used': 1},
            'volumes_sc1': {'limit': 10, 'used': 1}
        }
        self.assertEqual(quotas, expected_quotas, msg="ERROR: quotas do not match expected.")


if __name__ == '__main__':
    unittest.main()
