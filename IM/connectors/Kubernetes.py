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

import base64
import json
import requests
import time
import os
import re
import socket
from random import choice
from string import ascii_lowercase, digits
from netaddr import IPNetwork, IPAddress
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from .CloudConnector import CloudConnector
from IM.connectors.exceptions import NoAuthData, NoCorrectAuthData
from radl.radl import Feature
from IM.config import Config


class KubernetesCloudConnector(CloudConnector):
    """
    Cloud Launcher to Kubernetes platform
    """

    type = "Kubernetes"

    VM_STATE_MAP = {
        'Pending': VirtualMachine.PENDING,
        'Running': VirtualMachine.RUNNING,
        'Succeeded': VirtualMachine.OFF,
        'Failed': VirtualMachine.FAILED
    }
    """Dictionary with a map with the Kubernetes POD states to the IM states."""

    def create_request(self, method, url, auth_data, headers=None, body=None):
        auth_header, _, _ = self.get_auth_header(auth_data)
        if auth_header:
            if headers is None:
                headers = {}
            headers.update(auth_header)

        if body and isinstance(body, (dict, list)):
            data = json.dumps(body)
        else:
            data = body
        url = "%s://%s:%d%s%s" % (self.cloud.protocol, self.cloud.server, self.cloud.get_port(), self.cloud.path, url)
        resp = requests.request(method, url, verify=self.verify_ssl, headers=headers, data=data)

        return resp

    def get_auth_header(self, auth_data):
        """
        Generate the auth header needed to contact with the Kubernetes API server.
        """
        url = urlparse(self.cloud.server)
        auths = auth_data.getAuthInfo(self.type, url[1])
        if not auths:
            raise NoAuthData(self.type)
        else:
            auth = auths[0]

        auth_header = None

        if 'username' in auth and 'password' in auth:
            passwd = auth['password']
            user = auth['username']
            auth_header = {'Authorization': 'Basic ' +
                           (base64.b64encode((user + ':' + passwd).encode('utf-8'))).strip().decode('utf-8')}
        elif 'token' in auth:
            token = auth['token']
            auth_header = {'Authorization': 'Bearer ' + token}
        else:
            raise NoCorrectAuthData(self.type, "username and password or token.")

        namespace = None
        if 'namespace' in auth:
            namespace = auth['namespace']

        apps_dns = None
        if 'apps_dns' in auth:
            apps_dns = auth['apps_dns']

        return auth_header, namespace, apps_dns

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]
        # it can use the docker protocol or the have a empty protocol and a non empty path
        # docker://image:tag or image:tag
        if (protocol == 'docker' and url[1]) or (protocol == '' and url[1] == '' and url[2] != ''):
            res_system = radl_system.clone()

            res_system.addFeature(Feature("virtual_system_type", "=", "kubernetes"), conflict="other", missing="other")
            res_system.getFeature("cpu.count").operator = "="
            res_system.getFeature("memory.size").operator = "="

            # Set it as it is required by the IM but in this case it is not used
            username = res_system.getValue('disk.0.os.credentials.username')
            if not username:
                res_system.setValue('disk.0.os.credentials.username', 'username')

            return res_system
        else:
            return None

    def _delete_volume_claim(self, namespace, vc_name, auth_data):
        try:
            self.log_debug("Deleting PVC: %s/%s" % (namespace, vc_name))
            uri = "/api/v1/namespaces/%s/%s/%s" % (namespace, "persistentvolumeclaims", vc_name)
            resp = self.create_request('DELETE', uri, auth_data)

            if resp.status_code == 404:
                self.log_warn("Trying to remove a non existing PersistentVolumeClaim: " + vc_name)
                return True
            elif resp.status_code != 200:
                self.log_error("Error deleting the PersistentVolumeClaim: " + resp.txt)
                return False
            else:
                return True
        except Exception:
            self.log_exception("Error connecting with Kubernetes API server")
            return False

    def _delete_volume_claims(self, pod_data, auth_data):
        if 'volumes' in pod_data['spec']:
            for volume in pod_data['spec']['volumes']:
                if 'persistentVolumeClaim' in volume and 'claimName' in volume['persistentVolumeClaim']:
                    vc_name = volume['persistentVolumeClaim']['claimName']
                    success = self._delete_volume_claim(pod_data["metadata"]["namespace"], vc_name, auth_data)
                    if not success:
                        self.log_error("Error deleting PersistentVolumeClaim:" + vc_name)

    def _create_volume_claim(self, claim_data, auth_data):
        try:
            headers = {'Content-Type': 'application/json'}
            uri = "/api/v1/namespaces/%s/%s" % (claim_data['metadata']['namespace'], "persistentvolumeclaims")
            resp = self.create_request('POST', uri, auth_data, headers, claim_data)

            output = str(resp.text)
            if resp.status_code != 201:
                self.log_error("Error deleting the POD: " + output)
                return False
            else:
                return True
        except Exception:
            self.log_exception("Error connecting with Kubernetes API server")
            return False

    def _delete_config_map(self, namespace, cm_name, auth_data, secret=False):
        try:
            self.log_debug("Deleting CM/Secret: %s/%s" % (namespace, cm_name))
            if secret:
                uri = "/api/v1/namespaces/%s/%s/%s" % (namespace, "secrets", cm_name)
            else:
                uri = "/api/v1/namespaces/%s/%s/%s" % (namespace, "configmaps", cm_name)
            resp = self.create_request('DELETE', uri, auth_data)

            if resp.status_code == 404:
                self.log_warn("Trying to remove a non existing ConfigMap/Secret: " + cm_name)
                return True
            elif resp.status_code != 200:
                self.log_error("Error deleting the ConfigMap/Secret: " + resp.txt)
                return False
            else:
                return True
        except Exception:
            self.log_exception("Error connecting with Kubernetes API server")
            return False

    def _delete_config_maps(self, pod_data, auth_data):
        if 'volumes' in pod_data['spec']:
            for volume in pod_data['spec']['volumes']:
                if 'configMap' in volume and 'name' in volume['configMap']:
                    cm_name = volume['configMap']['name']
                    success = self._delete_config_map(pod_data["metadata"]["namespace"], cm_name, auth_data)
                    if not success:
                        self.log_error("Error deleting ConfigMap:" + cm_name)
                if 'secret' in volume and 'secretName' in volume['secret']:
                    cm_name = volume['secret']['secretName']
                    success = self._delete_config_map(pod_data["metadata"]["namespace"], cm_name, auth_data, True)
                    if not success:
                        self.log_error("Error deleting Secret:" + cm_name)

    def _create_config_maps(self, namespace, system, pod_name, auth_data):
        res = []
        cont = 1
        while system.getValue("disk." + str(cont) + ".mount_path"):

            if (system.getValue("disk." + str(cont) + ".content") and
                    not system.getValue("disk." + str(cont) + ".size")):

                mount_path = system.getValue("disk." + str(cont) + ".mount_path")
                content = system.getValue("disk." + str(cont) + ".content")
                if not mount_path.startswith('/'):
                    mount_path = '/' + mount_path
                name = "%s-cm-%d" % (pod_name, cont)

                # Let's assume that if content is base64 encoded it is a secret
                try:
                    base64.b64decode(content, validate=True)
                    secret = True
                except Exception:
                    secret = False

                if secret:
                    cm_data = self._gen_basic_k8s_elem(namespace, name, 'Secret')
                else:
                    cm_data = self._gen_basic_k8s_elem(namespace, name, 'ConfigMap')
                cm_data['data'] = {os.path.basename(mount_path): content}

                try:
                    self.log_debug("Creating ConfigMap: %s/%s" % (namespace, name))
                    headers = {'Content-Type': 'application/json'}
                    if secret:
                        uri = "/api/v1/namespaces/%s/%s" % (namespace, "secrets")
                    else:
                        uri = "/api/v1/namespaces/%s/%s" % (namespace, "configmaps")
                    svc_resp = self.create_request('POST', uri, auth_data, headers, cm_data)
                    if svc_resp.status_code != 201:
                        self.error_messages += "Error creating configmap/secret for pod %s: %s" % (name, svc_resp.text)
                        self.log_warn("Error creating configmap/secret: %s" % svc_resp.text)
                    else:
                        res.append((name, mount_path, secret))
                except Exception:
                    self.error_messages += "Error creating configmap/secret to access pod %s" % name
                    self.log_exception("Error creating configmap/secret.")

            cont += 1

        return res

    def _create_volumes(self, namespace, system, pod_name, auth_data):
        res = []
        cont = 1
        while system.getValue("disk." + str(cont) + ".mount_path"):

            if (system.getValue("disk." + str(cont) + ".size") or
                    system.getValue("disk." + str(cont) + ".image.url")):

                volume_id = system.getValue("disk." + str(cont) + ".image.url")
                disk_mount_path = system.getValue("disk." + str(cont) + ".mount_path")
                disk_size = system.getFeature("disk." + str(cont) + ".size").getValue('B')
                if not disk_mount_path.startswith('/'):
                    disk_mount_path = '/' + disk_mount_path
                name = "%s-%d" % (pod_name, cont)

                claim_data = self._gen_basic_k8s_elem(namespace, name, 'PersistentVolumeClaim')
                claim_data['spec'] = {'accessModes': ['ReadWriteOnce'], 'resources': {
                    'requests': {'storage': disk_size}}}

                if volume_id:
                    claim_data['spec']['storageClassName'] = ""
                    claim_data['spec']['volumeName'] = volume_id

                self.log_debug("Creating PVC: %s/%s" % (namespace, name))
                success = self._create_volume_claim(claim_data, auth_data)
                if success:
                    res.append((name, disk_size, disk_mount_path))
                else:
                    self.log_error("Error creating PersistentVolumeClaim:" + name)
                    self.error_messages += "Error creating PersistentVolumeClaim for pod %s" % name

            cont += 1

        return res

    def create_service_data(self, namespace, name, outports, public, auth_data, vm):
        try:
            service_data = self._generate_service_data(namespace, name, outports, public)
            self.log_debug("Creating Service: %s/%s" % (namespace, name))
            headers = {'Content-Type': 'application/json'}
            uri = "/api/v1/namespaces/%s/%s" % (namespace, "services")
            svc_resp = self.create_request('POST', uri, auth_data, headers, service_data)
            if svc_resp.status_code != 201:
                self.error_messages += "Error creating service for pod %s: %s" % (name, svc_resp.text)
                self.log_warn("Error creating service: %s" % svc_resp.text)
            else:
                # Wait a bit to assure the service has been created
                time.sleep(0.5)
                # Get Service data to get assigned nodePort
                uri = "/api/v1/namespaces/%s/%s/%s" % (namespace, "services", name)
                svc_resp = self.create_request('GET', uri, auth_data)
                if svc_resp.status_code == 200:
                    for port in svc_resp.json()['spec']['ports']:
                        # Set Out port in the RADL info of the VM
                        if 'nodePort' in port and port['nodePort']:
                            vm.setOutPort(int(port['port']), int(port['nodePort']))

        except Exception:
            self.error_messages += "Error creating service to access pod %s" % name
            self.log_exception("Error creating service.")

    def _generate_service_data(self, namespace, name, outports, public):
        service_data = self._gen_basic_k8s_elem(namespace, name, 'Service')

        ports = []
        if outports:
            for outport in outports:
                if outport.is_range():
                    self.log_warn("Port range not allowed in Kubernetes connector. Ignoring.")
                else:
                    port = {'port': outport.get_local_port(),
                            'protocol': outport.get_protocol().upper(),
                            'targetPort': outport.get_local_port(),
                            'name': 'port%s' % outport.get_local_port()}
                    if public and outport.get_remote_port():
                        port['nodePort'] = outport.get_remote_port()
                    ports.append(port)

        service_data['spec'] = {
            'type': 'ClusterIP',
            'ports': ports,
            'selector': {'name': name}
        }

        if public:
            service_data['spec']['type'] = 'NodePort'

        return service_data

    def create_ingress(self, namespace, name, dns, port, auth_data, vm):
        try:
            _, _, apps_dns = self.get_auth_header(auth_data)
            ingress_data = self._generate_ingress_data(namespace, name, dns, port, apps_dns, vm)
            self.log_debug("Creating Ingress: %s/%s" % (namespace, name))
            headers = {'Content-Type': 'application/json'}
            uri = "/apis/networking.k8s.io/v1/namespaces/%s/ingresses" % namespace
            svc_resp = self.create_request('POST', uri, auth_data, headers, ingress_data)
            if svc_resp.status_code != 201:
                self.error_messages += "Error creating ingress for pod %s: %s" % (name, svc_resp.text)
                self.log_warn("Error creating ingress: %s" % svc_resp.text)
                return False
            else:
                return True
        except Exception:
            self.error_messages += "Error creating ingress to access pod %s" % name
            self.log_exception("Error creating ingress.")
            return False

    def _generate_ingress_data(self, namespace, name, dns, port, apps_dns, vm):
        ingress_data = self._gen_basic_k8s_elem(namespace, name, 'Ingress', 'networking.k8s.io/v1')

        host = None
        path = "/"
        secure = False
        if dns.startswith("/"):  # It is only a path
            path = dns
        else:  # It is and endpoint
            # If not set, add the protocol to enable the parsing
            if dns.find("://") == -1:
                dns = "http://" + dns
            dns_url = urlparse(dns)
            if dns_url[0] == "https":
                secure = True
            if dns_url[1]:
                host = dns_url[1]
                if apps_dns and not host.endswith(apps_dns):
                    if host.endswith("."):
                        host = host[:-1]
                    host += "-" + self._random_string()
                    if apps_dns.startswith("."):
                        apps_dns = apps_dns[1:]
                    host += "." + apps_dns
            if dns_url[2]:
                path = dns_url[2]

            vm.info.systems[0].setValue('net_interface.0.dns_name', '%s://%s%s' % (dns_url[0], host, path))

        ingress_data["metadata"]["annotations"] = {
            "haproxy.router.openshift.io/ip_whitelist": "0.0.0.0/0",
        }
        # Add Let's Encrypt annotation asuming that the cluster has
        # cert-manager installed and the issuer is letsencrypt-prod
        if secure:
            ingress_data["metadata"]["annotations"]["cert-manager.io/cluster-issuer"] = "letsencrypt-prod"
            ingress_data["metadata"]["annotations"]["route.openshift.io/termination"] = "edge"
            ingress_data["metadata"]["annotations"]["haproxy.router.openshift.io/redirect-to-https"] = "True"

        ingress_data["spec"] = {
            "rules": [
                {
                    "http": {
                        "paths": [
                            {
                                "path": path,
                                "pathType": "Prefix",
                                "backend": {
                                    "service": {"name": name, "port": {"number": port}}
                                },
                            }
                        ]
                    },
                }
            ]
        }

        if host:
            ingress_data["spec"]["rules"][0]["host"] = host

        if secure and host and not apps_dns:
            ingress_data["spec"]["tls"] = [{"hosts": [host], "secretName": name + "-tls"}]

        return ingress_data

    @staticmethod
    def _gen_basic_k8s_elem(namespace, name, kind, version="v1"):
        k8s_elem = {'apiVersion': version, 'kind': kind}
        k8s_elem['metadata'] = {
            'name': name,
            'namespace': namespace,
            'labels': {'name': name}
        }
        return k8s_elem

    @staticmethod
    def _get_env_variables(radl_system):
        env_vars = []
        if radl_system.getValue('environment.variables'):
            # Parse the environment variables
            # The pattern is: key="value" or key=value
            # in case of value with commas it should be enclosed in double quotes
            pattern = r'([^,=]+)=(".*?(?<!\\)"|[^,]*)'
            keypairs = re.findall(pattern, radl_system.getValue('environment.variables'))
            for key, value in keypairs:
                env_vars.append({'name': key.strip(), 'value': value.strip(' "')})
        return env_vars

    def _generate_pod_data(self, namespace, name, outports, system, volumes, configmaps, tags):
        cpu = str(system.getValue('cpu.count'))
        gpu = system.getValue('gpu.count')
        memory = "%s" % system.getFeature('memory.size').getValue('B')
        image_url = urlparse(system.getValue("disk.0.image.url"))
        image_name = "".join(image_url[1:])

        ports = []
        if outports:
            for outport in outports:
                if outport.is_range():
                    self.log_warn("Port range not allowed in Kubernetes connector. Ignoring.")
                else:
                    ports.append({'containerPort': outport.get_local_port(),
                                  'protocol': outport.get_protocol().upper()})

        pod_data = self._gen_basic_k8s_elem(namespace, name, 'Pod')
        # Add instance tags
        if tags:
            for k, v in tags.items():
                # Remove special characters
                pod_data['metadata']['labels'][k] = re.sub('[!"#$%&\'()*+,/:;<=>?@[\\]^`{|}~ ]', '', v).lstrip("_-")

        containers = [{
            'name': name,
            'image': image_name,
            'imagePullPolicy': 'Always',
            'ports': ports,
            'resources': {'limits': {'cpu': cpu, 'memory': memory},
                          'requests': {'cpu': cpu, 'memory': memory}}
        }]

        if gpu:
            containers[0]['resources']['limits']['nvidia.com/gpu'] = str(gpu)
            containers[0]['resources']['requests']['nvidia.com/gpu'] = str(gpu)

        env_vars = self._get_env_variables(system)
        if env_vars:
            containers[0]["env"] = env_vars

        if system.getValue("docker.privileged") == 'yes':
            containers[0]['securityContext'] = {'privileged': True}

        if system.getValue('command'):
            command = system.getValue('command')
            if command and not isinstance(command, list):
                command = command.split()
            containers[0]["command"] = [command[0]]
            if len(command) > 1:
                containers[0]["args"] = command[1:]

        pod_data['spec'] = {'restartPolicy': 'OnFailure'}

        if volumes:
            containers[0]['volumeMounts'] = []
            pod_data['spec']['volumes'] = []

            for (v_name, _, v_mount_path) in volumes:
                containers[0]['volumeMounts'].append(
                    {'name': v_name, 'mountPath': v_mount_path})
                pod_data['spec']['volumes'].append(
                    {'name': v_name, 'persistentVolumeClaim': {'claimName': v_name}})

        if configmaps:
            containers[0]['volumeMounts'] = containers[0].get('volumeMounts', [])
            pod_data['spec']['volumes'] = pod_data['spec'].get('volumes', [])

            for (cm_name, cm_mount_path, secret) in configmaps:
                containers[0]['volumeMounts'].append(
                    {'name': cm_name, 'mountPath': cm_mount_path, "readOnly": True,
                     'subPath': os.path.basename(cm_mount_path)})
                if secret:
                    pod_data['spec']['volumes'].append(
                        {'name': cm_name,
                         'secret': {'secretName': cm_name}})
                else:
                    pod_data['spec']['volumes'].append(
                        {'name': cm_name,
                         'configMap': {'name': cm_name}})

        pod_data['spec']['containers'] = containers

        return pod_data

    def _get_namespace(self, inf, auth_data):
        _, namespace, _ = self.get_auth_header(auth_data)
        # If the namespace is set in the auth_data use it
        if not namespace:
            # If not by default use the Inf ID as namespace
            namespace = inf.id
            if inf.radl.description and inf.radl.description.getValue('namespace'):
                # finally if it is set in the RADL use it
                namespace = inf.radl.description.getValue('namespace')
        return namespace

    @staticmethod
    def _random_string(chars=4):
        return ''.join(choice(ascii_lowercase + digits) for _ in range(chars))

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        system = radl.systems[0]

        res = []
        namespace = self._get_namespace(inf, auth_data)

        # First create the namespace for the infrastructure
        headers = {'Content-Type': 'application/json'}
        uri = "/api/v1/namespaces/"
        with inf._lock:
            resp = self.create_request('GET', uri + namespace, auth_data, headers)
            if resp.status_code == 403:
                self.log_warn("No permissions to get Namespace: %s" % namespace)
            elif resp.status_code != 200:
                self.log_debug("Creating Namespace: %s" % namespace)
                namespace_data = {'apiVersion': 'v1', 'kind': 'Namespace',
                                  'metadata': {'name': namespace, 'labels': {'inf_id': inf.id}}}
                resp = self.create_request('POST', uri, auth_data, headers, namespace_data)

                if resp.status_code != 201:
                    for _ in range(num_vm):
                        res.append((False, "Error creating the Namespace: " + resp.text))
                        return res

                # we need to assure it has been created before creating other resources
                resp = self.create_request('GET', uri + namespace, auth_data, headers)
                if resp.status_code != 200:
                    for _ in range(num_vm):
                        res.append((False, "Error creating the Namespace"))
                        return res

        if num_vm != 1:
            self.log_warn("Num VM is not 1. Ignoring.")

        volumes = []
        configmaps = []
        try:
            vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl, self)
            vm.destroy = True
            inf.add_vm(vm)
            pod_name = re.sub('[!"#$%&\'()*+,/:;<=>?@[\\]^`{|}~_ ]', '-', system.name)
            pod_name += '-%s' % self._random_string()

            volumes = self._create_volumes(namespace, system, pod_name, auth_data)

            configmaps = self._create_config_maps(namespace, system, pod_name, auth_data)

            tags = self.get_instance_tags(system, auth_data, inf)

            outports = []
            pub_net = vm.getConnectedNet(public=True)
            priv_net = vm.getConnectedNet(public=False)
            if pub_net:
                outports = pub_net.getOutPorts()
            elif priv_net:
                outports = priv_net.getOutPorts()

            pod_data = self._generate_pod_data(namespace, pod_name, outports, system, volumes, configmaps, tags)

            self.log_debug("Creating POD: %s/%s" % (namespace, pod_name))
            uri = "/api/v1/namespaces/%s/%s" % (namespace, "pods")
            resp = self.create_request('POST', uri, auth_data, headers, pod_data)

            if resp.status_code != 201:
                self.log_error("Error creating the Container: " + resp.text)
                res.append((False, "Error creating the Container: " + resp.text))
                try:
                    self._delete_volume_claims(pod_data, auth_data)
                except Exception:
                    self.log_exception("Error deleting volumes.")
                try:
                    self._delete_config_maps(pod_data, auth_data)
                except Exception:
                    self.log_exception("Error deleting configmaps.")

            else:
                output = json.loads(resp.text)
                vm.id = namespace + "/" + output["metadata"]["name"]
                vm.info.systems[0].setValue('instance_id', str(vm.id))
                vm.info.systems[0].setValue('instance_name', str(vm.id))
                vm.destroy = False

                dns_name = system.getValue("net_interface.0.dns_name")
                self.create_service_data(namespace, pod_name, outports, pub_net, auth_data, vm)

                if dns_name and outports:
                    port = outports[0].get_local_port()
                    ingress_created = self.create_ingress(namespace, pod_name, dns_name, port, auth_data, vm)
                    if not ingress_created:
                        vm.info.systems[0].delValue("net_interface.0.dns_name")

                res.append((True, vm))

        except Exception as ex:
            self.log_exception("Error connecting with Kubernetes API server")
            # Delete the created resources
            try:
                for (vc_name, _, _) in volumes:
                    self._delete_volume_claim(namespace, vc_name, auth_data)
            except Exception:
                self.log_exception("Error deleting volumes.")
            try:
                for (cm_name, _, secret) in configmaps:
                    self._delete_config_map(namespace, cm_name, auth_data, secret)
            except Exception:
                self.log_exception("Error deleting configmaps.")
            res.append((False, "ERROR: " + str(ex)))

        return res

    def _get_pod(self, vm, auth_data):
        try:
            namespace = vm.id.split("/")[0]
            pod_name = vm.id.split("/")[1]
        except Exception as ex:
            self.log_exception("Error invalid VM id")
            return (False, None, "Error invalid VM id: " + str(ex))

        try:
            uri = "/api/v1/namespaces/%s/%s/%s" % (namespace, "pods", pod_name)
            resp = self.create_request('GET', uri, auth_data)

            if resp.status_code == 200:
                return (True, resp.status_code, resp.text)
            else:
                return (False, resp.status_code, resp.text)

        except Exception as ex:
            self.log_exception("Error connecting with Kubernetes API server")
            return (False, None, "Error connecting with Kubernetes API server: " + str(ex))

    def _get_float_cpu(self, cpu):
        if cpu.endswith("m"):
            return float(cpu[:-1]) / 1000
        else:
            return float(cpu)

    def updateVMInfo(self, vm, auth_data):
        success, status, output = self._get_pod(vm, auth_data)
        if success:
            output = json.loads(output)
            vm.state = self.VM_STATE_MAP.get(output["status"]["phase"], VirtualMachine.UNKNOWN)

            pod_limits = output['spec']['containers'][0].get('resources', {}).get('limits')
            if pod_limits:
                vm.info.systems[0].setValue('cpu.count', self._get_float_cpu(pod_limits['cpu']))
                memory = self.convert_memory_unit(pod_limits['memory'], "B")
                vm.info.systems[0].setValue('memory.size', memory)

            vm.info.systems[0].setValue('disk.0.image.url', output['spec']['containers'][0]['image'])

            # Update the network info
            self.setIPs(vm, output)
            return (True, vm)
        else:
            self.log_error("Error getting info about the POD: code: %s, msg: %s" % (status, output))
            return (False, "Error getting info about the POD: code: %s, msg: %s" % (status, output))

    def setIPs(self, vm, pod_info):
        """
        Adapt the RADL information of the VM to the real IPs assigned by the cloud provider

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - pod_info(dict): JSON information about the POD
        """
        public_ips = []
        private_ips = []
        if 'hostIP' in pod_info["status"]:
            host_ip = str(pod_info["status"]["hostIP"])
            is_private = any([IPAddress(host_ip) in IPNetwork(mask) for mask in Config.PRIVATE_NET_MASKS])
            if is_private:
                public_ips = [socket.gethostbyname(self.cloud.server)]
            else:
                public_ips = [host_ip]
        if 'podIP' in pod_info["status"]:
            private_ips = [str(pod_info["status"]["podIP"])]

        if not vm.getConnectedNet(public=True):
            public_ips = []
        if not vm.getConnectedNet(public=False):
            private_ips = []

        vm.setIps(public_ips, private_ips)

    def finalize(self, vm, last, auth_data):
        msg = ""
        if vm.id:
            success, status, output = self._get_pod(vm, auth_data)
            if success:
                if status == 404:
                    self.log_warn("Trying to remove a non existing POD id: %s" % vm.id)
                else:
                    pod_data = json.loads(output)
                    self._delete_volume_claims(pod_data, auth_data)
                    self._delete_config_maps(pod_data, auth_data)
                    success, msg = self._delete_pod(vm, auth_data)
                    if not success:
                        self.log_error("Error deleting Pod %s: %s" % (vm.id, msg))
                        return False, "Error deleting Pod %s: %s" % (vm.id, msg)

            del_svc_ok, svc_msg = self._delete_service(vm, auth_data)
            success = success and del_svc_ok
            msg += svc_msg

            del_ing_ok, ing_msg = self._delete_ingress(vm, auth_data)
            success = success and del_ing_ok
            msg += ing_msg
        else:
            self.log_warn("No VM ID. Ignoring")
            success = True

        if last:
            del_ns_ok, ns_msg = self._delete_namespace(vm, auth_data)
            success = success and del_ns_ok
            msg += ns_msg

        return success, msg

    def _delete_namespace(self, vm, auth_data):
        if vm.id:
            namespace = vm.id.split("/")[0]
        else:
            namespace = self._get_namespace(vm.inf, auth_data)
        self.log_debug("Deleting Namespace: %s" % namespace)
        uri = "/api/v1/namespaces/%s" % namespace

        resp = self.create_request('GET', uri, auth_data)
        if resp.status_code == 404:
            self.log_warn("Trying to remove a non existing Namespace: " + namespace)
        elif resp.status_code == 403:
            self.log_warn("Trying to remove a Namespace without permissions: " + namespace)
        elif resp.status_code == 200:
            output = resp.json()
            if output["metadata"].get("labels", {}).get("inf_id") == vm.inf.id:
                resp = self.create_request('DELETE', uri, auth_data)
                if resp.status_code != 200:
                    return (False, "Error deleting the Namespace: " + resp.text)
            else:
                self.log_info("Namespace %s was not created by the IM. Do not delete it." % namespace)
        else:
            return (False, "Error getting the Namespace: " + resp.text)

        return True, ""

    def _delete_service(self, vm, auth_data):
        try:
            namespace = vm.id.split("/")[0]
            service_name = vm.id.split("/")[1]

            self.log_debug("Deleting Service: %s/%s" % (namespace, service_name))
            uri = "/api/v1/namespaces/%s/%s/%s" % (namespace, "services", service_name)
            resp = self.create_request('DELETE', uri, auth_data)

            if resp.status_code == 404:
                self.log_warn("Trying to remove a non existing Service id: " + service_name)
                return (True, service_name)
            elif resp.status_code != 200:
                return (False, "Error deleting the Service: " + resp.text)
            else:
                return (True, service_name)
        except Exception:
            self.log_exception("Error connecting with Kubernetes API server")
            return (False, "Error connecting with Kubernetes API server")

    def _delete_ingress(self, vm, auth_data):
        try:
            namespace = vm.id.split("/")[0]
            ingress_name = vm.id.split("/")[1]

            self.log_debug("Deleting Ingress: %s/%s" % (namespace, ingress_name))
            uri = "/apis/networking.k8s.io/v1/namespaces/%s/ingresses/%s" % (namespace, ingress_name)
            resp = self.create_request('DELETE', uri, auth_data)

            if resp.status_code == 404:
                self.log_warn("Trying to remove a non existing Ingress id: " + ingress_name)
                return (True, ingress_name)
            elif resp.status_code != 200:
                return (False, "Error deleting the Ingress: " + resp.text)
            else:
                return (True, ingress_name)
        except Exception:
            self.log_exception("Error connecting with Kubernetes API server")
            return (False, "Error connecting with Kubernetes API server")

    def _delete_pod(self, vm, auth_data):
        try:
            namespace = vm.id.split("/")[0]
            pod_name = vm.id.split("/")[1]

            self.log_debug("Deleting POD: %s/%s" % (namespace, pod_name))
            uri = "/api/v1/namespaces/%s/%s/%s" % (namespace, "pods", pod_name)
            resp = self.create_request('DELETE', uri, auth_data)

            if resp.status_code == 404:
                self.log_warn("Trying to remove a non existing POD id: " + pod_name)
                return (True, pod_name)
            elif resp.status_code != 200:
                return (False, "Error deleting the POD: " + resp.text)
            else:
                return (True, pod_name)
        except Exception:
            self.log_exception("Error connecting with Kubernetes API server")
            return (False, "Error connecting with Kubernetes API server")

    def stop(self, vm, auth_data):
        return (False, "Not supported")

    def start(self, vm, auth_data):
        return (False, "Not supported")

    def reboot(self, vm, auth_data):
        return (False, "Not supported")

    def alterVM(self, vm, radl, auth_data):
        # This function is correctly implemented
        # But kubernetes only enable to change the image of the container
        system = radl.systems[0]

        try:
            pod_data = []

            image_url = urlparse(vm.info.systems[0].getValue('disk.0.image.url'))
            image = "".join(image_url[1:])
            new_image = system.getValue('disk.0.image.url')
            if system.getValue("disk.0.image.url"):
                new_image_url = urlparse(system.getValue("disk.0.image.url"))
                new_image = "".join(new_image_url[1:])

            changed = False
            if new_image and new_image != image:
                pod_data.append(
                    {"op": "replace", "path": "/spec/containers/0/image", "value": new_image})
                changed = True

            if not changed:
                self.log_info("Nothing changes in the kubernetes pod: " + str(vm.id))
                return (True, vm)

            # Create the container
            namespace = vm.id.split("/")[0]
            pod_name = vm.id.split("/")[1]

            headers = {'Content-Type': 'application/json-patch+json'}
            uri = "/api/v1/namespaces/%s/%s/%s" % (namespace, "pods", pod_name)
            resp = self.create_request('PATCH', uri, auth_data, headers, pod_data)

            if resp.status_code != 200:
                return (False, "Error updating the Pod: " + resp.text)
            else:
                if new_image:
                    vm.info.systems[0].setValue('disk.0.image.url', new_image)
                return (True, vm)

        except Exception as ex:
            self.log_exception(
                "Error connecting with Kubernetes API server")
            return (False, "ERROR: " + str(ex))
