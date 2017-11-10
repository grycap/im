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
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from .CloudConnector import CloudConnector
from radl.radl import Feature
from IM.config import Config


class KubernetesCloudConnector(CloudConnector):
    """
    Cloud Launcher to Kubernetes platform
    """

    type = "Kubernetes"

    _port_base_num = 35000
    """ Base number to assign SSH port on Kubernetes node."""
    _port_counter = 0
    """ Counter to assign SSH port on Kubernetes node."""
    _root_password = "Aspecial+0ne"
    """ Default password to set to the root in the container"""
    _apiVersions = ["v1", "v1beta3"]
    """ Supported API versions"""

    VM_STATE_MAP = {
        'Pending': VirtualMachine.PENDING,
        'Running': VirtualMachine.RUNNING,
        'Succeeded': VirtualMachine.OFF,
        'Failed': VirtualMachine.FAILED
    }
    """Dictionary with a map with the Kubernetes POD states to the IM states."""

    def create_request(self, method, url, auth_data, headers=None, body=None):
        auth_header = self.get_auth_header(auth_data)
        if auth_header:
            if headers is None:
                headers = {}
            headers.update(auth_header)

        url = "%s://%s:%d%s%s" % (self.cloud.protocol, self.cloud.server, self.cloud.port, self.cloud.path, url)
        resp = requests.request(method, url, verify=False, headers=headers, data=body)

        return resp

    def get_auth_header(self, auth_data):
        """
        Generate the auth header needed to contact with the Kubernetes API server.
        """
        url = uriparse(self.cloud.server)
        auths = auth_data.getAuthInfo(self.type, url[1])
        if not auths:
            self.log_error(
                "No correct auth data has been specified to Kubernetes.")
            return None
        else:
            auth = auths[0]

        auth_header = None

        if 'username' in auth and 'password' in auth:
            passwd = auth['password']
            user = auth['username']
            auth_header = {'Authorization': 'Basic ' +
                           (base64.encodestring((user + ':' + passwd).encode('utf-8'))).strip().decode('utf-8')}
        elif 'token' in auth:
            token = auth['token']
            auth_header = {'Authorization': 'Bearer ' + token}

        return auth_header

    def get_api_version(self, auth_data):
        """
        Return the API version to use to connect with kubernetes API server
        """
        version = self._apiVersions[0]

        try:
            resp = self.create_request('GET', "/api/", auth_data)

            if resp.status_code == 200:
                output = json.loads(resp.text)
                for v in self._apiVersions:
                    if v in output["versions"]:
                        return v

        except Exception:
            self.log_exception(
                "Error connecting with Kubernetes API server")

        self.log_warn("Error getting a compatible API version. Setting the default one.")
        self.log_debug("Using %s API version." % version)
        return version

    def concreteSystem(self, radl_system, auth_data):
        image_urls = radl_system.getValue("disk.0.image.url")
        if not image_urls:
            return [radl_system.clone()]
        else:
            if not isinstance(image_urls, list):
                image_urls = [image_urls]

            res = []
            for str_url in image_urls:
                url = uriparse(str_url)
                protocol = url[0]
                if protocol == 'docker' and url[1]:
                    res_system = radl_system.clone()

                    res_system.addFeature(Feature(
                        "virtual_system_type", "=", "docker"), conflict="other", missing="other")

                    res_system.getFeature("cpu.count").operator = "="
                    res_system.getFeature("memory.size").operator = "="

                    res_system.setValue(
                        'disk.0.os.credentials.username', 'root')
                    res_system.setValue(
                        'disk.0.os.credentials.password', self._root_password)

                    res_system.addFeature(
                        Feature("disk.0.image.url", "=", str_url), conflict="other", missing="other")

                    res_system.addFeature(
                        Feature("provider.type", "=", self.type), conflict="other", missing="other")
                    res_system.addFeature(Feature(
                        "provider.host", "=", self.cloud.server), conflict="other", missing="other")
                    res_system.addFeature(Feature(
                        "provider.port", "=", self.cloud.port), conflict="other", missing="other")

                    res.append(res_system)

            return res

    def _delete_volume_claim(self, namespace, vc_name, auth_data):
        try:
            apiVersion = self.get_api_version(auth_data)

            uri = "/api/" + apiVersion + "/namespaces/" + namespace + "/persistentvolumeclaims/" + vc_name
            resp = self.create_request('DELETE', uri, auth_data)

            if resp.status_code == 404:
                self.log_warn(
                    "Trying to remove a non existing PersistentVolumeClaim: " + vc_name)
                return True
            elif resp.status_code != 200:
                self.log_error(
                    "Error deleting the PersistentVolumeClaim: " + resp.txt)
                return False
            else:
                return True
        except Exception:
            self.log_exception(
                "Error connecting with Kubernetes API server")
            return False

    def _delete_volume_claims(self, pod_data, auth_data):
        if 'volumes' in pod_data['spec']:
            for volume in pod_data['spec']['volumes']:
                if 'persistentVolumeClaim' in volume and 'claimName' in volume['persistentVolumeClaim']:
                    vc_name = volume['persistentVolumeClaim']['claimName']
                    success = self._delete_volume_claim(
                        pod_data["metadata"]["namespace"], vc_name, auth_data)
                    if not success:
                        self.log_error(
                            "Error deleting PersistentVolumeClaim:" + vc_name)

    def _create_volume_claim(self, claim_data, auth_data):
        try:
            apiVersion = self.get_api_version(auth_data)

            headers = {'Content-Type': 'application/json'}
            uri = ("/api/" + apiVersion + "/namespaces/" +
                   claim_data['metadata']['namespace'] +
                   "/persistentvolumeclaims")
            body = json.dumps(claim_data)
            resp = self.create_request('POST', uri, auth_data, headers, body)

            output = str(resp.text)
            if resp.status_code != 201:
                self.log_error("Error deleting the POD: " + output)
                return False
            else:
                return True
        except Exception:
            self.log_exception(
                "Error connecting with Kubernetes API server")
            return False

    def _create_volumes(self, apiVersion, namespace, system, pod_name, auth_data, persistent=False):
        res = []
        cont = 1
        while (system.getValue("disk." + str(cont) + ".size") and
                system.getValue("disk." + str(cont) + ".mount_path") and
                system.getValue("disk." + str(cont) + ".device")):
            disk_mount_path = system.getValue(
                "disk." + str(cont) + ".mount_path")
            # Use the device as volume host path to bind
            disk_device = system.getValue("disk." + str(cont) + ".device")
            disk_size = system.getFeature(
                "disk." + str(cont) + ".size").getValue('B')
            if not disk_mount_path.startswith('/'):
                disk_mount_path = '/' + disk_mount_path
            if not disk_device.startswith('/'):
                disk_device = '/' + disk_device
            self.log_info("Binding a volume in %s to %s" % (disk_device, disk_mount_path))
            name = "%s-%d" % (pod_name, cont)

            if persistent:
                claim_data = {'apiVersion': apiVersion,
                              'kind': 'PersistentVolumeClaim'}
                claim_data['metadata'] = {'name': name, 'namespace': namespace}
                claim_data['spec'] = {'accessModes': ['ReadWriteOnce'], 'resources': {
                    'requests': {'storage': disk_size}}}

                success = self._create_volume_claim(claim_data, auth_data)
                if success:
                    res.append((name, disk_device, disk_size,
                                disk_mount_path, persistent))
                else:
                    self.log_error(
                        "Error creating PersistentVolumeClaim:" + name)
            else:
                res.append((name, disk_device, disk_size,
                            disk_mount_path, persistent))

            cont += 1

        return res

    def _generate_pod_data(self, apiVersion, namespace, name, outports, system, ssh_port, volumes):
        cpu = str(system.getValue('cpu.count'))
        memory = "%s" % system.getFeature('memory.size').getValue('B')
        # The URI has this format: docker://image_name
        image_name = system.getValue("disk.0.image.url")[9:]

        ports = [{'containerPort': 22, 'protocol': 'TCP', 'hostPort': ssh_port}]
        if outports:
            for outport in outports:
                if outport.is_range():
                    self.log_warn("Port range not allowed in Kubernetes connector. Ignoring.")
                elif outport.get_local_port() != 22:
                    ports.append({'containerPort': outport.get_local_port(), 'protocol': outport.get_protocol().upper(
                    ), 'hostPort': outport.get_remote_port()})

        pod_data = {'apiVersion': apiVersion, 'kind': 'Pod'}
        pod_data['metadata'] = {
            'name': name,
            'namespace': namespace,
            'labels': {'name': name}
        }
        command = "yum install -y openssh-server python"
        command += " ; "
        command += "apt-get update && apt-get install -y openssh-server python"
        command += " ; "
        command += "mkdir /var/run/sshd"
        command += " ; "
        command += "sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/g' /etc/ssh/sshd_config"
        command += " ; "
        command += "sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config"
        command += " ; "
        command += "ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''"
        command += " ; "
        command += "echo 'root:" + self._root_password + "' | chpasswd"
        command += " ; "
        command += "sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd"
        command += " ; "
        command += " /usr/sbin/sshd -D"
        containers = [{
            'name': name,
            'image': image_name,
            'command': ["/bin/bash", "-c", command],
            'imagePullPolicy': 'IfNotPresent',
            'ports': ports,
            'resources': {'limits': {'cpu': cpu, 'memory': memory}}
        }]

        if system.getValue("docker.privileged") == 'yes':
            containers[0]['securityContext'] = {'privileged': True}

        if volumes:
            containers[0]['volumeMounts'] = []
            for (v_name, _, _, v_mount_path, _) in volumes:
                containers[0]['volumeMounts'].append(
                    {'name': v_name, 'mountPath': v_mount_path})

        pod_data['spec'] = {'containers': containers, 'restartPolicy': 'Never'}

        if volumes:
            pod_data['spec']['volumes'] = []
            for (v_name, v_device, _, _, persistent) in volumes:
                if persistent:
                    pod_data['spec']['volumes'].append(
                        {'name': v_name, 'persistentVolumeClaim': {'claimName': v_name}})
                else:
                    if v_device:
                        # Use the device as volume host path to bind
                        pod_data['spec']['volumes'].append(
                            {'name': v_name, 'hostPath:': {'path': v_device}})
                    else:
                        pod_data['spec']['volumes'].append(
                            {'name': v_name, 'emptyDir:': {}})

        return pod_data

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        system = radl.systems[0]

        public_net = None
        for net in radl.networks:
            if net.isPublic():
                public_net = net

        outports = None
        if public_net:
            outports = public_net.getOutPorts()

        apiVersion = self.get_api_version(auth_data)

        res = []
        namespace = inf.id
        headers = {'Content-Type': 'application/json'}
        uri = "/api/" + apiVersion + "/namespaces"
        with inf._lock:
            resp = self.create_request('GET', uri + "/" + namespace, auth_data, headers)
            if resp.status_code != 200:
                namespace_data = {'apiVersion': apiVersion, 'kind': 'Namespace',
                                  'metadata': {'name': namespace}}
                body = json.dumps(namespace_data)
                resp = self.create_request('POST', uri, auth_data, headers, body)

                if resp.status_code != 201:
                    for _ in range(num_vm):
                        res.append((False, "Error creating the Namespace: " + resp.text))
                        return res

        i = 0
        while i < num_vm:
            try:
                i += 1

                vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl, self)
                vm.destroy = True
                inf.add_vm(vm)
                (nodename, _) = vm.getRequestedName(default_hostname=Config.DEFAULT_VM_NAME,
                                                    default_domain=Config.DEFAULT_DOMAIN)
                pod_name = nodename

                # Do not use the Persistent volumes yet
                volumes = self._create_volumes(apiVersion, namespace, system, pod_name, auth_data)

                ssh_port = (KubernetesCloudConnector._port_base_num +
                            KubernetesCloudConnector._port_counter) % 65535
                KubernetesCloudConnector._port_counter += 1
                pod_data = self._generate_pod_data(
                    apiVersion, namespace, pod_name, outports, system, ssh_port, volumes)
                body = json.dumps(pod_data)

                uri = "/api/" + apiVersion + "/namespaces/" + namespace + "/pods"
                resp = self.create_request('POST', uri, auth_data, headers, body)

                if resp.status_code != 201:
                    res.append((False, "Error creating the Container: " + resp.text))
                else:
                    output = json.loads(resp.text)
                    vm.id = output["metadata"]["name"]
                    # Set SSH port in the RADL info of the VM
                    vm.setSSHPort(ssh_port)
                    # Set the default user and password to access the container
                    vm.info.systems[0].setValue(
                        'disk.0.os.credentials.username', 'root')
                    vm.info.systems[0].setValue(
                        'disk.0.os.credentials.password', self._root_password)
                    vm.info.systems[0].setValue('instance_id', str(vm.id))
                    vm.info.systems[0].setValue('instance_name', str(vm.id))

                    vm.destroy = False
                    res.append((True, vm))

            except Exception as ex:
                self.log_exception("Error connecting with Kubernetes API server")
                res.append((False, "ERROR: " + str(ex)))

        return res

    def _get_pod(self, vm, auth_data):
        try:
            namespace = vm.inf.id
            pod_name = vm.id

            apiVersion = self.get_api_version(auth_data)

            uri = "/api/" + apiVersion + "/namespaces/" + namespace + "/pods/" + pod_name
            resp = self.create_request('GET', uri, auth_data)

            if resp.status_code == 200:
                return (True, resp.status_code, resp.text)
            else:
                return (False, resp.status_code, resp.text)

        except Exception as ex:
            self.log_exception(
                "Error connecting with Kubernetes API server")
            return (False, None, "Error connecting with Kubernetes API server: " + str(ex))

    def updateVMInfo(self, vm, auth_data):
        success, status, output = self._get_pod(vm, auth_data)
        if success:
            output = json.loads(output)
            vm.state = self.VM_STATE_MAP.get(
                output["status"]["phase"], VirtualMachine.UNKNOWN)

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
            public_ips = [str(pod_info["status"]["hostIP"])]
        if 'podIP' in pod_info["status"]:
            private_ips = [str(pod_info["status"]["podIP"])]

        vm.setIps(public_ips, private_ips)

    def finalize(self, vm, last, auth_data):
        success, status, output = self._get_pod(vm, auth_data)
        if success:
            if status == 404:
                self.log_warn(
                    "Trying to remove a non existing POD id: " + vm.id)
                return (True, vm.id)
            else:
                pod_data = json.loads(output)
                self._delete_volume_claims(pod_data, auth_data)

        success = self._delete_pod(vm, auth_data)

        if last:
            self._delete_namespace(vm, auth_data)

        return success

    def _delete_namespace(self, vm, auth_data):
        apiVersion = self.get_api_version(auth_data)
        headers = {'Content-Type': 'application/json'}
        uri = "/api/" + apiVersion + "/namespaces/" + vm.inf.id
        resp = self.create_request('DELETE', uri, auth_data, headers)
        if resp.status_code != 200:
            self.log_error("Error deleting Namespace")
            return False
        return True

    def _delete_pod(self, vm, auth_data):
        try:
            namespace = vm.inf.id
            pod_name = vm.id

            apiVersion = self.get_api_version(auth_data)
            uri = "/api/" + apiVersion + "/namespaces/" + namespace + "/pods/" + pod_name
            resp = self.create_request('DELETE', uri, auth_data)

            if resp.status_code == 404:
                self.log_warn(
                    "Trying to remove a non existing POD id: " + pod_name)
                return (True, pod_name)
            elif resp.status_code != 200:
                return (False, "Error deleting the POD: " + resp.text)
            else:
                return (True, pod_name)
        except Exception:
            self.log_exception(
                "Error connecting with Kubernetes API server")
            return (False, "Error connecting with Kubernetes API server")

    def stop(self, vm, auth_data):
        return (False, "Not supported")

    def start(self, vm, auth_data):
        return (False, "Not supported")

    def alterVM(self, vm, radl, auth_data):
        # This function is correctly implemented
        # But kubernetes does not permit cpu to be updated yet
        system = radl.systems[0]

        apiVersion = self.get_api_version(auth_data)

        try:
            pod_data = []

            cpu = vm.info.systems[0].getValue('cpu.count')
            memory = vm.info.systems[0].getFeature('memory.size').getValue('B')

            new_cpu = system.getValue('cpu.count')
            new_memory = system.getFeature('memory.size').getValue('B')

            changed = False
            if new_cpu and new_cpu != cpu:
                pod_data.append(
                    {"op": "replace", "path": "/spec/containers/0/resources/limits/cpu", "value": new_cpu})
                changed = True
            if new_memory and new_memory != memory:
                pod_data.append(
                    {"op": "replace", "path": "/spec/containers/0/resources/limits/memory", "value": new_memory})
                changed = True

            if not changed:
                self.log_info("Nothing changes in the kubernetes pod: " + str(vm.id))
                return (True, vm)

            # Create the container
            namespace = vm.inf.id
            pod_name = vm.id

            headers = {'Content-Type': 'application/json-patch+json'}
            uri = "/api/" + apiVersion + "/namespaces/" + namespace + "/pods/" + pod_name
            body = json.dumps(pod_data)
            resp = self.create_request('PATCH', uri, auth_data, headers, body)

            if resp.status_code != 201:
                return (False, "Error updating the Pod: " + resp.text)
            else:
                if new_cpu:
                    vm.info.systems[0].setValue('cpu.count', new_cpu)
                if new_memory:
                    vm.info.systems[0].addFeature(
                        Feature("memory.size", "=", new_memory, 'B'), conflict="other", missing="other")
                return (True, self.updateVMInfo(vm, auth_data))

        except Exception as ex:
            self.log_exception(
                "Error connecting with Kubernetes API server")
            return (False, "ERROR: " + str(ex))

        return (False, "Not supported")
