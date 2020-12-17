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
from netaddr import IPNetwork, IPAddress
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from .CloudConnector import CloudConnector
from radl.radl import Feature
from IM.config import Config


class KubernetesCloudConnector(CloudConnector):
    """
    Cloud Launcher to Kubernetes platform
    """

    type = "Kubernetes"

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

    def __init__(self, cloud_info, inf):
        self.apiVersion = None
        CloudConnector.__init__(self, cloud_info, inf)

    def _get_api_url(self, auth_data, namespace, path):
        apiVersion = self.get_api_version(auth_data)
        return "/api/" + apiVersion + "/namespaces/" + namespace + path

    def create_request(self, method, url, auth_data, headers=None, body=None):
        auth_header = self.get_auth_header(auth_data)
        if auth_header:
            if headers is None:
                headers = {}
            headers.update(auth_header)

        if body and isinstance(body, dict):
            data = json.dumps(body)
        else:
            data = body
        url = "%s://%s:%d%s%s" % (self.cloud.protocol, self.cloud.server, self.cloud.port, self.cloud.path, url)
        resp = requests.request(method, url, verify=self.verify_ssl, headers=headers, data=data)

        return resp

    def get_auth_header(self, auth_data):
        """
        Generate the auth header needed to contact with the Kubernetes API server.
        """
        url = urlparse(self.cloud.server)
        auths = auth_data.getAuthInfo(self.type, url[1])
        if not auths:
            raise Exception("No correct auth data has been specified to Kubernetes.")
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
        else:
            raise Exception("No correct auth data has been specified to Kubernetes: username and password or token.")

        return auth_header

    def get_api_version(self, auth_data):
        """
        Return the API version to use to connect with kubernetes API server
        """
        if self.apiVersion:
            return self.apiVersion

        version = self._apiVersions[0]

        try:
            resp = self.create_request('GET', "/api/", auth_data)

            if resp.status_code == 200:
                output = json.loads(resp.text)
                for v in self._apiVersions:
                    if v in output["versions"]:
                        self.apiVersion = v
                        return v

        except Exception:
            self.log_exception("Error connecting with Kubernetes API server")

        self.log_warn("Error getting a compatible API version. Setting the default one.")
        self.log_debug("Using %s API version." % version)
        return version

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]
        if protocol == 'docker' and url[1]:
            res_system = radl_system.clone()

            res_system.addFeature(Feature("virtual_system_type", "=", "docker"), conflict="other", missing="other")
            res_system.getFeature("cpu.count").operator = "="
            res_system.getFeature("memory.size").operator = "="

            res_system.setValue('disk.0.os.credentials.username', 'root')
            res_system.setValue('disk.0.os.credentials.password', self._root_password)

            return res_system
        else:
            return None

    def _delete_volume_claim(self, namespace, vc_name, auth_data):
        try:
            self.log_debug("Deleting PVC: %s/%s" % (namespace, vc_name))
            uri = self._get_api_url(auth_data, namespace, "/persistentvolumeclaims/" + vc_name)
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
            uri = self._get_api_url(auth_data, claim_data['metadata']['namespace'], "/persistentvolumeclaims")
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

    def _create_volumes(self, namespace, system, pod_name, auth_data, persistent=False):
        res = []
        cont = 1
        while (system.getValue("disk." + str(cont) + ".size") and
                system.getValue("disk." + str(cont) + ".mount_path") and
                system.getValue("disk." + str(cont) + ".device")):
            disk_mount_path = system.getValue("disk." + str(cont) + ".mount_path")
            # Use the device as volume host path to bind
            disk_device = system.getValue("disk." + str(cont) + ".device")
            disk_size = system.getFeature("disk." + str(cont) + ".size").getValue('B')
            if not disk_mount_path.startswith('/'):
                disk_mount_path = '/' + disk_mount_path
            if not disk_device.startswith('/'):
                disk_device = '/' + disk_device
            self.log_info("Binding a volume in %s to %s" % (disk_device, disk_mount_path))
            name = "%s-%d" % (pod_name, cont)

            if persistent:
                claim_data = {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim'}
                claim_data['metadata'] = {'name': name, 'namespace': namespace}
                claim_data['spec'] = {'accessModes': ['ReadWriteOnce'], 'resources': {
                    'requests': {'storage': disk_size}}}

                self.log_debug("Creating PVC: %s/%s" % (namespace, name))
                success = self._create_volume_claim(claim_data, auth_data)
                if success:
                    res.append((name, disk_device, disk_size, disk_mount_path, persistent))
                else:
                    self.log_error("Error creating PersistentVolumeClaim:" + name)
            else:
                res.append((name, disk_device, disk_size, disk_mount_path, persistent))

            cont += 1

        return res

    def create_service_data(self, namespace, name, outports, auth_data, vm):
        try:
            service_data = self._generate_service_data(namespace, name, outports)
            self.log_debug("Creating Service: %s/%s" % (namespace, name))
            headers = {'Content-Type': 'application/json'}
            uri = self._get_api_url(auth_data, namespace, '/services')
            svc_resp = self.create_request('POST', uri, auth_data, headers, service_data)
            if svc_resp.status_code != 201:
                self.error_messages += "Error creating service for pod %s: %s" % (name, svc_resp.text)
                self.log_warn("Error creating service: %s" % svc_resp.text)
            else:
                # Wait a bit to assure the service has been created
                time.sleep(0.5)
                # Get Service data to get assigned nodePort
                uri = self._get_api_url(auth_data, namespace, '/services/%s' % name)
                svc_resp = self.create_request('GET', uri, auth_data)
                if svc_resp.status_code == 200:
                    for port in svc_resp.json()['spec']['ports']:
                        # Set Out port in the RADL info of the VM
                        vm.setOutPort(int(port['port']), int(port['nodePort']))

        except Exception:
            self.error_messages += "Error creating service to access pod %s" % name
            self.log_exception("Error creating service.")

    def _generate_service_data(self, namespace, name, outports):
        service_data = {'apiVersion': 'v1', 'kind': 'Service'}
        service_data['metadata'] = {
            'name': name,
            'namespace': namespace,
            'labels': {'name': name}
        }

        ports = [{'port': 22, 'targetPort': 22, 'protocol': 'TCP', 'name': 'ssh'}]
        if outports:
            for outport in outports:
                if outport.is_range():
                    self.log_warn("Port range not allowed in Kubernetes connector. Ignoring.")
                elif outport.get_local_port() != 22:
                    ports.append({'port': outport.get_local_port(), 'protocol': outport.get_protocol().upper(),
                                  'targetPort': outport.get_local_port(), 'name': 'port%s' % outport.get_local_port()})

        service_data['spec'] = {
            'type': 'NodePort',
            'ports': ports,
            'selector': {'name': name}
        }

        return service_data

    def _generate_pod_data(self, namespace, name, outports, system, volumes):
        cpu = str(system.getValue('cpu.count'))
        memory = "%s" % system.getFeature('memory.size').getValue('B')
        # The URI has this format: docker://image_name
        image_name = system.getValue("disk.0.image.url")[9:]

        ports = [{'containerPort': 22, 'protocol': 'TCP'}]
        if outports:
            for outport in outports:
                if outport.is_range():
                    self.log_warn("Port range not allowed in Kubernetes connector. Ignoring.")
                elif outport.get_local_port() != 22:
                    ports.append({'containerPort': outport.get_local_port(),
                                  'protocol': outport.get_protocol().upper()})

        pod_data = {'apiVersion': 'v1', 'kind': 'Pod'}
        pod_data['metadata'] = {
            'name': name,
            'namespace': namespace,
            'labels': {'name': name}
        }
        command = "yum install -y openssh-server python sudo"
        command += " ; "
        command += "apt-get update && apt-get install -y openssh-server python sudo"
        command += " ; "
        command += "apk add --no-cache openssh-server python2 sudo"
        command += " ; "
        command += "mkdir /var/run/sshd"
        command += " ; "
        command += "sed -i '/PermitRootLogin/c\\PermitRootLogin yes' /etc/ssh/sshd_config"
        command += " ; "
        command += "ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''"
        command += " ; "
        command += "echo 'root:" + self._root_password + "' | chpasswd"
        command += " ; "
        command += ("sed 's@session\\s*required\\s*pam_loginuid.so@session"
                    " optional pam_loginuid.so@g' -i /etc/pam.d/sshd")
        command += " ; "
        command += " /usr/sbin/sshd -D"
        containers = [{
            'name': name,
            'image': image_name,
            'command': ["/bin/sh", "-c", command],
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

        res = []
        # First create the namespace for the infrastructure
        namespace = inf.id
        headers = {'Content-Type': 'application/json'}
        uri = self._get_api_url(auth_data, "", "")
        with inf._lock:
            resp = self.create_request('GET', uri + namespace, auth_data, headers)
            if resp.status_code != 200:
                self.log_debug("Creating Namespace: %s" % namespace)
                namespace_data = {'apiVersion': 'v1', 'kind': 'Namespace',
                                  'metadata': {'name': namespace}}
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
                volumes = self._create_volumes(namespace, system, pod_name, auth_data)

                pod_data = self._generate_pod_data(namespace, pod_name, outports, system, volumes)

                self.log_debug("Creating POD: %s/%s" % (namespace, pod_name))
                uri = self._get_api_url(auth_data, namespace, '/pods')
                resp = self.create_request('POST', uri, auth_data, headers, pod_data)

                if resp.status_code != 201:
                    self.log_error("Error creating the Container: " + resp.text)
                    res.append((False, "Error creating the Container: " + resp.text))
                    try:
                        self._delete_volume_claims(pod_data, auth_data)
                    except Exception:
                        self.log_exception("Error deleting volumes.")
                else:
                    self.create_service_data(namespace, pod_name, outports, auth_data, vm)

                    output = json.loads(resp.text)
                    vm.id = output["metadata"]["name"]
                    # Set the default user and password to access the container
                    vm.info.systems[0].setValue('disk.0.os.credentials.username', 'root')
                    vm.info.systems[0].setValue('disk.0.os.credentials.password', self._root_password)
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

            uri = self._get_api_url(auth_data, namespace, "/pods/" + pod_name)
            resp = self.create_request('GET', uri, auth_data)

            if resp.status_code == 200:
                return (True, resp.status_code, resp.text)
            else:
                return (False, resp.status_code, resp.text)

        except Exception as ex:
            self.log_exception("Error connecting with Kubernetes API server")
            return (False, None, "Error connecting with Kubernetes API server: " + str(ex))

    def updateVMInfo(self, vm, auth_data):
        success, status, output = self._get_pod(vm, auth_data)
        if success:
            output = json.loads(output)
            vm.state = self.VM_STATE_MAP.get(output["status"]["phase"], VirtualMachine.UNKNOWN)

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
                public_ips = [self.cloud.server]
            else:
                public_ips = [host_ip]
        if 'podIP' in pod_info["status"]:
            private_ips = [str(pod_info["status"]["podIP"])]

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
                    success, msg = self._delete_pod(vm, auth_data)
                    if not success:
                        self.log_error("Error deleting Pod %s: %s" % (vm.id, msg))
                        return False, "Error deleting Pod %s: %s" % (vm.id, msg)

            success, msg = self._delete_service(vm, auth_data)
        else:
            self.log_warn("No VM ID. Ignoring")
            success = True

        if last:
            self._delete_namespace(vm, auth_data)

        return success, msg

    def _delete_namespace(self, vm, auth_data):
        self.log_debug("Deleting Namespace: %s" % vm.inf.id)
        uri = self._get_api_url(auth_data, vm.inf.id, '')
        resp = self.create_request('DELETE', uri, auth_data)
        if resp.status_code == 404:
            self.log_warn("Trying to remove a non existing Namespace id: " + vm.inf.id)
        elif resp.status_code != 200:
            self.log_error("Error deleting Namespace")
            return False
        return True

    def _delete_service(self, vm, auth_data):
        try:
            namespace = vm.inf.id
            service_name = vm.id

            self.log_debug("Deleting Service: %s/%s" % (namespace, service_name))
            uri = self._get_api_url(auth_data, namespace, "/services/" + service_name)
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

    def _delete_pod(self, vm, auth_data):
        try:
            namespace = vm.inf.id
            pod_name = vm.id

            self.log_debug("Deleting POD: %s/%s" % (namespace, pod_name))
            uri = self._get_api_url(auth_data, namespace, "/pods/" + pod_name)
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
        # But kubernetes does not permit cpu to be updated yet
        system = radl.systems[0]

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
            uri = self._get_api_url(auth_data, namespace, "/pods/" + pod_name)
            resp = self.create_request('PATCH', uri, auth_data, headers, pod_data)

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
