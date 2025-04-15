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
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from .CloudConnector import CloudConnector
from radl.radl import Feature
from IM.SSH import SSH
from IM.config import Config


class KubeVirtCloudConnector(CloudConnector):
    """
    Cloud Launcher to Kubernetes platform
    """

    type = "KubeVirt"
    DEFAULT_USER = 'cloudadm'
    """ default user to SSH access the VM """
    API_VERSION = 'v1'
    """ Default API version to use in the Kubernetes API """

    VM_STATE_MAP = {
        'Starting': VirtualMachine.PENDING,
        'Provisioning': VirtualMachine.PENDING,
        'WaitingForVolumeBinding': VirtualMachine.PENDING,
        'Running': VirtualMachine.RUNNING,
        'Stopped': VirtualMachine.STOPPED,
        'Stopping': VirtualMachine.STOPPED,
        'Terminating': VirtualMachine.DELETING,
        'Paused': VirtualMachine.STOPPED,
        'CrashLoopBackOff': VirtualMachine.FAILED,
        'ImagePullBackOff': VirtualMachine.FAILED,
        'Error': VirtualMachine.FAILED
    }
    """Dictionary with a map with the KubeVirt VM states to the IM states."""

    def __init__(self, cloud_info, inf):
        self.apiVersion = None
        CloudConnector.__init__(self, cloud_info, inf)

    def _get_namespace(self, inf, auth_data):
        _, namespace = self.get_auth_header(auth_data)
        # If the namespace is set in the auth_data use it
        if not namespace:
            # If not by default use the Inf ID as namespace
            namespace = inf.id
            if inf.radl.description and inf.radl.description.getValue('namespace'):
                # finally if it is set in the RADL use it
                namespace = inf.radl.description.getValue('namespace')
        return namespace

    def _get_api_url(self, namespace, path, apiVersion=None):
        if apiVersion is None:
            apiVersion = f"/api/{self.API_VERSION}"
        else:
            apiVersion = f"/apis/{apiVersion}"
        return f"{apiVersion}/namespaces/{namespace}{path}"

    def create_request(self, method, url, auth_data, headers=None, body=None):
        auth_header, _ = self.get_auth_header(auth_data)
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

        namespace = None
        if 'namespace' in auth:
            namespace = auth['namespace']

        return auth_header, namespace

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]
        src_host = url[1].split(':')[0]

        if protocol == "kvr" and self.cloud.server == src_host:
            res_system = radl_system.clone()

            res_system.getFeature("cpu.count").operator = "="
            res_system.getFeature("memory.size").operator = "="

            username = res_system.getValue('disk.0.os.credentials.username')
            if not username:
                res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)

            return res_system
        else:
            return None

    def _delete_volume_claim(self, namespace, vc_name, auth_data):
        try:
            self.log_debug("Deleting PVC: %s/%s" % (namespace, vc_name))
            uri = self._get_api_url(namespace, "/persistentvolumeclaims/" + vc_name)
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

    def _delete_volume_claims(self, vm_data, auth_data):
        if 'volumes' in vm_data['spec']:
            for volume in vm_data['spec']['volumes']:
                if 'persistentVolumeClaim' in volume and 'claimName' in volume['persistentVolumeClaim']:
                    vc_name = volume['persistentVolumeClaim']['claimName']
                    success = self._delete_volume_claim(vm_data["metadata"]["namespace"], vc_name, auth_data)
                    if not success:
                        self.log_error("Error deleting PersistentVolumeClaim:" + vc_name)

    def _create_volume_claim(self, claim_data, auth_data):
        try:
            headers = {'Content-Type': 'application/json'}
            uri = self._get_api_url(claim_data['metadata']['namespace'], "/persistentvolumeclaims")
            resp = self.create_request('POST', uri, auth_data, headers, claim_data)

            output = str(resp.text)
            if resp.status_code != 201:
                self.log_error("Error creating PVC: " + output)
                return False
            else:
                return True
        except Exception:
            self.log_exception("Error connecting with Kubernetes API server")
            return False

    def _create_volumes(self, namespace, system, vm_name, auth_data, persistent=False):
        res = []
        cont = 1
        while (system.getValue("disk." + str(cont) + ".size")):
            disk_mount_path = system.getValue("disk." + str(cont) + ".mount_path")
            # Use the device as volume host path to bind
            disk_device = system.getValue("disk." + str(cont) + ".device")
            disk_size = system.getFeature("disk." + str(cont) + ".size").getValue('B')

            name = "%s-%d" % (vm_name, cont)

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
            uri = self._get_api_url(namespace, '/services')
            svc_resp = self.create_request('POST', uri, auth_data, headers, service_data)
            if svc_resp.status_code != 201:
                self.error_messages += "Error creating service for VM %s: %s" % (name, svc_resp.text)
                self.log_warn("Error creating service: %s" % svc_resp.text)
            else:
                # Wait a bit to assure the service has been created
                time.sleep(0.5)
                # Get Service data to get assigned nodePort
                uri = self._get_api_url(namespace, '/services/%s' % name)
                svc_resp = self.create_request('GET', uri, auth_data)
                if svc_resp.status_code == 200:
                    for port in svc_resp.json()['spec']['ports']:
                        # Set Out port in the RADL info of the VM
                        vm.setOutPort(int(port['port']), int(port['nodePort']))

        except Exception:
            self.error_messages += "Error creating service to access VM %s" % name
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
                elif outport.get_local_port() == 22:
                    if outport.get_remote_port() != 22:
                        ports[0]['nodePort'] = outport.get_remote_port()
                else:
                    port = {'port': outport.get_local_port(),
                            'protocol': outport.get_protocol().upper(),
                            'targetPort': outport.get_local_port(),
                            'name': 'port%s' % outport.get_local_port()}
                    if outport.get_remote_port() != outport.get_local_port():
                        port['nodePort'] = outport.get_remote_port()
                    ports.append(port)

        service_data['spec'] = {
            'type': 'NodePort',
            'ports': ports,
            'selector': {'kubevirt.io/domain': name}
        }

        return service_data

    def _generate_vm_data(self, radl, namespace, name, system, volumes, public_key, cdi):
        cpu = system.getValue('cpu.count')
        memory = "%sM" % system.getFeature('memory.size').getValue('M')
        image_name = urlparse(system.getValue("disk.0.image.url"))[2][1:]

        vm_data = {'apiVersion': 'kubevirt.io/v1', 'kind': 'VirtualMachine'}
        vm_data['metadata'] = {
            'name': name,
            'namespace': namespace,
            'labels': {'name': name}
        }

        domain = {
            'memory': {'guest': memory},
            'cpu': {'cores': cpu},
            'resources': {
                'limits': {'cpu': cpu, 'memory': memory},
                'requests': {'cpu': cpu, 'memory': memory},
            },
            'devices': {
                'interfaces': [{'name': 'default', 'masquerade': {}}],
                'disks': [
                    {
                        'name': 'containerdisk',
                        'disk': {'bus': 'virtio'}
                    },
                    {
                        'name': 'cloudinitdisk',
                        'disk': {'bus': 'virtio'}
                    }
                ]
            }
        }

        for (v_name, _, _, _, _) in volumes:
            domain['devices']['disks'].append(
                {'name': v_name, 'disk': {'bus': 'virtio'}})

        username = system.getValue('disk.0.os.credentials.username')
        user_data = self.get_cloud_init_data(radl=radl, public_key=public_key, user=username)

        vm_data['spec'] = {
            'runStrategy': 'Always',
            'template': {
                'metadata': {
                    'labels': {'kubevirt.io/domain': name}
                },
            }
        }

        vm_data['spec']['template']['spec'] = {
            'domain': domain,
            'networks': [{'name': 'default', 'pod': {}}],
            'volumes': [
                {
                    'name': 'containerdisk',
                    'containerDisk': {
                        'image': image_name
                    }
                },
                {
                    'name': 'cloudinitdisk',
                    'cloudInitNoCloud': {
                        'userData': user_data
                    }
                }
            ]
        }

        if cdi:
            # replace containerDisk with dataVolume
            vm_data['spec']['template']['spec']['volumes'][0] = {
                'name': 'containerdisk',
                'dataVolume': {
                    'name': f'{name}-rootdisk'
                }
            }
            # and add the dataVolumeTemplate
            disk_size = 10 if system.getValue("disk.0.size") is None else system.getFeature("disk.0.size").getValue('G')
            vm_data['spec']['dataVolumeTemplates'] = [{
                'metadata': {
                    'name': f'{name}-rootdisk',
                },
                'spec': {
                    'source': {
                        'registry': {
                            'url': 'docker://%s' % image_name
                        }
                    },
                    'storage': {
                        'resources': {
                            'requests': {
                                'storage': '%sG' % disk_size
                            }
                        },
                    }
                }
            }]

        if volumes:
            for (v_name, _, _, _, persistent) in volumes:
                if persistent:
                    vm_data['spec']['template']['spec']['volumes'].append(
                        {'name': v_name, 'persistentVolumeClaim': {'claimName': v_name}})
                else:
                    vm_data['spec']['template']['spec']['volumes'].append(
                        {'name': v_name, 'emptyDir:': {}})

        return vm_data

    def _check_cdi_installed(self, auth_data):
        # Check if CDI is installed
        cdi = False
        uri = '/apis/apiextensions.k8s.io/v1/customresourcedefinitions/datavolumes.cdi.kubevirt.io'
        resp = self.create_request('GET', uri, auth_data)
        if resp.status_code == 200:
            cdi = True
        else:
            self.log_warn("CDI not installed.")

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        system = radl.systems[0]

        public_net = None
        for net in radl.networks:
            if net.isPublic():
                public_net = net

        outports = None
        if public_net:
            outports = public_net.getOutPorts()

        public_key = system.getValue("disk.0.os.credentials.public_key")
        if not public_key:
            # We must generate them
            (public_key, private_key) = SSH.keygen()
            system.setValue('disk.0.os.credentials.private_key', private_key)

        # CDI is installed
        cdi = False
        uri = '/apis/apiextensions.k8s.io/v1/customresourcedefinitions/datavolumes.cdi.kubevirt.io'
        resp = self.create_request('GET', uri, auth_data)
        if resp.status_code == 200:
            cdi = True
        else:
            self.log_warn("CDI not installed.")

        res = []
        # First create the namespace for the infrastructure
        namespace = self._get_namespace(inf, auth_data)
        headers = {'Content-Type': 'application/json'}
        uri = self._get_api_url("", "")
        with inf._lock:
            resp = self.create_request('GET', uri + namespace, auth_data, headers)
            if resp.status_code != 200:
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

        i = 0
        while i < num_vm:
            try:
                i += 1

                vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl, self)
                vm.destroy = True
                inf.add_vm(vm)
                (nodename, _) = vm.getRequestedName(default_hostname=Config.DEFAULT_VM_NAME,
                                                    default_domain=Config.DEFAULT_DOMAIN)
                vm_name = nodename

                volumes = self._create_volumes(namespace, system, vm_name, auth_data, True)

                vm_data = self._generate_vm_data(radl, namespace, vm_name, system, volumes, public_key, cdi)

                self.log_debug("Creating VM: %s/%s" % (namespace, vm_name))
                uri = self._get_api_url(namespace, '/virtualmachines', 'kubevirt.io/v1')
                resp = self.create_request('POST', uri, auth_data, headers, vm_data)

                if resp.status_code != 201:
                    self.log_error("Error creating the VM: " + resp.text)
                    res.append((False, "Error creating the VM: " + resp.text))
                    try:
                        self._delete_volume_claims(vm_data, auth_data)
                    except Exception:
                        self.log_exception("Error deleting volumes.")
                else:
                    self.create_service_data(namespace, vm_name, outports, auth_data, vm)

                    output = json.loads(resp.text)
                    vm.id = output["metadata"]["name"]
                    vm.info.systems[0].setValue('instance_id', str(vm.id))
                    vm.info.systems[0].setValue('instance_name', str(vm.id))

                    vm.destroy = False
                    res.append((True, vm))

            except Exception as ex:
                self.log_exception("Error connecting with Kubernetes API server")
                res.append((False, "ERROR: " + str(ex)))

        return res

    def _get_vm(self, vm, auth_data):
        try:
            namespace = vm.inf.id
            vm_name = vm.id

            # First check if the VM exists
            uri = self._get_api_url(namespace, '/virtualmachines/' + vm_name, 'kubevirt.io/v1')
            respvm = self.create_request('GET', uri, auth_data)

            if respvm.status_code != 200:
                return (False, respvm.status_code, respvm.text)

            # Now check if the VM is running (a VM is running if the VMI exists)
            uri = self._get_api_url(namespace, '/virtualmachineinstances/' + vm_name, 'kubevirt.io/v1')
            resp = self.create_request('GET', uri, auth_data)

            if resp.status_code == 200:
                return (True, resp.status_code, resp.text)
            if resp.status_code == 404:
                return (True, respvm.status_code, respvm.text)
            else:
                return (False, resp.status_code, resp.text)

        except Exception as ex:
            self.log_exception("Error connecting with Kubernetes API server")
            return (False, None, "Error connecting with Kubernetes API server: " + str(ex))

    def updateVMInfo(self, vm, auth_data):
        success, status, output = self._get_vm(vm, auth_data)
        if success:
            output = json.loads(output)
            state = output["status"].get("phase", output["status"].get("printableStatus"))
            vm.state = self.VM_STATE_MAP.get(state, VirtualMachine.UNKNOWN)

            cpus = output["status"].get("currentCPUTopology", {}).get("cores")
            if cpus:
                vm.info.systems[0].addFeature(Feature("cpu.count", "=", cpus), conflict="other", missing="other")
            memory = output["status"].get("memory", {}).get("guestCurrent")
            if memory:
                memory = self.convert_memory_unit(memory, "M")
                vm.info.systems[0].addFeature(Feature("memory.size", "=", memory, "M"),
                                              conflict="other", missing="other")

            # Update the network info
            self.setIPs(vm, output)
            return (True, vm)
        else:
            self.log_error("Error getting info about the VM: code: %s, msg: %s" % (status, output))
            return (False, "Error getting info about the VM: code: %s, msg: %s" % (status, output))

    def setIPs(self, vm, vm_info):
        """
        Adapt the RADL information of the VM to the real IPs assigned by the cloud provider

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - vm_info(dict): JSON information about the VM
        """

        public_ips = [self.cloud.server]
        private_ips = [iface.get("ipAddress") for iface in vm_info["status"].get("interfaces", [])]

        vm.setIps(public_ips, private_ips)

    def finalize(self, vm, last, auth_data):
        msg = ""
        if vm.id:
            success, status, output = self._get_vm(vm, auth_data)
            if success:
                if status == 404:
                    self.log_warn("Trying to remove a non existing VM id: %s" % vm.id)
                else:
                    vm_data = json.loads(output)
                    self._delete_volume_claims(vm_data, auth_data)
                    success, msg = self._delete_vm(vm, auth_data)
                    if not success:
                        self.log_error("Error deleting VM %s: %s" % (vm.id, msg))
                        return False, "Error deleting VM %s: %s" % (vm.id, msg)

            success, msg = self._delete_service(vm, auth_data)
        else:
            self.log_warn("No VM ID. Ignoring")
            success = True

        if last:
            self._delete_namespace(vm, auth_data)

        return success, msg

    def _delete_namespace(self, vm, auth_data):
        self.log_debug("Deleting Namespace: %s" % vm.inf.id)
        uri = self._get_api_url(vm.inf.id, '')
        resp = self.create_request('GET', uri, auth_data)
        if resp.status_code == 404:
            self.log_warn("Trying to remove a non existing Namespace id: " + vm.inf.id)
        elif resp.status_code == 403:
            self.log_warn("Trying to remove a Namespace without permissions: " + vm.inf.id)
        elif resp.status_code == 200:
            output = resp.json()
            if output["metadata"].get("labels", {}).get("inf_id") == vm.inf.id:
                resp = self.create_request('DELETE', uri, auth_data)
                if resp.status_code != 200:
                    return (False, "Error deleting the Namespace: " + resp.text)
            else:
                self.log_info("Namespace %s was not created by the IM. Do not delete it." % vm.inf.id)
        else:
            self.log_error("Error deleting Namespace")
            return False
        return True

    def _delete_service(self, vm, auth_data):
        try:
            namespace = vm.inf.id
            service_name = vm.id

            self.log_debug("Deleting Service: %s/%s" % (namespace, service_name))
            uri = self._get_api_url(namespace, "/services/" + service_name)
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

    def _delete_vm(self, vm, auth_data):
        try:
            namespace = vm.inf.id
            vm_name = vm.id

            self.log_debug("Deleting VM: %s/%s" % (namespace, vm_name))
            uri = self._get_api_url(namespace, '/virtualmachines/' + vm_name, 'kubevirt.io/v1')
            resp = self.create_request('DELETE', uri, auth_data)

            if resp.status_code == 404:
                self.log_warn("Trying to remove a non existing VM id: " + vm_name)
                return (True, vm_name)
            elif resp.status_code != 200:
                return (False, "Error deleting the VM: " + resp.text)
            else:
                return (True, vm_name)
        except Exception:
            self.log_exception("Error connecting with Kubernetes API server")
            return (False, "Error connecting with Kubernetes API server")

    def vm_operation(self, vm, operation, auth_data):
        patch_data = {
            "spec": {
                "runStrategy": "Halted" if operation == "stop" else "Always",
            }
        }
        namespace = vm.inf.id
        vm_name = vm.id
        uri = self._get_api_url(namespace, '/virtualmachines/' + vm_name, 'kubevirt.io/v1')
        headers = {"Content-Type": "application/merge-patch+json"}
        resp = self.create_request('PATCH', uri, auth_data, headers, patch_data)
        if resp.status_code != 200:
            return (False, "Error in %s operation in the VM: %s" % (operation, resp.text))
        else:
            return (True, "")

    def stop(self, vm, auth_data):
        return self.vm_operation(vm, "stop", auth_data)

    def start(self, vm, auth_data):
        return self.vm_operation(vm, "stop", auth_data)

    def reboot(self, vm, auth_data):
        namespace = vm.inf.id
        vm_name = vm.id
        uri = self._get_api_url(namespace, '/virtualmachines/' + vm_name + '/restart', 'subresources.kubevirt.io/v1')
        resp = self.create_request('POST', uri, auth_data)
        if resp.status_code != 200:
            return (False, "Error in reboot operation in the VM: %s" % resp.text)
        return (True, "")

    def alterVM(self, vm, radl, auth_data):
        system = radl.systems[0]

        try:
            vm_data = []

            cpu = vm.info.systems[0].getValue('cpu.count')
            memory = vm.info.systems[0].getFeature('memory.size').getValue('B')

            new_cpu = system.getValue('cpu.count')
            new_memory = system.getFeature('memory.size').getValue('B')

            changed = False
            base_path = '/spec/template/spec/domain/'
            if new_cpu and new_cpu != cpu:
                vm_data.append({"op": "replace", "path": f"{base_path}/resources/limits/cpu", "value": new_cpu})
                vm_data.append({"op": "replace", "path": f"{base_path}/resources/requests/cpu", "value": new_cpu})
                vm_data.append({"op": "replace", "path": f"{base_path}/cpu/cores", "value": new_cpu})
                changed = True
            if new_memory and new_memory != memory:
                vm_data.append({"op": "replace", "path": f"{base_path}/resources/limits/memory", "value": new_memory})
                vm_data.append({"op": "replace", "path": f"{base_path}/resources/requests/memory", "value": new_memory})
                vm_data.append({"op": "replace", "path": f"{base_path}/memory/guest", "value": new_memory})
                changed = True

            if not changed:
                self.log_info("Nothing changes in the VM: " + str(vm.id))
                return (True, vm)

            namespace = vm.inf.id
            vm_name = vm.id

            headers = {'Content-Type': 'application/json-patch+json'}
            uri = self._get_api_url(namespace, '/virtualmachines/' + vm_name, 'kubevirt.io/v1')
            resp = self.create_request('PATCH', uri, auth_data, headers, vm_data)

            if resp.status_code != 201:
                return (False, "Error updating the VM: " + resp.text)
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
