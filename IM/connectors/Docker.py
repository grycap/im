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

import os
import time
import tempfile
import json
import socket
import requests
import random
import uuid
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from IM.config import Config
from .CloudConnector import CloudConnector
from radl.radl import Feature
from IM import UnixHTTPAdapter


class DockerCloudConnector(CloudConnector):
    """
    Cloud Launcher to Docker servers
    """

    type = "Docker"
    DEFAULT_USER = 'root'
    """ default user to SSH access the VM """

    _port_base_num = random.randint(35000, 40000)
    """ Base number to assign SSH port on Docker server host."""
    _port_counter = 0
    """ Counter to assign SSH port on Docker server host."""
    _root_password = "Aspecial+0ne"
    """ Default password to set to the root in the container"""

    def __init__(self, cloud_info, inf):
        self._swarm = None
        CloudConnector.__init__(self, cloud_info, inf)

    def create_request(self, method, url, auth_data, headers=None, body=None):

        auths = auth_data.getAuthInfo(DockerCloudConnector.type, self.cloud.server)
        if not auths:
            raise Exception("No correct auth data has been specified to Docker.")
        else:
            auth = auths[0]

        if self.cloud.protocol == 'unix':
            url = "http+unix://%%2F%s%s%s" % (self.cloud.server.replace("/", "%2F"),
                                              self.cloud.path.replace("/", "%2F"),
                                              url)
            session = requests.Session()
            session.mount('http+unix://', UnixHTTPAdapter.UnixHTTPAdapter())
            resp = session.request(method, url, verify=self.verify_ssl, headers=headers, data=body)
        else:
            url = "%s://%s:%d%s%s" % (self.cloud.protocol, self.cloud.server, self.cloud.port, self.cloud.path, url)
            if 'public_key' in auth and 'private_key' in auth:
                cert = self.get_user_cert_data(auth)
            else:
                cert = None

            try:
                resp = requests.request(method, url, verify=self.verify_ssl, cert=cert, headers=headers, data=body)
            finally:
                if cert:
                    try:
                        cert_file, key_file = cert
                        os.unlink(cert_file)
                        os.unlink(key_file)
                    except Exception:
                        pass

        return resp

    def get_user_cert_data(self, auth):
        """
        Get the Docker private_key and public_key files from the auth data
        """
        certificate = auth['public_key']
        fd, cert_file = tempfile.mkstemp()
        os.write(fd, certificate.encode())
        os.close(fd)
        os.chmod(cert_file, 0o644)

        private_key = auth['private_key']
        fd, key_file = tempfile.mkstemp()
        os.write(fd, private_key.encode())
        os.close(fd)
        os.chmod(key_file, 0o600)

        return (cert_file, key_file)

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]
        if protocol == 'docker' and url[1]:
            res_system = radl_system.clone()

            res_system.addFeature(Feature("virtual_system_type", "=", "docker"), conflict="other", missing="other")

            res_system.getFeature("cpu.count").operator = "="
            res_system.getFeature("memory.size").operator = "="

            res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)
            res_system.setValue('disk.0.os.credentials.password', self._root_password)

            return res_system
        else:
            return None

    def setIPs(self, vm, cont_info, auth_data):
        """
        Adapt the RADL information of the VM to the real IPs assigned by the cloud provider

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - cont_info(dict): JSON information about the container
           - auth_data: Athentication data.
        """

        public_ips = []
        if vm.hasPublicNet():
            if self.cloud.protocol == 'unix':
                # TODO: This will not get the correct IP if the hostname of the
                # machine is not correctly set
                public_ips = [socket.gethostbyname(socket.getfqdn())]
            else:
                public_ips = [socket.gethostbyname(self.cloud.server)]
        private_ips = []

        if self._is_swarm(auth_data):
            if "VirtualIPs" in cont_info["Endpoint"] and cont_info["Endpoint"]['VirtualIPs']:
                for vip in cont_info["Endpoint"]['VirtualIPs']:
                    private_ips.append(vip['Addr'][:-3])
        else:
            if str(cont_info["NetworkSettings"]["IPAddress"]):
                private_ips.append(str(cont_info["NetworkSettings"]["IPAddress"]))
            elif "Networks" in cont_info["NetworkSettings"]:
                for _, net_data in cont_info["NetworkSettings"]["Networks"].items():
                    if str(net_data["IPAddress"]):
                        private_ips.append(str(net_data["IPAddress"]))

        vm.setIps(public_ips, private_ips)

    def _generate_create_svc_request_data(self, image_name, outports, vm, ssh_port, auth_data):
        svc_data = {}
        system = vm.info.systems[0]

        cpu = int(system.getValue('cpu.count')) - 1
        memory = int(system.getFeature('memory.size').getValue('B'))
        name = system.getValue("disk.0.image.name")
        if not name:
            name = "imsvc"

        svc_data['Name'] = "%s-%s" % (name, str(uuid.uuid1()))
        svc_data['TaskTemplate'] = {}
        svc_data['TaskTemplate']['ContainerSpec'] = {}
        svc_data['TaskTemplate']['ContainerSpec']['Image'] = image_name
        svc_data['TaskTemplate']['ContainerSpec']['Mounts'] = self._generate_mounts(system)

        command = "yum install -y openssh-server python"
        command += " ; "
        command += "zypper -n install sudo which openssh"
        command += " ; "
        command += "apt-get update && apt-get install -y openssh-server python"
        command += " ; "
        command += "mkdir /var/run/sshd"
        command += " ; "
        command += "sed -i '/PermitRootLogin/c\PermitRootLogin yes' /etc/ssh/sshd_config"
        command += " ; "
        command += "rm -f /etc/ssh/ssh_host_rsa_key*"
        command += " ; "
        command += "ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''"
        command += " ; "
        command += "echo 'root:" + self._root_password + "' | chpasswd"
        command += " ; "
        command += "sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd"
        command += " ; "
        command += " /usr/sbin/sshd -D"

        svc_data['TaskTemplate']['ContainerSpec']['Args'] = ["/bin/bash", "-c", command]
        svc_data['TaskTemplate']['ContainerSpec']['User'] = "root"
        svc_data['TaskTemplate']['Resources'] = {"Limits": {}, "Reservation": {}}
        svc_data['TaskTemplate']['Resources']['Limits']['MemoryBytes'] = memory

        svc_data['Mode'] = {"Replicated": {"Replicas": 1}}

        if vm.hasPublicNet():
            ports = []
            ports.append({"Protocol": "tcp", "PublishedPort": ssh_port, "TargetPort": 22})
            if outports:
                for outport in outports:
                    if outport.is_range():
                        self.log_warn("Port range not allowed in Docker connector. Ignoring.")
                    else:
                        if outport.get_local_port() != 22:
                            ports.append({"Protocol": outport.get_protocol(),
                                          "PublishedPort": outport.get_remote_port(),
                                          "TargetPort": outport.get_local_port()})

            svc_data['EndpointSpec'] = {'Ports': ports}

        nets = []
        for net_name in system.getNetworkIDs():
            net = vm.info.get_network_by_id(net_name)
            num_conn = system.getNumNetworkWithConnection(net_name)
            if not net.isPublic() and num_conn is not None:
                net_name = net.getValue('provider_id')
                if not net_name:
                    net_name = "im_%s_%s" % (vm.inf.id, net_name)
                net_id = self._get_net_id(net_name, auth_data)
                (hostname, default_domain) = vm.getRequestedNameIface(num_conn,
                                                                      default_hostname=Config.DEFAULT_VM_NAME,
                                                                      default_domain=Config.DEFAULT_DOMAIN)
                aliases = [hostname, "%s.%s" % (hostname, default_domain)]
                nets.append({"Target": net_id, "Aliases": aliases})

        svc_data['Networks'] = nets

        self.log_debug(json.dumps(svc_data))

        return json.dumps(svc_data)

    def _generate_create_cont_request_data(self, image_name, outports, vm, ssh_port):
        cont_data = {}
        system = vm.info.systems[0]

        cpu = int(system.getValue('cpu.count')) - 1
        memory = system.getFeature('memory.size').getValue('B')
        # name = system.getValue("disk.0.image.name")

        (nodename, nodedom) = vm.getRequestedName(
            default_hostname=Config.DEFAULT_VM_NAME, default_domain=Config.DEFAULT_DOMAIN)

        cont_data['Hostname'] = nodename
        cont_data['Domainname'] = nodedom
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

        cont_data['Cmd'] = ["/bin/bash", "-c", command]
        cont_data['Image'] = image_name

        exposed_ports = {"22/tcp": {}}
        if outports:
            for outport in outports:
                if outport.is_range():
                    self.log_warn("Port range not allowed in Docker connector. Ignoring.")
                else:
                    if outport.get_local_port() != 22:
                        exposed_ports[str(outport.get_local_port()) + '/' + outport.get_protocol().lower()] = {}
        cont_data['ExposedPorts'] = exposed_ports

        # Attach to first private network
        cont_data['NetworkingConfig'] = {'EndpointsConfig': {}}
        for net_name in system.getNetworkIDs():
            net = vm.info.get_network_by_id(net_name)

            if not net.isPublic():
                num_conn = system.getNumNetworkWithConnection(net_name)
                (hostname, default_domain) = vm.getRequestedNameIface(num_conn,
                                                                      default_hostname=Config.DEFAULT_VM_NAME,
                                                                      default_domain=Config.DEFAULT_DOMAIN)
                net_name = "im_%s_%s" % (vm.inf.id, net_name)
                cont_data['NetworkingConfig']['EndpointsConfig'][net_name] = {}
                aliases = [hostname, "%s.%s" % (hostname, default_domain)]
                cont_data['NetworkingConfig']['EndpointsConfig'][net_name]['Aliases'] = aliases
                break

        HostConfig = {}
        # HostConfig['CpuShares'] = cpu
        HostConfig['Memory'] = memory
        HostConfig['Mounts'] = self._generate_mounts(system)

        if vm.hasPublicNet():
            port_bindings = {}
            port_bindings["22/tcp"] = [{"HostPort": str(ssh_port)}]
            if outports:
                for outport in outports:
                    if outport.is_range():
                        self.log_warn("Port range not allowed in Docker connector. Ignoring.")
                    else:
                        if outport.get_local_port() != 22:
                            port_bindings[str(outport.get_local_port()) +
                                          '/' + outport.get_protocol()] = [{"HostPort": str(outport.get_remote_port())}]
            HostConfig['PortBindings'] = port_bindings
        if system.getValue("docker.privileged") == 'yes':
            HostConfig['Privileged'] = True
        cont_data['HostConfig'] = HostConfig

        self.log_debug(json.dumps(cont_data))

        return json.dumps(cont_data)

    def _generate_mounts(self, system):
        mounts = []
        cont = 1
        while (system.getValue("disk." + str(cont) + ".mount_path") and
               system.getValue("disk." + str(cont) + ".device")):
            # user device as volume name
            source = system.getValue("disk." + str(cont) + ".device")
            disk_mount_path = system.getValue("disk." + str(cont) + ".mount_path")
            if not disk_mount_path.startswith('/'):
                disk_mount_path = '/' + disk_mount_path
            self.log_info("Attaching a volume in %s" % disk_mount_path)
            mount = {"Source": source, "Target": disk_mount_path}
            mount["Type"] = "volume"
            mount["ReadOnly"] = False
            # if the name of the source starts with / we assume it is a bind
            if source.startswith("/"):
                mount["Type"] = "bind"
            mounts.append(mount)
            cont += 1
        return mounts

    def _is_swarm(self, auth_data):
        if self._swarm is None:
            headers = {'Content-Type': 'application/json'}
            resp = self.create_request('GET', "/info", auth_data, headers)
            if resp.status_code != 200:
                self.log_error("Error getting node info: %s" % resp.text)
                self._swarm = False
            else:
                info = json.loads(resp.text)
                if ("Swarm" in info and "LocalNodeState" in info["Swarm"] and
                        info["Swarm"]["LocalNodeState"] == "active"):
                    self._swarm = True
                else:
                    self._swarm = False
        return self._swarm

    def _create_networks(self, inf, radl, auth_data):
        for net in radl.networks:
            if not net.isPublic() and radl.systems[0].getNumNetworkWithConnection(net.id) is not None:
                headers = {'Content-Type': 'application/json'}

                net_name = net.getValue('provider_id')
                if not net_name:
                    net_name = "im_%s_%s" % (inf.id, net.id)
                    net.setValue('provider_id', net_name)

                data = {"Name": net_name, "CheckDuplicate": True}
                # In case of Swarm, create an overlay network
                if self._is_swarm(auth_data):
                    data["Driver"] = "overlay"
                    data["Scope"] = "swarm"
                    data["IPAM"] = {"Driver": "default"}

                body = json.dumps(data)
                resp = self.create_request('POST', "/networks/create", auth_data, headers, body)

                if resp.status_code not in [201, 200]:
                    self.log_error("Error creating network %s: %s" % (net.id, resp.text))
                    return False

        return True

    def _get_net_id(self, net_name, auth_data):
        headers = {'Content-Type': 'application/json'}
        resp = self.create_request('GET', '/networks?filters={"name":{"%s":true}}' % net_name, auth_data, headers)
        if resp.status_code != 200:
            self.log_error("Error searching for network %s: %s" % (net_name, resp.text))
        else:
            net_data = json.loads(resp.text)
            if len(net_data) > 0:
                for net in net_data:
                    if net['Name'] == net_name:
                        return net['Id']
            else:
                self.log_error("No data returned for network %s" % net_name)
        return None

    def _delete_volumes(self, vm, auth_data):
        cont = 1
        headers = {'Content-Type': 'application/json'}
        system = vm.info.systems[0]

        while system.getValue("disk." + str(cont) + ".mount_path"):
            # user device as volume name
            created = system.getValue("disk." + str(cont) + ".created")
            source = system.getValue("disk." + str(cont) + ".device")
            cont += 1
            if not source:
                self.log_warn("Disk without source, not deleting it.")
            elif created == "yes":
                retries = 5
                delay = 10
                curr = 0
                while curr < retries:
                    curr += 1
                    resp = self.create_request('DELETE', "/volumes/%s" % source, auth_data, headers)
                    if resp.status_code not in [204, 404]:
                        self.log_warn("Error deleting volume %s: %s." % (source, resp.text))
                        time.sleep(delay)
                    else:
                        self.log_info("Volume %s successfully deleted." % source)
                        break
            else:
                self.log_info("Volume %s not created by the IM, not deleting it." % source)

    def _delete_networks(self, vm, auth_data):
        for net in vm.info.networks:
            if not net.isPublic():
                headers = {'Content-Type': 'application/json'}

                net_name = net.getValue('provider_id')
                if not net_name:
                    net_name = "im_%s_%s" % (vm.inf.id, net.id)
                    net.setValue('provider_id', net_name)

                net_id = self._get_net_id(net_name, auth_data)
                if net_id:
                    resp = self.create_request('DELETE', "/networks/%s" % net_id, auth_data, headers)

                    if resp.status_code not in [204, 404]:
                        self.log_error("Error deleting network %s: %s" % (net.id, resp.text))
                    else:
                        self.log_info("Network %s deleted successfully" % net.id)

    def _attach_cont_to_networks(self, vm, auth_data):
        system = vm.info.systems[0]
        first = True
        all_ok = True
        for net_name in system.getNetworkIDs():
            net = vm.info.get_network_by_id(net_name)

            if not net.isPublic():
                if first:
                    first = False
                else:
                    num_conn = system.getNumNetworkWithConnection(net_name)
                    (hostname, default_domain) = vm.getRequestedNameIface(num_conn,
                                                                          default_hostname=Config.DEFAULT_VM_NAME,
                                                                          default_domain=Config.DEFAULT_DOMAIN)
                    net_name = "im_%s_%s" % (vm.inf.id, net_name)
                    net_id = self._get_net_id(net_name, auth_data)
                    headers = {'Content-Type': 'application/json'}
                    aliases = [hostname, "%s.%s" % (hostname, default_domain)]
                    body = json.dumps({"Container": vm.id, "EndpointConfig": {"Aliases": aliases}})
                    resp = self.create_request('POST', "/networks/%s/connect" % net_id, auth_data, headers, body)

                    if resp.status_code != 200:
                        self.log_error("Error attaching cont %s to network %s: %s" % (vm.id, net_name, resp.text))
                        all_ok = False
                    else:
                        self.log_info("Cont %s attached to network %s" % (vm.id, net_name))
        return all_ok

    def _create_volumes(self, system, auth_data):
        cont = 1
        headers = {'Content-Type': 'application/json'}

        while system.getValue("disk." + str(cont) + ".mount_path"):
            # user device as volume name
            source = system.getValue("disk." + str(cont) + ".device")
            if not source:
                source = "d-%s-%d" % (str(uuid.uuid1()), cont)
                system.setValue("disk." + str(cont) + ".device", source)

            # if the name of the source starts with / we assume it is a bind, so do not create a volume
            if not source.startswith("/"):
                driver = system.getValue("disk." + str(cont) + ".fstype")
                if not driver:
                    driver = "local"
                resp = self.create_request('GET', "/volumes/%s" % source, auth_data, headers)
                if resp.status_code == 200:
                    # the volume already exists
                    self.log_info("Volume named %s already exists." % source)
                else:
                    body = json.dumps({"Name": source, "Driver": driver})
                    resp = self.create_request('POST', "/volumes/create", auth_data, headers, body)

                    if resp.status_code != 201:
                        self.log_error("Error creating volume %s: %s." % (source, resp.text))
                    else:
                        system.setValue("disk." + str(cont) + ".created", "yes")
                        self.log_info("Volume %s successfully created." % source)

            cont += 1

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        system = radl.systems[0]

        # Get the public network connected with this VM
        public_net = None
        for net in radl.networks:
            if net.isPublic() and system.getNumNetworkWithConnection(net.id) is not None:
                public_net = net

        outports = None
        if public_net:
            outports = public_net.getOutPorts()

        self._create_networks(inf, radl, auth_data)

        with inf._lock:
            self._create_volumes(system, auth_data)

        headers = {'Content-Type': 'application/json'}
        res = []
        i = 0
        while i < num_vm:
            try:
                i += 1
                # Create the VM to get the nodename
                vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl, self)
                vm.destroy = True
                inf.add_vm(vm)

                ssh_port = 22
                if vm.hasPublicNet():
                    ssh_port = (DockerCloudConnector._port_base_num +
                                DockerCloudConnector._port_counter) % 65535
                    DockerCloudConnector._port_counter += 1

                # The URI has this format: docker://image_name
                full_image_name = system.getValue("disk.0.image.url")[9:]

                # Create the container
                if self._is_swarm(auth_data):
                    cont_data = self._generate_create_svc_request_data(full_image_name, outports, vm,
                                                                       ssh_port, auth_data)
                    resp = self.create_request('POST', "/services/create", auth_data, headers, cont_data)
                else:
                    # First we have to pull the image
                    image_parts = full_image_name.split(":")
                    image_name = image_parts[0]
                    if len(image_parts) < 2:
                        tag = "latest"
                    else:
                        tag = image_parts[1]
                    resp = self.create_request('POST', "/images/create?fromImage=%s&tag=%s" % (image_name, tag),
                                               auth_data, headers)

                    if resp.status_code not in [201, 200]:
                        res.append((False, "Error pulling the image: " + resp.text))
                        continue

                    cont_data = self._generate_create_cont_request_data(full_image_name, outports, vm, ssh_port)
                    resp = self.create_request('POST', "/containers/create", auth_data, headers, cont_data)

                if resp.status_code != 201:
                    res.append((False, "Error creating the Container: " + resp.text))
                    continue

                output = json.loads(resp.text)
                # Set the cloud id to the VM
                if "Id" in output:
                    vm.id = output["Id"]
                elif "ID" in output:
                    vm.id = output["ID"]
                else:
                    res.append((False, "Error: response format not expected."))

                vm.info.systems[0].setValue('instance_id', str(vm.id))

                if not self._is_swarm(auth_data):
                    # In creation a container can only be attached to one one network
                    # so now we must attach to the rest of networks (if any)
                    success = self._attach_cont_to_networks(vm, auth_data)
                    if not success:
                        res.append((False, "Error attaching to networks the Container"))
                        # Delete the container
                        resp = self.create_request('DELETE', "/containers/" + vm.id, auth_data)
                        continue

                    # Now start it
                    success, msg = self.start(vm, auth_data)
                    if not success:
                        res.append((False, "Error starting the Container: " + str(msg)))
                        # Delete the container
                        resp = self.create_request('DELETE', "/containers/" + vm.id, auth_data)
                        continue

                # Set the default user and password to access the container
                vm.info.systems[0].setValue('disk.0.os.credentials.username', 'root')
                vm.info.systems[0].setValue('disk.0.os.credentials.password', self._root_password)

                # Set ssh port in the RADL info of the VM
                vm.setSSHPort(ssh_port)

                vm.destroy = False
                res.append((True, vm))

            except Exception as ex:
                self.log_exception("Error connecting with Docker server")
                res.append((False, "ERROR: " + str(ex)))

        return res

    def updateVMInfo(self, vm, auth_data):
        try:
            if self._is_swarm(auth_data):
                resp = self.create_request('GET', "/services/" + vm.id, auth_data)
            else:
                resp = self.create_request('GET', "/containers/" + vm.id + "/json", auth_data)

            if resp.status_code != 200:
                return (False, "Error getting info about the Container: " + resp.text)

            output = json.loads(resp.text)
            if self._is_swarm(auth_data):
                vm.state = self._get_svc_state(output['Spec']['Name'], auth_data)
            else:
                if output["State"]["Running"]:
                    vm.state = VirtualMachine.RUNNING
                else:
                    vm.state = VirtualMachine.STOPPED

            # Update network data
            self.setIPs(vm, output, auth_data)
            return (True, vm)

        except Exception as ex:
            self.log_exception("Error connecting with Docker server")
            self.log_error(ex)
            return (False, "Error connecting with Docker server")

    def _get_svc_state(self, svc_name, auth_data):
        headers = {'Content-Type': 'application/json'}
        resp = self.create_request('GET', '/tasks?filters={"service":{"%s":true}}' % svc_name, auth_data, headers)
        if resp.status_code != 200:
            self.log_error("Error searching tasks for service %s: %s" % (svc_name, resp.text))
        else:
            task_data = json.loads(resp.text)
            if len(task_data) > 0:
                for task in reversed(task_data):
                    if task["Status"]["State"] == "running":
                        return VirtualMachine.RUNNING
                    elif task["Status"]["State"] == "rejected":
                        self.log_info("Task %s rejected: %s." % (task["ID"], task["Status"]["Err"]))
                return VirtualMachine.PENDING
            else:
                return VirtualMachine.PENDING
        return VirtualMachine.UNKNOWN

    def finalize(self, vm, last, auth_data):
        try:
            if vm.id:
                if self._is_swarm(auth_data):
                    resp = self.create_request('DELETE', "/services/" + vm.id, auth_data)
                else:
                    # First Stop it
                    self.stop(vm, auth_data)
                    # Now delete it
                    resp = self.create_request('DELETE', "/containers/" + vm.id, auth_data)

                res = (False, "")
                if resp.status_code == 404:
                    self.log_warn("Trying to remove a non existing container id: " + vm.id)
                    res = (True, "")
                elif resp.status_code not in [204, 200]:
                    res = (False, "Error deleting the Container: " + resp.text)
                else:
                    res = (True, "")
            else:
                self.log_warn("No VM ID. Ignoring")
                res = (True, "")

            self._delete_volumes(vm, auth_data)

            # if it is the last VM delete the Docker networks
            if last:
                try:
                    self._delete_networks(vm, auth_data)
                except Exception:
                    self.log_exception("Error deleting networks.")

            return res
        except Exception:
            self.log_exception("Error connecting with Docker server")
            return (False, "Error connecting with Docker server")

    def stop(self, vm, auth_data):
        return self.cont_action(vm, 'stop', auth_data)

    def start(self, vm, auth_data):
        return self.cont_action(vm, 'start', auth_data)

    def reboot(self, vm, auth_data):
        return self.cont_action(vm, 'restart', auth_data)

    def cont_action(self, vm, action, auth_data):
        try:
            if self._is_swarm(auth_data):
                return (False, "Not supported")

            resp = self.create_request('POST', "/containers/" + vm.id + "/" + action, auth_data)

            if resp.status_code != 204:
                return (False, "Error in Container Action the Container: " + resp.text)
            else:
                return (True, vm.id)
        except Exception:
            self.log_exception("Error connecting with Docker server")
            return (False, "Error connecting with Docker server")

    def alterVM(self, vm, radl, auth_data):
        return (False, "Not supported")
