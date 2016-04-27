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
import tempfile
import json
import socket
import httplib
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from IM.config import Config
from CloudConnector import CloudConnector
from radl.radl import Feature
from IM import UnixHTTPConnection


class DockerCloudConnector(CloudConnector):
    """
    Cloud Launcher to Docker servers
    """

    type = "Docker"

    _port_base_num = 35000
    """ Base number to assign SSH port on Docker server host."""
    _port_counter = 0
    """ Counter to assign SSH port on Docker server host."""
    _root_password = "Aspecial+0ne"
    """ Default password to set to the root in the container"""

    def __init__(self, cloud_info):
        self.cert_file = ''
        self.key_file = ''
        CloudConnector.__init__(self, cloud_info)

    def get_http_connection(self, auth_data):
        """
        Get the HTTPConnection object to contact the Docker API

        Arguments:
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
        Returns(HTTPConnection or HTTPSConnection): HTTPConnection connection object
        """

        self.cert_file or os.path.isfile(self.cert_file)

        auths = auth_data.getAuthInfo(
            DockerCloudConnector.type, self.cloud.server)
        if not auths:
            self.logger.error(
                "No correct auth data has been specified to Docker.")
            return None
        else:
            auth = auths[0]

        if self.cloud.protocol == 'unix':
            socket_path = "/" + self.cloud.server
            conn = UnixHTTPConnection.UnixHTTPConnection(socket_path)
        elif self.cloud.protocol == 'https':
            if 'cert' in auth and 'key' in auth:
                if os.path.isfile(self.cert_file) and os.path.isfile(self.key_file):
                    cert_file = self.cert_file
                    key_file = self.key_file
                else:
                    cert_file, key_file = self.get_user_cert_data(auth)
                    self.cert_file = cert_file
                    self.key_file = key_file
                conn = httplib.HTTPSConnection(
                    self.cloud.server, self.cloud.port, cert_file=cert_file, key_file=key_file)
            else:
                conn = httplib.HTTPSConnection(
                    self.cloud.server, self.cloud.port)
        elif self.cloud.protocol == 'http':
            self.logger.warn("Using a unsecure connection to docker API!")
            conn = httplib.HTTPConnection(self.cloud.server, self.cloud.port)

        return conn

    def get_user_cert_data(self, auth):
        """
        Get the Docker private_key and public_key files from the auth data
        """
        certificate = auth['cert']
        fd, cert_file = tempfile.mkstemp()
        os.write(fd, certificate)
        os.close(fd)
        os.chmod(cert_file, 0644)

        private_key = auth['key']
        fd, key_file = tempfile.mkstemp()
        os.write(fd, private_key)
        os.close(fd)
        os.chmod(key_file, 0600)

        return (cert_file, key_file)

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

                    res_system.addFeature(
                        Feature("disk.0.image.url", "=", str_url), conflict="other", missing="other")
                    res_system.addFeature(Feature(
                        "virtual_system_type", "=", "docker"), conflict="other", missing="other")

                    res_system.getFeature("cpu.count").operator = "="
                    res_system.getFeature("memory.size").operator = "="

                    res_system.setValue(
                        'disk.0.os.credentials.username', 'root')
                    res_system.setValue(
                        'disk.0.os.credentials.password', self._root_password)

                    res_system.addFeature(
                        Feature("provider.type", "=", self.type), conflict="other", missing="other")
                    res_system.addFeature(Feature(
                        "provider.host", "=", self.cloud.server), conflict="other", missing="other")
                    res_system.addFeature(Feature(
                        "provider.port", "=", self.cloud.port), conflict="other", missing="other")

                    res.append(res_system)

            return res

    def setIPs(self, vm, cont_info):
        """
        Adapt the RADL information of the VM to the real IPs assigned by the cloud provider

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - cont_info(dict): JSON information about the container
        """

        if self.cloud.protocol == 'unix':
            # TODO: This will not get the correct IP if the hostname of the
            # machine is not correctly set
            public_ips = [socket.gethostbyname(socket.getfqdn())]
        else:
            public_ips = [socket.gethostbyname(self.cloud.server)]
        private_ips = []
        if str(cont_info["NetworkSettings"]["IPAddress"]):
            private_ips.append(str(cont_info["NetworkSettings"]["IPAddress"]))

        vm.setIps(public_ips, private_ips)

    def _generate_create_request_data(self, outports, system, vm, ssh_port):
        cont_data = {}

        cpu = int(system.getValue('cpu.count')) - 1
        memory = system.getFeature('memory.size').getValue('B')
        # name = system.getValue("disk.0.image.name")
        # The URI has this format: docker://image_name
        image_name = system.getValue("disk.0.image.url")[9:]

        (nodename, nodedom) = vm.getRequestedName(
            default_hostname=Config.DEFAULT_VM_NAME, default_domain=Config.DEFAULT_DOMAIN)

        volumes = self._generate_volumes(system)

        cont_data['Hostname'] = nodename
        cont_data['Domainname'] = nodedom
        cont_data['Cmd'] = ["/bin/bash", "-c", ("yum install -y openssh-server ;  apt-get update && apt-get install"
                                                " -y openssh-server && sed -i 's/PermitRootLogin without-password/"
                                                "PermitRootLogin yes/g' /etc/ssh/sshd_config && service ssh start "
                                                "&& service ssh stop ; echo 'root:" + self._root_password +
                                                "' | chpasswd ; /usr/sbin/sshd -D")]
        cont_data['Image'] = image_name
        cont_data['ExposedPorts'] = self._generate_exposed_ports(outports)
        if volumes:
            cont_data['Volumes'] = volumes

        HostConfig = {}
        HostConfig['CpuShares'] = "%d" % cpu
        HostConfig['Memory'] = memory
        HostConfig['PortBindings'] = self._generate_port_bindings(
            outports, ssh_port)
        HostConfig['Binds'] = self._generate_volumes_binds(system)
        cont_data['HostConfig'] = HostConfig

        return cont_data

    def _generate_volumes_binds(self, system):
        binds = []

        cont = 1
        while (system.getValue("disk." + str(cont) + ".size") and
               system.getValue("disk." + str(cont) + ".mount_path") and
               system.getValue("disk." + str(cont) + ".device")):
            disk_mount_path = system.getValue(
                "disk." + str(cont) + ".mount_path")
            # Use the device as volume host path to bind
            disk_device = system.getValue("disk." + str(cont) + ".device")
            if not disk_mount_path.startswith('/'):
                disk_mount_path = '/' + disk_mount_path
            if not disk_device.startswith('/'):
                disk_device = '/' + disk_device
            self.logger.debug("Binding a volume in %s to %s" %
                              (disk_device, disk_mount_path))
            binds.append(disk_device + ":" + disk_mount_path)
            cont += 1

        return binds

    def _generate_volumes(self, system):
        volumes = {}

        cont = 1
        while system.getValue("disk." + str(cont) + ".size") and system.getValue("disk." + str(cont) + ".mount_path"):
            # Use the mount_path as the volume dir
            disk_mount_path = system.getValue(
                "disk." + str(cont) + ".mount_path")
            if not disk_mount_path.startswith('/'):
                disk_mount_path = '/' + disk_mount_path
            self.logger.debug("Attaching a volume in %s" % disk_mount_path)
            volumes[disk_mount_path] = {}
            cont += 1

        return volumes

    def _generate_exposed_ports(self, outports):
        exposed_ports = {"22/tcp": {}}
        if outports:
            for _, _, local_port, local_protocol in outports:
                if local_port != 22:
                    exposed_ports[str(local_port) + '/' +
                                  local_protocol.lower()] = {}
        return exposed_ports

    def _generate_port_bindings(self, outports, ssh_port):
        res = {}
        res["22/tcp"] = [{"HostPort": str(ssh_port)}]
        if outports:
            for remote_port, _, local_port, local_protocol in outports:
                if local_port != 22:
                    res[str(local_port) + '/' +
                        local_protocol] = [{"HostPort": str(remote_port)}]

        return res

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        system = radl.systems[0]

        public_net = None
        for net in radl.networks:
            if net.isPublic():
                public_net = net

        outports = None
        if public_net:
            outports = public_net.getOutPorts()

        conn = self.get_http_connection(auth_data)
        res = []
        i = 0
        while i < num_vm:
            try:
                i += 1

                ssh_port = 22
                if public_net:
                    ssh_port = (DockerCloudConnector._port_base_num +
                                DockerCloudConnector._port_counter) % 65535
                    DockerCloudConnector._port_counter += 1

                # Create the VM to get the nodename
                vm = VirtualMachine(inf, None, self.cloud,
                                    radl, requested_radl, self)

                # Create the container
                conn.putrequest('POST', "/containers/create")
                conn.putheader('Content-Type', 'application/json')

                cont_data = self._generate_create_request_data(
                    outports, system, vm, ssh_port)
                body = json.dumps(cont_data)

                conn.putheader('Content-Length', len(body))
                conn.endheaders(body)

                resp = conn.getresponse()
                output = resp.read()
                if resp.status != 201:
                    res.append(
                        (False, "Error creating the Container: " + output))
                    continue

                output = json.loads(output)
                # Set the cloud id to the VM
                vm.id = output["Id"]
                vm.info.systems[0].setValue('instance_id', str(vm.id))

                # Now start it
                success, _ = self.start(vm, auth_data)
                if not success:
                    res.append(
                        (False, "Error starting the Container: " + output))
                    # Delete the container
                    conn.request('DELETE', "/containers/" + vm.id)
                    resp = conn.getresponse()
                    resp.read()
                    continue

                # Set the default user and password to access the container
                vm.info.systems[0].setValue(
                    'disk.0.os.credentials.username', 'root')
                vm.info.systems[0].setValue(
                    'disk.0.os.credentials.password', self._root_password)

                # Set ssh port in the RADL info of the VM
                vm.setSSHPort(ssh_port)

                res.append((True, vm))

            except Exception, ex:
                self.logger.exception("Error connecting with Docker server")
                res.append((False, "ERROR: " + str(ex)))

        return res

    def updateVMInfo(self, vm, auth_data):
        try:
            conn = self.get_http_connection(auth_data)
            conn.request('GET', "/containers/" + vm.id + "/json")
            resp = conn.getresponse()
            output = resp.read()
            if resp.status == 404:
                # If the container does not exist, set state to OFF
                vm.state = VirtualMachine.OFF
                return (True, vm)
            elif resp.status != 200:
                return (False, "Error getting info about the Container: " + output)

            output = json.loads(output)
            if output["State"]["Running"]:
                vm.state = VirtualMachine.RUNNING
            else:
                vm.state = VirtualMachine.STOPPED

            # Actualizamos los datos de la red
            self.setIPs(vm, output)
            return (True, vm)

        except Exception, ex:
            self.logger.exception("Error connecting with Docker server")
            self.logger.error(ex)
            return (False, "Error connecting with Docker server")

    def finalize(self, vm, auth_data):
        try:
            # First Stop it
            self.stop(vm, auth_data)

            # Now delete it
            conn = self.get_http_connection(auth_data)
            conn.request('DELETE', "/containers/" + vm.id)
            resp = conn.getresponse()
            output = str(resp.read())
            if resp.status == 404:
                self.logger.warn(
                    "Trying to remove a non existing container id: " + vm.id)
                return (True, vm.id)
            elif resp.status != 204:
                return (False, "Error deleting the Container: " + output)
            else:
                return (True, vm.id)
        except Exception:
            self.logger.exception("Error connecting with Docker server")
            return (False, "Error connecting with Docker server")

    def stop(self, vm, auth_data):
        try:
            conn = self.get_http_connection(auth_data)
            conn.request('POST', "/containers/" + vm.id + "/stop")
            resp = conn.getresponse()
            output = str(resp.read())
            if resp.status != 204:
                return (False, "Error stopping the Container: " + output)
            else:
                return (True, vm.id)
        except Exception:
            self.logger.exception("Error connecting with Docker server")
            return (False, "Error connecting with Docker server")

    def start(self, vm, auth_data):
        try:
            conn = self.get_http_connection(auth_data)
            conn.request('POST', "/containers/" + vm.id + "/start")
            resp = conn.getresponse()
            output = str(resp.read())
            if resp.status != 204:
                return (False, "Error starting the Container: " + output)
            else:
                return (True, vm.id)
        except Exception:
            self.logger.exception("Error connecting with Docker server")
            return (False, "Error connecting with Docker server")

    def alterVM(self, vm, radl, auth_data):
        return (False, "Not supported")
