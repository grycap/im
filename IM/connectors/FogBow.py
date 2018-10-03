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
import os
import sys
import requests
import base64
from uuid import uuid1

from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from .CloudConnector import CloudConnector
from radl.radl import Feature


class FogBowCloudConnector(CloudConnector):
    """
    Cloud Launcher to the FogBow platform
    """

    type = "FogBow"
    """str with the name of the provider."""

    VM_STATE_MAP = {
        'DISPATCHED': VirtualMachine.RUNNING,
        'READY': VirtualMachine.RUNNING,
        'INACTIVE': VirtualMachine.PENDING,
        'SPAWNING': VirtualMachine.PENDING,
        'CREATING': VirtualMachine.PENDING,
        'ATTACHING': VirtualMachine.RUNNING,
        'IN_USE': VirtualMachine.RUNNING,
        'UNAVAILABLE': VirtualMachine.STOPPED,
        'FAILED': VirtualMachine.FAILED,
        'INCONSISTENT': VirtualMachine.FAILED
    }
    """Dictionary with a map with the FogBow VM states to the IM states."""

    def create_request(self, method, url, auth_data, headers=None, body=None):
        auth_header = self.get_auth_header(auth_data)
        if auth_header:
            if headers is None:
                headers = {}
            headers.update(auth_header)

        protocol = "http"
        if self.cloud.protocol:
            protocol = self.cloud.protocol

        url = "%s://%s:%d%s%s" % (protocol, self.cloud.server, self.cloud.port, self.cloud.path, url)
        resp = requests.request(method, url, verify=self.verify_ssl, headers=headers, data=body)

        return resp

    def get_auth_header(self, auth_data):
        """
        Generate the auth header needed to contact with the FogBow server.
        """
        auth = auth_data.getAuthInfo(FogBowCloudConnector.type)
        if not auth:
            raise Exception("No correct auth data has been specified to FogBow.")

        if 'token' in auth[0]:
            token = auth[0]['token']
        else:
            self.log_error("No correct auth data has been specified to FogBow: token")
            self.log_debug(auth)
            raise Exception("No correct auth data has been specified to FogBow: token")

        auth_headers = {'federationTokenValue': token}

        return auth_headers

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
                if protocol in ['fbw']:
                    res_system = radl_system.clone()

                    res_system.addFeature(
                        Feature("disk.0.image.url", "=", str_url), conflict="other", missing="other")

                    res_system.addFeature(
                        Feature("provider.type", "=", self.type), conflict="other", missing="other")
                    res_system.addFeature(Feature(
                        "provider.host", "=", self.cloud.server), conflict="other", missing="other")
                    res_system.addFeature(Feature(
                        "provider.port", "=", self.cloud.port), conflict="other", missing="other")

                    res_system.delValue('disk.0.os.credentials.username')
                    res_system.setValue('disk.0.os.credentials.username', 'fogbow')

                    res.append(res_system)

            return res

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        system = radl.systems[0]
        res = []
        i = 0

        url = uriparse(system.getValue("disk.0.image.url"))
        if url[1].startswith('http'):
            image = url[1] + url[2]
        else:
            image = url[1]

        # set the credentials the FogBow default username: fogbow
        system.delValue('disk.0.os.credentials.username')
        system.setValue('disk.0.os.credentials.username', 'fogbow')

        public_key = system.getValue('disk.0.os.credentials.public_key')

        if not public_key:
            # We must generate them
            (public_key, private_key) = self.keygen()
            system.setValue('disk.0.os.credentials.private_key', private_key)

        cpu = system.getValue('cpu.count')
        memory = system.getFeature('memory.size').getValue('M')
        name = system.getValue("instance_name")
        if not name:
            name = system.getValue("disk.0.image.name")
        if not name:
            name = "userimage"

        while i < num_vm:
            try:
                headers = {'Content-Type': 'application/json'}

                nets = []
                for net in radl.networks:
                    if not net.isPublic() and radl.systems[0].getNumNetworkWithConnection(net.id) is not None:
                        provider_id = net.getValue('provider_id')
                        if provider_id:
                            nets.append(provider_id)

                body = {
                    "imageId": image,
                    "memory": memory,
                    "name": "%s-%s" % (name.lower().replace("_", "-"), str(uuid1())),
                    "publicKey": public_key,
                    "vCPU": cpu
                    }

                if nets:
                    body["networkIds"] = nets

                resp = self.create_request('POST', '/computes/', auth_data, headers, json.dumps(body))

                if resp.status_code not in [201, 200]:
                    res.append((False, resp.reason + "\n" + resp.text))
                else:
                    output = resp.json()
                    vm = VirtualMachine(inf, output["id"], self.cloud, radl, requested_radl)
                    vm.info.systems[0].setValue('instance_id', str(output["id"]))
                    inf.add_vm(vm)
                    res.append((True, vm))

            except Exception as ex:
                self.log_exception("Error connecting with FogBow manager")
                res.append((False, "ERROR: " + str(ex)))

            i += 1

        return res

    def attach_volumes(self, vm, auth_data):
        """
        Attach a the required volumes (in the RADL) to the launched node

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - node(:py:class:`libcloud.compute.base.Node`): node object.
        """
        try:
            headers = {'Content-Type': 'application/json'}
            if "volumes" not in vm.__dict__.keys():
                vm.volumes = []
                cont = 1
                while (vm.info.systems[0].getValue("disk." + str(cont) + ".size") or
                       vm.info.systems[0].getValue("disk." + str(cont) + ".image.url")):
                    disk_size = None
                    if vm.info.systems[0].getValue("disk." + str(cont) + ".size"):
                        disk_size = vm.info.systems[0].getFeature("disk." + str(cont) + ".size").getValue('M')
                    disk_device = vm.info.systems[0].getValue("disk." + str(cont) + ".device")
                    disk_url = vm.info.systems[0].getValue("disk." + str(cont) + ".image.url")
                    if disk_device:
                        disk_device = "/dev/" + disk_device
                    else:
                        disk_device = "/dev/hdb"
                    if disk_url:
                        volume_id = os.path.basename(disk_url)
                        try:
                            resp = self.create_request('GET', '/volumes/%s' % volume_id, auth_data, headers)
                            resp.raise_for_status()
                            success = True
                        except:
                            success = False
                            self.log_exception("Error getting volume ID %s" % volume_id)
                    else:
                        self.log_debug("Creating a %d MB volume for the disk %d" % (int(disk_size), cont))
                        volume_name = "im-%s" % str(uuid1())

                        body = '{"name": "%s", "volumeSize": %d}' % (volume_name, int(disk_size))
                        resp = self.create_request('POST', '/volumes/', auth_data, headers, body)

                        if resp.status_code not in [201, 200]:
                            self.log_error("Error creating volume: %s. %s" % (resp.reason, resp.text))
                        else:
                            volume_id = resp.json()["id"]

                        success = self.wait_volume(volume_id)
                        if success:
                            # Add the volume to the VM to remove it later
                            vm.volumes.append(volume_id)

                    if success:
                        self.log_debug("Attach the volume ID %s" % volume_id)
                        body = '{"computeId": "%s","device": "%s","volumeId": "%s"}' % (vm.id, disk_device, volume_id)
                        resp = self.create_request('POST', '/attachment/', auth_data, headers, body)

                        # wait the volume to be attached
                        if resp.status_code not in [201, 200]:
                            self.log_error("Error attaching volume: %s. %s" % (resp.reason, resp.text))
                        else:
                            attach_id = resp.json()["id"]

                        vm.info.systems[0].setValue("disk." + str(cont) + ".device", disk_device)
                    else:
                        self.log_error("Error waiting the volume ID not attaching to the VM.")
                        if not disk_url:
                            self.log_error("Destroying it.")
                            resp = self.create_request('DELETE', '/volumes/%s' % volume_id, auth_data, headers)
                            if resp.status_code not in [204, 200]:
                                self.log_error("Error deleting volume: %s. %s" % (resp.reason, resp.text))

                    cont += 1
            return True
        except Exception:
            self.log_exception("Error creating or attaching the volume to the node")
            return False

    def _get_instance_public_ips(self, vm_id, auth_data):
        """
        Get the IPs associated with the compute specified
        """
        return []

    def manage_elastic_ip(self, vm, public_ips, auth_data):
        """
        Get a public IP if needed.
        """
        if not public_ips and vm.getRequestedSystem().hasPublicNet():
            self.log_debug("VM ID %s requests a public IP and it does not have it. Requesting the IP." % vm.id)
            headers = {'Accept': 'application/json'}
            body = '{"computeOrderId": "%s"}' % vm.id
            resp = self.create_request('POST', "/publicIps/", auth_data, headers=headers, body=body)
            if resp.status_code not in [201, 200]:
                self.log_error("Error getting a public IP: %s. %s." % (resp.reason, resp.text))
                return None
            else:
                ip = resp.json()["ip"]
                self.log_debug("IP obtained: %s." % ip)
                return ip

        return None

    def updateVMInfo(self, vm, auth_data):
        try:
            # First get the request info
            headers = {'Accept': 'application/json'}
            resp = self.create_request('GET', "/computes/" + vm.id, auth_data, headers=headers)

            if resp.status_code != 200:
                return (False, resp.reason + "\n" + resp.text)
            else:
                output = resp.json()
                vm.state = self.VM_STATE_MAP.get(output["state"], VirtualMachine.UNKNOWN)
                
                # Update the network data
                private_ips = []
                if output["localIpAddress"]:
                    private_ips.append(output["localIpAddress"])
                public_ips = self._get_instance_public_ips(vm.id, auth_data)
                
                self.manage_elastic_ip(vm, public_ips, auth_data)
                vm.setIps(public_ips, private_ips)

                return (True, vm)
        except Exception as ex:
            self.log_exception("Error connecting with FogBow Manager")
            return (False, "Error connecting with FogBow Manager: %s" % ex.message)

    def finalize(self, vm, last, auth_data):
        if not vm.id:
            self.log_warn("No VM ID. Ignoring")
            return True, "No VM ID. Ignoring"

        headers = {'Accept': 'text/plain'}

        try:
            resp = self.create_request('DELETE', "/computes/" + vm.id, auth_data, headers=headers)

            if resp.status_code == 404:
                vm.state = VirtualMachine.OFF
                return (True, "")
            elif resp.status_code not in [200, 204]:
                return (False, "Error removing the VM: " + resp.reason + "\n" + resp.text)
            else:
                return (True, "")
        except Exception as ex:
            self.log_exception("Error connecting with FogBow server")
            return (False, "Error connecting with FogBow server: %s" % ex.message)

    def stop(self, vm, auth_data):
        return (False, "Not supported")

    def start(self, vm, auth_data):
        return (False, "Not supported")

    def alterVM(self, vm, radl, auth_data):
        return (False, "Not supported")
