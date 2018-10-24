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
import time
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
        'INACTIVE': VirtualMachine.STOPPED,
        'CREATING': VirtualMachine.PENDING,
        'ATTACHING': VirtualMachine.PENDING,
        'DISPATCHED': VirtualMachine.PENDING,
        'SPAWNING': VirtualMachine.PENDING,
        'READY': VirtualMachine.RUNNING,
        'IN_USE': VirtualMachine.RUNNING,
        'FAILED': VirtualMachine.FAILED,
        'INCONSISTENT': VirtualMachine.UNKNOWN,
        'UNAVAILABLE': VirtualMachine.STOPPED
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

                body = {"computeOrder":
                        {"imageId": image,
                         "memory": memory,
                         "name": "%s-%s" % (name.lower().replace("_", "-"), str(uuid1())),
                         "publicKey": public_key,
                         "vCPU": cpu}
                        }

                if nets:
                    body["networkIds"] = nets

                if system.getValue('availability_zone'):
                    body['provider'] = system.getValue('availability_zone')

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

    def wait_volume(self, volume_id, auth_data, state='READY', timeout=60, delay=5):
        """
        Wait a volume to be in certain state.
        """
        if volume_id:
            count = 0
            vol_state = ""
            while vol_state != state and vol_state != "FAILED" and count < timeout:
                time.sleep(delay)
                count += delay
                resp = self.create_request('GET', '/volumes/%s' % volume_id, auth_data)
                if resp.status_code != 200:
                    self.log_error("Error getting volume state: %s. %s." % (resp.reason, resp.text))
                    return False
                else:
                    vol_state = resp.json()["state"]

            return vol_state == state
        else:
            return False

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

                        success = self.wait_volume(volume_id, auth_data)
                        if success:
                            # Add the volume to the VM to remove it later
                            vm.volumes.append(volume_id)

                    if success:
                        self.log_debug("Attach the volume ID %s" % volume_id)
                        body = '{"computeId": "%s","device": "%s","volumeId": "%s"}' % (vm.id, disk_device, volume_id)
                        resp = self.create_request('POST', '/attachments/', auth_data, headers, body)

                        # wait the volume to be attached
                        if resp.status_code not in [201, 200]:
                            self.log_error("Error attaching volume: %s. %s" % (resp.reason, resp.text))
                        else:
                            disk_device = resp.json()["device"]

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

    def _get_instance_public_ips(self, vm_id, auth_data, field="ip"):
        """
        Get the IPs associated with the compute specified
        """
        res = []
        headers = {'Accept': 'application/json'}
        resp = self.create_request('GET', '/publicIps/status', auth_data, headers=headers)
        if resp.status_code == 200:
            for ipstatus in resp.json():
                resp_ip = self.create_request('GET', '/publicIps/%s' % ipstatus['instanceId'], auth_data, headers=headers)
                if resp_ip.status_code == 200:
                    ipdata = resp_ip.json()
                    if ipdata['computeId'] == vm_id:
                        res.append(ipdata[field])
                else:
                    self.log_error("Error getting public IP info: %s. %s." % (resp.reason, resp.text))
        else:
            self.log_error("Error getting public IP info: %s. %s." % (resp.reason, resp.text))
        return res

    def add_elastic_ip(self, vm, public_ips, auth_data):
        """
        Get a public IP if needed.
        """
        if not public_ips and vm.hasPublicNet():
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

                if output["vCPU"]:
                    vm.info.systems[0].addFeature(Feature(
                        "cpu.count", "=", output["vCPU"]), conflict="other", missing="other")
                if output["ram"]:
                    vm.info.systems[0].addFeature(Feature(
                        "memory.size", "=", output["ram"], 'M'), conflict="other", missing="other")

                # Update the network data
                private_ips = []
                if output["localIpAddress"]:
                    private_ips.append(output["localIpAddress"])
                public_ips = self._get_instance_public_ips(vm.id, auth_data)

                if 'providingMember' in output:
                    vm.info.systems[0].setValue('availability_zone', output['providingMember'])

                ip = self.add_elastic_ip(vm, public_ips, auth_data)
                if ip:
                    public_ips.append(ip)
                vm.setIps(public_ips, private_ips)

                self.attach_volumes(vm, auth_data)

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
                res = (True, "")
            elif resp.status_code not in [200, 204]:
                res = (False, "Error removing the VM: " + resp.reason + "\n" + resp.text)
            else:
                res = (True, "")

            self.delete_volumes(vm, auth_data)
            self.delete_public_ips(vm, auth_data)

            return res
        except Exception as ex:
            self.log_exception("Error connecting with FogBow server")
            return (False, "Error connecting with FogBow server: %s" % ex.message)

    def delete_volumes(self, vm, auth_data):
        """
        Delete the volumes of a VM
        """
        all_ok = True
        if "volumes" in vm.__dict__.keys() and vm.volumes:
            for volumeid in vm.volumes:
                self.log_debug("Deleting volume ID %s" % volumeid)
                try:
                    resp = self.create_request('DELETE', '/volumes/%s' % volumeid, auth_data)
                    if resp.status_code not in [200, 204, 404]:
                        success = False
                        raise Exception(resp.reason + "\n" + resp.text)
                    else:
                        success = True
                except:
                    self.log_exception("Error destroying the volume: " + str(volumeid) +
                                       " from the node: " + str(vm.id))
                    success = False

                if not success:
                    all_ok = False
        return all_ok

    def delete_public_ips(self, vm, auth_data):
        """
        Release the public IPs of this VM
        """
        all_ok = True
        public_ips = self._get_instance_public_ips(vm.id, auth_data, "id")
        for ip_id in public_ips:
            try:
                resp = self.create_request('DELETE', '/publicIps/%s' % ip_id, auth_data)
                if resp.status_code not in [200, 204, 404]:
                    success = False
                    raise Exception(resp.reason + "\n" + resp.text)
                else:
                    success = True
                success = True
            except:
                self.log_exception("Error releasing the IP: " + str(ip_id) +
                                   " from the node: " + str(vm.id))
                success = False
            if not success:
                all_ok = False
        return all_ok

    def stop(self, vm, auth_data):
        return (False, "Not supported")

    def start(self, vm, auth_data):
        return (False, "Not supported")

    def alterVM(self, vm, radl, auth_data):
        return (False, "Not supported")
