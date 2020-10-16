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
import requests
import time
from uuid import uuid1
from netaddr import IPNetwork, IPAddress

from IM.config import Config

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from .CloudConnector import CloudConnector
from radl.radl import Feature, outport


class FogBowCloudConnector(CloudConnector):
    """
    Cloud Launcher to the FogBow platform
    """

    type = "FogBow"
    """str with the name of the provider."""
    DEFAULT_USER = 'fogbow'
    """ default user to SSH access the VM """

    VM_STATE_MAP = {
        'INACTIVE': VirtualMachine.STOPPED,
        'CREATING': VirtualMachine.PENDING,
        'ATTACHING': VirtualMachine.PENDING,
        'DISPATCHED': VirtualMachine.PENDING,
        'SPAWNING': VirtualMachine.PENDING,
        'READY': VirtualMachine.RUNNING,
        'IN_USE': VirtualMachine.RUNNING,
        'BUSY': VirtualMachine.RUNNING,
        'FAILED': VirtualMachine.FAILED,
        'ERROR': VirtualMachine.FAILED,
        'INCONSISTENT': VirtualMachine.UNKNOWN,
        'UNAVAILABLE': VirtualMachine.STOPPED
    }
    """Dictionary with a map with the FogBow VM states to the IM states."""

    MAX_ADD_IP_COUNT = 5
    """ Max number of retries to get a public IP """

    def __init__(self, cloud_info, inf):
        self.add_public_ip_count = 0
        self.token = None
        CloudConnector.__init__(self, cloud_info, inf)

    def get_full_url(self, url, remove_path=False):
        protocol = "http"
        if self.cloud.protocol:
            protocol = self.cloud.protocol

        if remove_path:
            path = ''
        else:
            path = self.cloud.path
        if self.cloud.port > 0:
            url = "%s://%s:%d%s%s" % (protocol, self.cloud.server, self.cloud.port, path, url)
        else:
            url = "%s://%s%s%s" % (protocol, self.cloud.server, path, url)
        return url

    def create_request(self, method, url, auth_data, headers=None, body=None):
        auth_header = self.get_auth_header(auth_data)
        if auth_header:
            if headers is None:
                headers = {}
            headers.update(auth_header)

        resp = requests.request(method, self.get_full_url(url), verify=self.verify_ssl, headers=headers, data=body)

        return resp

    def post_and_get(self, path, body, auth_data, failed_states=['FAILED', 'ERROR'], max_wait=30):
        headers = {'Content-Type': 'application/json'}
        resp = self.create_request('POST', path, auth_data, headers, body)
        if resp.status_code not in [201, 200]:
            self.log_error("Error creating %s. %s. %s." % (path, resp.reason, resp.text))
            return None
        else:
            obj_id = resp.json()['id']
            time.sleep(1)
            cont = 0
            while cont < max_wait:
                cont += 1
                resp = self.create_request('GET', '%s%s' % (path, obj_id), auth_data, headers)
                if resp.status_code != 404:
                    break
                else:
                    time.sleep(1)

            # in some cases at first stage it get an error, but then it becomes ready
            if resp.status_code == 200:
                obj_info = resp.json()
                state = None
                if 'state' in obj_info:
                    state = obj_info['state']
                if state in failed_states:
                    time.sleep(4)
                    resp = self.create_request('GET', '%s%s' % (path, obj_id), auth_data, headers)

            if resp.status_code == 200:
                obj_info = resp.json()
                state = None
                if 'state' in obj_info:
                    state = obj_info['state']
                if state in failed_states:
                    self.log_error("%s%s is in state %s." % (path, obj_id, state))
                    try:
                        resp = self.create_request('DELETE', '%s%s' % (path, obj_id), auth_data, headers)
                        if resp.status_code not in [200, 204]:
                            self.log_error("Error deleting %s%s." % (path, obj_id))
                        else:
                            self.log_info("%s%s deleted." % (path, obj_id))
                    except Exception:
                        self.log_exception("Error deleting %s%s." % (path, obj_id))
                else:
                    return obj_info
            else:
                self.log_error("Error %s%s. %s. %s." % (path, obj_id, resp.reason, resp.text))
                resp = self.create_request('DELETE', '%s%s' % (path, obj_id), auth_data, headers)
                if resp.status_code not in [200, 204]:
                    self.log_error("Error deleting %s%s." % (path, obj_id))
                else:
                    self.log_info("%s%s deleted." % (path, obj_id))

        return None

    def get_token(self, auth_data):
        headers = {'Content-Type': 'application/json'}

        if self.token:
            self.log_debug("We have a token. Check if it is valid.")
            resp = requests.request('HEAD', self.get_full_url('/clouds/'), verify=self.verify_ssl,
                                    headers={'Fogbow-User-Token': self.token})
            if resp.status_code in [200, 201]:
                return self.token
            else:
                self.log_debug("It is not valid. Request for a new one.")
                self.token = None

        if 'as_host' in auth_data:
            # if no as_host specified assume the same host and default path /as
            as_host = auth_data['as_host']
        else:
            as_host = self.get_full_url('/as', True)

        resp = requests.request('GET', self.get_full_url('/publicKey/'), verify=self.verify_ssl)
        if resp.status_code == 200:
            public_key = resp.json()['publicKey']

        body = {'publicKey': public_key, 'credentials': {}}
        for key, value in auth_data.items():
            if key not in ['id', 'type', 'host', 'as_host']:
                body['credentials'][key] = value

        resp = requests.request('POST', '%s/tokens/' % as_host, verify=self.verify_ssl,
                                headers=headers, data=json.dumps(body))
        if resp.status_code in [200, 201]:
            self.token = resp.json()['token']
            return self.token
        else:
            self.log_error("Error getting token: %s. %s" % (resp.reason, resp.text))
            raise Exception("Error getting token: %s. %s" % (resp.reason, resp.text))

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
            token = self.get_token(auth[0])

        auth_headers = {'Fogbow-User-Token': token}

        return auth_headers

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]
        src_host = url[1].split(':')[0]

        if protocol == "fbw" and self.cloud.server == src_host:
            res_system = radl_system.clone()

            res_system.delValue('disk.0.os.credentials.username')
            res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)

            return res_system
        else:
            return None

    def get_fbw_nets(self, auth_data, fed=False, fetch=False):
        """
        Get a dict with the name and ID of the fogbow nets
        """
        fbw_nets = {}
        if fed:
            resp = self.create_request('GET', '/federatedNetworks/status', auth_data)
        else:
            resp = self.create_request('GET', '/networks/status', auth_data)
        if resp.status_code == 200:
            if fetch:
                for net in resp.json():
                    if fed:
                        resp = self.create_request('GET', '/federatedNetworks/%s' % net['instanceId'], auth_data)
                    else:
                        resp = self.create_request('GET', '/networks/%s' % net['instanceId'], auth_data)
                    if resp.status_code == 200:
                        fbw_nets[net['instanceName']] = resp.json()
                    else:
                        self.log_error("Error getting network info ID %s: %s" % (net['instanceId'], resp.text))
                        fbw_nets[net['instanceName']] = net['instanceId']
            else:
                for net in resp.json():
                    fbw_nets[net['instanceName']] = net['instanceId']

        else:
            raise Exception("Error getting networks: %s. %s" % (resp.reason, resp.text))
        return fbw_nets

    def create_nets(self, inf, radl, auth_data):
        fbw_nets = self.get_fbw_nets(auth_data, False, True)
        fbw_fed_nets = self.get_fbw_nets(auth_data, True, True)
        member = radl.systems[0].getValue('availability_zone')
        if member:
            if '@' in member:
                parts = member.split('@')
                member = parts[1]

        for net in radl.networks:
            net_name = "im_%s_%s" % (inf.id, net.id)
            if net.getValue("federated") == "yes":
                if net_name in fbw_fed_nets:
                    self.log_info("Fed Net %s exists in FogBow do not create it again." % net_name)
                    if not net.getValue("provider_id"):
                        net.setValue("provider_id", fbw_fed_nets[net_name]["id"])
                else:
                    self.log_info("Creating federated net %s." % net_name)
                    used_cidrs = [elem['cidr'] for elem in list(fbw_fed_nets.values())]
                    cidr = self.get_free_cidr(net.getValue("cidr"), used_cidrs, inf)

                    body = {"name": net_name, "cidr": cidr}
                    net_providers = net.getValue("providers")
                    if net_providers:
                        if isinstance(net_providers, list):
                            body["providers"] = net_providers
                        else:
                            body["providers"] = [a.strip() for a in net_providers.split(",")]
                    self.log_debug(body)
                    net_info = self.post_and_get('/federatedNetworks/', json.dumps(body), auth_data)
                    if net_info:
                        net.setValue("provider_id", net_info['instanceId'])
                        net.setValue('cidr', cidr)
                        # Set also the cidr in the inf RADL
                        inf.radl.get_network_by_id(net.id).setValue('cidr', cidr)
                    else:
                        self.log_error("Error creating federated net %s." % net_name)
            elif not net.isPublic():
                if net_name in fbw_nets:
                    self.log_info("Net %s exists in FogBow do not create it again." % net_name)
                    if not net.getValue("provider_id"):
                        net.setValue("provider_id", fbw_nets[net_name]["id"])
                else:
                    self.log_info("Creating net %s." % net_name)

                    body = {"allocationMode": "dynamic", "name": net_name}
                    if member:
                        body['provider'] = member
                    self.log_debug(body)

                    net_info = self.post_and_get('/networks/', json.dumps(body), auth_data)
                    if net_info:
                        self.log_debug("Network %s created successfully." % net_info['id'])
                        net.setValue("provider_id", net_info['id'])
                        self.create_security_rules("networks", net, net_info['id'], auth_data)
                    else:
                        self.log_error("Error creating net %s." % net_name)

    def create_security_rules(self, path, net, obj_id, auth_data):
        """
        Create security rules for a net
        """
        # First get the current opened ports
        resp = self.create_request('GET', '/%s/%s/securityRules' % (path, obj_id), auth_data)
        sec_groups = []
        if resp.status_code == 200:
            sec_groups = resp.json()

        outports = net.getOutPorts()

        if path == "publicIps":
            if outports is None:
                outports = []
            outports.append(outport(22, 22, 'tcp'))

        if outports:
            for op in outports:
                body = {"cidr": "0.0.0.0/0",
                        "direction": "IN",
                        "etherType": "IPv4",
                        "protocol": op.get_protocol().upper()
                        }

                if op.is_range():
                    body["portTo"] = op.get_port_init()
                    body["portFrom"] = op.get_port_end()
                else:
                    body["portTo"] = op.get_remote_port()
                    body["portFrom"] = op.get_remote_port()

                if body not in sec_groups:
                    headers = {'Content-Type': 'application/json'}
                    resp = self.create_request('POST', '/%s/%s/securityRules' % (path, obj_id),
                                               auth_data, headers, json.dumps(body))
                    if resp.status_code not in [201, 200]:
                        self.log_error("Error creating Security Rule in %s. %s. %s." % (resp.reason,
                                                                                        path, resp.text))

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        system = radl.systems[0]
        res = []
        i = 0

        image = os.path.basename(system.getValue("disk.0.image.url"))

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
        requirements = {}
        sgx = system.getValue('cpu.sgx.epc_size')
        if sgx:
            requirements["sgx:epc_size"] = str(sgx)
        gpu = system.getValue('gpu.count')
        if gpu:
            requirements["gpu"] = "true"

        with inf._lock:
            self.create_nets(inf, radl, auth_data)

        while i < num_vm:
            try:
                headers = {'Content-Type': 'application/json'}

                nets = []
                fed_net = None
                for net in radl.networks:
                    if not net.isPublic() and radl.systems[0].getNumNetworkWithConnection(net.id) is not None:
                        provider_id = net.getValue('provider_id')
                        if provider_id:
                            if net.getValue("federated") == "yes":
                                fed_net = provider_id
                            else:
                                nets.append(provider_id)

                body = {"compute":
                        {"imageId": image,
                         "memory": memory,
                         "name": self.gen_instance_name(system),
                         "publicKey": public_key,
                         "vCPU": cpu}
                        }

                if requirements:
                    body["compute"]["requirements"] = requirements
                if nets:
                    body["compute"]["networkIds"] = nets
                if fed_net:
                    body["federatedNetworkId"] = fed_net

                if system.getValue('availability_zone'):
                    if '@' in system.getValue('availability_zone'):
                        parts = system.getValue('availability_zone').split('@')
                        body["compute"]['cloudName'] = parts[0]
                        body["compute"]['provider'] = parts[1]
                    else:
                        body["compute"]['provider'] = system.getValue('availability_zone')

                self.log_debug(body)

                resp = self.create_request('POST', '/computes/', auth_data, headers, json.dumps(body))

                if resp.status_code not in [201, 200]:
                    res.append((False, resp.reason + "\n" + resp.text))
                else:
                    vm = VirtualMachine(inf, str(resp.json()['id']), self.cloud, radl, requested_radl)
                    vm.info.systems[0].setValue('instance_id', str(vm.id))
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
            while vol_state != state and vol_state not in ["FAILED", "ERROR"] and count < timeout:
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
                vm.attachments = []
                cont = 1
                while (vm.info.systems[0].getValue("disk." + str(cont) + ".size") or
                       vm.info.systems[0].getValue("disk." + str(cont) + ".image.url")):
                    disk_size = None
                    if vm.info.systems[0].getValue("disk." + str(cont) + ".size"):
                        disk_size = vm.info.systems[0].getFeature("disk." + str(cont) + ".size").getValue('G')
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
                        except Exception:
                            success = False
                            self.log_exception("Error getting volume ID %s" % volume_id)
                    else:
                        self.log_info("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
                        volume_name = "im-%s" % str(uuid1())

                        body = '{"name": "%s", "size": %d}' % (volume_name, int(disk_size))
                        self.log_debug(body)
                        resp = self.create_request('POST', '/volumes/', auth_data, headers, body)

                        if resp.status_code not in [201, 200]:
                            self.log_error("Error creating volume: %s. %s" % (resp.reason, resp.text))
                        else:
                            volume_id = resp.json()['id']

                        success = self.wait_volume(volume_id, auth_data)
                        if success:
                            # Add the volume to the VM to remove it later
                            vm.volumes.append(volume_id)

                    if success:
                        self.log_info("Attach the volume ID %s" % volume_id)
                        body = '{"computeId": "%s","device": "%s","volumeId": "%s"}' % (vm.id, disk_device, volume_id)
                        self.log_debug(body)
                        attach_info = self.post_and_get('/attachments/', body, auth_data)
                        if attach_info:
                            vm.attachments.append(attach_info['id'])
                            disk_device = attach_info["device"]
                            if disk_device:
                                vm.info.systems[0].setValue("disk." + str(cont) + ".device", disk_device)
                        else:
                            success = False

                    if not success:
                        self.log_error("Error waiting the volume ID not attaching to the VM.")
                        if not disk_url:
                            self.log_error("Destroying it.")
                            resp = self.create_request('DELETE', '/volumes/%s' % volume_id, auth_data, headers)
                            if resp.status_code not in [204, 200, 404]:
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
        try:
            headers = {'Accept': 'application/json'}
            resp = self.create_request('GET', '/publicIps/status', auth_data, headers=headers)
            if resp.status_code == 200:
                for ipstatus in resp.json():
                    resp_ip = self.create_request('GET', '/publicIps/%s' % ipstatus['instanceId'], auth_data)
                    if resp_ip.status_code == 200:
                        ipdata = resp_ip.json()
                        if ipdata['state'] in ['FAILED', 'ERROR']:
                            try:
                                self.log_warn("Public IP id: %s is FAILED. Trying to delete." % ipstatus['instanceId'])
                                resp_del = self.create_request('DELETE', '/publicIps/%s' % ipstatus['instanceId'],
                                                               auth_data, headers)
                                if resp_del.status_code in [200, 204]:
                                    self.log_info("Public IP id: %s deleted." % ipstatus['instanceId'])
                                else:
                                    self.log_warn("Error deleting public IP id: %s. %s. %s." % (ipstatus['instanceId'],
                                                                                                resp.reason, resp.text))
                            except Exception:
                                self.log_warn("Error deleting public IP id: %s" % ipstatus['instanceId'])

                        elif ipdata['computeId'] == vm_id:
                            res.append(ipdata[field])
                    else:
                        self.log_error("Error getting public IP info: %s. %s." % (resp.reason, resp.text))
            else:
                self.log_error("Error getting public IP info: %s. %s." % (resp.reason, resp.text))
        except Exception:
            self.log_exception("Error getting public IP info")
        return res

    def add_elastic_ip(self, vm, public_ips, member, auth_data):
        """
        Get a public IP if needed.
        """
        if self.add_public_ip_count >= self.MAX_ADD_IP_COUNT:
            self.log_error("Error adding a floating IP: Max number of retries reached.")
            self.error_messages += "Error adding a floating IP: Max number of retries reached.\n"
            return None

        if not public_ips and vm.hasPublicNet() and vm.state == VirtualMachine.RUNNING:
            self.log_debug("VM ID %s requests a public IP and it does not have it. Requesting the IP." % vm.id)
            body = {"computeId": vm.id}
            if member:
                body['provider'] = member

            self.log_debug(body)
            ip_info = self.post_and_get('/publicIps/', json.dumps(body), auth_data)
            if ip_info:
                self.log_debug("IP obtained: %s." % ip_info['ip'])
                # Open ports for public IPs
                for net in vm.info.networks:
                    if net.isPublic() and vm.info.systems[0].getNumNetworkWithConnection(net.id) is not None:
                        self.create_security_rules('publicIps', net, ip_info['id'], auth_data)
                return ip_info['ip']
            else:
                self.add_public_ip_count += 1
                self.log_warn("Error adding a floating IP the VM: (%d/%d)\n" % (self.add_public_ip_count,
                                                                                self.MAX_ADD_IP_COUNT))
                self.error_messages += "Error adding a floating IP: (%d/%d)\n" % (self.add_public_ip_count,
                                                                                  self.MAX_ADD_IP_COUNT)
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

                if "vCPU" in output and output["vCPU"]:
                    vm.info.systems[0].addFeature(Feature(
                        "cpu.count", "=", output["vCPU"]), conflict="other", missing="other")
                if "memory" in output and output["memory"]:
                    vm.info.systems[0].addFeature(Feature(
                        "memory.size", "=", output["memory"], 'M'), conflict="other", missing="other")
                if "disk" in output and output["disk"]:
                    vm.info.systems[0].addFeature(Feature(
                        "disk.0.size", "=", output["disk"], 'G'), conflict="other", missing="other")

                # Update the network data
                private_ips = []
                public_ips = []
                if "ipAddresses" in output and output["ipAddresses"]:
                    for ip in output["ipAddresses"]:
                        is_public = not (any([IPAddress(ip) in IPNetwork(mask)
                                              for mask in Config.PRIVATE_NET_MASKS]))
                        if is_public:
                            public_ips.append(ip)
                        else:
                            private_ips.append(ip)

                member = None
                if "provider" in output and output["provider"]:
                    member = output["provider"]
                cloud = None
                if "cloudName" in output and output["cloudName"]:
                    cloud = output["cloudName"]

                if member or cloud:
                    availability_zone = "%s@%s" % (cloud if cloud else "", member if member else "")
                    vm.info.systems[0].setValue('availability_zone', availability_zone)

                ip = self.add_elastic_ip(vm, public_ips, member, auth_data)
                if ip:
                    public_ips.append(ip)

                fed_net_name = None
                if private_ips and "federatedIp" in output and output["federatedIp"]:
                    for net in vm.info.networks:
                        if net.getValue("federated") == "yes":
                            fed_net_name = net.id
                            num_net = vm.getNumNetworkWithConnection(net.id)
                            if num_net is not None:
                                vm.info.systems[0].setValue('net_interface.%s.ip' % num_net, str(output["federatedIp"]))

                vm.setIps(public_ips, private_ips, ignore_nets=[fed_net_name])

                self.attach_volumes(vm, auth_data)

                return (True, vm)
        except Exception as ex:
            self.log_exception("Error connecting with FogBow Manager")
            return (False, "Error connecting with FogBow Manager: %s" % ex)

    def finalize(self, vm, last, auth_data):
        if not vm.id:
            self.log_warn("No VM ID. Ignoring")
            return True, "No VM ID. Ignoring"

        public_ips = self._get_instance_public_ips(vm.id, auth_data, "id")

        res = (True, "")
        try:
            # First delete the public IPs
            retries = 3
            success = False
            cont = 0
            while not success and cont < retries:
                cont += 1
                success = self.delete_public_ips(vm.id, public_ips, auth_data)
            if not success:
                res = (False, "Error deleting Public IPs")

            # then delete the attachments
            success = False
            cont = 0
            while not success and cont < retries:
                cont += 1
                success = self.delete_attachments(vm, auth_data)
            if not success:
                msg = res[1]
                res = (False, "%s%sError deleting attachments." % (msg, "\n" if msg else ""))

            resp = self.create_request('DELETE', "/computes/" + vm.id, auth_data)

            if resp.status_code == 404:
                vm.state = VirtualMachine.OFF
            elif resp.status_code not in [200, 204]:
                msg = res[1]
                res = (False, "%s%sError removing the VM: %s, %s." % (msg, "\n" if msg else "",
                                                                      resp.reason, resp.text))

            # then delete the volumes
            success = False
            cont = 0
            while not success and cont < retries:
                cont += 1
                success = self.delete_volumes(vm, auth_data)
            if not success:
                msg = res[1]
                res = (False, "%s%sError deleting Volumes." % (msg, "\n" if msg else ""))

            if last:
                success = False
                cont = 0
                while not success and cont < retries:
                    cont += 1
                    success = self.delete_nets(vm, auth_data)
                if not success:
                    msg = res[1]
                    res = (False, "%s%sError deleting Networks." % (msg, "\n" if msg else ""))

            return res
        except Exception as ex:
            self.log_exception("Error connecting with FogBow server")
            return (False, "Error connecting with FogBow server: %s" % ex)

    def delete_nets(self, vm, auth_data):
        """
        Delete the created nets
        """
        try:
            fbw_nets = self.get_fbw_nets(auth_data)
            fbw_fed_nets = self.get_fbw_nets(auth_data, True)
        except Exception:
            self.log_exception("Error getting FogBow nets.")
            fbw_nets = {}
            fbw_fed_nets = {}
        success = True
        try:
            for net in vm.info.networks:
                if not net.isPublic():
                    net_name = "im_%s_%s" % (vm.inf.id, net.id)
                    resp = None
                    if net_name in fbw_nets:
                        net_id = fbw_nets[net_name]
                        resp = self.create_request('DELETE', '/networks/%s' % net_id, auth_data)
                    if net_name in fbw_fed_nets:
                        net_id = fbw_fed_nets[net_name]
                        resp = self.create_request('DELETE', '/federatedNetworks/%s' % net_id, auth_data)

                    if resp:
                        if resp.status_code not in [200, 204, 404]:
                            success = False
                            self.log_error("Error deleting net %s: %s. %s." % (net_name, resp.reason, resp.text))
                        else:
                            self.log_info("Net %s: Successfully deleted." % net_name)
                    else:
                        self.log_warn("Net %s not appears in the list of FogBow nets." % net_name)
        except Exception:
            success = False
            self.log_exception("Error deleting net %s." % net_name)
        return success

    def delete_attachments(self, vm, auth_data):
        """
        Delete the attachments of a VM
        """
        all_ok = True
        if "attachments" in vm.__dict__.keys() and vm.attachments:
            for attachmentid in vm.attachments:
                self.log_debug("Deleting attachment ID %s" % attachmentid)
                try:
                    resp = self.create_request('DELETE', '/attachments/%s' % attachmentid, auth_data)
                    if resp.status_code not in [200, 204, 404]:
                        success = False
                        raise Exception(resp.reason + "\n" + resp.text)
                    else:
                        success = True
                except Exception:
                    self.log_exception("Error destroying attachment: %s from the node: %s" % (attachmentid, vm.id))
                    success = False

                if not success:
                    all_ok = False
        return all_ok

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
                except Exception:
                    self.log_exception("Error destroying the volume: " + str(volumeid) +
                                       " from the node: " + str(vm.id))
                    success = False

                if not success:
                    all_ok = False
        return all_ok

    def delete_public_ips(self, vm_id, public_ips, auth_data):
        """
        Release the public IPs of this VM
        """
        all_ok = True
        for ip_id in public_ips:
            try:
                self.log_info("Deleting IP with ID: %s" % ip_id)
                resp = self.create_request('DELETE', '/publicIps/%s' % ip_id, auth_data)
                if resp.status_code not in [200, 204, 404]:
                    success = False
                    raise Exception(resp.reason + "\n" + resp.text)
                success = True
            except Exception:
                self.log_exception("Error releasing the IP: " + str(ip_id) +
                                   " from the node: " + str(vm_id))
                success = False
            if not success:
                all_ok = False
        return all_ok

    def stop(self, vm, auth_data):
        return (False, "Not supported")

    def start(self, vm, auth_data):
        return (False, "Not supported")

    def reboot(self, vm, auth_data):
        return (False, "Not supported")

    def alterVM(self, vm, radl, auth_data):
        return (False, "Not supported")
