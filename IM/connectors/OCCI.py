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

import random
import time
import os
import re
import base64
import tempfile
import uuid
import json
import requests
from netaddr import IPNetwork, IPAddress
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from .CloudConnector import CloudConnector
from IM.AppDB import AppDB
from IM.config import Config


class OCCICloudConnector(CloudConnector):
    """
    Cloud Launcher to the OCCI platform (FedCloud)
    """

    type = "OCCI"
    """str with the name of the provider."""
    INSTANCE_TYPE = 'small'
    """str with the name of the default instance type to launch."""
    DEFAULT_USER = 'cloudadm'
    """ default user to SSH access the VM """
    MAX_ADD_IP_COUNT = 5
    """ Max number of retries to get a public IP """

    VM_STATE_MAP = {
        'waiting': VirtualMachine.PENDING,
        'active': VirtualMachine.RUNNING,
        'inactive': VirtualMachine.OFF,
        'error': VirtualMachine.FAILED,
        'suspended': VirtualMachine.STOPPED
    }
    """Dictionary with a map with the OCCI VM states to the IM states."""
    PUBLIC_NET_NAMES = ["public", "PUBLIC", "floating"]

    def __init__(self, cloud_info, inf):
        self.add_public_ip_count = 0
        self.keystone_token = None
        if cloud_info.path.endswith("/"):
            cloud_info.path = cloud_info.path[:-1]
        CloudConnector.__init__(self, cloud_info, inf)

    @staticmethod
    def create_request_static(method, url, auth, headers, verify=False, body=None):
        if auth and 'proxy' in auth:
            proxy = auth['proxy']

            (fproxy, proxy_filename) = tempfile.mkstemp()
            os.write(fproxy, proxy.encode())
            os.close(fproxy)
            cert = proxy_filename
        else:
            cert = None

        if auth and "token" in auth:
            headers.update({'Authorization': 'Bearer ' + auth["token"]})

        try:
            resp = requests.request(method, url, verify=verify, cert=cert, headers=headers, data=body)
        finally:
            if cert:
                try:
                    os.unlink(cert)
                except Exception:
                    pass

        return resp

    def create_request(self, method, url, auth_data, headers, body=None):
        if not url.startswith("http://") and not url.startswith("https://"):
            if self.cloud.port > 0:
                url = "%s://%s:%d%s" % (self.cloud.protocol, self.cloud.server, self.cloud.port, url)
            else:
                url = "%s://%s%s" % (self.cloud.protocol, self.cloud.server, url)

        if auth_data:
            auths = auth_data.getAuthInfo(self.type, self.cloud.server)
            if not auths:
                raise Exception("No correct auth data has been specified to OCCI.")
            else:
                auth = auths[0]
        else:
            auth = None

        return self.create_request_static(method, url, auth, headers, self.verify_ssl, body)

    def get_auth_header(self, auth_data):
        """
        Generate the auth header needed to contact with the OCCI server.
        I supports Keystone tokens and basic auth.
        """
        auths = auth_data.getAuthInfo(self.type, self.cloud.server)
        if not auths:
            raise Exception("No correct auth data has been specified to OCCI.")
        else:
            auth = auths[0]

        auth_header = None
        keystone_uri, keystone_token = KeyStoneAuth.get_keystone_uri(self)

        if keystone_token:
            auth_header = {'X-Auth-Token': keystone_token}
        elif keystone_uri:
            keystone_token = KeyStoneAuth.get_keystone_token(self, keystone_uri, auth)
            auth_header = {'X-Auth-Token': keystone_token}
        else:
            if 'username' in auth and 'password' in auth:
                passwd = auth['password']
                user = auth['username']
                auth_header = {'Authorization': 'Basic ' +
                               (base64.encodestring((user + ':' + passwd).encode('utf-8'))).strip().decode('utf-8')}

        return auth_header

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]
        cloud_url = self.cloud.protocol + "://" + self.cloud.server
        if self.cloud.port > 0:
            cloud_url += ":" + str(self.cloud.port)
        site_url = None
        if protocol == "appdb":
            # The url has this format: appdb://UPV-GRyCAP/egi.docker.ubuntu.16.04?fedcloud.egi.eu
            # Get the Site url from the AppDB
            site_name = url[1]
            site_id = AppDB.get_site_id(site_name)
            if not site_id:
                self.log_error("No site ID returned from EGI AppDB for site: %s." % site_name)
                return None
            site_url = AppDB.get_site_url(site_id)

        if ((protocol in ['https', 'http'] and url[2] and url[0] + "://" + url[1] == cloud_url) or
                (protocol == "appdb" and site_url.startswith(cloud_url))):
            res_system = radl_system.clone()

            res_system.getFeature("cpu.count").operator = "="
            res_system.getFeature("memory.size").operator = "="

            username = res_system.getValue('disk.0.os.credentials.username')
            if not username:
                res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)

            return res_system
        else:
            return None

    @staticmethod
    def get_attached_volumes_from_info(occi_res):
        """
        Get the attached volumes in VM from the OCCI information returned by the server
        """
        # Link:
        # </storage/0>;rel="http://schemas.ogf.org/occi/infrastructure#storage";self="/link/storagelink/compute_10_disk_0";category="http://schemas.ogf.org/occi/infrastructure#storagelink
        # http://opennebula.org/occi/infrastructure#storagelink";occi.core.id="compute_10_disk_0";occi.core.title="ttylinux
        # -
        # kvm_file0";occi.core.target="/storage/0";occi.core.source="/compute/10";occi.storagelink.deviceid="/dev/hda";occi.storagelink.state="active"
        lines = occi_res.split("\n")
        res = []
        for line in lines:
            if 'Link:' in line and '/storage/' in line:
                num_link = None
                num_storage = None
                device = None
                parts = line.split(';')
                for part in parts:
                    kv = part.split('=')
                    if kv[0].strip() == "self":
                        num_link = kv[1].strip('"')
                    elif kv[0].strip() == "occi.storagelink.deviceid":
                        device = kv[1].strip('"')
                    elif kv[0].strip() == "occi.core.target":
                        num_storage = kv[1].strip('"')
                if num_link and num_storage:
                    res.append((num_link, num_storage, device))
        return res

    @staticmethod
    def get_net_info(occi_res):
        """
        Get the net related information about a VM from the OCCI information returned by the server
        """
        # Link:
        # </network/1>;rel="http://schemas.ogf.org/occi/infrastructure#network";self="/link/networkinterface/compute_10_nic_0";category="http://schemas.ogf.org/occi/infrastructure#networkinterface
        # http://schemas.ogf.org/occi/infrastructure/networkinterface#ipnetworkinterface
        # http://opennebula.org/occi/infrastructure#networkinterface";occi.core.id="compute_10_nic_0";occi.core.title="private";occi.core.target="/network/1";occi.core.source="/compute/10";occi.networkinterface.interface="eth0";occi.networkinterface.mac="10:00:00:00:00:05";occi.networkinterface.state="active";occi.networkinterface.address="10.100.1.5";org.opennebula.networkinterface.bridge="br1"
        lines = occi_res.split("\n")
        res = []
        link_to_public = False
        num_interface = None
        ip_address = None
        link = None
        for line in lines:
            if 'Link:' in line and '/network/public' in line:
                link_to_public = True
            if 'Link:' in line and ('/network/' in line or '/networklink/' in line):
                parts = line.split(';')
                for part in parts:
                    kv = part.split('=')
                    if kv[0].strip() == "occi.networkinterface.address":
                        if kv[1].count('.') == 3 or ip_address is None:
                            ip_address = kv[1].strip('"')
                            is_private = any([IPAddress(ip_address) in IPNetwork(
                                mask) for mask in Config.PRIVATE_NET_MASKS])
                    elif kv[0].strip() == "occi.networkinterface.interface":
                        net_interface = kv[1].strip('"')
                        num_interface = re.findall('\d+', net_interface)[0]
                    elif kv[0].strip() == "self":
                        link = kv[1].strip('"')
                if num_interface and ip_address:
                    res.append((num_interface, ip_address, not is_private, link))
        return link_to_public, res

    def manage_public_ips(self, vm, auth_data, auth_header):
        """
        Manage public IPs in the VM
        """
        self.log_info("The VM does not have public IP trying to add one.")
        if self.add_public_ip_count < self.MAX_ADD_IP_COUNT:
            success, msgs = self.add_public_ip(vm, auth_data, auth_header)
            if success:
                self.log_info("Public IP successfully added.")
            else:
                self.add_public_ip_count += 1
                self.log_warn("Error adding public IP the VM: %s (%d/%d)\n" % (msgs,
                                                                               self.add_public_ip_count,
                                                                               self.MAX_ADD_IP_COUNT))
                self.error_messages += "Error adding public IP the VM: %s (%d/%d)\n" % (msgs,
                                                                                        self.add_public_ip_count,
                                                                                        self.MAX_ADD_IP_COUNT)
        else:
            self.log_error("Error adding public IP the VM: Max number of retries reached.")
            # self.error_messages += "Error adding public IP the VM: Max number of retries reached.\n"
            # this is a total fail, stop contextualization
            vm.configured = False
            vm.inf.set_configured(False)
            vm.inf.stop()

    def setIPs(self, vm, occi_res, auth_data, auth_header):
        """
        Set to the VM info the IPs obtained from the OCCI info
        """
        public_ips = []
        private_ips = []

        link_to_public, addresses = self.get_net_info(occi_res)
        for _, ip_address, is_public, _ in addresses:
            if is_public:
                public_ips.append(ip_address)
            else:
                private_ips.append(ip_address)

        if (vm.state == VirtualMachine.RUNNING and not link_to_public and
                not public_ips and vm.requested_radl.hasPublicNet(vm.info.systems[0].name)):
            self.manage_public_ips(vm, auth_data, auth_header)

        vm.setIps(public_ips, private_ips, remove_old=True)

    @staticmethod
    def get_property_from_category(occi_res, category, prop_name):
        """
        Get a property of an OCCI category returned by an OCCI server
        """
        lines = occi_res.split("\n")
        for line in lines:
            if line.find('Category: ' + category + ';') != -1:
                for elem in line.split(';'):
                    kv = elem.split('=')
                    if len(kv) == 2:
                        key = kv[0].strip()
                        value = kv[1].strip('"')
                        if key == prop_name:
                            return value
        return None

    @staticmethod
    def get_floating_pool(occi_data):
        """
        Get a random floating pool available (For OpenStack sites with Neutron)
        """
        lines = occi_data.split("\n")
        pools = []
        for line in lines:
            if 'http://schemas.openstack.org/network/floatingippool#' in line:
                for elem in l.split(';'):
                    if elem.startswith('Category: '):
                        pools.append(elem[10:])
        if pools:
            return pools[random.randint(0, len(pools) - 1)]
        else:
            return None

    def get_net_name(self, auth_data, auth_header, is_public):
        """
        Get the public/private network name contacting with the OCCI server
        """
        headers = {'Accept': 'text/plain', 'Connection': 'close'}
        if auth_header:
            headers.update(auth_header)
        try:
            resp = self.create_request('GET', self.cloud.path + "/network/", auth_data, headers)

            if resp.status_code != 200:
                self.log_error("Error querying the OCCI server: %s" % resp.reason)
                return None
        except Exception:
            self.log_exception("Error querying the OCCI server")
            return None

        lines = resp.text.split("\n")
        # If there are only one net, return it
        if len(lines) == 1 and lines[0].startswith("X-OCCI-Location: "):
            return os.path.basename(lines[0][17:])

        # if not, try to find one with a public ip
        for line in lines:
            if line.startswith("X-OCCI-Location: "):
                net_url = line[17:]
                net_name = os.path.basename(line[17:])
                resp = self.create_request('GET', net_url, auth_data, headers)
                if resp.status_code == 200:
                    net_addr = self.get_occi_attribute_value(resp.text, "occi.network.address")
                    if net_addr:
                        net_ip = net_addr.split("/")[0]
                        is_private = any([IPAddress(net_ip) in IPNetwork(mask) for mask in Config.PRIVATE_NET_MASKS])
                        if is_private != is_public:
                            return net_name

        # if not, try to find one with the expected names
        for line in lines:
            if line.startswith("X-OCCI-Location: "):
                net_name = os.path.basename(line[17:])
            if is_public:
                if net_name.startswith(tuple(self.PUBLIC_NET_NAMES)):
                    return net_name
            else:
                if not net_name.startswith(tuple(self.PUBLIC_NET_NAMES)):
                    return net_name

        # if not, return a random one and pray
        if len(lines) > 0:
            return os.path.basename(lines[random.randint(0, len(lines) - 1)][17:])

        return None

    def add_public_ip(self, vm, auth_data, auth_header):
        """
        Add a public IP to the VM
        """
        network_name = self.get_net_name(auth_data, auth_header, True)
        if not network_name:
            return (False, "No correct network name found.")

        _, occi_info = self.query_occi(auth_data, auth_header)
        url = self.get_property_from_category(occi_info, "networkinterface", "location")
        if not url:
            self.log_error("No location for networkinterface category.")
            return (False, "No location for networkinterface category.")

        try:
            net_id = "imnet-%s" % str(uuid.uuid1())

            body = 'Category: networkinterface;scheme="http://schemas.ogf.org/occi/infrastructure#";class="kind"\n'
            pool_name = self.get_floating_pool(occi_info)
            if pool_name:
                body += ('Category: %s;scheme="http://schemas.openstack.org/network/floatingippool#";'
                         'class="mixin"\n' % pool_name)
            body += 'X-OCCI-Attribute: occi.core.id="%s"\n' % net_id
            body += 'X-OCCI-Attribute: occi.core.target="%s/network/%s"\n' % (self.cloud.path, network_name)
            body += 'X-OCCI-Attribute: occi.core.source="%s/compute/%s"' % (self.cloud.path, vm.id)

            headers = {'Accept': 'text/plain', 'Connection': 'close', 'Content-Type': 'text/plain,text/occi'}
            if auth_header:
                headers.update(auth_header)
            resp = self.create_request('POST', url, auth_data, headers, body)

            output = str(resp.text)
            if resp.status_code != 201 and resp.status_code != 200:
                return (False, output)
            else:
                self.log_info("Public IP added from pool %s" % network_name)
                return (True, vm.id)
        except Exception:
            self.log_exception("Error connecting with OCCI server")
            return (False, "Error connecting with OCCI server")

    @staticmethod
    def get_occi_attribute_value(occi_res, attr_name):
        """
        Get the value of an OCCI attribute returned by an OCCI server
        """
        lines = occi_res.split("\n")
        for line in lines:
            if line.find('X-OCCI-Attribute: ' + attr_name + '=') != -1:
                return line.split('=')[1].strip('"')
        return None

    def updateVMInfo(self, vm, auth_data):
        auth = self.get_auth_header(auth_data)
        headers = {'Accept': 'text/plain', 'Connection': 'close'}
        if auth:
            headers.update(auth)
        try:
            resp = self.create_request('GET', self.cloud.path + "/compute/" + vm.id, auth_data, headers)

            if resp.status_code == 404:
                # if the VM does not exists return off
                vm.state = VirtualMachine.OFF
                return (True, vm)
            elif resp.status_code != 200:
                return (False, resp.reason + "\n" + resp.text)
            else:
                old_state = vm.state
                occi_state = self.get_occi_attribute_value(resp.text, 'occi.compute.state')

                occi_name = self.get_occi_attribute_value(resp.text, 'occi.core.title')
                if occi_name:
                    vm.info.systems[0].setValue('instance_name', occi_name)

                # I have to do that because OCCI returns 'inactive' when a VM is starting
                # to distinguish from the OFF state
                if old_state == VirtualMachine.PENDING and occi_state == 'inactive':
                    vm.state = VirtualMachine.PENDING
                else:
                    vm.state = self.VM_STATE_MAP.get(occi_state, VirtualMachine.UNKNOWN)

                cores = self.get_occi_attribute_value(resp.text, 'occi.compute.cores')
                if cores:
                    vm.info.systems[0].setValue("cpu.count", int(cores))
                memory = self.get_occi_attribute_value(resp.text, 'occi.compute.memory')
                if memory:
                    # a Patch to solve the issue that some site return memory in GB and other in MB
                    # if the number is lower than 128 we assume that the unit is GB
                    if float(memory) < 128:
                        memory = float(memory) * 1024
                    vm.info.systems[0].setValue("memory.size", int(memory), 'M')

                console_vnc = self.get_occi_attribute_value(resp.text, 'org.openstack.compute.console.vnc')
                if console_vnc:
                    vm.info.systems[0].setValue("console_vnc", console_vnc)

                # Update the network data
                self.setIPs(vm, resp.text, auth_data, auth)

                # Update disks data
                self.set_disk_info(vm, resp.text)
                return (True, vm)

        except Exception as ex:
            self.log_exception("Error connecting with OCCI server")
            return (False, "Error connecting with OCCI server: " + str(ex))

    def set_disk_info(self, vm, occi_res):
        """
        Update the disks info with the actual device assigned by OCCI
        """
        system = vm.info.systems[0]

        for _, num_storage, device in self.get_attached_volumes_from_info(occi_res):
            cont = 1
            while (device and (system.getValue("disk." + str(cont) + ".image.url") or
                               system.getValue("disk." + str(cont) + ".size"))):
                if os.path.basename(num_storage) == system.getValue("disk." + str(cont) + ".provider_id"):
                    system.setValue("disk." + str(cont) + ".device", device)
                cont += 1

    def query_occi(self, auth_data, auth_header):
        """
        Get the info contacting with the OCCI server
        """
        headers = {'Accept': 'text/plain', 'Connection': 'close'}
        if auth_header:
            headers.update(auth_header)
        try:
            resp = self.create_request('GET', self.cloud.path + "/-/", auth_data, headers)

            if resp.status_code != 200:
                return False, "Error querying the OCCI server: %s, %s" % (resp.reason, resp.text)
            else:
                return True, resp.text
        except Exception as ex:
            return False, "Error querying the OCCI server: %s" % str(ex)

    def get_scheme(self, occi_info, category, ctype):
        """
        Get the scheme of an OCCI category contacting with the OCCI server
        """
        lines = occi_info.split("\n")
        for line in lines:
            if line.find('Category: ' + category) != -1 and line.find(ctype) != -1:
                parts = line.split(';')
                for p in parts:
                    kv = p.split("=")
                    if kv[0].strip() == "scheme":
                        return kv[1].replace('"', '').replace("'", '')

        self.log_error("Error getting scheme for category: " + category)
        return ""

    def get_instance_type_uri(self, occi_info, instance_type):
        """
        Get the whole URI of an OCCI instance from the OCCI info
        """
        if instance_type.startswith('http'):
            # If the user set the whole uri, do not search
            return instance_type
        else:
            return self.get_scheme(occi_info, instance_type, 'resource_tpl') + instance_type

    def get_os_tpl_scheme(self, occi_info, os_tpl):
        """
        Get the whole URI of an OCCI os template from the OCCI info
        """
        return self.get_scheme(occi_info, os_tpl, 'os_tpl')

    def create_volumes(self, system, auth_data, auth_header):
        """
        Attach the required volumes (in the RADL) to the launched instance

        Arguments:
           - instance(:py:class:`boto.ec2.instance`): object to connect to EC2 instance.
           - vm(:py:class:`IM.VirtualMachine`): VM information.
        """
        volumes = []
        cont = 1
        while system.getValue("disk." + str(cont) + ".image.url") or system.getValue("disk." + str(cont) + ".size"):
            disk_image = system.getValue("disk." + str(cont) + ".image.url")
            disk_device = system.getValue("disk." + str(cont) + ".device")
            if disk_device:
                # get the last letter and use vd
                disk_device = "vd" + disk_device[-1]
                system.setValue("disk." + str(cont) + ".device", disk_device)
            if disk_image:
                volume_id = os.path.basename(urlparse(disk_image)[2])
                volumes.append((False, disk_device, volume_id))
                system.setValue("disk." + str(cont) + ".provider_id", volume_id)
                self.log_info("User set a specific Volume id %s." % volume_id)
            else:
                disk_size = system.getFeature("disk." + str(cont) + ".size").getValue('G')
                self.log_info("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
                storage_name = "im-disk-%s" % str(uuid.uuid1())
                success, volume_id = self.create_volume(int(disk_size), storage_name, auth_data, auth_header)
                if success:
                    self.log_info("Volume id %s successfully created." % volume_id)

                    # let's wait the storage to be ready "online"
                    wait_ok = self.wait_volume_state(volume_id, auth_data, auth_header)
                    if not wait_ok:
                        self.log_error("Error waiting volume %s. Deleting it." % volume_id)
                        self.delete_volume(volume_id, auth_data, auth_header)
                        self.error_messages += "Error waiting volume: %s. Deleting it." % volume_id
                    else:
                        volumes.append((True, disk_device, volume_id))
                        system.setValue("disk." + str(cont) + ".provider_id", volume_id)
                else:
                    self.log_error("Error creating volume: %s" % volume_id)
                    self.error_messages += "Error creating volume: %s. Deleting it." % volume_id

            cont += 1

        return volumes

    def wait_volume_state(self, volume_id, auth_data, auth_header, wait_state="online", timeout=180, delay=5):
        """
        Wait a storage to be in the specified state (by default "online")
        """
        wait = 0
        online = False
        while not online and wait < timeout:
            # sleep a bit at the beginning to assure a correct state of the vol
            time.sleep(delay)
            wait += delay
            success, storage_info = self.get_volume_info(volume_id, auth_data, auth_header)
            state = self.get_occi_attribute_value(storage_info, 'occi.storage.state')
            self.log_info("Waiting volume %s to be %s. Current state: %s" % (volume_id, wait_state, state))
            if success and state == wait_state:
                online = True
            elif not success:
                self.log_error("Error waiting volume %s to be ready: %s" % (volume_id, state))
                return False

        return online

    def get_volume_info(self, storage_id, auth_data, auth_header):
        """
        Get the OCCI info about the storage
        """
        headers = {'Accept': 'text/plain', 'Connection': 'close'}
        if auth_header:
            headers.update(auth_header)
        try:
            resp = self.create_request('GET', self.cloud.path + "/storage/" + storage_id, auth_data, headers)

            if resp.status_code == 404 or resp.status_code == 204:
                return (False, "Volume not found.")
            elif resp.status_code != 200:
                return (False, resp.reason + "\n" + resp.text)
            else:
                return (True, resp.text)
        except Exception as ex:
            self.log_exception("Error getting volume info")
            return False, str(ex)

    def create_volume(self, size, name, auth_data, auth_header):
        """
        Creates a volume of the specified data (in GB)

        returns the OCCI ID of the storage object
        """
        try:
            volume_id = "im-vol-%s" % str(uuid.uuid1())
            body = 'Category: storage; scheme="http://schemas.ogf.org/occi/infrastructure#"; class="kind"\n'
            body += 'X-OCCI-Attribute: occi.core.id="%s"\n' % volume_id
            body += 'X-OCCI-Attribute: occi.core.title="%s"\n' % name
            body += 'X-OCCI-Attribute: occi.storage.size=%d\n' % int(size)

            headers = {'Accept': 'text/plain', 'Connection': 'close', 'Content-Type': 'text/plain,text/occi'}
            if auth_header:
                headers.update(auth_header)
            resp = self.create_request('POST', self.cloud.path + "/storage/", auth_data, headers, body)

            if resp.status_code != 201 and resp.status_code != 200:
                return False, resp.reason + "\n" + resp.text
            else:
                occi_id = os.path.basename(resp.text)
                return True, occi_id
        except Exception as ex:
            self.log_exception("Error creating volume")
            return False, str(ex)

    def detach_volume(self, volume, auth_data, auth_header, timeout=60, delay=5):
        headers = {'Accept': 'text/plain', 'Connection': 'close'}
        if auth_header:
            headers.update(auth_header)

        link, storage_id, _ = volume
        if not link.startswith("http"):
            link = self.cloud.path + "/" + link

        wait = 0
        while wait < timeout:
            try:
                self.log_info("Detaching volume: %s" % storage_id)
                resp = self.create_request('GET', link, auth_data, headers)
                if resp.status_code == 200:
                    self.log_info("Volume link %s exists. Try to delete it." % link)
                    resp = self.create_request('DELETE', link, auth_data, headers)
                    if resp.status_code in [204, 200]:
                        self.log_info("Successfully detached. Wait it to be deleted.")
                    else:
                        self.log_error("Error detaching volume: %s" + resp.reason + "\n" + resp.text)
                elif resp.status_code == 404:
                    # wait until the resource does not exist
                    self.log_info("Successfully detached")
                    return (True, "")
                else:
                    self.log_warn("Error detaching volume: %s" + resp.reason + "\n" + resp.text)
            except Exception as ex:
                self.log_warn("Error detaching volume " + str(ex))

            time.sleep(delay)
            wait += delay

        return (False, "Error detaching the Volume: Timeout.")

    def delete_volume(self, storage_id, auth_data, auth_header, timeout=180, delay=5):
        """
        Delete a volume
        """
        headers = {'Accept': 'text/plain', 'Connection': 'close'}
        if auth_header:
            headers.update(auth_header)

        if storage_id.startswith("http"):
            storage_id = urlparse(storage_id)[2]
        else:
            if not storage_id.startswith("/storage"):
                storage_id = "/storage/%s" % storage_id
            storage_id = self.cloud.path + storage_id

        wait = 0
        while wait < timeout:
            self.log_info("Delete storage: %s" % storage_id)
            try:
                resp = self.create_request('GET', storage_id, auth_data, headers)
                if resp.status_code == 200:
                    self.log_info("Storage %s exists. Try to delete it." % storage_id)
                    resp = self.create_request('DELETE', storage_id, auth_data, headers)

                    if resp.status_code == 404:
                        self.log_info("It does not exist.")
                        return (True, "")
                    elif resp.status_code in [403, 401]:
                        self.log_info("You are not authorized to delete it. Ignore.")
                        return (True, "")
                    elif resp.status_code == 409:
                        self.log_info("Error deleting the Volume. It seems that it is still "
                                      "attached to a VM: %s" % resp.text)
                    elif resp.status_code != 200 and resp.status_code != 204:
                        self.log_warn("Error deleting the Volume: " + resp.reason + "\n" + resp.text)
                    else:
                        self.log_info("Successfully deleted")
                        return (True, "")
                elif resp.status_code == 404:
                    self.log_info("It does not exist.")
                    return (True, "")
                else:
                    self.log_warn("Error deleting storage: %s" + resp.reason + "\n" + resp.text)
                time.sleep(delay)
                wait += delay
            except Exception:
                self.log_exception("Error connecting with OCCI server")
                return (False, "Error connecting with OCCI server")

        self.log_error("Error deleting the Volume: Timeout")
        return (False, "Error deleting the Volume: Timeout.")

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        system = radl.systems[0]

        cpu = system.getValue('cpu.count')
        memory = None
        if system.getFeature('memory.size'):
            memory = system.getFeature('memory.size').getValue('G')
        name = self.gen_instance_name(system, False)
        arch = system.getValue('cpu.arch')

        if arch.find('64'):
            arch = 'x64'
        else:
            arch = 'x86'

        res = []
        i = 0

        public_key = system.getValue('disk.0.os.credentials.public_key')
        # OCCI only uses private key
        if system.getValue('disk.0.os.credentials.password'):
            system.delValue('disk.0.os.credentials.password')

        if not public_key:
            # We must generate them
            (public_key, private_key) = self.keygen()
            system.setValue('disk.0.os.credentials.private_key', private_key)

        user = system.getValue('disk.0.os.credentials.username')
        if not user:
            user = self.DEFAULT_USER
            system.setValue('disk.0.os.credentials.username', user)

        # Parse the info to get the os_tpl scheme
        url = urlparse(system.getValue("disk.0.image.url"))

        if url[0] == "appdb":
            # the url has this format appdb://UPV-GRyCAP/egi.docker.ubuntu.16.04?fedcloud.egi.eu
            # Get the Image ID from the AppDB
            site_name = url[1]
            image_name = url[2][1:]
            vo_name = url[4]
            site_id = AppDB.get_site_id(site_name)
            os_tpl = AppDB.get_image_id(site_id, image_name, vo_name)
        else:
            # Get the Image ID from the last part of the path
            os_tpl = os.path.basename(url[2])

        # Get the info about the OCCI server (GET /-/)
        auth_header = self.get_auth_header(auth_data)
        success, occi_info = self.query_occi(auth_data, auth_header)
        if not success:
            raise Exception(occi_info)

        os_tpl_scheme = self.get_os_tpl_scheme(occi_info, os_tpl)
        if not os_tpl_scheme:
            raise Exception(
                "Error getting os_tpl scheme. Check that the image specified is supported in the OCCI server.")

        # Parse the info to get the instance_type (resource_tpl) scheme
        instance_type_uri = None
        if system.getValue('instance_type'):
            instance_type = self.get_instance_type_uri(occi_info, system.getValue('instance_type'))
            instance_type_uri = urlparse(instance_type)
            if not instance_type_uri[5]:
                raise Exception("Error getting Instance type URI. Check that the instance_type specified is "
                                "supported in the OCCI server.")
            else:
                instance_name = instance_type_uri[5]
                instance_scheme = instance_type_uri[0] + "://" + instance_type_uri[1] + instance_type_uri[2] + "#"

        while i < num_vm:
            volumes = []
            try:
                # First create the volumes
                volumes = self.create_volumes(system, auth_data, auth_header)

                body = 'Category: compute; scheme="http://schemas.ogf.org/occi/infrastructure#"; class="kind"\n'
                body += 'Category: ' + os_tpl + '; scheme="' + os_tpl_scheme + '"; class="mixin"\n'
                body += 'Category: user_data; scheme="http://schemas.openstack.org/compute/instance#"; class="mixin"\n'
                body += 'Category: public_key; scheme="http://schemas.openstack.org/instance/credentials#";' + \
                    ' class="mixin"\n'

                if instance_type_uri:
                    body += 'Category: ' + instance_name + '; scheme="' + instance_scheme + '"; class="mixin"\n'
                else:
                    # Try to use this OCCI attributes (not supported by openstack)
                    if cpu:
                        body += 'X-OCCI-Attribute: occi.compute.cores=' + str(cpu) + '\n'
                    # body += 'X-OCCI-Attribute: occi.compute.architecture=' + arch +'\n'
                    if memory:
                        body += 'X-OCCI-Attribute: occi.compute.memory=' + str(memory) + '\n'

                compute_id = "im-%s" % str(uuid.uuid1())
                body += 'X-OCCI-Attribute: occi.core.id="' + compute_id + '"\n'
                body += 'X-OCCI-Attribute: occi.core.title="' + name + '"\n'

                # Set the hostname defined in the RADL
                # Create the VM to get the nodename
                vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl, self)
                vm.destroy = True
                inf.add_vm(vm)
                (nodename, _) = vm.getRequestedName(default_hostname=Config.DEFAULT_VM_NAME,
                                                    default_domain=Config.DEFAULT_DOMAIN)

                # Add user cloud init data
                cloud_config = self.get_cloud_init_data(radl, vm, public_key, user).encode()
                user_data = base64.b64encode(cloud_config).decode().replace("\n", "")
                self.log_debug("Cloud init: %s" % cloud_config.decode())

                body += 'X-OCCI-Attribute: occi.compute.hostname="' + nodename + '"\n'
                if user_data:
                    body += 'X-OCCI-Attribute: org.openstack.compute.user_data="' + user_data + '"\n'
                if public_key:
                    body += 'X-OCCI-Attribute: org.openstack.credentials.publickey.data="' + public_key + '"\n'

                # Add volume links
                for _, device, volume_id in volumes:
                    link_id = "im-%s" % str(uuid.uuid1())
                    body += ('Link: <%s/storage/%s>; rel="http://schemas.ogf.org/occi/infrastructure#storage"; '
                             'self="/storagelink/%s"; '
                             'category="http://schemas.ogf.org/occi/infrastructure#storagelink"; '
                             'occi.core.target="%s/storage/%s"; '
                             'occi.core.source="%s/compute/%s"; '
                             'occi.core.id="%s"' % (self.cloud.path, volume_id, link_id,
                                                    self.cloud.path, volume_id,
                                                    self.cloud.path, compute_id, link_id))
                    if device:
                        body += ';occi.storagelink.deviceid="/dev/%s"' % device
                    body += '\n'

                self.log_debug(body)

                headers = {'Accept': 'text/plain', 'Connection': 'close', 'Content-Type': 'text/plain,text/occi'}
                auth_header = self.get_auth_header(auth_data)
                if auth_header:
                    headers.update(auth_header)
                resp = self.create_request('POST', self.cloud.path + "/compute/", auth_data, headers, body)

                # This error is returned is some sites if the network id is not specified
                if resp.status_code == 409:
                    self.log_warn("Conflict creating the VM. Let's try to add the net id: %s" % resp.text)

                    net_ids = []

                    # If the site does not have IP pools
                    if not self.get_floating_pool(occi_info):
                        # First add public ip (if needed)
                        if radl.hasPublicNet(system.name):
                            pub_net_id = self.get_net_name(auth_data, auth_header, True)
                            if pub_net_id:
                                net_ids.append(pub_net_id)
                    # Then add private one
                    priv_net_id = self.get_net_name(auth_data, auth_header, False)
                    if priv_net_id and priv_net_id not in net_ids:
                        net_ids.append(priv_net_id)

                    for net_id in net_ids:
                        link_id = "im-%s" % str(uuid.uuid1())
                        body += ('Link: <%s/network/%s>; rel="http://schemas.ogf.org/occi/infrastructure#network"; '
                                 'self="/networkinterface/%s"; '
                                 'category="http://schemas.ogf.org/occi/infrastructure#networkinterface"; '
                                 'occi.core.target="%s/network/%s"; '
                                 'occi.core.source="%s/compute/%s"; '
                                 'occi.core.id="%s"' % (self.cloud.path, net_id, link_id,
                                                        self.cloud.path, net_id,
                                                        self.cloud.path, compute_id, link_id))
                        body += '\n'
                    self.log_debug(body)

                    resp = self.create_request('POST', self.cloud.path + "/compute/", auth_data, headers, body)

                # some servers return 201 and other 200
                if resp.status_code not in [201, 200]:
                    self.log_error("Error creating VM: %s. %s." % (resp.reason, resp.text))
                    res.append((False, resp.reason + "\n" + resp.text))
                    for created, _, volume_id in volumes:
                        if created:
                            self.delete_volume(volume_id, auth_data, auth_header)
                else:
                    if 'location' in resp.headers:
                        occi_vm_id = os.path.basename(resp.headers['location'])
                    else:
                        occi_vm_id = os.path.basename(resp.text)
                    if occi_vm_id:
                        vm.id = occi_vm_id
                        vm.info.systems[0].setValue('instance_id', str(occi_vm_id))
                        vm.destroy = False
                        res.append((True, vm))
                    else:
                        res.append((False, 'Unknown Error launching the VM.'))

            except Exception as ex:
                self.log_exception("Error connecting with OCCI server")
                res.append((False, "ERROR: " + str(ex)))
                for created, _, volume_id in volumes:
                    if created:
                        self.delete_volume(volume_id, auth_data, auth_header)

            i += 1

        return res

    @staticmethod
    def get_volume_ids_from_radl(system):
        volumes = []
        cont = 1
        while system.getValue("disk." + str(cont) + ".image.url") or system.getValue("disk." + str(cont) + ".size"):
            disk_image = system.getValue("disk." + str(cont) + ".image.url")
            provider_id = system.getValue("disk." + str(cont) + ".provider_id")
            if not disk_image and provider_id:
                volumes.append(provider_id)
            cont += 1

        return volumes

    @staticmethod
    def get_volume_not_delete(system):
        volumes = []
        cont = 1
        while system.getValue("disk." + str(cont) + ".image.url") or system.getValue("disk." + str(cont) + ".size"):
            disk_image = system.getValue("disk." + str(cont) + ".image.url")
            if disk_image:
                volume_id = urlparse(disk_image)[2]
                volumes.append(volume_id)
            cont += 1

        return volumes

    def get_attached_volumes(self, vm, auth_data, auth_header):
        headers = {'Accept': 'text/plain', 'Connection': 'close'}
        if auth_header:
            headers.update(auth_header)
        try:
            resp = self.create_request('GET', self.cloud.path + "/compute/" + vm.id, auth_data, headers)

            if resp.status_code == 404 or resp.status_code == 204:
                return (True, "")
            elif resp.status_code != 200:
                return (False, resp.reason + "\n" + resp.text)
            else:
                occi_volumes = self.get_attached_volumes_from_info(resp.text)
                deleted_vols = []
                for link, num_storage, device in occi_volumes:
                    if device is None or (not device.endswith("vda") and not device.endswith("hda")):
                        deleted_vols.append((link, num_storage, device))
                return (True, deleted_vols)
        except Exception as ex:
            self.log_exception("Error deleting volumes")
            return (False, "Error deleting volumes " + str(ex))

    def finalize(self, vm, last, auth_data):
        if not vm.id:
            self.log_warn("No VM ID. Ignoring")
            return True, "No VM ID. Ignoring"

        auth_header = self.get_auth_header(auth_data)
        # First try to get the volumes
        get_vols_ok, volumes = self.get_attached_volumes(vm, auth_data, auth_header)
        if not get_vols_ok:
            self.log_error("Error getting attached volumes: %s" % volumes)
        else:
            for volume in volumes:
                self.detach_volume(volume, auth_data, auth_header)

        headers = {'Accept': 'text/plain', 'Connection': 'close'}
        if auth_header:
            headers.update(auth_header)
        try:
            resp = self.create_request('DELETE', self.cloud.path + "/compute/" + vm.id, auth_data, headers)

            if resp.status_code not in [200, 204, 404]:
                return (False, "Error removing the VM: " + resp.reason + "\n" + resp.text)
        except Exception:
            self.log_exception("Error connecting with OCCI server")
            return (False, "Error connecting with OCCI server")

        vols_not_to_delete = self.get_volume_not_delete(vm.info.systems[0])

        # now delete the volumes
        if get_vols_ok:
            for _, storage_id, _ in volumes:
                storage_path = urlparse(storage_id)[2]
                if storage_path not in vols_not_to_delete:
                    self.delete_volume(storage_id, auth_data, auth_header)

        # sometime we have created a volume that is not correctly attached to the vm
        # check the RADL of the VM to get them
        radl_volumes = self.get_volume_ids_from_radl(vm.info.systems[0])
        for num_storage in radl_volumes:
            self.delete_volume(num_storage, auth_data, auth_header)

        return (True, vm.id)

    def stop(self, vm, auth_data):
        return self.vm_action(vm, 'suspend', auth_data)

    def start(self, vm, auth_data):
        return self.vm_action(vm, 'start', auth_data)

    def reboot(self, vm, auth_data):
        return self.vm_action(vm, 'restart', auth_data)

    def vm_action(self, vm, action, auth_data):
        auth_header = self.get_auth_header(auth_data)
        try:
            headers = {'Accept': 'text/plain', 'Connection': 'close', 'Content-Type': 'text/plain,text/occi'}
            if auth_header:
                headers.update(auth_header)

            body = ('Category: ' + action + ';scheme="http://schemas.ogf.org/occi/infrastructure/compute/action#"'
                    ';class="action"\n')
            resp = self.create_request('POST', self.cloud.path + "/compute/" + vm.id + "?action=" + action,
                                       auth_data, headers, body)

            if resp.status_code not in [200, 204]:
                return (False, "Error in " + action + " action in VM: " + resp.reason + "\n" + resp.text)
            else:
                return (True, vm.id)
        except Exception:
            self.log_exception("Error connecting with OCCI server")
            return (False, "Error connecting with OCCI server")

    def add_new_disks(self, vm, radl, auth_data, auth_header):
        """
        Add new disks specified in the radl to the vm
        """
        try:
            orig_system = vm.info.systems[0]

            cont = 1
            while (orig_system.getValue("disk." + str(cont) + ".image.url") or
                   orig_system.getValue("disk." + str(cont) + ".size")):
                cont += 1

            system = radl.systems[0]
            # TODO: enable to attach an existing disk
            while system.getValue("disk." + str(cont) + ".size"):
                disk_size = system.getFeature("disk." + str(cont) + ".size").getValue('G')
                disk_device = system.getValue("disk." + str(cont) + ".device")
                mount_path = system.getValue("disk." + str(cont) + ".mount_path")
                if disk_device:
                    # get the last letter and use vd
                    disk_device = "vd" + disk_device[-1]
                    system.setValue("disk." + str(cont) + ".device", disk_device)
                self.log_info("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
                storage_name = "im-disk-%s" % str(uuid.uuid1())
                success, volume_id = self.create_volume(int(disk_size), storage_name, auth_data, auth_header)

                if success:
                    self.log_info("Volume id %s successfuly created." % volume_id)
                    # let's wait the storage to be ready "online"
                    wait_ok = self.wait_volume_state(volume_id, auth_data, auth_header)
                    if not wait_ok:
                        self.log_info("Error waiting volume %s. Deleting it." % volume_id)
                        self.delete_volume(volume_id, auth_data, auth_header)
                        return (False, "Error waiting volume %s. Deleting it." % volume_id)
                    else:
                        self.log_info("Attaching to the instance")
                        attached = self.attach_volume(vm, volume_id, disk_device, mount_path, auth_data, auth_header)
                        if attached:
                            orig_system.setValue("disk." + str(cont) + ".size", disk_size, "G")
                            orig_system.setValue("disk." + str(cont) + ".provider_id", volume_id)
                            if disk_device:
                                orig_system.setValue("disk." + str(cont) + ".device", disk_device)
                            if mount_path:
                                orig_system.setValue("disk." + str(cont) + ".mount_path", mount_path)
                        else:
                            self.log_error("Error attaching a %d GB volume for the disk %d."
                                           " Deleting it." % (int(disk_size), cont))
                            self.delete_volume(volume_id, auth_data, auth_header)
                            return (False, "Error attaching the new volume")
                else:
                    self.log_error("Error creating volume: %s" % volume_id)
                    return (False, "Error creating volume: %s" % volume_id)

                cont += 1
            return (True, "")
        except Exception as ex:
            self.log_exception("Error connecting with OCCI server")
            return (False, "Error connecting with OCCI server: " + str(ex))

    def get_public_ip_link(self, occi_res):
        """
        Get the link of the first public IP
        """
        _, addresses = self.get_net_info(occi_res)
        link = None
        for _, _, is_public, addr_link in addresses:
            if is_public:
                link = addr_link
                break
        return link

    def remove_public_ip(self, vm, auth_data, auth_header):
        """
        Remove/Detach public IP from VM
        """
        self.log_info("Removing Public IP from VM %s" % vm.id)

        headers = {'Accept': 'text/plain', 'Connection': 'close'}
        if auth_header:
            headers.update(auth_header)

        try:
            resp = self.create_request('GET', self.cloud.path + "/compute/" + vm.id, auth_data, headers)

            if resp.status_code != 200:
                self.log_error("Error getting VM info: " + resp.reason + "\n" + resp.text)
                return (False, "Error getting VM info: " + resp.reason + "\n" + resp.text)
            else:
                link = self.get_public_ip_link(resp.text)
                if not link:
                    self.log_warn("No public IP to delete.")
                    return (True, "No public IP to delete.")
                resp = self.create_request('DELETE', link, auth_data, headers)
                if resp.status_code in [404, 204, 200]:
                    self.log_info("Successfully removed")
                    return (True, "")
                else:
                    self.log_error("Error removing public IP: " + resp.reason + "\n" + resp.text)
                    return (False, resp.reason + "\n" + resp.text)
        except Exception as ex:
            self.log_exception("Error removing public IP")
            return (False, str(ex))

    def manage_nics(self, vm, radl, auth_data, auth_header):
        """
        Add/remove public IP if currently it does not have one and new RADL requests it or vice versa
        """
        # update VM info
        try:
            vm.update_status(auth_data, force=True)
            current_has_public_ip = vm.hasPublicIP()
            new_has_public_ip = radl.hasPublicNet(vm.info.systems[0].name)
            if new_has_public_ip and not current_has_public_ip:
                success, msg = self.add_public_ip(vm, auth_data, auth_header)

                if success:
                    # Add public net in the Requested RADL
                    public_net, num_net = VirtualMachine.add_public_net(vm.requested_radl)
                    vm.requested_radl.systems[0].setValue("net_interface.%d.connection" % num_net, public_net.id)
                    return True, ""
                else:
                    return False, msg
            if not new_has_public_ip and current_has_public_ip:
                success, msg = self.remove_public_ip(vm, auth_data, auth_header)

                if success:
                    # Remove all public net connections in the Requested RADL
                    vm.delete_public_nets(vm.requested_radl)
                    return True, ""
                else:
                    return False, msg
        except Exception as ex:
            self.log_exception("Error adding new public IP")
            return (False, "Error adding new public IP: " + str(ex))
        return True, ""

    def alterVM(self, vm, radl, auth_data):
        """
        In the OCCI case it only enables attaching new disks or add a public IP
        """
        if not radl.systems:
            return (True, "")

        auth_header = self.get_auth_header(auth_data)

        success, msg = self.add_new_disks(vm, radl, auth_data, auth_header)
        if not success:
            return (success, msg)

        success, msg = self.manage_nics(vm, radl, auth_data, auth_header)
        if not success:
            return (success, msg)

        return (True, "")

    def attach_volume(self, vm, volume_id, device, mount_path, auth_data, auth_header):
        """
        Attach a volume to a running VM
        """
        _, occi_info = self.query_occi(auth_data, auth_header)
        url = self.get_property_from_category(occi_info, "storagelink", "location")
        if not url:
            self.log_error("No location for storagelink category.")
            return (False, "No location for storagelink category.")

        try:
            headers = {'Accept': 'text/plain', 'Connection': 'close', 'Content-Type': 'text/plain,text/occi'}
            if auth_header:
                headers.update(auth_header)

            disk_id = "imdisk-%s" % str(uuid.uuid1())

            body = 'Category: storagelink;scheme="http://schemas.ogf.org/occi/infrastructure#";class="kind"\n'
            body += 'X-OCCI-Attribute: occi.core.id="%s"\n' % disk_id
            body += 'X-OCCI-Attribute: occi.core.target="%s/storage/%s"\n' % (self.cloud.path, volume_id)
            body += 'X-OCCI-Attribute: occi.core.source="%s/compute/%s"' % (self.cloud.path, vm.id)
            if device:
                body += '\nX-OCCI-Attribute: occi.storagelink.deviceid="/dev/%s"' % device
            # body += 'X-OCCI-Attribute: occi.storagelink.mountpoint="%s"' % mount_path
            resp = self.create_request('POST', url, auth_data, headers, body)

            if resp.status_code != 201 and resp.status_code != 200:
                self.log_error("Error attaching disk to the VM: " + resp.reason + "\n" + resp.text)
                return False
            else:
                return True
        except Exception:
            self.log_exception("Error connecting with OCCI server")
            return False


class KeyStoneAuth:
    """
    Class to manage the Keystone auth tokens used in OpenStack
    """

    @staticmethod
    def get_keystone_uri(occi):
        """
        Contact the OCCI server to check if it needs to contact a keystone server.
        It returns the keystone server URI or None.
        """
        try:
            headers = {'Accept': 'text/plain', 'Connection': 'close'}

            if occi.keystone_token:
                headers = {'Accept': 'text/plain', 'X-Auth-Token': occi.keystone_token, 'Connection': 'close'}

            resp = occi.create_request('HEAD', occi.cloud.path + "/-/", None, headers)
            if resp.status_code == 200:
                return None, occi.keystone_token

            www_auth_head = None
            if 'Www-Authenticate' in resp.headers:
                www_auth_head = resp.headers['Www-Authenticate']

            if www_auth_head and www_auth_head.startswith('Keystone uri'):
                keystone_uri = www_auth_head.split('=')[1].replace("'", "")
                # remove version in some old OpenStack sites
                if keystone_uri.endswith("/v2.0"):
                    keystone_uri = keystone_uri[:-5]
                if keystone_uri.endswith("/v3"):
                    keystone_uri = keystone_uri[:-3]
                return keystone_uri, None
            else:
                return None, None
        except Exception:
            return None, None

    @staticmethod
    def get_keystone_token(occi, keystone_uri, auth):
        """
        Contact the specified keystone server to return the token
        """
        version = KeyStoneAuth.get_keystone_version(occi, keystone_uri, auth)

        if version == 2:
            occi.log_info("Getting Keystone v2 token")
            occi.keystone_token = KeyStoneAuth.get_keystone_token_v2(occi, keystone_uri, auth)
            return occi.keystone_token
        elif version == 3:
            occi.log_info("Getting Keystone v3 token")
            occi.keystone_token = KeyStoneAuth.get_keystone_token_v3(occi, keystone_uri, auth)
            return occi.keystone_token
        else:
            # this must never happen
            raise Exception("Error obtaining Keystone Token: Unknown version %d" % version)

    @staticmethod
    def get_keystone_version(occi, keystone_uri, auth):
        """
        Contact the specified keystone server to return version to use
        """
        version = None
        token = auth and "token" in auth

        try:
            headers = {"Accept": "application/json"}
            resp = occi.create_request_static('GET', keystone_uri, auth, headers, occi.verify_ssl)
            if resp.status_code in [200, 300]:
                versions = []
                json_data = resp.json()
                if 'versions' in json_data:
                    versions = json_data["versions"]["values"]
                elif 'version' in json_data:
                    versions = [json_data["version"]]
                else:
                    occi.log_error("Error obtaining Keystone versions: versions or version expected.")

                for elem in versions:
                    if not token and elem["id"].startswith("v2"):
                        version = 2
                    if (not version or token) and elem["id"].startswith("v3"):
                        # only use version 3 if 2 is not available
                        version = 3
            else:
                occi.log_error("Error obtaining Keystone versions: %s" % resp.text)
        except Exception:
            occi.log_exception("Error obtaining Keystone versions.")

        if not version:
            # use version 2 as the default one in case of error
            occi.log_warn("Keystone Version not obtained, using default one v2.")
            return 2
        else:
            return version

    @staticmethod
    def get_keystone_token_v2(occi, keystone_uri, auth):
        """
        Contact the specified keystone v2 server to return the token
        """
        try:
            body = '{"auth":{"voms":true}}'
            headers = {'Accept': 'application/json', 'Connection': 'close', 'Content-Type': 'application/json'}
            url = "%s/v2.0/tokens" % keystone_uri
            resp = occi.create_request_static('POST', url, auth, headers, occi.verify_ssl, body)
            resp.raise_for_status()

            # format: -> "{\"access\": {\"token\": {\"issued_at\":
            # \"2014-12-29T17:10:49.609894\", \"expires\":
            # \"2014-12-30T17:10:49Z\", \"id\":
            # \"c861ab413e844d12a61d09b23dc4fb9c\"}, \"serviceCatalog\": [],
            # \"user\": {\"username\":
            # \"/DC=es/DC=irisgrid/O=upv/CN=miguel-caballer\", \"roles_links\":
            # [], \"id\": \"475ce4978fb042e49ce0391de9bab49b\", \"roles\": [],
            # \"name\": \"/DC=es/DC=irisgrid/O=upv/CN=miguel-caballer\"},
            # \"metadata\": {\"is_admin\": 0, \"roles\": []}}}"
            output = resp.json()
            if 'access' in output:
                token_id = output['access']['token']['id']
            else:
                occi.log_exception("Error obtaining Keystone Token.")
                raise Exception("Error obtaining Keystone Token: %s" % str(output))

            headers = {'Accept': 'application/json', 'Content-Type': 'application/json',
                       'X-Auth-Token': token_id, 'Connection': 'close'}
            url = "%s/v2.0/tenants" % keystone_uri
            resp = occi.create_request_static('GET', url, auth, headers, occi.verify_ssl)
            resp.raise_for_status()

            # format: -> "{\"tenants_links\": [], \"tenants\":
            # [{\"description\": \"egi fedcloud\", \"enabled\": true, \"id\":
            # \"fffd98393bae4bf0acf66237c8f292ad\", \"name\": \"egi\"}]}"
            output = resp.json()
            tenants = output['tenants']

            tenant_token_id = None

            # retry for each available tenant (usually only one)
            for tenant in tenants:
                body = '{"auth":{"voms":true,"tenantName":"' + str(tenant['name']) + '"}}'

                headers = {'Accept': 'application/json', 'Content-Type': 'application/json',
                           'X-Auth-Token': token_id, 'Connection': 'close'}
                url = "%s/v2.0/tokens" % keystone_uri
                resp = occi.create_request_static('POST', url, auth, headers, occi.verify_ssl, body)
                if resp.status_code in [200, 202]:
                    # format: -> "{\"access\": {\"token\": {\"issued_at\":
                    # \"2014-12-29T17:10:49.609894\", \"expires\":
                    # \"2014-12-30T17:10:49Z\", \"id\":
                    # \"c861ab413e844d12a61d09b23dc4fb9c\"}, \"serviceCatalog\": [],
                    # \"user\": {\"username\":
                    # \"/DC=es/DC=irisgrid/O=upv/CN=miguel-caballer\", \"roles_links\":
                    # [], \"id\": \"475ce4978fb042e49ce0391de9bab49b\", \"roles\": [],
                    # \"name\": \"/DC=es/DC=irisgrid/O=upv/CN=miguel-caballer\"},
                    # \"metadata\": {\"is_admin\": 0, \"roles\": []}}}"
                    output = resp.json()
                    if 'access' in output:
                        occi.log_info("Using tenant: %s" % tenant["name"])
                        tenant_token_id = str(output['access']['token']['id'])
                        break

            if not tenant_token_id:
                raise Exception("Error obtaining Keystone v2 Token: No tenant scoped token.")
            return tenant_token_id
        except Exception as ex:
            occi.log_exception("Error obtaining Keystone v2 Token.")
            raise Exception("Error obtaining Keystone v2 Token: %s" % str(ex))

    @staticmethod
    def get_keystone_token_v3(occi, keystone_uri, auth):
        """
        Contact the specified keystone v3 server to return the token
        """
        try:
            headers = {'Accept': 'application/json', 'Connection': 'close', 'Content-Type': 'application/json'}

            if auth and "token" in auth:
                # Use OpenID
                url = "%s/v3/OS-FEDERATION/identity_providers/egi.eu/protocols/oidc/auth" % keystone_uri
            else:
                # Use VOMS proxy
                url = "%s/v3/OS-FEDERATION/identity_providers/egi.eu/protocols/mapped/auth" % keystone_uri

            resp = occi.create_request_static('GET', url, auth, headers, occi.verify_ssl)
            resp.raise_for_status()

            token = resp.headers['X-Subject-Token']

            headers = {'Accept': 'application/json', 'Content-Type': 'application/json',
                       'X-Auth-Token': token, 'Connection': 'close'}
            url = "%s/v3/auth/projects" % keystone_uri
            resp = occi.create_request_static('GET', url, auth, headers, occi.verify_ssl)
            resp.raise_for_status()

            output = resp.json()

            if len(output['projects']) == 1:
                # If there are only one get the first project
                projects = output['projects']
            elif len(output['projects']) > 1:
                # If there are more than one
                if auth and "project" in auth:
                    project_found = None
                    for elem in output['projects']:
                        if elem['id'] == auth["project"] or elem['name'] == auth["project"]:
                            project_found = elem
                    if project_found:
                        projects = [project_found]
                    else:
                        projects = output['projects']
                        occi.log_warn("Keystone 3 project %s not found." % auth["project"])

            scoped_token = None
            for project in projects:
                # get scoped token for allowed project
                headers = {'Accept': 'application/json', 'Content-Type': 'application/json',
                           'X-Auth-Token': token, 'Connection': 'close'}
                body = {"auth": {"identity": {"methods": ["token"], "token": {"id": token}},
                                 "scope": {"project": {"id": project["id"]}}}}
                url = "%s/v3/auth/tokens" % keystone_uri
                resp = occi.create_request_static('POST', url, auth, headers, occi.verify_ssl, json.dumps(body))
                if resp.status_code in [200, 201, 202]:
                    occi.log_info("Using project: %s" % project["name"])
                    scoped_token = resp.headers['X-Subject-Token']
                    break

            if not scoped_token:
                occi.log_error("Not project accesible for the user.")

            return scoped_token
        except Exception as ex:
            occi.log_exception("Error obtaining Keystone v3 Token.")
            raise Exception("Error obtaining Keystone v3 Token: %s" % str(ex))
