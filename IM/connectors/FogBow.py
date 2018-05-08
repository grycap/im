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
    INSTANCE_TYPE = 'fogbow_small'
    """str with the name of the default instance type to launch."""

    VM_STATE_MAP = {
        'waiting': VirtualMachine.PENDING,
        'active': VirtualMachine.RUNNING,
        'inactive': VirtualMachine.PENDING,
        'suspended': VirtualMachine.STOPPED
    }
    """Dictionary with a map with the FogBow VM states to the IM states."""

    VM_REQ_STATE_MAP = {
        'open': VirtualMachine.PENDING,
        'failed': VirtualMachine.FAILED,
        'fulfilled': VirtualMachine.PENDING,
        'deleted': VirtualMachine.OFF,
        'closed': VirtualMachine.OFF
    }
    """Dictionary with a map with the FogBow Request states to the IM states."""

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
        resp = requests.request(method, url, verify=False, headers=headers, data=body)

        return resp

    def get_auth_header(self, auth_data):
        """
        Generate the auth header needed to contact with the FogBow server.
        """
        auth = auth_data.getAuthInfo(FogBowCloudConnector.type)
        if not auth:
            raise Exception("No correct auth data has been specified to FogBow.")

        if 'token_type' in auth[0]:
            token_type = auth[0]['token_type']
        else:
            # If not token_type supplied, we assume that is VOMS one
            token_type = 'Token'

        plugin = IdentityPlugin.getIdentityPlugin(token_type)
        token = plugin.create_token(auth[0]).replace("\n", "").replace("\r", "")

        auth_headers = {'X-Auth-Token': token}

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

    def get_occi_attribute_value(self, occi_res, attr_name):
        """
        Get the value of an OCCI attribute returned by an OCCI server
        """
        lines = occi_res.split("\n")
        for l in lines:
            if l.find('X-OCCI-Attribute: ' + attr_name + '=') != -1:
                return str(l.split('=')[1].strip().strip('"'))
        return None

    def set_extra_ports(self, vm, extra_ports):
        """
        Set extra ports in the net outports
        Format:
        '{"tcp8080":"150.165.85.18:10067"}
        """
        try:
            ports = json.loads(extra_ports)
            for name, address in ports.items():
                local_port = int(name[3:])
                parts = address.split(":")
                remote_port = int(parts[1])
                vm.setOutPort(local_port, remote_port)
        except:
            self.log_exception("Error setting extra ports: %s" % extra_ports)

    """
    text/plain format:
        Recurso:
        Category: order; scheme="http://schemas.fogbowcloud.org/order#"; class="kind";
               title="Request new Instances"; rel="http://schemas.ogf.org/occi/core#resource";
               location="http://localhost:8182/order/";
               attributes="org.fogbowcloud.order.instance-count ..."
        Category: fogbow_small; scheme="http://schemas.fogbowcloud.org/template/resource#"; class="mixin";
               title="Small Flavor"; rel="http://schemas.ogf.org/occi/infrastructure#resource_tpl";
               location="http://localhost:8182/fogbow_small/"
        Category: fogbow-linux-x86; scheme="http://schemas.fogbowcloud.org/template/os#"; class="mixin";
               title="fogbow-linux-x86 image"; rel="http://schemas.ogf.org/occi/infrastructure#os_tpl";
               location="http://localhost:8182/fogbow-linux-x86/"
        Category: fogbow_userdata; scheme="http://schemas.fogbowcloud.org/request#"; class="mixin";
               location="http://localhost:8182/fogbow_userdata/"
        X-OCCI-Attribute: org.fogbowcloud.credentials.publickey.data="Not defined"
        X-OCCI-Attribute: org.fogbowcloud.order.state="fulfilled"
        X-OCCI-Attribute: org.fogbowcloud.order.valid-from="Not defined"
        X-OCCI-Attribute: occi.core.id="32b9f297-2728-4155-bcf5-409348aa474e"
        X-OCCI-Attribute: org.fogbowcloud.order.user-data="IyEvYmluL3NoC ..."
        X-OCCI-Attribute: org.fogbowcloud.order.type="one-time"
        X-OCCI-Attribute: org.fogbowcloud.order.valid-until="Not defined"
        X-OCCI-Attribute: org.fogbowcloud.order.instance-count="1"
        X-OCCI-Attribute: org.fogbowcloud.order.instance-id="267@manager.i3m.upv.es"

        Instancia:
        Category: compute; scheme="http://schemas.ogf.org/occi/infrastructure#"; class="kind";
            title="Compute Resource"; rel="http://schemas.ogf.org/occi/core#resource";
            location="http://localhost:8182/compute/"; attributes="occi.compute.architecture ..."
        Category: os_tpl; scheme="http://schemas.ogf.org/occi/infrastructure#"; class="mixin";
            location="http://localhost:8182/os_tpl/"
        Category: fogbow_small; scheme="http://schemas.fogbowcloud.org/template/resource#"; class="mixin";
            title="Small Flavor"; rel="http://schemas.ogf.org/occi/infrastructure#resource_tpl";
            location="http://localhost:8182/fogbow_small/"
        Category: fogbow-linux-x86; scheme="http://schemas.fogbowcloud.org/template/os#"; class="mixin";
            title="fogbow-linux-x86 image"; rel="http://schemas.ogf.org/occi/infrastructure#os_tpl";
            location="http://localhost:8182/fogbow-linux-x86/"
        X-OCCI-Attribute: occi.compute.state="active"
        X-OCCI-Attribute: occi.compute.hostname="one-267"
        X-OCCI-Attribute: occi.compute.memory="0.125"
        X-OCCI-Attribute: occi.compute.cores="1"
        X-OCCI-Attribute: org.fogbowcloud.order.ssh-public-address="158.42.104.75:20001"
        X-OCCI-Attribute: occi.core.id="267"
        X-OCCI-Attribute: occi.compute.architecture="x86"
        X-OCCI-Attribute: occi.compute.speed="Not defined"

    """

    def updateVMInfo(self, vm, auth_data):
        try:
            # First get the request info
            headers = {'Accept': 'text/plain'}
            resp = self.create_request('GET', "/order/" + vm.id, auth_data, headers=headers)

            if resp.status_code != 200:
                return (False, resp.reason + "\n" + resp.text)
            else:
                providing_member = self.get_occi_attribute_value(resp.text, 'org.fogbowcloud.order.providing-member')
                if providing_member == "null":
                    providing_member = None
                instance_id = self.get_occi_attribute_value(resp.text, 'org.fogbowcloud.order.instance-id')
                if instance_id == "null":
                    instance_id = None

                if not instance_id:
                    vm.state = VirtualMachine.PENDING
                    return (True, vm)
                else:
                    # Now get the instance info
                    resp = self.create_request('GET', "/compute/" + instance_id, auth_data, headers=headers)

                    if resp.status_code == 404:
                        vm.state = VirtualMachine.OFF
                        return (True, vm)
                    elif resp.status_code != 200:
                        return (False, resp.reason + "\n" + resp.text)
                    else:
                        vm.state = self.VM_STATE_MAP.get(self.get_occi_attribute_value(
                            resp.text, 'occi.compute.state'), VirtualMachine.UNKNOWN)

                        cores = self.get_occi_attribute_value(resp.text, 'occi.compute.cores')
                        if cores:
                            vm.info.systems[0].addFeature(
                                Feature("cpu.count", "=", int(cores)), conflict="other", missing="other")
                        memory = self.get_occi_attribute_value(resp.text, 'occi.compute.memory')
                        if memory:
                            vm.info.systems[0].addFeature(Feature("memory.size", "=", float(
                                memory), 'G'), conflict="other", missing="other")

                        # Update the network data
                        private_ips = []
                        public_ips = []

                        ssh_public_address = self.get_occi_attribute_value(
                            resp.text, 'org.fogbowcloud.order.ssh-public-address')
                        local_ip_address = self.get_occi_attribute_value(
                            resp.text, 'org.fogbowcloud.order.local-ip-address')

                        if local_ip_address:
                            private_ips.append(local_ip_address)

                        if ssh_public_address:
                            parts = ssh_public_address.split(':')
                            public_ips.append(parts[0])
                            if len(parts) > 1:
                                vm.setSSHPort(int(parts[1]))

                        vm.setIps(public_ips, private_ips)

                        extra_ports = self.get_occi_attribute_value(resp.text, 'org.fogbowcloud.order.extra-ports')
                        if extra_ports:
                            self.set_extra_ports(vm, extra_ports)

                        ssh_user = self.get_occi_attribute_value(resp.text, 'org.fogbowcloud.order.ssh-username')
                        if ssh_user:
                            vm.info.systems[0].addFeature(Feature(
                                "disk.0.os.credentials.username", "=", ssh_user), conflict="other", missing="other")

                        vm.info.systems[0].setValue('instance_id', instance_id)
                        vm.info.systems[0].setValue('availability_zone', providing_member)

                        return (True, vm)

        except Exception as ex:
            self.log_exception("Error connecting with FogBow Manager")
            return (False, "Error connecting with FogBow Manager: " + str(ex))

    def create_extra_ports_script(self, radl):
        """
        Create the Script to create the tunneled ports
        """
        res = ""
        i = 0
        system = radl.systems[0]
        while system.getValue("net_interface." + str(i) + ".connection"):
            network_name = system.getValue("net_interface." + str(i) + ".connection")
            network = radl.get_network_by_id(network_name)

            outports = network.getOutPorts()
            if outports:
                for outport in outports:
                    protocol = outport.get_protocol()
                    if not protocol:
                        protocol = "tcp"
                    if outport.is_range():
                        for port in range(outport.get_port_init(), outport.get_port_end()):
                            res += "create-fogbow-tunnel %s%d %d &\n" % (protocol, port, port)
                    else:
                        if outport.get_remote_port() != 22:
                            port = outport.get_remote_port()
                            res += "create-fogbow-tunnel %s%d %d &\n" % (protocol, port, port)

            i += 1

        if res:
            return "#!/bin/bash\n" + res
        else:
            return res

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        system = radl.systems[0]
        # name = system.getValue("disk.0.image.name")

        res = []
        i = 0

        url = uriparse(system.getValue("disk.0.image.url"))
        if url[1].startswith('http'):
            os_tpl = url[1] + url[2]
        else:
            os_tpl = url[1]

        # set the credentials the FogBow default username: fogbow
        system.delValue('disk.0.os.credentials.username')
        system.setValue('disk.0.os.credentials.username', 'fogbow')

        public_key = system.getValue('disk.0.os.credentials.public_key')

        if not public_key:
            # We must generate them
            (public_key, private_key) = self.keygen()
            system.setValue('disk.0.os.credentials.private_key', private_key)

        while i < num_vm:
            try:
                headers = {'Content-Type': 'text/occi'}
                headers['Category'] = 'order; scheme="http://schemas.fogbowcloud.org/order#"; class="kind"'
                headers['X-OCCI-Attribute'] = 'org.fogbowcloud.order.instance-count=1'
                headers['X-OCCI-Attribute'] += ',org.fogbowcloud.order.type="one-time"'
                headers['X-OCCI-Attribute'] += ',org.fogbowcloud.order.resource-kind="compute"'
                headers['X-OCCI-Attribute'] += (',org.fogbowcloud.credentials.publickey.data="' +
                                                public_key.strip() + '"')

                requirements = ""
                if system.getValue('instance_type'):
                    headers['Category'] += ("," + system.getValue('instance_type') +
                                            '; scheme="http://schemas.fogbowcloud.org/template/resource#";'
                                            ' class="mixin"')
                else:
                    cpu = system.getValue('cpu.count')
                    memory = system.getFeature('memory.size').getValue('M')
                    if cpu:
                        requirements += "Glue2vCPU >= %d" % cpu
                    if memory:
                        if requirements:
                            requirements += " && "
                        requirements += "Glue2RAM >= %d" % memory

                headers['Category'] += ("," + os_tpl +
                                        '; scheme="http://schemas.fogbowcloud.org/template/os#"; class="mixin"')
                headers['Category'] += (',fogbow_public_key; scheme="http://schemas.fogbowcloud/credentials#";'
                                        ' class="mixin"')

                if system.getValue('availability_zone'):
                    if requirements:
                        requirements += ' && '
                    requirements += 'Glue2CloudComputeManagerID == "%s"' % system.getValue('availability_zone')

                if requirements:
                    headers['X-OCCI-Attribute'] += ',org.fogbowcloud.order.requirements="%s"' % requirements

                for net in radl.networks:
                    if not net.isPublic() and radl.systems[0].getNumNetworkWithConnection(net.id) is not None:
                        provider_id = net.getValue('provider_id')
                        if provider_id:
                            headers['Link'] = ('</network/' + provider_id + '>; ' +
                                               'rel="http://schemas.ogf.org/occi/infrastructure#network"; category=' +
                                               '"http://schemas.ogf.org/occi/infrastructure#networkinterface";')

                extra_ports_script = self.create_extra_ports_script(radl)
                if extra_ports_script:
                    user_data = base64.b64encode(extra_ports_script.replace("\n", "[[\\n]]").encode())
                    headers['X-OCCI-Attribute'] += ',org.fogbowcloud.order.extra-user-data="%s"' % user_data.decode()
                    headers['X-OCCI-Attribute'] += (',org.fogbowcloud.order.extra-user-data-content-type'
                                                    '="text/x-shellscript"')

                resp = self.create_request('POST', '/order/', auth_data, headers)

                if resp.status_code != 201:
                    res.append((False, resp.reason + "\n" + resp.text))
                else:
                    if 'location' in resp.headers:
                        occi_vm_id = os.path.basename(resp.headers['location'])
                    else:
                        occi_vm_id = os.path.basename(resp.text)
                    vm = VirtualMachine(inf, occi_vm_id, self.cloud, radl, requested_radl)
                    vm.info.systems[0].setValue('instance_id', str(vm.id))
                    inf.add_vm(vm)
                    res.append((True, vm))

            except Exception as ex:
                self.log_exception("Error connecting with FogBow manager")
                res.append((False, "ERROR: " + str(ex)))

            i += 1

        return res

    def finalize(self, vm, last, auth_data):
        if not vm.id:
            self.log_warn("No VM ID. Ignoring")
            return True, "No VM ID. Ignoring"

        headers = {'Accept': 'text/plain'}

        try:
            # First get the order info
            resp = self.create_request('GET', "/order/" + vm.id, auth_data, headers=headers)

            if resp.status_code == 404:
                vm.state = VirtualMachine.OFF
                return (True, "")
            elif resp.status_code != 200:
                return (False, "Error removing the VM: " + resp.reason + "\n" + resp.text)
            else:
                instance_id = self.get_occi_attribute_value(resp.text, 'org.fogbowcloud.order.instance-id')
                if instance_id == "null":
                    instance_id = None

                if instance_id:
                    resp = self.create_request('DELETE', "/compute/" + instance_id, auth_data, headers=headers)

                    if resp.status_code != 404 and resp.status_code != 200:
                        return (False, "Error removing the VM: " + resp.reason + "\n" + resp.text)

            resp = self.create_request('DELETE', "/order/" + vm.id, auth_data, headers=headers)

            if resp.status_code == 404 or resp.status_code == 200:
                return (True, "")
            else:
                return (False, "Error removing the VM: " + resp.reason + "\n" + resp.text)
        except Exception:
            self.log_exception("Error connecting with OCCI server")
            return (False, "Error connecting with OCCI server")

    def stop(self, vm, auth_data):
        return (False, "Not supported")

    def start(self, vm, auth_data):
        return (False, "Not supported")

    def alterVM(self, vm, radl, auth_data):
        return (False, "Not supported")


class IdentityPlugin:

    @staticmethod
    def create_token(params):
        """
        Creates a token
        """
        raise NotImplementedError("Should have implemented this")

    @staticmethod
    def getIdentityPlugin(identity_type):
        """
        Returns the appropriate object to contact the IdentityPlugin
        """
        if len(identity_type) > 15 or "." in identity_type:
            raise Exception("Not valid Identity Plugin.")
        try:
            return getattr(sys.modules[__name__], identity_type + "IdentityPlugin")()
        except Exception as ex:
            raise Exception("IdentityPlugin not supported: %s (error: %s)" % (identity_type, str(ex)))


class OpenNebulaIdentityPlugin(IdentityPlugin):

    @staticmethod
    def create_token(params):
        if 'username' in params and 'password' in params:
            return params['username'] + ":" + params['password']
        else:
            raise Exception("Incorrect auth data, username and password must be specified")


class TokenIdentityPlugin(IdentityPlugin):

    @staticmethod
    def create_token(params):
        if 'token' in params:
            return params['token']
        else:
            raise Exception("Incorrect auth data, token must be specified")


class X509IdentityPlugin(IdentityPlugin):

    @staticmethod
    def create_token(params):
        if 'proxy' in params:
            return params['proxy']
        else:
            raise Exception("Incorrect auth data, proxy must be specified")


class VOMSIdentityPlugin(IdentityPlugin):

    @staticmethod
    def create_token(params):
        if 'proxy' in params:
            return params['proxy']
        else:
            raise Exception("Incorrect auth data, no proxy has been specified")


class KeyStoneIdentityPlugin(IdentityPlugin):
    """
    Class to manage the Keystone auth tokens used in OpenStack
    """

    @staticmethod
    def create_token(params):
        """
        Contact the specified keystone server to return the token
        """
        if 'username' in params and 'password' in params and 'auth_url' in params and 'tenant' in params:
            try:
                keystone_uri = params['auth_url']

                headers = {'Accept': 'application/json', 'Connection': 'close', 'Content-Type': 'application/json'}
                body = ('{"auth":{"passwordCredentials":{"username": "' + params['username'] +
                        '","password": "' + params['password'] + '"},"tenantName": "' + params['tenant'] + '"}}')

                url = "%s/v2.0/tokens" % keystone_uri
                resp = requests.request('POST', url, verify=False, headers=headers, data=body)

                # format: -> "{\"access\": {\"token\": {\"issued_at\":
                # \"2014-12-29T17:10:49.609894\", \"expires\":
                # \"2014-12-30T17:10:49Z\", \"id\":
                # \"c861ab413e844d12a61d09b23dc4fb9c\"}, \"serviceCatalog\":
                # [], \"user\": {\"username\":
                # \"/DC=es/DC=irisgrid/O=upv/CN=miguel-caballer\",
                # \"roles_links\": [], \"id\":
                # \"475ce4978fb042e49ce0391de9bab49b\", \"roles\": [],
                # \"name\": \"/DC=es/DC=irisgrid/O=upv/CN=miguel-caballer\"},
                # \"metadata\": {\"is_admin\": 0, \"roles\": []}}}"
                output = resp.json()
                token_id = output['access']['token']['id']

                return token_id
            except:
                return None
        else:
            raise Exception(
                "Incorrect auth data, auth_url, username, password and tenant must be specified")
