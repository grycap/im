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
import httplib
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from CloudConnector import CloudConnector
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
        'inactive': VirtualMachine.OFF,
        'suspended': VirtualMachine.OFF
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

    def get_http_connection(self):
        """
        Get the HTTPConnection object to contact the FogBow API

        Returns(HTTPConnection or HTTPSConnection): HTTPConnection connection object
        """

        if self.cloud.protocol == 'https':
            conn = httplib.HTTPSConnection(self.cloud.server, self.cloud.port)
        else:
            conn = httplib.HTTPConnection(self.cloud.server, self.cloud.port)

        return conn

    def get_auth_headers(self, auth_data):
        """
        Generate the auth header needed to contact with the FogBow server.
        """
        auth = auth_data.getAuthInfo(FogBowCloudConnector.type)
        if not auth:
            raise Exception(
                "No correct auth data has been specified to FogBow.")

        if 'token_type' in auth[0]:
            token_type = auth[0]['token_type']
        else:
            # If not token_type supplied, we assume that is VOMS one
            token_type = 'VOMS'

        plugin = IdentityPlugin.getIdentityPlugin(token_type)
        token = plugin.create_token(auth[0]).replace(
            "\n", "").replace("\r", "")

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

    """
    text/plain format:
        Recurso:
        Category: fogbow_request; scheme="http://schemas.fogbowcloud.org/request#"; class="kind";
               title="Request new Instances"; rel="http://schemas.ogf.org/occi/core#resource";
               location="http://localhost:8182/fogbow_request/";
               attributes="org.fogbowcloud.request.instance-count ..."
        Category: fogbow_small; scheme="http://schemas.fogbowcloud.org/template/resource#"; class="mixin";
               title="Small Flavor"; rel="http://schemas.ogf.org/occi/infrastructure#resource_tpl";
               location="http://localhost:8182/fogbow_small/"
        Category: fogbow-linux-x86; scheme="http://schemas.fogbowcloud.org/template/os#"; class="mixin";
               title="fogbow-linux-x86 image"; rel="http://schemas.ogf.org/occi/infrastructure#os_tpl";
               location="http://localhost:8182/fogbow-linux-x86/"
        Category: fogbow_userdata; scheme="http://schemas.fogbowcloud.org/request#"; class="mixin";
               location="http://localhost:8182/fogbow_userdata/"
        X-OCCI-Attribute: org.fogbowcloud.credentials.publickey.data="Not defined"
        X-OCCI-Attribute: org.fogbowcloud.request.state="fulfilled"
        X-OCCI-Attribute: org.fogbowcloud.request.valid-from="Not defined"
        X-OCCI-Attribute: occi.core.id="32b9f297-2728-4155-bcf5-409348aa474e"
        X-OCCI-Attribute: org.fogbowcloud.request.user-data="IyEvYmluL3NoC ..."
        X-OCCI-Attribute: org.fogbowcloud.request.type="one-time"
        X-OCCI-Attribute: org.fogbowcloud.request.valid-until="Not defined"
        X-OCCI-Attribute: org.fogbowcloud.request.instance-count="1"
        X-OCCI-Attribute: org.fogbowcloud.request.instance-id="267@manager.i3m.upv.es"

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
        X-OCCI-Attribute: org.fogbowcloud.request.ssh-public-address="158.42.104.75:20001"
        X-OCCI-Attribute: occi.core.id="267"
        X-OCCI-Attribute: occi.compute.architecture="x86"
        X-OCCI-Attribute: occi.compute.speed="Not defined"

    """

    def updateVMInfo(self, vm, auth_data):
        auth = self.get_auth_headers(auth_data)
        headers = {'Accept': 'text/plain'}
        if auth:
            headers.update(auth)

        try:
            # First get the request info
            conn = self.get_http_connection()
            conn.request('GET', "/fogbow_request/" + vm.id, headers=headers)
            resp = conn.getresponse()

            output = resp.read()
            if resp.status == 404:
                vm.state = VirtualMachine.OFF
                return (True, vm)
            elif resp.status != 200:
                return (False, resp.reason + "\n" + output)
            else:
                providing_member = self.get_occi_attribute_value(
                    output, 'org.fogbowcloud.request.providing-member')
                if providing_member == "null":
                    providing_member = None
                instance_id = self.get_occi_attribute_value(
                    output, 'org.fogbowcloud.request.instance-id')
                if instance_id == "null":
                    instance_id = None

                if not instance_id:
                    vm.state = VirtualMachine.PENDING
                    return (True, vm)
                else:
                    # Now get the instance info
                    conn = self.get_http_connection()
                    conn.request('GET', "/compute/" +
                                 instance_id, headers=headers)
                    resp = conn.getresponse()

                    output = resp.read()
                    if resp.status == 404:
                        vm.state = VirtualMachine.OFF
                        return (True, vm)
                    elif resp.status != 200:
                        return (False, resp.reason + "\n" + output)
                    else:
                        vm.state = self.VM_STATE_MAP.get(self.get_occi_attribute_value(
                            output, 'occi.compute.state'), VirtualMachine.UNKNOWN)

                        cores = self.get_occi_attribute_value(
                            output, 'occi.compute.cores')
                        if cores:
                            vm.info.systems[0].addFeature(
                                Feature("cpu.count", "=", int(cores)), conflict="other", missing="other")
                        memory = self.get_occi_attribute_value(
                            output, 'occi.compute.memory')
                        if memory:
                            vm.info.systems[0].addFeature(Feature("memory.size", "=", float(
                                memory), 'G'), conflict="other", missing="other")

                        # Update the network data
                        ssh_public_address = self.get_occi_attribute_value(
                            output, 'org.fogbowcloud.request.ssh-public-address')
                        if ssh_public_address:
                            parts = ssh_public_address.split(':')
                            vm.setIps([parts[0]], [])
                            if len(parts) > 1:
                                vm.setSSHPort(int(parts[1]))

                        extra_ports = self.get_occi_attribute_value(
                            output, 'org.fogbowcloud.request.extra-ports')
                        if extra_ports:
                            vm.info.systems[0].addFeature(Feature(
                                "fogbow.extra-ports", "=", extra_ports), conflict="other", missing="other")

                        ssh_user = self.get_occi_attribute_value(
                            output, 'org.fogbowcloud.request.ssh-username')
                        if ssh_user:
                            vm.info.systems[0].addFeature(Feature(
                                "disk.0.os.credentials.username", "=", ssh_user), conflict="other", missing="other")

                        vm.info.systems[0].setValue('instance_id', instance_id)
                        vm.info.systems[0].setValue(
                            'availability_zone', providing_member)

                        return (True, vm)

        except Exception, ex:
            self.logger.exception("Error connecting with FogBow Manager")
            return (False, "Error connecting with FogBow Manager: " + str(ex))

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        system = radl.systems[0]
        auth_headers = self.get_auth_headers(auth_data)

        # name = system.getValue("disk.0.image.name")

        res = []
        i = 0
        conn = self.get_http_connection()

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
                conn.putrequest('POST', "/fogbow_request/")
                conn.putheader('Content-Type', 'text/occi')
                # conn.putheader('Accept', 'text/occi')
                if auth_headers:
                    for k, v in auth_headers.iteritems():
                        conn.putheader(k, v)

                conn.putheader(
                    'Category', 'fogbow_request; scheme="http://schemas.fogbowcloud.org/request#"; class="kind"')

                conn.putheader('X-OCCI-Attribute',
                               'org.fogbowcloud.request.instance-count=1')
                conn.putheader('X-OCCI-Attribute',
                               'org.fogbowcloud.request.type="one-time"')
                conn.putheader('X-OCCI-Attribute',
                               'org.fogbowcloud.order.resource-kind="compute"')

                requirements = ""
                if system.getValue('instance_type'):
                    conn.putheader('Category', system.getValue('instance_type') +
                                   '; scheme="http://schemas.fogbowcloud.org/template/resource#"; class="mixin"')
                else:
                    cpu = system.getValue('cpu.count')
                    memory = system.getFeature('memory.size').getValue('M')
                    if cpu:
                        requirements += "Glue2vCPU >= %d" % cpu
                    if memory:
                        if requirements:
                            requirements += " && "
                        requirements += "Glue2RAM >= %d" % memory

                conn.putheader(
                    'Category', os_tpl + '; scheme="http://schemas.fogbowcloud.org/template/os#"; class="mixin"')
                conn.putheader(
                    'Category', 'fogbow_public_key; scheme="http://schemas.fogbowcloud/credentials#"; class="mixin"')
                conn.putheader(
                    'X-OCCI-Attribute', 'org.fogbowcloud.credentials.publickey.data="' + public_key.strip() + '"')

                if system.getValue('availability_zone'):
                    if requirements:
                        requirements += ' && '
                        requirements += 'Glue2CloudComputeManagerID == "%s"' % system.getValue(
                            'availability_zone')

                if requirements:
                    conn.putheader(
                        'X-OCCI-Attribute', 'org.fogbowcloud.request.requirements=' + requirements)

                conn.endheaders()

                resp = conn.getresponse()

                # With this format: X-OCCI-Location:
                # http://158.42.104.75:8182/fogbow_request/436e76ef-9980-4fdb-87fe-71e82655f578
                output = resp.read()

                if resp.status != 201:
                    res.append((False, resp.reason + "\n" + output))
                else:
                    occi_vm_id = os.path.basename(resp.msg.dict['location'])
                    # occi_vm_id = os.path.basename(output)
                    vm = VirtualMachine(
                        inf, occi_vm_id, self.cloud, radl, requested_radl)
                    vm.info.systems[0].setValue('instance_id', str(vm.id))
                    res.append((True, vm))

            except Exception, ex:
                self.logger.exception("Error connecting with FogBow manager")
                res.append((False, "ERROR: " + str(ex)))

            i += 1

        return res

    def finalize(self, vm, auth_data):
        auth = self.get_auth_headers(auth_data)
        headers = {'Accept': 'text/plain'}
        if auth:
            headers.update(auth)

        try:
            # First get the request info
            conn = self.get_http_connection()
            conn.request('GET', "/fogbow_request/" + vm.id, headers=headers)
            resp = conn.getresponse()

            output = resp.read()
            if resp.status == 404:
                vm.state = VirtualMachine.OFF
                return (True, vm.id)
            elif resp.status != 200:
                return (False, "Error removing the VM: " + resp.reason + "\n" + output)
            else:
                instance_id = self.get_occi_attribute_value(
                    output, 'org.fogbowcloud.request.instance-id')
                if instance_id == "null":
                    instance_id = None

                if instance_id:
                    conn = self.get_http_connection()
                    conn.request('DELETE', "/compute/" +
                                 instance_id, headers=headers)
                    resp = conn.getresponse()

                    output = str(resp.read())
                    if resp.status != 404 and resp.status != 200:
                        return (False, "Error removing the VM: " + resp.reason + "\n" + output)

            conn = self.get_http_connection()
            conn.request('DELETE', "/fogbow_request/" + vm.id, headers=headers)
            resp = conn.getresponse()

            output = str(resp.read())
            if resp.status == 404:
                return (True, vm.id)
            elif resp.status != 200:
                return (False, "Error removing the VM: " + resp.reason + "\n" + output)
            else:
                return (True, vm.id)
        except Exception:
            self.logger.exception("Error connecting with OCCI server")
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
        except Exception, ex:
            raise Exception("IdentityPlugin not supported: %s (error: %s)" % (
                identity_type, str(ex)))


class OpenNebulaIdentityPlugin(IdentityPlugin):

    @staticmethod
    def create_token(params):
        if 'username' in params and 'password' in params:
            return params['username'] + ":" + params['password']
        else:
            raise Exception(
                "Incorrect auth data, username and password must be specified")


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
                uri = uriparse(keystone_uri)
                server = uri[1].split(":")[0]
                port = int(uri[1].split(":")[1])

                conn = httplib.HTTPSConnection(server, port)
                conn.putrequest('POST', "/v2.0/tokens")
                conn.putheader('Accept', 'application/json')
                conn.putheader('Content-Type', 'application/json')
                conn.putheader('Connection', 'close')

                body = ('{"auth":{"passwordCredentials":{"username": "' + params['username'] +
                        '","password": "' + params['password'] + '"},"tenantName": "' + params['tenant'] + '"}}')

                conn.putheader('Content-Length', len(body))
                conn.endheaders(body)

                resp = conn.getresponse()

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
                output = json.loads(resp.read())
                token_id = output['access']['token']['id']

                if conn.cert_file and os.path.isfile(conn.cert_file):
                    os.unlink(conn.cert_file)

                return token_id
            except:
                return None
        else:
            raise Exception(
                "Incorrect auth data, auth_url, username, password and tenant must be specified")
