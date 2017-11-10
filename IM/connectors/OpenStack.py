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

import time
from netaddr import IPNetwork, IPAddress
import os.path
import tempfile

try:
    from libcloud.compute.types import Provider, NodeState
    from libcloud.compute.providers import get_driver
    from libcloud.compute.base import NodeImage, NodeAuthSSHKey
except Exception as ex:
    print("WARN: libcloud library not correctly installed. OpenStackCloudConnector will not work!.")
    print(ex)

from IM.connectors.LibCloud import LibCloudCloudConnector
from IM.config import Config
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from radl.radl import Feature


class OpenStackCloudConnector(LibCloudCloudConnector):
    """
    Cloud Launcher to OpenStack using LibCloud (Needs version 0.16.0 or higher version)
    """

    type = "OpenStack"
    """str with the name of the provider."""
    DEFAULT_USER = 'cloudadm'
    """ default user to SSH access the VM """
    MAX_ADD_IP_COUNT = 5
    """ Max number of retries to get a public IP """
    CONFIG_DRIVE = False
    """ Enable config drive """

    def __init__(self, cloud_info, inf):
        self.auth = None
        self.add_public_ip_count = 0
        LibCloudCloudConnector.__init__(self, cloud_info, inf)

    def get_driver(self, auth_data):
        """
        Get the driver from the auth data

        Arguments:
                - auth(Authentication): parsed authentication tokens.

        Returns: a :py:class:`libcloud.compute.base.NodeDriver` or None in case of error
        """
        auths = auth_data.getAuthInfo(self.type, self.cloud.server)
        if not auths:
            raise Exception("No auth data has been specified to OpenStack.")
        else:
            auth = auths[0]

        if self.driver and self.auth.compare(auth_data, self.type):
            return self.driver
        else:
            self.auth = auth_data

            protocol = self.cloud.protocol
            if not protocol:
                protocol = "http"

            parameters = {"auth_version": '2.0_password',
                          "auth_url": protocol + "://" + self.cloud.server + ":" + str(self.cloud.port),
                          "auth_token": None,
                          "service_type": None,
                          "service_name": None,
                          "service_region": 'RegionOne',
                          "base_url": None,
                          "domain": None}

            if 'username' in auth and 'password' in auth and 'tenant' in auth:
                username = auth['username']
                password = auth['password']
                tenant = auth['tenant']
                for param in parameters:
                    if param in auth:
                        parameters[param] = auth[param]
            elif 'proxy' in auth:
                (fproxy, proxy_filename) = tempfile.mkstemp()
                os.write(fproxy, auth['proxy'].encode())
                os.close(fproxy)
                username = ''
                password = proxy_filename
                tenant = auth['tenant']
                parameters["auth_version"] = '2.0_voms'

                for param in parameters:
                    if param in auth:
                        parameters[param] = auth[param]
            else:
                self.log_error(
                    "No correct auth data has been specified to OpenStack: username, password and tenant or proxy")
                raise Exception(
                    "No correct auth data has been specified to OpenStack: username, password and tenant or proxy")

            # To avoid errors with host certificates
            # if you want to do it in a more secure way check this:
            # http://libcloud.readthedocs.org/en/latest/other/ssl-certificate-validation.html
            import libcloud.security
            libcloud.security.VERIFY_SSL_CERT = False

            try:
                import ssl
                ssl._create_default_https_context = ssl._create_unverified_context
            except:
                pass

            # Workaround to OTC to enable to set service_name as None
            service_name = parameters["service_name"]
            if parameters["service_name"] == "None":
                service_name = None

            cls = get_driver(Provider.OPENSTACK)
            driver = cls(username, password,
                         ex_tenant_name=tenant,
                         ex_domain_name=parameters['domain'],
                         ex_force_auth_url=parameters["auth_url"],
                         ex_force_auth_version=parameters["auth_version"],
                         ex_force_service_region=parameters["service_region"],
                         ex_force_base_url=parameters["base_url"],
                         ex_force_service_name=service_name,
                         ex_force_service_type=parameters["service_type"],
                         ex_force_auth_token=parameters["auth_token"])

            # Workaround to OTC to enable to set service_name as None
            if parameters["service_name"] == "None":
                driver.connection.service_name = None

            self.driver = driver
            return driver

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

                src_host = url[1].split(':')[0]
                # TODO: check the port
                if protocol == "ost" and self.cloud.server == src_host:
                    driver = self.get_driver(auth_data)

                    res_system = radl_system.clone()
                    instance_type = self.get_instance_type(driver.list_sizes(), res_system)
                    self.update_system_info_from_instance(res_system, instance_type)

                    res_system.addFeature(
                        Feature("disk.0.image.url", "=", str_url), conflict="other", missing="other")

                    res_system.addFeature(
                        Feature("provider.type", "=", self.type), conflict="other", missing="other")
                    res_system.addFeature(Feature(
                        "provider.host", "=", self.cloud.server), conflict="other", missing="other")
                    res_system.addFeature(Feature(
                        "provider.port", "=", self.cloud.port), conflict="other", missing="other")

                    username = res_system.getValue('disk.0.os.credentials.username')
                    if not username:
                        res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)

                    res.append(res_system)

            return res

    def updateVMInfo(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            if node.state == NodeState.RUNNING or node.state == NodeState.REBOOTING:
                res_state = VirtualMachine.RUNNING
            elif node.state == NodeState.PENDING:
                res_state = VirtualMachine.PENDING
            elif node.state == NodeState.TERMINATED:
                res_state = VirtualMachine.OFF
            elif node.state == NodeState.STOPPED:
                res_state = VirtualMachine.STOPPED
            elif node.state == NodeState.ERROR:
                res_state = VirtualMachine.FAILED
            else:
                res_state = VirtualMachine.UNKNOWN

            vm.state = res_state

            flavorId = node.extra['flavorId']
            instance_type = node.driver.ex_get_size(flavorId)
            self.update_system_info_from_instance(
                vm.info.systems[0], instance_type)

            self.setIPsFromInstance(vm, node)
            self.attach_volumes(vm, node)
        else:
            self.log_warn("Error updating the instance %s. VM not found." % vm.id)
            return (False, "Error updating the instance %s. VM not found." % vm.id)

        return (True, vm)

    def map_radl_ost_networks(self, radl_nets, ost_nets):
        """
        Generate a mapping between the RADL networks and the OST networks

        Arguments:
           - radl_nets(list of :py:class:`radl.network` objects): RADL networks.
           - ost_nets(a list of tuples (net_name, is_public)): OST networks.

         Returns: a dict with key the RADL network id and value a tuple (ost_net_name, is_public)
        """

        res = {"#UNMAPPED#": []}
        for ip, (net_name, is_public) in ost_nets.items():
            if net_name:
                for radl_net in radl_nets:
                    net_provider_id = radl_net.getValue('provider_id')
                    if net_provider_id:
                        if net_name == net_provider_id:
                            res[radl_net.id] = ip
                            break
                    else:
                        if radl_net.id not in res:
                            if radl_net.isPublic() == is_public:
                                res[radl_net.id] = ip
                                radl_net.setValue('provider_id', net_name)
                                break
                            else:
                                # the ip not matches the is_public value
                                res["#UNMAPPED#"].append(ip)
            else:
                # It seems to be a floating IP
                for radl_net in radl_nets:
                    if radl_net.id not in res and radl_net.isPublic() == is_public:
                        res[radl_net.id] = ip
                        break

        return res

    def get_node_floating_ips(self, node):
        """
        Get a list of ip addresses associated with a node
        """
        ips = []
        try:
            for pool in node.driver.ex_list_floating_ip_pools():
                for ip in pool.list_floating_ips():
                    if ip.node_id == node.id:
                        ips.append(ip.ip_address)
        except:
            self.log_exception("Error node floating ips")
        return ips

    def setIPsFromInstance(self, vm, node):
        """
        Adapt the RADL information of the VM to the real IPs assigned by the cloud provider

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - node(:py:class:`libcloud.compute.base.Node`): object to connect to EC2 instance.
        """

        if 'addresses' in node.extra:
            public_ips = []
            ip_net_map = {}

            for net_name, ips in node.extra['addresses'].items():
                for ipo in ips:
                    ip = ipo['addr']
                    is_private = any([IPAddress(ip) in IPNetwork(mask) for mask in Config.PRIVATE_NET_MASKS])

                    if ipo['OS-EXT-IPS:type'] == 'floating':
                        ip_net_map[ip] = (None, not is_private)
                    else:
                        ip_net_map[ip] = (net_name, not is_private)
                    if not is_private:
                        public_ips.append(ip)

            for float_ip in self.get_node_floating_ips(node):
                if float_ip not in ip_net_map:
                    is_private = any([IPAddress(float_ip) in IPNetwork(mask) for mask in Config.PRIVATE_NET_MASKS])
                    ip_net_map[float_ip] = (None, not is_private)
                    if not is_private:
                        public_ips.append(float_ip)

            map_nets = self.map_radl_ost_networks(vm.info.networks, ip_net_map)

            system = vm.info.systems[0]
            i = 0
            ips_assigned = []
            while system.getValue("net_interface." + str(i) + ".connection"):
                net_name = system.getValue("net_interface." + str(i) + ".connection")
                if net_name in map_nets:
                    ip = map_nets[net_name]
                    system.setValue("net_interface." + str(i) + ".ip", ip)
                    ips_assigned.append(ip)
                i += 1

            # For IPs not correctly mapped
            # e.g. If you request a private IP and you get a public one it is
            # not correctly mapped
            for net_name, ip in map_nets.items():
                if net_name != '#UNMAPPED#':
                    if ip not in ips_assigned:
                        num_net = system.getNumNetworkIfaces()
                        system.setValue('net_interface.' + str(num_net) + '.ip', ip)
                        system.setValue('net_interface.' + str(num_net) + '.connection', net_name)
                else:
                    pub_ips = []
                    priv_ips = []
                    for ipu in ip:
                        if any([IPAddress(ipu) in IPNetwork(mask) for mask in Config.PRIVATE_NET_MASKS]):
                            priv_ips.append(ipu)
                        else:
                            pub_ips.append(ipu)
                    vm.setIps(pub_ips, priv_ips)

        else:
            # if addresses are not available use the old method
            public_ips = []
            private_ips = []
            for ip in node.public_ips + node.private_ips + self.get_node_floating_ips(node):
                if any([IPAddress(ip) in IPNetwork(mask) for mask in Config.PRIVATE_NET_MASKS]):
                    private_ips.append(ip)
                else:
                    public_ips.append(ip)
            vm.setIps(public_ips, private_ips)

        if vm.state == VirtualMachine.RUNNING:
            if self.add_public_ip_count < self.MAX_ADD_IP_COUNT:
                self.manage_elastic_ips(vm, node, public_ips)
            else:
                self.log_error("Error adding a floating IP: Max number of retries reached.")
                self.error_messages += "Error adding a floating IP: Max number of retries reached.\n"
        else:
            self.log_info("The VM is not running, not adding Elastic/Floating IPs.")

    def update_system_info_from_instance(self, system, instance_type):
        """
        Update the features of the system with the information of the instance_type
        """
        if instance_type:
            LibCloudCloudConnector.update_system_info_from_instance(self, system, instance_type)
            if instance_type.vcpus:
                system.addFeature(
                    Feature("cpu.count", "=", instance_type.vcpus), conflict="me", missing="other")

    def get_networks(self, driver, radl):
        """
        Get the list of networks to connect the VM
        """
        nets = []
        ost_nets = driver.ex_list_networks()
        used_nets = []

        pool_names = [pool.name for pool in driver.ex_list_floating_ip_pools()]

        num_nets = radl.systems[0].getNumNetworkIfaces()

        i = 0
        while radl.systems[0].getValue("net_interface." + str(i) + ".connection"):
            net_name = radl.systems[0].getValue("net_interface." + str(i) + ".connection")
            network = radl.get_network_by_id(net_name)
            net_provider_id = network.getValue('provider_id')

            # if the network is public, and the VM has another interface and the
            # site has IP pools, we do not need to assign a network to this interface
            # it will be assigned with a floating IP
            if network.isPublic() and num_nets > 1 and pool_names:
                self.log_info("Public IP to be assigned with a floating IP. Do not set a net.")
            else:
                # First check if the user has specified a provider ID
                if net_provider_id:
                    for net in ost_nets:
                        if net.name == net_provider_id:
                            if net.name not in used_nets:
                                nets.append(net)
                                used_nets.append(net.name)
                            break
                else:
                    # if not select the first not used net
                    for net in ost_nets:
                        # do not use nets that are IP pools
                        if net.name not in pool_names:
                            if net.name not in used_nets:
                                nets.append(net)
                                used_nets.append(net.name)
                                break

            i += 1

        return nets

    def get_cloud_init_data(self, radl):
        """
        Get the cloud init data specified by the user in the RADL
        """
        configure_name = None
        if radl.contextualize.items:
            system_name = radl.systems[0].name

            for item in radl.contextualize.items.values():
                if item.system == system_name and item.get_ctxt_tool() == "cloud_init":
                    configure_name = item.configure

        if configure_name:
            return radl.get_configure_by_name(configure_name).recipes
        else:
            return None

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        driver = self.get_driver(auth_data)

        system = radl.systems[0]
        image_id = self.get_image_id(system.getValue("disk.0.image.url"))
        image = NodeImage(id=image_id, name=None, driver=driver)

        instance_type = self.get_instance_type(driver.list_sizes(), system)
        if not instance_type:
            raise Exception("No flavor found for the specified VM requirements.")

        name = system.getValue("instance_name")
        if not name:
            name = system.getValue("disk.0.image.name")
        if not name:
            name = "userimage"

        nets = self.get_networks(driver, radl)

        sgs = self.create_security_groups(driver, inf, radl)

        args = {'size': instance_type,
                'image': image,
                'networks': nets,
                'ex_security_groups': sgs,
                'name': "%s-%s" % (name, int(time.time() * 100))}

        keypair = None
        keypair_name = None
        keypair_created = False
        public_key = system.getValue("disk.0.os.credentials.public_key")
        if public_key:
            keypair = driver.get_key_pair(public_key)
            if keypair:
                system.setUserKeyCredentials(
                    system.getCredentials().username, None, keypair.private_key)
            else:
                if "ssh_key" in driver.features.get("create_node", []):
                    args["auth"] = NodeAuthSSHKey(public_key)

        elif not system.getValue("disk.0.os.credentials.password"):
            keypair_name = "im-%d" % int(time.time() * 100.0)
            self.log_info("Create keypair: %s" % keypair_name)
            keypair = driver.create_key_pair(keypair_name)
            keypair_created = True
            public_key = keypair.public_key
            system.setUserKeyCredentials(
                system.getCredentials().username, None, keypair.private_key)

            if keypair.public_key and "ssh_key" in driver.features.get("create_node", []):
                args["auth"] = NodeAuthSSHKey(keypair.public_key)
            else:
                args["ex_keyname"] = keypair_name

        user = system.getValue('disk.0.os.credentials.username')
        if not user:
            user = self.DEFAULT_USER
            system.setValue('disk.0.os.credentials.username', user)

        cloud_init = self.get_cloud_init_data(radl)
        if public_key:
            cloud_init = self.gen_cloud_config(public_key, user, cloud_init)

        if cloud_init:
            args['ex_userdata'] = cloud_init

        if self.CONFIG_DRIVE:
            args['ex_config_drive'] = self.CONFIG_DRIVE

        res = []
        i = 0
        all_failed = True
        while i < num_vm:
            self.log_info("Creating node")

            node = None
            retries = 0
            msg = ""
            while not node and retries < Config.MAX_VM_FAILS:
                retries += 1
                msg += "Error creating the node (%d/%d): " % (retries, Config.MAX_VM_FAILS)
                try:
                    node = driver.create_node(**args)
                except Exception as ex:
                    msg += str(ex) + "\n"

            if node:
                vm = VirtualMachine(inf, node.id, self.cloud, radl, requested_radl, self.cloud.getCloudConnector(inf))
                vm.info.systems[0].setValue('instance_id', str(node.id))
                vm.info.systems[0].setValue('instance_name', str(node.name))
                # Add the keypair name to remove it later
                if keypair_name:
                    vm.keypair = keypair_name
                self.log_info("Node successfully created.")
                all_failed = False
                inf.add_vm(vm)
                res.append((True, vm))
            else:
                res.append((False, msg))
            i += 1

        # if all the VMs have failed, remove the sgs and keypair
        if all_failed:
            if keypair_created:
                # only delete in case of the user do not specify the keypair name
                self.log_info("Deleting keypair: %s." % keypair_name)
                driver.delete_key_pair(keypair)
            for sg in sgs:
                self.log_info("Deleting security group: %s." % sg.id)
                driver.ex_delete_security_group(sg)

        return res

    def get_ip_pool(self, driver, pool_name=None):
        """
        Return the most suitable IP pool
        """
        pools = driver.ex_list_floating_ip_pools()

        if pool_name:
            for pool in pools:
                if pool.name == pool_name:
                    return pool
        else:
            # Currently returns the first one
            # until I see what metric use to select one
            return pools[0]

        # otherwise return None
        return None

    def manage_elastic_ips(self, vm, node, public_ips):
        """
        Manage the elastic IPs

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - node(:py:class:`libcloud.compute.base.Node`): node object.
        """
        n = 0
        requested_ips = []
        while vm.getRequestedSystem().getValue("net_interface." + str(n) + ".connection"):
            net_conn = vm.getRequestedSystem().getValue('net_interface.' + str(n) + '.connection')
            net = vm.info.get_network_by_id(net_conn)
            if net.isPublic():
                fixed_ip = vm.getRequestedSystem().getValue("net_interface." + str(n) + ".ip")
                pool_name = net.getValue("pool_name")
                requested_ips.append((fixed_ip, pool_name))
            n += 1

        for num, elem in enumerate(sorted(requested_ips, reverse=True)):
            ip, pool_name = elem
            success = True
            if ip:
                # It is a fixed IP
                if ip not in public_ips:
                    # It has not been created yet, do it
                    self.log_info("Asking for a fixed ip: %s." % ip)
                    success, msg = self.add_elastic_ip(vm, node, ip, pool_name)
            else:
                if num >= len(public_ips):
                    self.log_info("Asking for public IP %d and there are %d" % (num + 1, len(public_ips)))
                    success, msg = self.add_elastic_ip(vm, node, None, pool_name)

            if not success:
                self.add_public_ip_count += 1
                self.log_warn("Error adding a floating IP the VM: %s (%d/%d)\n" % (msg,
                                                                                   self.add_public_ip_count,
                                                                                   self.MAX_ADD_IP_COUNT))
                self.error_messages += "Error adding a floating IP: %s (%d/%d)\n" % (msg,
                                                                                     self.add_public_ip_count,
                                                                                     self.MAX_ADD_IP_COUNT)

    def get_floating_ip(self, pool):
        """
        Get a floating IP
        """
        for ip in pool.list_floating_ips():
            if not ip.node_id:
                is_private = any([IPAddress(ip.ip_address) in IPNetwork(mask) for mask in Config.PRIVATE_NET_MASKS])
                if is_private:
                    self.log_info("Floating IP found %s, but it is private. Ignore." % ip.ip_address)
                else:
                    return True, ip

        return False, "No Float IP free found."

    def add_elastic_ip(self, vm, node, fixed_ip=None, pool_name=None):
        """
        Add an elastic IP to an instance

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - node(:py:class:`libcloud.compute.base.Node`): node object to attach the volumes.
           - fixed_ip(str, optional): specifies a fixed IP to add to the instance.
        Returns: a :py:class:`OpenStack_1_1_FloatingIpAddress` added or None if some problem occur.
        """
        try:
            self.log_info("Add an Floating IP")

            pool = self.get_ip_pool(node.driver, pool_name)
            if not pool:
                if pool_name:
                    msg = "Incorrect pool name: %s." % pool_name
                else:
                    msg = "No pools available."
                self.log_info("No Floating IP assigned: %s" % msg)
                return False, msg

            if node.driver.ex_list_floating_ip_pools():
                if fixed_ip:
                    floating_ip = node.driver.ex_get_floating_ip(fixed_ip)
                else:
                    # First try to check if there is a Float IP free to attach to the node
                    found, floating_ip = self.get_floating_ip(pool)
                    if found:
                        try:
                            node.driver.ex_attach_floating_ip_to_node(node, floating_ip)
                        except Exception as atex:
                            self.log_warn("Error attaching a found Floating IP to the node. "
                                          "Create a new one (%s)." % str(atex))
                    else:
                        self.log_debug(floating_ip)

                    # Now create a Float IP
                    floating_ip = pool.create_floating_ip()

                    is_private = any([IPAddress(floating_ip.ip_address) in IPNetwork(mask)
                                      for mask in Config.PRIVATE_NET_MASKS])

                    if is_private:
                        self.log_error("Error getting a Floating IP from pool %s. The IP is private." % pool_name)
                        self.log_info("We have created it, so release it.")
                        floating_ip.delete()
                        return False, "Error attaching a Floating IP to the node. Private IP returned."

                    # sometimes the ip cannot be attached inmediately
                    # we have to try and wait
                    cont = 0
                    retries = 5
                    delay = 5
                    attached = False
                    while not attached and cont < retries:
                        try:
                            node.driver.ex_attach_floating_ip_to_node(node, floating_ip)
                            attached = True
                        except Exception as atex:
                            self.log_warn("Error attaching a Floating IP to the node: %s" % str(atex))
                            cont += 1
                            if cont < retries:
                                time.sleep(delay)

                    if not attached:
                        self.log_error("Error attaching a Floating IP to the node.")
                        self.log_info("We have created it, so release it.")
                        floating_ip.delete()
                        return False, "Error attaching a Floating IP to the node."
                return True, floating_ip
            else:
                self.log_error("No pools available.")
                return False, "No pools available."

        except Exception as ex:
            self.log_exception("Error adding an Elastic/Floating IP to VM ID: " + str(vm.id))
            return False, str(ex)

    def _get_security_group(self, driver, sg_name):
        try:
            sg = None
            for elem in driver.ex_list_security_groups():
                if elem.name == sg_name:
                    sg = elem
                    break
            return sg
        except Exception:
            self.log_exception("Error getting security groups.")
            return None

    def create_security_groups(self, driver, inf, radl):
        res = []
        i = 0
        system = radl.systems[0]
        while system.getValue("net_interface." + str(i) + ".connection"):
            network_name = system.getValue("net_interface." + str(i) + ".connection")
            network = radl.get_network_by_id(network_name)
            sg_name = network.getValue("sg_name")
            if not sg_name:
                sg_name = "im-%s-%s" % (str(inf.id), network_name)

            # Use the InfrastructureInfo lock to assure that only one VM create the SG
            with inf._lock:
                sg = self._get_security_group(driver, sg_name)
                if not sg:
                    self.log_info("Creating security group: %s" % sg_name)
                    sg = driver.ex_create_security_group(sg_name, "Security group created by the IM")
                res.append(sg)

            try:
                # open always SSH port on public nets
                if network.isPublic():
                    driver.ex_create_security_group_rule(sg, 'tcp', 22, 22, '0.0.0.0/0')
                # open all the ports for the VMs in the security group
                driver.ex_create_security_group_rule(sg, 'tcp', 1, 65535, source_security_group=sg)
                driver.ex_create_security_group_rule(sg, 'udp', 1, 65535, source_security_group=sg)
            except Exception as addex:
                self.log_warn("Exception adding SG rules. Probably the rules exists:" + str(addex))

            outports = network.getOutPorts()
            if outports:
                for outport in outports:
                    if outport.is_range():
                        try:
                            driver.ex_create_security_group_rule(sg, outport.get_protocol(),
                                                                 outport.get_port_init(),
                                                                 outport.get_port_end(), '0.0.0.0/0')
                        except Exception as ex:
                            self.log_warn("Exception adding SG rules: " + str(ex))
                    else:
                        if outport.get_remote_port() != 22:
                            try:
                                driver.ex_create_security_group_rule(sg, outport.get_protocol(),
                                                                     outport.get_remote_port(),
                                                                     outport.get_remote_port(), '0.0.0.0/0')
                            except Exception as ex:
                                self.log_warn("Exception adding SG rules: " + str(ex))

            i += 1

        return res

    def finalize(self, vm, last, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)

        if node:
            success = node.destroy()

            try:
                public_key = vm.getRequestedSystem().getValue('disk.0.os.credentials.public_key')
                if (vm.keypair and public_key is None or len(public_key) == 0 or
                        (len(public_key) >= 1 and public_key.find('-----BEGIN CERTIFICATE-----') != -1)):
                    # only delete in case of the user do not specify the
                    # keypair name
                    keypair = node.driver.get_key_pair(vm.keypair)
                    if keypair:
                        node.driver.delete_key_pair(keypair)
            except:
                self.log_exception("Error deleting keypair.")

            try:
                self.delete_elastic_ips(node, vm)
            except:
                self.log_exception("Error deleting elastic ips.")

            try:
                # Delete the EBS volumes
                self.delete_volumes(node, vm)
            except:
                self.log_exception("Error deleting volumes.")

            try:
                # Delete the SG if this is the last VM
                if last:
                    self.delete_security_groups(node, vm.inf)
                else:
                    # If this is not the last vm, we skip this step
                    self.log_info("There are active instances. Not removing the SG")
            except:
                self.log_exception("Error deleting security groups.")

            if not success:
                return (False, "Error destroying node: " + vm.id)

            self.log_info("VM " + str(vm.id) + " successfully destroyed")
        else:
            self.log_warn("VM " + str(vm.id) + " not found.")

        return (True, "")

    def delete_security_groups(self, node, inf, timeout=90, delay=10):
        """
        Delete the SG of this node
        """
        for net in inf.radl.networks:
            sg_name = "im-%s-%s" % (str(inf.id), net.id)

            # wait it to terminate and then remove the SG
            cont = 0
            deleted = False
            while not deleted and cont < timeout:
                # Get the SG to delete
                sg = self._get_security_group(node.driver, sg_name)
                if not sg:
                    self.log_info("The SG %s does not exist. Do not delete it." % sg_name)
                    deleted = True
                else:
                    try:
                        self.log_info("Deleting SG: %s" % sg_name)
                        node.driver.ex_delete_security_group(sg)
                        deleted = True
                    except Exception as ex:
                        self.log_warn("Error deleting the SG: %s" % str(ex))

                    if not deleted:
                        time.sleep(delay)
                        cont += delay

            if not deleted:
                self.log_error("Error deleting the SG: Timeout.")

    def gen_cloud_config(self, public_key, user=None, cloud_config_str=None):
        """
        Generate the cloud-config file to be used in the user_data of the OCCI VM
        """
        if not user:
            user = self.DEFAULT_USER
        config = """#cloud-config
users:
  - name: %s
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock-passwd: true
    ssh-import-id: %s
    ssh-authorized-keys:
      - %s
""" % (user, user, public_key)
        if cloud_config_str:
            config += "\n%s\n\n" % cloud_config_str.replace("\\n", "\n")
        return config

    def get_node_location(self, node):
        """
        Get the location of a node

        Arguments:
           - node(:py:class:`libcloud.compute.base.Node`): node object.
        Returns: a String
        """
        if 'availability_zone' in node.extra:
            return node.extra['availability_zone']

        locations = node.driver.list_locations()

        # If there is only 1 location return it
        if len(locations) == 1 and locations[0].name:
            return locations[0].name

        return None

    def create_snapshot(self, vm, disk_num, image_name, auto_delete, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)

        if node:
            try:
                image = node.driver.create_image(node, image_name)
            except Exception as ex:
                self.log_exception("Error creating image.")
                return False, "Error creating image: %s." % str(ex)
            new_url = "ost://%s/%s" % (self.cloud.server, image.id)
            if auto_delete:
                vm.inf.snapshots.append(new_url)
            return True, new_url
        else:
            return (False, "VM not found with id: %s" % vm.id)

    def delete_image(self, image_url, auth_data):
        driver = self.get_driver(auth_data)
        image_id = os.path.basename(image_url)
        try:
            image = driver.get_image(image_id)
        except Exception as ex:
            self.log_exception("Error getting image.")
            return (False, "Error getting image %s: %s" % (image_id, str(ex)))
        try:
            driver.delete_image(image)
            return True, ""
        except Exception as ex:
            self.log_exception("Error deleting image.")
            return (False, "Error deleting image.: %s" % str(ex))
