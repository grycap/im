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

import uuid
import time
from netaddr import IPNetwork, IPAddress
import os.path
import tempfile

try:
    from libcloud.common.exceptions import BaseHTTPError
    from libcloud.compute.types import Provider
    from libcloud.compute.providers import get_driver
    from libcloud.compute.base import NodeAuthSSHKey
    from libcloud.compute.drivers.openstack import OpenStack_2_NodeDriver, OpenStack_2_SubNet, OpenStackSecurityGroup
except Exception as ex:
    print("WARN: libcloud library not correctly installed. OpenStackCloudConnector will not work!.")
    print(ex)

from IM.connectors.LibCloud import LibCloudCloudConnector
from IM.config import Config
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from radl.radl import Feature
from IM.AppDB import AppDB
from IM import get_ex_error


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
    CONFIRM_TIMEOUT = 120
    """ Confirm Timeout """

    def __init__(self, cloud_info, inf):
        self.auth = None
        self.add_public_ip_count = 0
        LibCloudCloudConnector.__init__(self, cloud_info, inf)

    def get_node_with_id(self, node_id, auth_data):
        """
        Get the node with the specified ID

        Arguments:
           - node_id(str): ID of the node to get
           - auth(Authentication): parsed authentication tokens.
        Returns: a :py:class:`libcloud.compute.base.Node` with the node info
        """
        driver = self.get_driver(auth_data)
        node = driver.ex_get_node_details(node_id)
        return node

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

        if self.driver and self.auth.compare(auth_data, self.type, self.cloud.server):
            return self.driver
        else:
            self.auth = auth_data

            protocol = self.cloud.protocol
            if not protocol:
                protocol = "http"
            port = self.cloud.port
            if port == -1:
                if protocol == "http":
                    port = 80
                elif protocol == "https":
                    port = 443
                else:
                    raise Exception("Invalid port/protocol specified for OpenStack site: %s" % self.cloud.server)

            parameters = {"auth_version": '2.0_password',
                          "auth_url": protocol + "://" + self.cloud.server + ":" + str(port),
                          "auth_token": None,
                          "service_type": None,
                          "service_name": None,
                          "service_region": None,
                          "base_url": None,
                          "network_url": None,
                          "image_url": None,
                          "volume_url": None,
                          "api_version": "2.0",
                          "domain": None,
                          "tenant_domain_id": None}

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
                tenant = None
                if 'tenant' in auth:
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

            if not self.verify_ssl:
                # To avoid errors with host certificates
                # if you want to do it in a more secure way check this:
                # http://libcloud.readthedocs.org/en/latest/other/ssl-certificate-validation.html
                import libcloud.security
                libcloud.security.VERIFY_SSL_CERT = False

            kwargs = {}
            for key, value in parameters.items():
                if value:
                    if key in ['base_url', 'auth_token', 'service_type', 'image_url', 'volume_url',
                               'network_url', 'service_region', 'auth_version', 'auth_url']:
                        key = 'ex_force_%s' % key
                    elif key == 'domain':
                        key = 'ex_domain_name'
                    elif key == 'tenant_domain_id':
                        key = 'ex_tenant_domain_id'
                    kwargs[key] = value

            # Workaround to OTC to enable to set service_name as None
            if parameters["service_name"] is not None and parameters["service_name"] != "None":
                kwargs['ex_force_service_name'] = parameters["service_name"]

            cls = get_driver(Provider.OPENSTACK)
            driver = cls(username, password, ex_tenant_name=tenant, **kwargs)

            # Workaround to OTC to enable to set service_name as None
            if parameters["service_name"] == "None":
                driver.connection.service_name = None
            # Workaround to unset default service_region (RegionOne)
            if parameters["service_region"] is None:
                driver.connection.service_region = None
                if isinstance(driver, OpenStack_2_NodeDriver):
                    driver.connection.service_region = None
                    driver.image_connection.service_region = None
                    driver.network_connection.service_region = None
                    driver.volumev2_connection.service_region = None

            self.driver = driver
            return driver

    def guess_instance_type_gpu(self, size):
        """Try to guess if this NodeSize has GPU support"""
        try:
            extra_specs = size.driver.ex_get_size_extra_specs(size.id)
            for k, v in extra_specs.items():
                if k.lower().find("gpu") and v.lower() not in ['false', 'no', '0']:
                    return True
        except Exception:
            self.log_exception("Error trying to get flavor extra_specs.")
        return False

    def get_instance_type(self, sizes, radl):
        """
        Get the name of the instance type to launch to LibCloud

        Arguments:
           - size(list of :py:class: `libcloud.compute.base.NodeSize`): List of sizes on a provider
           - radl(str): RADL document with the requirements of the VM to get the instance type
        Returns: a :py:class:`libcloud.compute.base.NodeSize` with the instance type to launch
        """
        instance_type_name = radl.getValue('instance_type')

        (cpu, cpu_op, memory, memory_op, disk_free, disk_free_op) = self.get_instance_selectors(radl, disk_unit="G")
        gpu = radl.getValue('gpu.count')

        # get the node size with the lowest price, vcpus, memory and disk
        sizes.sort(key=lambda x: (x.price, x.vcpus, x.ram, x.disk))
        for size in sizes:
            comparison = cpu_op(size.vcpus, cpu)
            comparison = comparison and memory_op(size.ram, memory)
            comparison = comparison and disk_free_op(size.disk, disk_free)
            if gpu and not self.guess_instance_type_gpu(size):
                continue

            if comparison:
                if not instance_type_name or size.name == instance_type_name:
                    return size

        self.log_error("No compatible size found")
        return None

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]
        src_host = url[1].split(':')[0]

        if protocol == "appdb":
            site_url, image_id, msg = AppDB.get_image_data(str_url, "openstack")
            if not image_id or not site_url:
                self.log_error(msg)
                return None

            protocol = "ost"
            url = urlparse(site_url)
            src_host = url[1].split(':')[0]

        if protocol == "ost" and self.cloud.server == src_host:
            driver = self.get_driver(auth_data)

            res_system = radl_system.clone()
            instance_type = self.get_instance_type(driver.list_sizes(), res_system)
            self.update_system_info_from_instance(res_system, instance_type)

            username = res_system.getValue('disk.0.os.credentials.username')
            if not username:
                res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)

            return res_system
        else:
            return None

    def addRouterInstance(self, vm, driver):
        """
        Add support for IndigoVR

        openstack subnet set --host-route destination=10.0.0.0/16,gateway=10.0.1.5 subnet1
        openstack port list --server net1-router
        openstack port set --disable-port-security { port from previous step }
        """
        success = True
        try:
            i = 0
            while vm.info.systems[0].getValue("net_interface." + str(i) + ".connection"):
                net_name = vm.info.systems[0].getValue("net_interface." + str(i) + ".connection")
                i += 1
                network = vm.info.get_network_by_id(net_name)
                if network.getValue('router'):
                    net_provider_id = network.getValue('provider_id')
                    router_info = network.getValue('router').split(",")
                    if len(router_info) != 2:
                        self.log_error("Incorrect router format.")
                        success = False
                        break

                    system_router = router_info[1]
                    router_cidr = router_info[0]

                    vrouter = None
                    for v in vm.inf.vm_list:
                        if v.info.systems[0].name == system_router:
                            vrouter = v
                            break
                    if not vrouter:
                        self.log_error("No VRouter instance found with name %s" % system_router)
                        success = False
                        break

                    vrouter = vrouter.getIfaceIP(0)
                    if not vrouter:
                        self.log_warn("VRouter %s has no IP. wait." % system_router)
                        success = False
                        break

                    ost_net = self.get_ost_net(driver, name=net_provider_id)
                    if 'subnets' in ost_net.extra and len(ost_net.extra['subnets']) == 1:
                        subnet_id = ost_net.extra['subnets'][0]
                    else:
                        self.log_error("Unexpected subnet values in OST net.")
                        success = False
                        break

                    subnet = OpenStack_2_SubNet(subnet_id, None, None, ost_net.id, driver)

                    host_routes = [{"destination": router_cidr, "nexthop": vrouter}]
                    self.log_info("Updating subnet %s setting host routes: %s" % (subnet.id, host_routes))
                    driver.ex_update_subnet(subnet, host_routes=host_routes)

                    # Disable port security in the node
                    # first remove the default SG from the node
                    node = driver.ex_get_node_details(vm.id)
                    self.log_debug("Removing SG default from node %s" % node.id)
                    try:
                        security_group = OpenStackSecurityGroup(None, None, "default", "", driver)
                        driver.ex_remove_security_group_from_node(security_group, node)
                    except Exception:
                        self.log_warn("Removing SG default from node %s" % node.id)

                    # Then disable port security
                    for port in driver.ex_list_ports():
                        if port.extra['device_id'] == node.id:
                            self.log_info("Disabling security port in %s" % port.id)
                            try:
                                driver.ex_update_port(port, port_security_enabled=False)
                            except Exception:
                                self.log_exception("Error disabling security port in %s" % port.id)

                    # once set, delete it to not set it again
                    network.delValue('router')
        except Exception:
            success = False
            self.log_exception("Error adding Router Instance")

        return success

    def setVolumesInfo(self, vm, node):
        try:
            cont = 1
            if 'volumes_attached' in node.extra and node.extra['volumes_attached']:
                for vol_info in node.extra['volumes_attached']:
                    vol_id = vol_info['id']
                    self.log_debug("Getting Volume info %s" % vol_id)
                    volume = node.driver.ex_get_volume(vol_id)
                    disk_size = None
                    if vm.info.systems[0].getValue("disk." + str(cont) + ".size"):
                        disk_size = vm.info.systems[0].getFeature("disk." + str(cont) + ".size").getValue('G')
                    if disk_size and disk_size != volume.size:
                        self.log_warn("Volume ID %s does not have the expected size %s != %s" % (vol_id,
                                                                                                 volume.size,
                                                                                                 disk_size))
                        continue
                    vm.info.systems[0].setValue("disk." + str(cont) + ".size", volume.size, 'G')

                    disk_url = vm.info.systems[0].getValue("disk." + str(cont) + ".image.url")
                    if disk_url and os.path.basename(disk_url) != vol_id:
                        self.log_warn("Volume does not have the expected id %s != %s" % (vol_id,
                                                                                         os.path.basename(disk_url)))
                    vm.info.systems[0].setValue("disk." + str(cont) + ".image.url", "ost://%s/%s" % (self.cloud.server,
                                                                                                     volume.id))
                    if 'attachments' in volume.extra and volume.extra['attachments']:
                        vm.info.systems[0].setValue("disk." + str(cont) + ".device",
                                                    os.path.basename(volume.extra['attachments'][0]['device']))
                    cont += 1
        except Exception as ex:
            self.log_warn("Error getting volume info: %s" % get_ex_error(ex))

    def updateVMInfo(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            vm.state = self.VM_STATE_MAP.get(node.state, VirtualMachine.UNKNOWN)

            if vm.state == VirtualMachine.FAILED:
                if 'fault' in node.extra and node.extra['fault']:
                    error_msg = str(node.extra['fault']['message'])
                    if error_msg not in self.error_messages:
                        self.error_messages += error_msg

            try:
                flavorId = node.extra['flavorId']
                instance_type = node.driver.ex_get_size(flavorId)
                self.update_system_info_from_instance(vm.info.systems[0], instance_type)
            except Exception as ex:
                self.log_warn("Error updating VM info from flavor ID: %s" % get_ex_error(ex))

            self.addRouterInstance(vm, node.driver)
            self.setIPsFromInstance(vm, node)
            self.setVolumesInfo(vm, node)
        else:
            self.log_warn("Error updating the instance %s. VM not found." % vm.id)
            return (False, "Error updating the instance %s. VM not found." % vm.id)

        return (True, vm)

    @staticmethod
    def map_radl_ost_networks(vm, ost_nets):
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
                for radl_net in vm.info.networks:
                    net_provider_id = radl_net.getValue('provider_id')
                    net_cidr = radl_net.getValue('cidr')

                    if net_provider_id:
                        if net_name == net_provider_id:
                            if radl_net.isPublic() == is_public:
                                res[radl_net.id] = ip
                                if ip in res["#UNMAPPED#"]:
                                    res["#UNMAPPED#"].remove(ip)
                                break
                            else:
                                # the ip not matches the is_public value
                                if ip not in res["#UNMAPPED#"]:
                                    res["#UNMAPPED#"].append(ip)
                    elif net_cidr and "*" in net_cidr:
                        # in this case the net is not connected to this VM
                        continue
                    elif net_cidr and IPAddress(ip) in IPNetwork(net_cidr):
                        res[radl_net.id] = ip
                        radl_net.setValue('provider_id', net_name)
                        if ip in res["#UNMAPPED#"]:
                            res["#UNMAPPED#"].remove(ip)
                        break
                    else:
                        if radl_net.id not in res:
                            if radl_net.isPublic() == is_public and vm.getNumNetworkWithConnection(radl_net.id):
                                res[radl_net.id] = ip
                                radl_net.setValue('provider_id', net_name)
                                if ip in res["#UNMAPPED#"]:
                                    res["#UNMAPPED#"].remove(ip)
                                break
                            else:
                                # the ip not matches the is_public value
                                if ip not in res["#UNMAPPED#"]:
                                    res["#UNMAPPED#"].append(ip)
            else:
                # It seems to be a floating IP
                added = False
                for radl_net in vm.info.networks:
                    if radl_net.id not in res and radl_net.isPublic() == is_public:
                        res[radl_net.id] = ip
                        added = True
                        break

                if not added and ip not in res["#UNMAPPED#"]:
                    res["#UNMAPPED#"].append(ip)

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
        except BaseHTTPError as ex:
            if ex.code == 404:
                self.log_warn("Error getting node floating ips. It seems that the site does not support them.")
        except Exception:
            self.log_exception("Error getting node floating ips")
        return ips

    def setIPsFromInstance(self, vm, node):
        """
        Adapt the RADL information of the VM to the real IPs assigned by the cloud provider

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - node(:py:class:`libcloud.compute.base.Node`): object to connect to EC2 instance.
        """
        system = vm.info.systems[0]

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

            map_nets = self.map_radl_ost_networks(vm, ip_net_map)

            i = 0
            ips_assigned = []
            while system.getValue("net_interface." + str(i) + ".connection"):
                # First remove old
                if system.getValue('net_interface.%d.ip' % i):
                    system.delValue('net_interface.%d.ip' % i)
                net_name = system.getValue("net_interface." + str(i) + ".connection")
                if net_name in map_nets:
                    ip = map_nets[net_name]
                    if IPAddress(ip).version == 6:
                        system.setValue("net_interface." + str(i) + ".ipv6", ip)
                    else:
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
                        if IPAddress(ip).version == 6:
                            system.setValue('net_interface.' + str(num_net) + '.ipv6', ip)
                        else:
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
            vm.setIps(public_ips, private_ips, True)

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
            LibCloudCloudConnector.update_system_info_from_instance(system, instance_type)
            if instance_type.vcpus:
                system.addFeature(Feature("cpu.count", "=", instance_type.vcpus), conflict="other", missing="other")

    @staticmethod
    def get_ost_net(driver, name=None, netid=None):
        """
        Get a OST network
        """
        for ost_net in driver.ex_list_networks():
            if name and ost_net.name == name:
                return ost_net
            if netid and ost_net.id == netid:
                return ost_net
        return None

    @staticmethod
    def get_ost_network_info(driver, pool_names):
        ost_nets = driver.ex_list_networks()
        get_subnets = False
        if "ex_list_subnets" in dir(driver):
            ost_subnets = driver.ex_list_subnets()
            get_subnets = True

            for ost_net in ost_nets:
                if not ost_net.cidr and 'subnets' in ost_net.extra:
                    net_subnets = ost_net.extra['subnets']
                    for subnet in ost_subnets:
                        if subnet.id in net_subnets and subnet.cidr:
                            ost_net.cidr = subnet.cidr
                            ost_net.extra['is_public'] = not (any([IPNetwork(ost_net.cidr).ip in IPNetwork(mask)
                                                                   for mask in Config.PRIVATE_NET_MASKS]))
                            break

        for ost_net in ost_nets:
            # If we do not have the IP range try to use the router:external to identify a net as public
            if 'is_public' not in ost_net.extra:
                if 'router:external' in ost_net.extra and ost_net.extra['router:external']:
                    ost_net.extra['is_public'] = True
                elif ost_net.name in pool_names:
                    # If we do not have any clue assume that if it is
                    # in the pool it should be a public net
                    ost_net.extra['is_public'] = True
                else:
                    # let's assume that is not public
                    ost_net.extra['is_public'] = False

        return get_subnets, ost_nets

    @staticmethod
    def map_networks(radl, ost_nets):
        i = 0
        net_map = {}
        used_nets = []
        while radl.systems[0].getValue("net_interface." + str(i) + ".connection"):
            net_name = radl.systems[0].getValue("net_interface." + str(i) + ".connection")
            network = radl.get_network_by_id(net_name)
            net_provider_id = network.getValue('provider_id')
            net_map[i] = None

            if net_provider_id:
                found = False
                for net in ost_nets:
                    if net.name == net_provider_id:
                        if net in used_nets:
                            raise Exception("Two different networks assigned to the same provider_id")
                        net_map[i] = net
                        used_nets.append(net)
                        found = True
                        break
                if not found:
                    raise Exception("Network with provider_id %s not found." % net_provider_id)
            else:
                for net in ost_nets:
                    if net not in used_nets:
                        if network.isPublic() == net.extra['is_public']:
                            net_map[i] = net
                            used_nets.append(net)
                            break

            i += 1

        return net_map

    def get_router_public(self, driver, radl):
        try:
            # Get the public net provider id
            pub_net_provider_id = None
            for net in radl.networks:
                if net.isPublic():
                    pub_net_provider_id = net.getValue('provider_id')
                    break

            # Get the OST public net ids and names
            pub_nets = {}
            for net in driver.ex_list_networks():
                if 'router:external' in net.extra and net.extra['router:external']:
                    pub_nets[net.id] = net.name

            # Get the routers associated with public nets
            routers = {}
            try:
                for router in driver.ex_list_routers():
                    if router.extra['external_gateway_info']:
                        if router.extra['external_gateway_info']['network_id'] in pub_nets:
                            routers[pub_nets[router.extra['external_gateway_info']['network_id']]] = router
            except Exception as ex:
                self.log_warn("Error listing routers: %s." % get_ex_error(ex))

            # try to select first the router of the net provider id
            if pub_net_provider_id in routers:
                return routers[pub_net_provider_id]
            else:
                if len(routers) > 0:
                    return routers[list(routers.keys())[0]]
                else:
                    self.log_warn("No public router found!.")
                    return None

        except Exception:
            self.log_exception("Error getting public router.")

        return None

    @staticmethod
    def is_net_in_router(driver, net, router):
        """
        Check if a net has an interface in a router
        """
        for port in driver.ex_list_ports():
            if port.extra['device_id'] == router.id and port.extra['network_id'] == net.id:
                return True
        return False

    def delete_networks(self, driver, inf):
        """
        Delete created OST networks
        """
        router = self.get_router_public(driver, inf.radl)
        msg = ""
        res = True
        for ost_net in driver.ex_list_networks():
            net_prefix = "im-%s-" % inf.id
            if ost_net.name.startswith(net_prefix):
                if 'subnets' in ost_net.extra and len(ost_net.extra['subnets']) == 1:
                    subnet_id = ost_net.extra['subnets'][0]
                    if router is None:
                        self.log_warn("No public router found.")
                    else:
                        self.log_info("Deleting subnet %s to the router %s" % (subnet_id, router.name))
                        subnet = OpenStack_2_SubNet(subnet_id, None, None, ost_net.id, driver)
                        try:
                            driver.ex_del_router_subnet(router, subnet)
                        except Exception as ex:
                            self.log_exception("Error deleting subnet %s from the router %s" % (subnet_id,
                                                                                                router.name))
                            res = False
                            msg = "Error deleting subnet %s from the router %s: %s" % (subnet_id,
                                                                                       router.name,
                                                                                       get_ex_error(ex))

                    self.log_info("Deleting net %s." % ost_net.name)
                    driver.ex_delete_network(ost_net)

        return res, msg

    def create_networks(self, driver, radl, inf):
        """
        Create OST networks
        """
        try:
            i = 0
            router = self.get_router_public(driver, radl)

            while radl.systems[0].getValue("net_interface." + str(i) + ".connection"):
                net_name = radl.systems[0].getValue("net_interface." + str(i) + ".connection")
                i += 1
                network = radl.get_network_by_id(net_name)
                if network.getValue('create') == 'yes' and not network.isPublic():
                    ost_net_name = network.getValue('provider_id')
                    if not ost_net_name:
                        ost_net_name = "im-%s-%s" % (inf.id, net_name)

                    # First check if the net already exists
                    if self.get_ost_net(driver, name=ost_net_name):
                        network.setValue('provider_id', ost_net_name)
                        network.delValue('cidr')
                        self.log_debug("Ost network %s exists. Do not create." % ost_net_name)
                        continue

                    net_cidr = network.getValue('cidr')
                    if not net_cidr or "*" in net_cidr:
                        _, ost_nets = self.get_ost_network_info(driver, [])
                        used_cidrs = [ost_net.cidr for ost_net in ost_nets if ost_net.cidr]
                        net_cidr = self.get_free_cidr(net_cidr, used_cidrs, inf)
                        if not net_cidr:
                            self.log_error("No free net CIDR found.")
                            raise Exception("No net CIDR specified nor free net CIDR found.")
                        self.log_debug("Free net CIDR found: %s." % net_cidr)
                        network.setValue('cidr', net_cidr)
                        # Set also the cidr in the inf RADL
                        inf.radl.get_network_by_id(net_name).setValue('cidr', net_cidr)
                    net_dnsserver = network.getValue('dnsserver')
                    if net_dnsserver:
                        net_dnsserver = [net_dnsserver]

                    # create the network
                    try:
                        self.log_info("Creating ost network: %s" % ost_net_name)
                        ost_net = driver.ex_create_network(ost_net_name)
                    except Exception as ex:
                        self.log_exception("Error creating ost network for net %s." % net_name)
                        raise Exception("Error creating ost network for net %s: %s" % (net_name,
                                                                                       get_ex_error(ex)))

                    # now create the subnet
                    ost_subnet_name = "im-%s-sub%s" % (inf.id, net_name)
                    try:
                        self.log_info("Creating ost subnet: %s" % ost_subnet_name)
                        ost_subnet = driver.ex_create_subnet(ost_subnet_name, ost_net, net_cidr,
                                                             ip_version=4, dns_nameservers=net_dnsserver)
                    except Exception as ex:
                        self.log_exception("Error creating ost subnet for net %s." % net_name)
                        # in case of error delete the associated network
                        self.log_debug("Deleting net: %s" % ost_net_name)
                        driver.ex_delete_network(ost_net)
                        raise Exception("Error creating ost subnet for net %s: %s" % (net_name,
                                                                                      get_ex_error(ex)))

                    if router is None:
                        self.log_warn("No public router found.")
                    else:
                        self.log_info("Adding subnet %s to the router %s" % (ost_subnet.name, router.name))
                        try:
                            driver.ex_add_router_subnet(router, ost_subnet)
                        except Exception as ex:
                            # some time the nets are auto added to the router
                            if self.is_net_in_router(driver, ost_net, router):
                                self.log_info("Net %s already in the router %s" % (ost_net.name, router.name))
                            else:
                                self.log_error("Error adding subnet to the router. Deleting net and subnet.")
                                driver.ex_delete_subnet(ost_subnet)
                                driver.ex_delete_network(ost_net)
                                raise Exception("Error adding subnet to the router: %s" % get_ex_error(ex))

                    network.setValue('provider_id', ost_net_name)
        except Exception as ext:
            self.log_exception("Error creating networks.")
            try:
                self.delete_networks(driver, inf)
            except Exception:
                self.log_exception("Error deleting networks.")
            raise Exception("Error creating networks: %s" % ext.args[0])

        return True

    def get_networks(self, driver, radl):
        """
        Get the list of networks to connect the VM
        """
        nets = []
        pool_names = [pool.name for pool in driver.ex_list_floating_ip_pools()]
        get_subnets, ost_nets = self.get_ost_network_info(driver, pool_names)

        if get_subnets:
            net_map = self.map_networks(radl, ost_nets)

            # First set the public ones
            for public in [True, False]:
                i = 0
                while radl.systems[0].getValue("net_interface." + str(i) + ".connection"):
                    net_name = radl.systems[0].getValue("net_interface." + str(i) + ".connection")
                    network = radl.get_network_by_id(net_name)

                    if public == network.isPublic():
                        if net_map[i]:
                            network.setValue('provider_id', net_map[i].name)
                            if net_map[i].name not in pool_names:
                                nets.append(net_map[i])
                    i += 1
        else:
            # TO BE DEPRECATED
            num_nets = radl.systems[0].getNumNetworkIfaces()
            used_nets = []

            # First set the public ones
            for public in [True, False]:
                i = 0
                while radl.systems[0].getValue("net_interface." + str(i) + ".connection"):
                    net_name = radl.systems[0].getValue("net_interface." + str(i) + ".connection")
                    network = radl.get_network_by_id(net_name)
                    net_provider_id = network.getValue('provider_id')

                    if public == network.isPublic():
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

    @staticmethod
    def get_volumes(driver, image, radl):
        """
        Create the required volumes (in the RADL) for the VM.

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM to modify.
        """
        system = radl.systems[0]

        boot_disk = {
            'boot_index': 0,
            'device_name': 'vda',
            'source_type': "image",
            'delete_on_termination': False,
            'uuid': image.id
        }

        # if the user sets the size, we create a volume with this size
        # instead of booting directly from the image
        if system.getValue("disk.0.size"):
            boot_disk['destination_type'] = 'volume'
            boot_disk['volume_size'] = system.getFeature("disk.0.size").getValue('G')
            boot_disk['delete_on_termination'] = True
            del boot_disk['device_name']

        res = [boot_disk]

        cont = 1
        while (system.getValue("disk." + str(cont) + ".size") or
                system.getValue("disk." + str(cont) + ".image.url")):
            disk_url = system.getValue("disk." + str(cont) + ".image.url")
            disk_device = system.getValue("disk." + str(cont) + ".device")
            disk_type = system.getValue("disk." + str(cont) + ".type")
            if disk_device:
                disk_device = "vd%s" % disk_device[-1]
            disk_fstype = system.getValue("disk." + str(cont) + ".fstype")
            if not disk_fstype:
                disk_fstype = 'ext3'

            disk_size = None
            if disk_url:
                volume = driver.ex_get_volume(os.path.basename(disk_url))
                disk = {
                    'boot_index': cont,
                    'source_type': "volume",
                    'delete_on_termination': False,
                    'destination_type': "volume",
                    'uuid': volume.id
                }
            else:
                disk_size = system.getFeature("disk." + str(cont) + ".size").getValue('G')

                disk = {
                    'boot_index': cont,
                    'source_type': "blank",
                    'guest_format': disk_fstype,
                    'destination_type': "volume",
                    'delete_on_termination': True,
                    'volume_size': disk_size
                }
                if disk_type:
                    disk['volume_type'] = disk_type
            if disk_device:
                disk['device_name'] = disk_device
            res.append(disk)
            cont += 1

        return res

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        driver = self.get_driver(auth_data)

        system = radl.systems[0]

        image_url = system.getValue("disk.0.image.url")
        if urlparse(image_url)[0] == "appdb":
            _, image_id, msg = AppDB.get_image_data(image_url, "openstack")
            if not image_id:
                self.log_error(msg)
                raise Exception("Error in appdb image: %s" % msg)
        else:
            image_id = self.get_image_id(system.getValue("disk.0.image.url"))
        image = driver.get_image(image_id)

        instance_type = self.get_instance_type(driver.list_sizes(), system)
        if not instance_type:
            raise Exception("No flavor found for the specified VM requirements.")

        blockdevicemappings = self.get_volumes(driver, image, radl)

        with inf._lock:
            self.create_networks(driver, radl, inf)

        nets = self.get_networks(driver, radl)

        sgs = self.create_security_groups(driver, inf, radl)

        args = {'size': instance_type,
                'networks': nets,
                'image': image,
                'ex_security_groups': sgs,
                'name': self.gen_instance_name(system)}

        if blockdevicemappings:
            args['ex_blockdevicemappings'] = blockdevicemappings

        tags = self.get_instance_tags(system, auth_data, inf)
        if tags:
            args['ex_metadata'] = tags

        public_key = system.getValue("disk.0.os.credentials.public_key")
        if not public_key:
            # We must generate them
            (public_key, private_key) = self.keygen()
            system.setValue('disk.0.os.credentials.private_key', private_key)

        if "ssh_key" in driver.features.get("create_node", []):
            args["auth"] = NodeAuthSSHKey(public_key)

        user = system.getValue('disk.0.os.credentials.username')
        if not user:
            user = self.DEFAULT_USER
            system.setValue('disk.0.os.credentials.username', user)

        if self.CONFIG_DRIVE:
            args['ex_config_drive'] = self.CONFIG_DRIVE

        if system.getValue('availability_zone'):
            self.log_debug("Setting availability_zone: %s" % system.getValue('availability_zone'))
            args['ex_availability_zone'] = system.getValue('availability_zone')

        res = []
        i = 0
        all_failed = True
        while i < num_vm:
            self.log_info("Creating node")

            vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl, self.cloud.getCloudConnector(inf))
            # to store the dynamically attached volumes
            vm.volumes = []
            # to store the floating IPs not to be deleted
            vm.floating_ips = []
            vm.destroy = True
            inf.add_vm(vm)
            cloud_init = self.get_cloud_init_data(radl, vm, public_key, user)

            if cloud_init:
                args['ex_userdata'] = cloud_init

            node = None
            try:
                node = driver.create_node(**args)

                vm.id = node.id
                vm.info.systems[0].setValue('instance_id', str(node.id))
                vm.info.systems[0].setValue('instance_name', str(node.name))
                self.log_info("Node successfully created.")
                all_failed = False
                vm.destroy = False
                res.append((True, vm))
            except Exception as ex:
                self.log_exception("Error creating node: %s." % get_ex_error(ex))
                res.append((False, "%s" % get_ex_error(ex)))

            i += 1

        # if all the VMs have failed, remove the sgs
        if all_failed:
            for sg in sgs:
                self.log_info("Deleting security group: %s." % sg.id)
                try:
                    driver.ex_delete_security_group(sg)
                except Exception as ex:
                    self.log_exception("Error deleting security group: %s." % get_ex_error(ex))

        return res

    @staticmethod
    def get_ip_pool(driver, pool_name=None):
        """
        Return the most suitable IP pool
        """
        pools = driver.ex_list_floating_ip_pools()

        if pool_name:
            for pool in pools:
                if pool.name == pool_name:
                    return pool
        elif pools:
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
           - public_ips(list of str): list of Public IPs of the node
        """
        n = 0
        requested_ips = []
        while vm.getRequestedSystem().getValue("net_interface." + str(n) + ".connection"):
            net_conn = vm.getRequestedSystem().getValue('net_interface.' + str(n) + '.connection')
            net = vm.info.get_network_by_id(net_conn)
            if net and net.isPublic():
                fixed_ip = vm.getRequestedSystem().getValue("net_interface." + str(n) + ".ip")
                pool_name = net.getValue("provider_id")
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
                    success, msg = self.add_elastic_ip_from_pool(vm, node, ip, pool_name)
            else:
                if num >= len(public_ips):
                    self.log_info("Asking for public IP %d and there are %d" % (num + 1, len(public_ips)))
                    success, msg = self.add_elastic_ip_from_pool(vm, node, None, pool_name)

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

    def add_elastic_ip_from_pool(self, vm, node, fixed_ip=None, pool_name=None):
        """
        Add an elastic IP to an instance

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - node(:py:class:`libcloud.compute.base.Node`): node object to attach the ip.
           - fixed_ip(str, optional): specifies a fixed IP to add to the instance.
           - pool_name(str, optional): specifies a pool to get the elastic IP
        Returns: a :py:class:`OpenStack_1_1_FloatingIpAddress` added or None if some problem occur.
        """
        try:
            self.log_info("Add a Floating IP")

            pool = self.get_ip_pool(node.driver, pool_name)
            if not pool:
                if pool_name:
                    msg = "Incorrect pool name: %s." % pool_name
                else:
                    msg = "No pools available."
                self.log_info("No Floating IP assigned: %s" % msg)
                return False, msg

            found = False
            if node.driver.ex_list_floating_ip_pools():
                if fixed_ip:
                    floating_ip = node.driver.ex_get_floating_ip(fixed_ip)
                    if floating_ip:
                        found = True
                    else:
                        return False, "Fixed IP %s not found." % fixed_ip
                else:
                    # First try to check if there is a Float IP free to attach to the node
                    found, floating_ip = self.get_floating_ip(pool)
                    if not found:
                        # Now create a Float IP
                        floating_ip = pool.create_floating_ip()

                        is_private = any([IPAddress(floating_ip.ip_address) in IPNetwork(mask)
                                          for mask in Config.PRIVATE_NET_MASKS])

                        if is_private:
                            self.log_error("Error getting a Floating IP from pool %s. The IP is private." % pool_name)
                            self.log_info("We have created it, so release it.")
                            floating_ip.delete()
                            return False, "Error attaching a Floating IP to the node. Private IP returned."

                self.log_debug(floating_ip)
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
                        self.log_warn("Error attaching a Floating IP to the node: %s" % get_ex_error(atex))
                        cont += 1
                        if cont < retries:
                            time.sleep(delay)

                if not attached:
                    self.log_error("Error attaching a Floating IP to the node.")
                    self.log_info("We have created it, so release it.")
                    floating_ip.delete()
                    return False, "Error attaching a Floating IP to the node."

                if found:
                    vm.floating_ips.append(floating_ip.ip_address)
                return True, floating_ip
            else:
                self.log_error("No pools available.")
                return False, "No pools available."

        except Exception as ex:
            self.log_exception("Error adding an Elastic/Floating IP to VM ID: %s" % vm.id)
            return False, "%s" % get_ex_error(ex)

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
        system = radl.systems[0]

        # First check if the node is "routed"
        i = 0
        while system.getValue("net_interface." + str(i) + ".connection"):
            network_name = system.getValue("net_interface." + str(i) + ".connection")
            i += 1
            network = radl.get_network_by_id(network_name)
            if network.getValue('router'):
                self.log_info("Network has a router set. Do not create security groups.")
                return res

        # First create a SG for the entire Infra
        # Use the InfrastructureInfo lock to assure that only one VM create the SG
        with inf._lock:
            sg_name = "im-%s" % inf.id
            sg = self._get_security_group(driver, sg_name)
            if not sg:
                self.log_info("Creating security group: %s" % sg_name)
                sg = driver.ex_create_security_group(sg_name, "Security group created by the IM")
                # open all the ports for the VMs in the security group
                driver.ex_create_security_group_rule(sg, 'tcp', 1, 65535, source_security_group=sg)
                driver.ex_create_security_group_rule(sg, 'udp', 1, 65535, source_security_group=sg)
            res.append(sg)

        i = 0
        while system.getValue("net_interface." + str(i) + ".connection"):
            network_name = system.getValue("net_interface." + str(i) + ".connection")
            i += 1
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
                self.log_warn("Exception adding SG rules. Probably the rules exists: %s" % get_ex_error(addex))

            outports = network.getOutPorts()
            if outports:
                for outport in outports:
                    if outport.is_range():
                        try:
                            driver.ex_create_security_group_rule(sg, outport.get_protocol(),
                                                                 outport.get_port_init(),
                                                                 outport.get_port_end(), '0.0.0.0/0')
                        except Exception as ex:
                            self.log_warn("Exception adding SG rules: %s" % get_ex_error(ex))
                    else:
                        if outport.get_remote_port() != 22 or not network.isPublic():
                            try:
                                driver.ex_create_security_group_rule(sg, outport.get_protocol(),
                                                                     outport.get_remote_port(),
                                                                     outport.get_remote_port(), '0.0.0.0/0')
                            except Exception as ex:
                                self.log_warn("Exception adding SG rules: %s" % get_ex_error(ex))

        return res

    def finalize(self, vm, last, auth_data):
        if vm.id:
            node = self.get_node_with_id(vm.id, auth_data)
        else:
            self.log_warn("No VM ID. Ignoring")
            node = None

        success = []
        msgs = []
        if node:
            # First try to detach the volumes and the SGs
            for vol_id in vm.volumes:
                try:
                    self.log_debug("Dettaching volume %s." % vol_id)
                    volume = node.driver.ex_get_volume(vol_id)
                    node.driver.detach_volume(volume)
                except Exception as ex:
                    self.log_exception("Error dettaching volume %s." % vol_id)

            try:
                for sg_name in self._get_security_names(vm.inf):
                    self.log_debug("Dettaching SG %s." % sg_name)
                    security_group = OpenStackSecurityGroup(None, None, sg_name, "", node.driver)
                    node.driver.ex_remove_security_group_from_node(security_group, node)
            except Exception as ex:
                self.log_exception("Error dettaching SGs.")

            res = node.destroy()
            success.append(res)

            try:
                res, msg = self.delete_elastic_ips(node, vm)
            except Exception as ex:
                res = False
                msg = get_ex_error(ex)
            success.append(res)
            msgs.append(msg)

            try:
                for vol_id in vm.volumes:
                    volume = None
                    try:
                        volume = node.driver.ex_get_volume(vol_id)
                        self.wait_volume(volume)
                    except Exception:
                        self.log_exception("Error getting volume ID: %s. No deleting it." % vol_id)
                    if volume:
                        volume.destroy()
            except Exception as ex:
                res = False
                msg = get_ex_error(ex)
            success.append(res)
            msgs.append(msg)

            self.log_info("VM " + str(vm.id) + " successfully destroyed")
        else:
            self.log_warn("VM " + str(vm.id) + " not found.")

        driver = self.get_driver(auth_data)

        if last:
            # Delete the SG if this is the last VM
            try:
                res, msg = self.delete_security_groups(driver, vm.inf)
            except Exception as ex:
                res = False
                msg = get_ex_error(ex)
            success.append(res)
            msgs.append(msg)

            # Delete the created networks
            try:
                res, msg = self.delete_networks(driver, vm.inf)
            except Exception as ex:
                res = False
                msg = get_ex_error(ex)
            success.append(res)
            msgs.append(msg)
        else:
            # If this is not the last vm, we skip this step
            self.log_info("There are active instances. Not removing the SGs or nets.")

        return (all(success), "\n ".join(msgs))

    def _get_security_names(self, inf):
        """
        Get the list of SGs for this infra
        """
        sg_names = ["im-%s" % inf.id]
        for net in inf.radl.networks:
            sg_name = net.getValue("sg_name")
            if not sg_name:
                sg_name = "im-%s-%s" % (inf.id, net.id)
            sg_names.append(sg_name)

        return sg_names

    def delete_security_groups(self, driver, inf, timeout=180, delay=10):
        """
        Delete the SG of this inf
        """
        sg_names = self._get_security_names(inf)

        msg = ""
        deleted = True
        for sg_name in sg_names:
            # wait it to terminate and then remove the SG
            cont = 0
            deleted = False
            while not deleted and cont < timeout:
                # Get the SG to delete
                sg = self._get_security_group(driver, sg_name)
                if not sg:
                    self.log_info("The SG %s does not exist. Do not delete it." % sg_name)
                    deleted = True
                else:
                    if sg.description != "Security group created by the IM":
                        self.log_info("SG %s not created by the IM. Do not delete it." % sg_name)
                        deleted = True
                    else:
                        try:
                            self.log_info("Deleting SG: %s" % sg_name)
                            driver.ex_delete_security_group(sg)
                            deleted = True
                        except Exception as ex:
                            self.log_warn("Error deleting the SG: %s" % get_ex_error(ex))
                            msg = "Error deleting the SG: %s" % get_ex_error(ex)

                    if not deleted:
                        time.sleep(delay)
                        cont += delay

            if not deleted:
                self.log_error("Error deleting the SG: Timeout.")

        return deleted, msg

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
                return False, "Error creating image: %s." % get_ex_error(ex)
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
            return (False, "Error getting image %s: %s" % (image_id, get_ex_error(ex)))
        try:
            driver.delete_image(image)
            return True, ""
        except Exception as ex:
            self.log_exception("Error deleting image.")
            return (False, "Error deleting image.: %s" % get_ex_error(ex))

    def reboot(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            success = node.driver.ex_hard_reboot_node(node)
            if success:
                return (True, "")
            else:
                return (False, "Error in reboot operation")
        else:
            return (False, "VM not found with id: " + vm.id)

    def alterVM(self, vm, radl, auth_data):
        success, msg = self.resizeVM(vm, radl, auth_data)
        if not success:
            return (success, msg)

        success, msg = self.add_new_disks(vm, radl, auth_data)
        if not success:
            return (success, msg)

        success, msg = self.alter_public_ips(vm, radl, auth_data)
        if not success:
            return (success, msg)

        return (True, "")

    def resizeVM(self, vm, radl, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            new_cpu = radl.systems[0].getValue('cpu.count')
            new_memory = radl.systems[0].getValue('memory.size')
            instance_type = radl.systems[0].getValue('instance_type')
            if not any([new_cpu, new_memory, instance_type]):
                self.log_debug("No memory nor cpu nor instance_type specified. VM not resized.")
                return (True, "")
            else:
                instance_type = self.get_instance_type(node.driver.list_sizes(), radl.systems[0])
                if instance_type is None:
                    return (False, "Error resizing VM: No instance type found.")
                if node.extra['flavorId'] != instance_type.id:
                    try:
                        self.log_debug("Resizing node: %s" % node.id)
                        success = node.driver.ex_resize(node, instance_type)
                        if success:
                            cont = 0
                            # wait the node to be in correct state to confirm
                            while node.extra['vm_state'] != 'resized' and cont < self.CONFIRM_TIMEOUT:
                                time.sleep(3)
                                cont += 3
                                self.log_debug("Confirming resize of the node: %s" % node.id)
                                node = self.get_node_with_id(vm.id, auth_data)

                            if node.extra['vm_state'] == 'resized':
                                success = node.driver.ex_confirm_resize(node)
                            else:
                                return (False, "Error resizing VM: Resize cannot be confirmed.")
                    except Exception as ex:
                        self.log_exception("Error resizing VM.")
                        return (False, "Error resizing VM: " + str(ex))
                else:
                    self.log_debug("Same instance_type of the current node. No need to resize.")
                    return (True, "")

                if success:
                    return (True, "")
                else:
                    return (False, "Error in resize operation")
        else:
            return (False, "VM not found with id: " + vm.id)

    def create_attach_volume(self, node, disk_size, disk_device, volume_name, location):
        try:
            volume = node.driver.create_volume(int(disk_size), volume_name, location=location)
        except Exception as ex:
            self.log_exception("Error creating volume.")
            return False, None, get_ex_error(ex)
        success = self.wait_volume(volume)
        if not success:
            self.log_error("Error waiting the volume ID %s." % volume.id)
            return False, volume, "Error waiting the volume ID %s." % volume.id
        else:
            self.log_debug("Attach the volume ID %s" % volume.id)
            try:
                volume.attach(node, disk_device)
            except Exception as ex:
                self.log_exception("Error attaching volume ID %s" % volume.id)
                return False, volume, get_ex_error(ex)
            # wait the volume to be attached
            success = self.wait_volume(volume, state='in-use')
            # update the volume data
            volume = volume.driver.ex_get_volume(volume.id)
            return success, volume, ""

    def add_new_disks(self, vm, radl, auth_data):
        """
        Add new disks specified in the radl to the vm
        """
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            try:
                orig_system = vm.info.systems[0]

                cont = 1
                while (orig_system.getValue("disk." + str(cont) + ".image.url") or
                       orig_system.getValue("disk." + str(cont) + ".size")):
                    cont += 1

                system = radl.systems[0]

                while system.getValue("disk." + str(cont) + ".size"):
                    disk_size = system.getFeature("disk." + str(cont) + ".size").getValue('G')
                    disk_device = system.getValue("disk." + str(cont) + ".device")
                    self.log_info("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))

                    volume_name = "im-%s" % str(uuid.uuid1())

                    location = self.get_node_location(node)
                    success, volume, msg = self.create_attach_volume(node, disk_size, disk_device,
                                                                     volume_name, location)
                    if not success and volume:
                        try:
                            self.log_debug("Deleting volume %s" % volume.id)
                            volume.destroy()
                        except Exception:
                            self.log_exception("Error deleteing volume %s." % volume.id)

                        return (False, "Error creating or attaching the Volume: %s" % msg)

                    # Add the volume to the VM to remove it later
                    vm.volumes.append(volume.id)
                    vm.info.systems[0].setValue("disk." + str(cont) + ".size", disk_size, 'G')
                    if 'attachments' in volume.extra and volume.extra['attachments']:
                        disk_device = volume.extra['attachments'][0]['device']
                    vm.info.systems[0].setValue("disk." + str(cont) + ".device", disk_device)

                    cont += 1
                return (True, "")
            except Exception as ex:
                self.log_exception("Error connecting with OpenStack server")
                return (False, "Error connecting with OpenStack server: " + get_ex_error(ex))

    def alter_public_ips(self, vm, radl, auth_data):
        """
        Add/remove public IP if currently it does not have one and new RADL requests it or vice versa
        """
        # update VM info
        try:
            vm.update_status(auth_data, force=True)
            node = self.get_node_with_id(vm.id, auth_data)
            current_public_ip = vm.getPublicIP()
            new_has_public_ip = radl.hasPublicNet(vm.info.systems[0].name)
            if new_has_public_ip and not current_public_ip:
                self.log_info("Adding Public IP.")
                for net in radl.networks:
                    if net.isPublic():
                        new_public_net = net.clone()
                new_public_net.id = "public.%d" % int(time.time() * 100)
                vm.requested_radl.networks.append(new_public_net)
                num_net = vm.requested_radl.systems[0].getNumNetworkIfaces()
                vm.requested_radl.systems[0].setValue("net_interface.%d.connection" % num_net, new_public_net.id)
                pool_name = new_public_net.getValue("provider_id")
                return self.add_elastic_ip_from_pool(vm, node, None, pool_name)

            if not new_has_public_ip and current_public_ip:
                floating_ip = node.driver.ex_get_floating_ip(current_public_ip)
                self.log_info("Removing Public IP: %s." % floating_ip)
                if node.driver.ex_detach_floating_ip_from_node(node, floating_ip):
                    floating_ip.delete()

                    # Remove all public net connections in the Requested RADL
                    vm.delete_public_nets(vm.requested_radl)

                    return True, ""
                else:
                    return False, "Error detaching IP %s from node %s" % (current_public_ip, node.id)
        except Exception as ex:
            self.log_exception("Error adding/removing new public IP")
            return (False, "Error adding/removing new public IP: " + get_ex_error(ex))
        return True, ""

    def delete_elastic_ips(self, node, vm):
        """
        remove the elastic IPs of a VM

        Arguments:
           - node(:py:class:`libcloud.compute.base.Node`): node object to attach the volumes.
           - vm(:py:class:`IM.VirtualMachine`): VM information.
        """
        try:
            no_delete_ips = []
            if "floating_ips" in vm.__dict__.keys():
                no_delete_ips = vm.floating_ips

            for floating_ip in node.driver.ex_list_floating_ips():
                if floating_ip.node_id == node.id:
                    # remove it from the node
                    try:
                        node.driver.ex_detach_floating_ip_from_node(node, floating_ip)
                    except Exception as ex:
                        self.log_warn("Error detaching Floating IP: %s. %s" % (floating_ip.ip_address,
                                                                               get_ex_error(ex)))
                    # if it is in the list do not release it
                    if floating_ip.ip_address in no_delete_ips:
                        self.log_debug("Do not remove Floating IP: %s" % floating_ip.ip_address)
                    else:
                        self.log_debug("Remove Floating IP: %s" % floating_ip.ip_address)
                        # delete the ip
                        floating_ip.delete()
            return True, ""
        except Exception as ex:
            self.log_exception("Error removing Floating IPs to VM ID: " + str(vm.id))
            return False, "Error removing Floating IPs: %s" % get_ex_error(ex)

    def list_images(self, auth_data, filters=None):
        driver = self.get_driver(auth_data)
        images = []
        for image in driver.list_images():
            images.append({"uri": "ost://%s/%s" % (self.cloud.server, image.id), "name": image.name})
        return images

    @staticmethod
    def _get_tenant_id(driver, auth):
        """
        Workaround function to get tenant id from tenant name
        """
        if 'auth_version' in auth and auth['auth_version'] == '3.x_oidc_access_token':
            return auth['domain']
        else:
            if 'tenant_id' in auth:
                return auth['tenant_id']
            else:
                return auth['tenant']

        return None

    def get_quotas(self, auth_data):
        driver = self.get_driver(auth_data)
        tenant_id = self._get_tenant_id(driver, auth_data.getAuthInfo(self.type, self.cloud.server)[0])
        quotas = driver.ex_get_quota_set(tenant_id)
        try:
            net_quotas = driver.ex_get_network_quotas(tenant_id)
        except Exception:
            net_quotas = None

        quotas_dict = {}
        quotas_dict["cores"] = {"used": quotas.cores.in_use + quotas.cores.reserved,
                                "limit": quotas.cores.limit}
        quotas_dict["ram"] = {"used": (quotas.ram.in_use + quotas.ram.reserved) / 1024,
                              "limit": quotas.ram.limit / 1024}
        quotas_dict["instances"] = {"used": quotas.instances.in_use + quotas.instances.reserved,
                                    "limit": quotas.instances.limit}
        quotas_dict["floating_ips"] = {"used": quotas.floating_ips.in_use + quotas.floating_ips.reserved,
                                       "limit": quotas.floating_ips.limit}
        quotas_dict["security_groups"] = {"used": quotas.security_groups.in_use + quotas.security_groups.reserved,
                                          "limit": quotas.security_groups.limit}

        if net_quotas:
            quotas_dict["floating_ips"] = {"used": net_quotas.floatingip.in_use + net_quotas.floatingip.reserved,
                                           "limit": net_quotas.floatingip.limit}
            quotas_dict["security_groups"] = {"used": net_quotas.security_group.in_use +
                                              net_quotas.security_group.reserved,
                                              "limit": net_quotas.security_group.limit}
        return quotas_dict
