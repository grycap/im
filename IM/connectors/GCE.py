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
import os
import time

try:
    from libcloud.compute.base import NodeSize, NodeState
    from libcloud.compute.types import Provider
    from libcloud.compute.providers import get_driver as libcloud_get_driver
    from libcloud.common.google import ResourceNotFoundError, ResourceExistsError
    from libcloud.dns.types import Provider as DNSProvider
    from libcloud.dns.types import RecordType
    from libcloud.dns.providers import get_driver as get_dns_driver
    from libcloud.compute.drivers.gce import GCENodeSize
except Exception as ex:
    print("WARN: libcloud library not correctly installed. GCECloudConnector will not work!.")
    print(ex)

from IM.connectors.LibCloud import LibCloudCloudConnector
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from radl.radl import Feature
from IM.config import Config


class GCECloudConnector(LibCloudCloudConnector):
    """
    Cloud Launcher to GCE using LibCloud
    """

    type = "GCE"
    """str with the name of the provider."""
    DEFAULT_ZONE = "us-central1-a"
    DEFAULT_USER = 'gceuser'
    """ default user to SSH access the VM """

    def __init__(self, cloud_info, inf):
        self.auth = None
        self.datacenter = None
        self.driver = None
        self.dns_driver = None
        LibCloudCloudConnector.__init__(self, cloud_info, inf)

    def get_driver(self, auth_data, datacenter=None):
        """
        Get the compute driver from the auth data

        Arguments:
            - auth(Authentication): parsed authentication tokens.
            - datacenter(str): datacenter to connect.

        Returns: a :py:class:`libcloud.compute.base.NodeDriver` or None in case of error
        """
        auths = auth_data.getAuthInfo(self.type)
        if not auths:
            raise Exception("No auth data has been specified to GCE.")
        else:
            auth = auths[0]

        if self.driver and self.auth.compare(auth_data, self.type) and self.datacenter == datacenter:
            return self.driver
        else:
            self.auth = auth_data
            self.datacenter = datacenter

            if 'username' in auth and 'password' in auth and 'project' in auth:
                cls = libcloud_get_driver(Provider.GCE)
                # Patch to solve some client problems with \\n
                auth['password'] = auth['password'].replace('\\n', '\n')
                lines = len(auth['password'].replace(" ", "").split())
                if lines < 2:
                    raise Exception("The certificate provided to the GCE plugin has an incorrect format."
                                    " Check that it has more than one line.")

                driver = cls(auth['username'], auth['password'], project=auth['project'], datacenter=datacenter)

                self.driver = driver
                return driver
            else:
                self.log_error("No correct auth data has been specified to GCE: username, password and project")
                self.log_debug(auth)
                raise Exception(
                    "No correct auth data has been specified to GCE: username, password and project")

    def get_dns_driver(self, auth_data):
        """
        Get the DNS driver from the auth data

        Arguments:
            - auth(Authentication): parsed authentication tokens.

        Returns: a :py:class:`libcloud.dns.base.DNSDriver` or None in case of error
        """
        auths = auth_data.getAuthInfo(self.type)
        if not auths:
            raise Exception("No auth data has been specified to GCE.")
        else:
            auth = auths[0]

        if self.dns_driver and self.auth.compare(auth_data, self.type):
            return self.dns_driver
        else:
            self.auth = auth_data

            if 'username' in auth and 'password' in auth and 'project' in auth:
                cls = get_dns_driver(DNSProvider.GOOGLE)
                # Patch to solve some client problems with \\n
                auth['password'] = auth['password'].replace('\\n', '\n')
                lines = len(auth['password'].replace(" ", "").split())
                if lines < 2:
                    raise Exception("The certificate provided to the GCE plugin has an incorrect format."
                                    " Check that it has more than one line.")

                driver = cls(auth['username'], auth['password'], project=auth['project'])

                self.dns_driver = driver
                return driver
            else:
                self.log_error("No correct auth data has been specified to GCE: username, password and project")
                self.log_debug(auth)
                raise Exception(
                    "No correct auth data has been specified to GCE: username, password and project")

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]

        if protocol == "gce":
            driver = self.get_driver(auth_data)

            res_system = radl_system.clone()
            res_system.addFeature(Feature("disk.0.image.url", "=", str_url), conflict="other", missing="other")

            if res_system.getValue('availability_zone'):
                region = res_system.getValue('availability_zone')
            else:
                region, _ = self.get_image_data(str_url)

            instance_type = self.get_instance_type(driver.list_sizes(region), res_system)
            if not instance_type:
                return None

            self.update_system_info_from_instance(res_system, instance_type)

            username = res_system.getValue('disk.0.os.credentials.username')
            if not username:
                res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)

            return res_system
        else:
            return None

    @staticmethod
    def update_system_info_from_instance(system, instance_type):
        """
        Update the features of the system with the information of the instance_type
        """
        if isinstance(instance_type, NodeSize):
            LibCloudCloudConnector.update_system_info_from_instance(system, instance_type)
            if 'guestCpus' in instance_type.extra:
                system.addFeature(Feature("cpu.count", "=", instance_type.extra[
                                  'guestCpus']), conflict="other", missing="other")

    @staticmethod
    def set_net_provider_id(radl, net_name):
        """
        Set the provider ID on all the nets of the system
        """
        system = radl.systems[0]
        for i in range(system.getNumNetworkIfaces()):
            net_id = system.getValue('net_interface.' + str(i) + '.connection')
            net = radl.get_network_by_id(net_id)
            if net:
                net.setValue('provider_id', net_name)

    @staticmethod
    def get_net_provider_id(radl):
        """
        Get the provider ID of the first net that has specified it
        Returns: The net provider ID or None if not defined
        """
        provider_id = None
        system = radl.systems[0]
        for i in range(system.getNumNetworkIfaces()):
            net_id = system.getValue('net_interface.' + str(i) + '.connection')
            net = radl.get_network_by_id(net_id)

            if net:
                provider_id = net.getValue('provider_id')
                if provider_id:
                    return provider_id

        return provider_id

    def get_instance_type(self, sizes, radl):
        """
        Get the name of the instance type to launch to LibCloud

        Arguments:
           - size(list of :py:class: `libcloud.compute.base.NodeSize`): List of sizes on a provider
           - radl(str): RADL document with the requirements of the VM to get the instance type
        Returns: a :py:class:`libcloud.compute.base.NodeSize` with the instance type to launch
        """
        instance_type_name = radl.getValue('instance_type')

        (cpu, cpu_op, memory, memory_op, _, _) = self.get_instance_selectors(radl)

        res = None
        for size in sizes:
            # get the node size with the lowest price and memory (in the case
            # of the price is not set)
            if size.price is None:
                size.price = 9999
            if res is None or (size.price <= res.price or size.ram <= res.ram):
                comparison = memory_op(size.ram, memory)
                if 'guestCpus' in size.extra and size.extra['guestCpus']:
                    comparison = comparison and cpu_op(size.extra['guestCpus'], cpu)

                if comparison:
                    if not instance_type_name or size.name == instance_type_name:
                        res = size

        if res is None and (not instance_type_name or instance_type_name.startswith("custom")):
            name = "custom-%s-%s" % (cpu, memory)
            path = os.path.dirname(sizes[0].extra['selfLink'])
            selfLink = path + "/" + name
            res = GCENodeSize(id=name, name=name, ram=memory, disk=0, bandwidth=0, price=0,
                              driver=None, extra={'guestCpus': cpu, 'selfLink': selfLink})

        if res is None:
            self.log_error("No compatible size found")

        return res

    @staticmethod
    def request_external_ip(radl):
        """
        Check if the user has requested for a public ip
        """
        system = radl.systems[0]
        n = 0
        while system.getValue("net_interface." + str(n) + ".connection"):
            net_conn = system.getValue('net_interface.' + str(n) + '.connection')
            if radl.get_network_by_id(net_conn).isPublic():
                return True
            n += 1

        return False

    def request_fixed_ip(self, radl):
        """
        Check if the user has requested for a fixed ip
        """
        system = radl.systems[0]
        n = 0
        requested_ips = []
        while system.getValue("net_interface." + str(n) + ".connection"):
            net_conn = system.getValue('net_interface.' + str(n) + '.connection')
            if radl.get_network_by_id(net_conn).isPublic():
                fixed_ip = system.getValue("net_interface." + str(n) + ".ip")
                if fixed_ip:
                    requested_ips.append(fixed_ip)
            n += 1

        if requested_ips:
            self.log_info("The user requested for a fixed IP")
            if len(requested_ips) > 1:
                self.log_warn("The user has requested more than one fixed IP. Using only the first one")
            return requested_ips[0]
        else:
            return None

    # The path must be: gce://us-central1/debian-7 or gce://debian-7
    def get_image_data(self, path):
        """
        Get the region and the image name from an URL of a VMI

        Arguments:
           - path(str): URL of a VMI (some like this: gce://us-central1/debian-7 or gce://debian-7)
        Returns: a tuple (region, image_name) with the region and the AMI ID
        """
        uri = urlparse(path)
        if uri[2]:
            region = uri[1]
            image_name = uri[2][1:]
        else:
            # If the image do not specify the zone, use the default one
            region = self.DEFAULT_ZONE
            image_name = uri[1]

        return (region, image_name)

    @staticmethod
    def get_default_net(driver):
        """
        Get the first net
        """
        nets = driver.ex_list_networks()
        if nets:
            for net in nets:
                if net.name == "default":
                    return "default"
            return nets[0].name
        else:
            return None

    def create_firewall(self, inf, net_name, radl, driver):
        """
        Create a firewall for the net using the outports param
        """
        with inf._lock:
            public_net = None
            for net in radl.networks:
                if net.isPublic():
                    public_net = net

            # Create FW rules to allow all inside the VMs
            if inf.id in net_name:
                firewall_name = "%s-all" % net_name
            else:
                firewall_name = "im-%s-%s-all" % (inf.id, net_name)
            allowed = [{'IPProtocol': 'udp', 'ports': '1-65535'},
                       {'IPProtocol': 'tcp', 'ports': '1-65535'},
                       {'IPProtocol': 'icmp'}]

            try:
                driver.ex_create_firewall(firewall_name, allowed, network=net_name, source_tags=['imid-%s' % inf.id])
                self.log_info("Firewall %s successfully created." % firewall_name)
            except ResourceExistsError:
                self.log_debug("FW already exists. Ignore.")
            except Exception as addex:
                self.log_warn("Exception creating FW: " + str(addex))

            ports = {"tcp": ["22"]}
            if public_net:
                if inf.id in net_name:
                    firewall_name = "%s" % net_name
                else:
                    firewall_name = "im-%s-%s" % (inf.id, net_name)

                outports = public_net.getOutPorts()
                if outports:
                    for outport in outports:
                        if outport.get_protocol() not in ports:
                            ports[outport.get_protocol()] = []
                        if outport.is_range():
                            port_range = "%d-%d" % (outport.get_port_init(), outport.get_port_end())
                            ports[outport.get_protocol()].append(port_range)
                        elif outport.get_local_port() != 22:
                            ports[outport.get_protocol()].append(str(outport.get_remote_port()))

                allowed = [{'IPProtocol': 'tcp', 'ports': ports['tcp']}]
                if 'udp' in ports:
                    allowed.append({'IPProtocol': 'udp', 'ports': ports['udp']})

                try:
                    driver.ex_create_firewall(firewall_name, allowed, network=net_name)
                    self.log_info("Firewall %s successfully created." % firewall_name)
                except ResourceExistsError:
                    self.log_debug("FW already exists. Ignore.")
                except Exception as addex:
                    self.log_warn("Exception creating FW: " + str(addex))

    def create_networks(self, driver, radl, inf):
        """
        Create GCE networks
        """
        try:
            i = 0

            while radl.systems[0].getValue("net_interface." + str(i) + ".connection"):
                net_name = radl.systems[0].getValue("net_interface." + str(i) + ".connection")
                i += 1
                network = radl.get_network_by_id(net_name)
                if network.getValue('create') == 'yes' and not network.isPublic():
                    gce_net_name = "im-%s-%s" % (inf.id, net_name)

                    # First check if the net already exists
                    net = None
                    try:
                        net = driver.ex_get_network(gce_net_name)
                    except Exception:
                        self.log_debug("Net %s does not exist." % gce_net_name)

                    if net:
                        self.log_debug("Net %s already exist. Do not create it." % gce_net_name)
                    else:
                        net_cidr = network.getValue('cidr')
                        if net_cidr:
                            mode = "legacy"
                            used_cidrs = [gce_net.cidr for gce_net in driver.ex_list_networks()]
                            net_cidr = self.get_free_cidr(net_cidr, used_cidrs, inf)
                        else:
                            mode = "auto"
                        self.log_info("Create net %s with cidr %s." % (gce_net_name, net_cidr))
                        driver.ex_create_network(gce_net_name, net_cidr, "Net created by the IM", mode=mode)
                        if net_cidr:
                            network.setValue('cidr', net_cidr)
                            # Set also the cidr in the inf RADL
                            inf.radl.get_network_by_id(network.id).setValue('cidr', net_cidr)

                    network.setValue('provider_id', gce_net_name)
        except Exception as ext:
            self.log_exception("Error creating networks.")
            try:
                self.delete_networks(driver, inf)
            except Exception:
                self.log_exception("Error deleting networks.")
            raise Exception("Error creating networks: %s" % ext)

        return True

    def gen_disks_gce_struct(self, radl, driver, inf, image, location):
        """
        Return the required volumes (in the RADL) to be attached to the launched node

        Arguments:
           - radl(RADL): RADL document.
           - driver: libCloud driver object
           - inf: Infrastructure info
           - image: image object
           - location: disks location
        Returns: A list of dicts as expected by the ex_disks_gce_struct
        See: https://cloud.google.com/compute/docs/reference/rest/v1/instances
        "disks" section
        """
        boot_disk_name = "bootd-%s" % uuid.uuid1()
        boot_disk = {
            'autoDelete': True,
            'boot': True,
            'type': 'PERSISTENT',
            'mode': 'READ_WRITE',
            'deviceName': boot_disk_name,
            'initializeParams': {
                'diskName': boot_disk_name,
                'diskType': driver.ex_get_disktype('pd-standard', zone=location).extra['selfLink'],
                'sourceImage': image.extra['selfLink']
            }
        }

        res = [boot_disk]
        cont = 1
        while ((radl.systems[0].getValue("disk." + str(cont) + ".size") or
                radl.systems[0].getValue("disk." + str(cont) + ".image.url")) and
                radl.systems[0].getValue("disk." + str(cont) + ".device")):
            disk_url = radl.systems[0].getValue("disk." + str(cont) + ".image.url")
            disk_device = radl.systems[0].getValue("disk." + str(cont) + ".device")
            disk_type = radl.systems[0].getValue("disk." + str(cont) + ".type")
            if not disk_type:
                disk_type = 'pd-standard'

            disk = {'boot': False,
                    'type': 'PERSISTENT',
                    'mode': 'READ_WRITE',
                    'deviceName': disk_device}

            if disk_url:
                # If the user has specified the volume name, try to get it
                region, image_id = self.get_image_data(disk_url)
                location = driver.ex_get_zone(region)
                volume = driver.ex_get_volume(image_id, zone=location)
                disk['source'] = volume.extra['selfLink']
                disk['autoDelete'] = False
            else:
                disk_size = radl.systems[0].getFeature("disk." + str(cont) + ".size").getValue('G')
                disk['autoDelete'] = True
                disk['initializeParams'] = {'diskName': "im-%s-%s" % (inf.id, str(cont)),
                                            'diskSizeGb': str(disk_size),
                                            'diskType': driver.ex_get_disktype(disk_type,
                                                                               zone=location).extra['selfLink']}

            res.append(disk)

            cont += 1

        return res

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        system = radl.systems[0]
        region, image_id = self.get_image_data(system.getValue("disk.0.image.url"))

        if system.getValue('availability_zone'):
            region = system.getValue('availability_zone')

        driver = self.get_driver(auth_data, region)

        region = driver.ex_get_zone(region)
        if not region:
            return [(False, "Incorrect region specified.") for _ in range(num_vm)]

        image = driver.ex_get_image(image_id)
        if not image:
            return [(False, "Incorrect image name") for _ in range(num_vm)]

        instance_type = self.get_instance_type(driver.list_sizes(region), system)

        if not instance_type:
            raise Exception("No compatible size found")

        name = self.gen_instance_name(system)

        args = {'size': instance_type,
                'image': image,
                'external_ip': None,
                'location': region}

        tags = self.get_instance_tags(system, auth_data, inf)
        if tags:
            args['ex_labels'] = {}
            for key, value in tags.items():
                args['ex_labels'][key.replace("-", "_").lower()] = value

        # include the SSH_KEYS
        username = system.getValue('disk.0.os.credentials.username')
        private = system.getValue('disk.0.os.credentials.private_key')
        public = system.getValue('disk.0.os.credentials.public_key')

        if not public or not private:
            # We must generate them
            self.log_debug("No keys. Generating key pair.")
            (public, private) = self.keygen()
            system.setValue('disk.0.os.credentials.private_key', private)

        metadata = {}
        if private and public:
            metadata = {"sshKeys": username + ":" + public}
            self.log_info("Setting ssh for user: " + username)

        startup_script = self.get_cloud_init_data(radl)
        if startup_script:
            metadata['startup-script'] = startup_script

        if metadata:
            args['ex_metadata'] = metadata

        # Create the info about disks
        args['ex_disks_gce_struct'] = self.gen_disks_gce_struct(radl, driver, inf, image, region)

        with inf._lock:
            self.create_networks(driver, radl, inf)

        net_provider_id = self.get_net_provider_id(radl)
        if not net_provider_id:
            net_provider_id = self.get_default_net(driver)
            if not net_provider_id:
                net_provider_id = "default"

        args['ex_network'] = net_provider_id
        self.create_firewall(inf, net_provider_id, radl, driver)

        args['ex_can_ip_forward'] = self.can_ip_forward(radl)

        node_tags = ["imid-%s" % inf.id]
        if self.request_external_ip(radl):
            args['external_ip'] = 'ephemeral'
            fixed_ip = self.request_fixed_ip(radl)
            if fixed_ip:
                if num_vm > 1:
                    raise Exception("A fixed IP cannot be specified to a set of nodes (deploy is higher than 1)")

                args['external_ip'] = driver.ex_create_address(name="im-" + fixed_ip, region=region, address=fixed_ip)
        else:
            node_tags = ["imid-%s-nopubip" % inf.id, "imid-%s" % inf.id]

        args['ex_tags'] = node_tags
        res = []
        error_msg = "Error launching VM."
        if num_vm > 1:
            args['number'] = num_vm
            args['base_name'] = name
            self.log_debug(args)
            try:
                nodes = driver.ex_create_multiple_nodes(**args)
            except Exception as ex:
                nodes = []
                self.log_exception("Error launching VMs.")
                error_msg = str(ex)
        else:
            args['name'] = name
            self.log_debug(args)
            try:
                nodes = [driver.create_node(**args)]
            except Exception as ex:
                nodes = []
                self.log_exception("Error launching VM.")
                error_msg = str(ex)

        for node in nodes:
            vm = VirtualMachine(inf, node.extra['name'], self.cloud, radl,
                                requested_radl, self.cloud.getCloudConnector(inf))
            vm.info.systems[0].setValue('instance_id', str(vm.id))
            vm.info.systems[0].setValue('instance_name', str(vm.id))
            inf.add_vm(vm)
            self.log_info("Node successfully created.")

            res.append((True, vm))

        all_ok = True
        for _ in range(len(nodes), num_vm):
            all_ok = False
            res.append((False, "ERROR: %s" % error_msg))

        if not all_ok:
            if args['external_ip'] != 'ephemeral':
                try:
                    driver.ex_destroy_address(args['external_ip'])
                except Exception:
                    self.log_exception("Error deleting extenal IP.")

        return res

    def delete_networks(self, driver, inf, timeout=120):
        """
        Delete created GCE networks
        """
        for gce_net in driver.ex_list_networks():
            net_prefix = "im-%s-" % inf.id
            if gce_net.name.startswith(net_prefix):
                self.log_info("Deleting net %s." % gce_net.name)

                cont = 0
                deleted = False
                while not deleted and cont < timeout:
                    cont += 5
                    try:
                        gce_net.destroy()
                        deleted = True
                    except Exception as ex:
                        self.log_warn("Error removing net: " + str(ex))

                    if not deleted:
                        time.sleep(5)

        return True

    def delete_routes(self, driver, inf):
        """
        Delete created GCE routes
        """
        for gce_route in driver.ex_list_routes():
            name_prefix = "im-%s-" % inf.id
            if gce_route.name.startswith(name_prefix):
                self.log_info("Deleting route %s." % gce_route.name)
                gce_route.destroy()

        return True

    def finalize(self, vm, last, auth_data):
        try:
            if vm.id:
                node = self.get_node_with_id(vm.id, auth_data)
            else:
                self.log_warn("No VM ID. Ignoring")
                node = None
        except Exception as ex:
            self.log_exception("Error getting VM: %s. Err: %s." % (vm.id, str(ex)))
            return (False, "Error getting VM: %s. Err: %s." % (vm.id, str(ex)))

        if node:
            success = node.destroy()
            self.del_dns_entries(vm, auth_data)

            if not success:
                return (False, "Error destroying node: " + vm.id)

            self.log_info("VM " + str(vm.id) + " successfully destroyed")
        else:
            self.log_warn("VM " + str(vm.id) + " not found.")

        if last:
            driver = self.get_driver(auth_data)
            self.delete_firewall(vm, driver)
            self.delete_routes(driver, vm.inf)
            self.delete_networks(driver, vm.inf)

        return (True, "")

    def delete_firewall(self, vm, driver):
        """
        Delete the FWs
        """
        for gce_fw in driver.ex_list_firewalls():
            if vm.inf.id in gce_fw.name:
                self.log_info("Deleting FW %s." % gce_fw.name)
                gce_fw.destroy()

    def get_node_with_id(self, node_id, auth_data):
        """
        Get the node with the specified ID

        Arguments:
           - node_id(str): ID of the node to get
           - auth(Authentication): parsed authentication tokens.
        Returns: a :py:class:`libcloud.compute.base.Node` with the node info
        """
        driver = self.get_driver(auth_data)

        node = None

        try:
            node = driver.ex_get_node(node_id)
        except ResourceNotFoundError:
            self.log_warn("VM " + str(node_id) + " does not exist.")

        return node

    def can_ip_forward(self, radl):
        """
        Check if this node is specified as router
        """
        for network in radl.networks:
            if network.getValue('router'):
                router_info = network.getValue('router').split(",")
                if len(router_info) != 2:
                    self.log_error("Incorrect router format.")
                    break

                if radl.systems[0].name == router_info[1]:
                    return True

        return False

    def addRouterInstance(self, vm, driver):
        """
        Set an instance as router
        """
        success = True
        try:
            i = 0
            while vm.info.systems[0].getValue("net_interface." + str(i) + ".connection"):
                net_name = vm.info.systems[0].getValue("net_interface." + str(i) + ".connection")
                i += 1

                network = vm.info.get_network_by_id(net_name)
                if not network.getValue('provider_id'):
                    gce_net = driver.ex_get_network('default')
                else:
                    gce_net = driver.ex_get_network(network.getValue('provider_id'))

                if network.getValue('router'):
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
                            vrouter = v.id
                            break
                    if not vrouter:
                        self.log_error("No VRouter instance found with name %s" % system_router)
                        success = False
                        break

                    vrouter_instance = driver.ex_get_node(vrouter)

                    if vrouter_instance.state != NodeState.RUNNING:
                        self.log_debug("VRouter instance %s is not running." % system_router)
                        success = False
                        break

                    route_name = "im-%s-%s" % (vm.inf.id, net_name)
                    self.log_info("Adding route %s to instance ID: %s." % (router_cidr, vrouter))
                    try:
                        driver.ex_create_route(route_name, router_cidr, priority=800, network=gce_net,
                                               next_hop=vrouter_instance, tags=["imid-%s-nopubip" % vm.inf.id],
                                               description="Route created by the IM")
                    except ResourceExistsError:
                        self.log_debug("Route already exists. Ignore.")

                    # once set, delete it to not set it again
                    network.delValue('router')
        except Exception:
            success = False
            self.log_exception("Error adding Router Instance")

        return success

    @staticmethod
    def get_node_location(node):
        """
        Get the location of a node

        Arguments:
           - node(:py:class:`libcloud.compute.base.Node`): node object.
        Returns: a :py:class:`libcloud.compute.drivers.gce.GCEZone`
        """
        return node.extra['zone']

    def updateVMInfo(self, vm, auth_data):
        driver = self.get_driver(auth_data)

        node = None
        try:
            node = driver.ex_get_node(vm.id)
        except ResourceNotFoundError:
            self.log_warn("VM " + str(vm.id) + " does not exist.")
            return (False, "Error getting VM info: %s. VM does not exist." % vm.id)
        except Exception as ex:
            self.log_exception("Error getting VM info: %s" % vm.id)
            return (False, "Error getting VM info: %s. %s" % (vm.id, str(ex)))

        if node:
            vm.state = self.VM_STATE_MAP.get(node.state, VirtualMachine.UNKNOWN)

            if 'zone' in node.extra:
                vm.info.systems[0].setValue('availability_zone', node.extra['zone'].name)

            self.update_system_info_from_instance(vm.info.systems[0], node.size)

            vm.setIps(node.public_ips, node.private_ips)
            self.add_dns_entries(vm, auth_data)
            self.addRouterInstance(vm, driver)
        else:
            vm.state = VirtualMachine.OFF

        return (True, vm)

    def add_dns_entries(self, vm, auth_data):
        """
        Add the required entries in the Google DNS system

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
        """
        try:
            driver = self.get_dns_driver(auth_data)
            system = vm.info.systems[0]
            for net_name in system.getNetworkIDs():
                num_conn = system.getNumNetworkWithConnection(net_name)
                ip = system.getIfaceIP(num_conn)
                (hostname, domain) = vm.getRequestedNameIface(num_conn,
                                                              default_hostname=Config.DEFAULT_VM_NAME,
                                                              default_domain=Config.DEFAULT_DOMAIN)
                if domain != "localdomain" and ip:
                    if not domain.endswith("."):
                        domain += "."
                    zone = [z for z in driver.iterate_zones() if z.domain == domain]
                    if not zone:
                        self.log_info("Creating DNS zone %s" % domain)
                        zone = driver.create_zone(domain)
                    else:
                        zone = zone[0]
                        self.log_info("DNS zone %s exists. Do not create." % domain)

                    if zone:
                        fqdn = hostname + "." + domain
                        record = [r for r in driver.iterate_records(zone) if r.name == fqdn]
                        if not record:
                            self.log_info("Creating DNS record %s." % fqdn)
                            driver.create_record(fqdn, zone, RecordType.A, dict(ttl=300, rrdatas=[ip]))
                        else:
                            self.log_info("DNS record %s exists. Do not create." % fqdn)

            return True
        except Exception:
            self.log_exception("Error creating DNS entries")
            return False

    def del_dns_entries(self, vm, auth_data):
        """
        Delete the added entries in the Google DNS system

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
        """
        try:
            driver = self.get_dns_driver(auth_data)
            system = vm.info.systems[0]
            for net_name in system.getNetworkIDs():
                num_conn = system.getNumNetworkWithConnection(net_name)
                ip = system.getIfaceIP(num_conn)
                (hostname, domain) = vm.getRequestedNameIface(num_conn,
                                                              default_hostname=Config.DEFAULT_VM_NAME,
                                                              default_domain=Config.DEFAULT_DOMAIN)
                if domain != "localdomain" and ip:
                    if not domain.endswith("."):
                        domain += "."
                    zone = [z for z in driver.iterate_zones() if z.domain == domain]
                    if not zone:
                        self.log_info("The DNS zone %s does not exists. Do not delete records." % domain)
                    else:
                        zone = zone[0]
                        fqdn = hostname + "." + domain
                        record = [r for r in driver.iterate_records(zone) if r.name == fqdn]
                        if not record:
                            self.log_info("DNS record %s does not exists. Do not delete." % fqdn)
                        else:
                            record = record[0]
                            if record.data['rrdatas'] != [ip]:
                                self.log_info("DNS record %s mapped to unexpected IP: %s != %s."
                                              "Do not delete." % (fqdn, record.data['rrdatas'], ip))
                            else:
                                self.log_info("Deleting DNS record %s." % fqdn)
                                if not driver.delete_record(record):
                                    self.log_error("Error deleting DNS record %s." % fqdn)

                        # if there are no records (except the NS and SOA auto added ones), delete the zone
                        all_records = [r for r in driver.iterate_records(zone)
                                       if r.type not in [RecordType.NS, RecordType.SOA]]
                        if not all_records:
                            driver.delete_zone(zone)

            return True
        except Exception:
            self.log_exception("Error deleting DNS entries")
            return False

    def start(self, vm, auth_data):
        return self.vm_action(vm, 'start', auth_data)

    def stop(self, vm, auth_data):
        return self.vm_action(vm, 'stop', auth_data)

    def reboot(self, vm, auth_data):
        return self.vm_action(vm, 'reboot', auth_data)

    def vm_action(self, vm, action, auth_data):
        driver = self.get_driver(auth_data)

        try:
            node = driver.ex_get_node(vm.id)
        except ResourceNotFoundError:
            return (False, "VM " + str(vm.id) + " does not exist.")
        except Exception as ex:
            self.log_exception("Error getting VM %s" % vm.id)
            return (False, "Error getting VM %s: %s" % (vm.id, str(ex)))

        try:
            if action == 'stop':
                driver.ex_stop_node(node)
            elif action == 'start':
                driver.ex_start_node(node)
            elif action == 'reboot':
                driver.reboot_node(node)
        except Exception as ex:
            self.log_exception("Error in VM action %s" % vm.id)
            return (False, "Error in VM action %s: %s" % (vm.id, str(ex)))

        return (True, "")

    def alterVM(self, vm, radl, auth_data):
        return (False, "Not supported")
