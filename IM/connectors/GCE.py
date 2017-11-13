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
import uuid
import os

try:
    from libcloud.compute.base import NodeSize
    from libcloud.compute.types import NodeState, Provider
    from libcloud.compute.providers import get_driver
    from libcloud.common.google import ResourceNotFoundError
    from libcloud.dns.types import Provider as DNSProvider
    from libcloud.dns.types import RecordType
    from libcloud.dns.providers import get_driver as get_dns_driver
    from libcloud.compute.drivers.gce import GCENodeSize
except Exception as ex:
    print("WARN: libcloud library not correctly installed. GCECloudConnector will not work!.")
    print(ex)

from .CloudConnector import CloudConnector
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from radl.radl import Feature
from IM.config import Config


class GCECloudConnector(CloudConnector):
    """
    Cloud Launcher to GCE using LibCloud
    """

    type = "GCE"
    """str with the name of the provider."""
    DEFAULT_ZONE = "us-central1-a"

    def __init__(self, cloud_info, inf):
        self.auth = None
        self.datacenter = None
        self.driver = None
        self.dns_driver = None
        CloudConnector.__init__(self, cloud_info, inf)

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
                cls = get_driver(Provider.GCE)
                # Patch to solve some client problems with \\n
                auth['password'] = auth['password'].replace('\\n', '\n')
                lines = len(auth['password'].replace(" ", "").split())
                if lines < 2:
                    raise Exception("The certificate provided to the GCE plugin has an incorrect format."
                                    " Check that it has more than one line.")

                driver = cls(auth['username'], auth['password'],
                             project=auth['project'], datacenter=datacenter)

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
                if protocol == "gce":
                    driver = self.get_driver(auth_data)

                    res_system = radl_system.clone()
                    res_system.addFeature(
                        Feature("disk.0.image.url", "=", str_url), conflict="other", missing="other")

                    if res_system.getValue('availability_zone'):
                        region = res_system.getValue('availability_zone')
                    else:
                        region, _ = self.get_image_data(str_url)

                    instance_type = self.get_instance_type(
                        driver.list_sizes(region), res_system)

                    if not instance_type:
                        return []

                    self.update_system_info_from_instance(
                        res_system, instance_type)

                    username = res_system.getValue(
                        'disk.0.os.credentials.username')
                    if not username:
                        res_system.setValue(
                            'disk.0.os.credentials.username', 'gceuser')
                    res_system.addFeature(
                        Feature("provider.type", "=", self.type), conflict="other", missing="other")

                    res.append(res_system)

            return res

    def update_system_info_from_instance(self, system, instance_type):
        """
        Update the features of the system with the information of the instance_type
        """
        if isinstance(instance_type, NodeSize):
            system.addFeature(Feature(
                "memory.size", "=", instance_type.ram, 'M'), conflict="other", missing="other")
            if instance_type.disk:
                system.addFeature(Feature(
                    "disk.0.free_size", "=", instance_type.disk, 'G'), conflict="other", missing="other")
            if instance_type.price:
                system.addFeature(
                    Feature("price", "=", instance_type.price), conflict="me", missing="other")
            if 'guestCpus' in instance_type.extra:
                system.addFeature(Feature("cpu.count", "=", instance_type.extra[
                                  'guestCpus']), conflict="other", missing="other")

            system.addFeature(Feature(
                "instance_type", "=", instance_type.name), conflict="other", missing="other")

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
                    break

        # TODO: check that the net exist in GCE
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

        cpu = 1
        cpu_op = ">="
        if radl.getFeature('cpu.count'):
            cpu = radl.getValue('cpu.count')
            cpu_op = radl.getFeature('cpu.count').getLogOperator()

        memory = 1
        memory_op = ">1"
        if radl.getFeature('memory.size'):
            memory = radl.getFeature('memory.size').getValue('M')
            memory_op = radl.getFeature('memory.size').getLogOperator()

        res = None
        for size in sizes:
            # get the node size with the lowest price and memory (in the case
            # of the price is not set)
            if size.price is None:
                size.price = 0
            if res is None or (size.price <= res.price and size.ram <= res.ram):
                str_compare = ""
                if 'guestCpus' in size.extra and size.extra['guestCpus']:
                    str_compare = "size.extra['guestCpus'] " + cpu_op + " cpu and "
                str_compare += "size.ram " + memory_op + " memory"

                if eval(str_compare):
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

    def request_external_ip(self, radl):
        """
        Check if the user has requested for a fixed ip
        """
        system = radl.systems[0]
        n = 0
        requested_ips = []
        while system.getValue("net_interface." + str(n) + ".connection"):
            net_conn = system.getValue(
                'net_interface.' + str(n) + '.connection')
            if radl.get_network_by_id(net_conn).isPublic():
                fixed_ip = system.getValue("net_interface." + str(n) + ".ip")
                if fixed_ip:
                    requested_ips.append(fixed_ip)
            n += 1

        if requested_ips:
            self.log_info("The user requested for a fixed IP")
            if len(requested_ips) > 1:
                self.log_warn(
                    "The user has requested more than one fixed IP. Using only the first one")
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
        uri = uriparse(path)
        if uri[2]:
            region = uri[1]
            image_name = uri[2][1:]
        else:
            # If the image do not specify the zone, use the default one
            region = self.DEFAULT_ZONE
            image_name = uri[1]

        return (region, image_name)

    def get_default_net(self, driver):
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

    def create_firewall(self, inf, net_name, radl, driver):
        """
        Create a firewall for the net using the outports param
        """
        with inf._lock:
            public_net = None
            for net in radl.networks:
                if net.isPublic():
                    public_net = net

            ports = {"tcp": ["22"]}
            if public_net:
                outports = public_net.getOutPorts()
                if outports:
                    firewall_name = public_net.getValue("sg_name")
                    if not firewall_name:
                        firewall_name = "fw-im-%s" % net_name
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

                    firewall = None
                    try:
                        firewall = driver.ex_get_firewall(firewall_name)
                    except ResourceNotFoundError:
                        self.log_info("The firewall %s does not exist." % firewall_name)
                    except:
                        self.log_exception("Error trying to get FW %s." % firewall_name)

                    if firewall:
                        try:
                            firewall.allowed = allowed
                            firewall.update()
                            self.log_info("Firewall %s existing. Rules updated." % firewall_name)
                        except:
                            self.log_exception("Error updating the firewall %s." % firewall_name)
                        return

                    try:
                        driver.ex_create_firewall(firewall_name, allowed, network=net_name)
                        self.log_info("Firewall %s successfully created." % firewall_name)
                    except Exception as addex:
                        self.log_warn("Exception creating FW: " + str(addex))

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        system = radl.systems[0]
        region, image_id = self.get_image_data(
            system.getValue("disk.0.image.url"))

        if system.getValue('availability_zone'):
            region = system.getValue('availability_zone')

        driver = self.get_driver(auth_data, region)

        image = driver.ex_get_image(image_id)
        if not image:
            return [(False, "Incorrect image name") for _ in range(num_vm)]

        instance_type = self.get_instance_type(driver.list_sizes(region), system)

        if not instance_type:
            raise Exception("No compatible size found")

        name = system.getValue("instance_name")
        if not name:
            name = system.getValue("disk.0.image.name")
        if not name:
            name = "userimage"

        args = {'size': instance_type,
                'image': image,
                'external_ip': 'ephemeral',
                'location': region}

        if self.request_external_ip(radl):
            if num_vm > 1:
                raise Exception(
                    "A fixed IP cannot be specified to a set of nodes (deploy is higher than 1)")
            fixed_ip = self.request_external_ip(radl)
            args['external_ip'] = driver.ex_create_address(
                name="im-" + fixed_ip, region=region, address=fixed_ip)

        # include the SSH_KEYS
        username = system.getValue('disk.0.os.credentials.username')
        private = system.getValue('disk.0.os.credentials.private_key')
        public = system.getValue('disk.0.os.credentials.public_key')

        if not public or not private:
            # We must generate them
            self.log_info("No keys. Generating key pair.")
            (public, private) = self.keygen()
            system.setValue('disk.0.os.credentials.private_key', private)

        metadata = {}
        if private and public:
            metadata = {"sshKeys": username + ":" + public}
            self.log_info("Setting ssh for user: " + username)
            self.log_debug(metadata)

        startup_script = self.get_cloud_init_data(radl)
        if startup_script:
            metadata['startup-script'] = startup_script

        if metadata:
            args['ex_metadata'] = metadata

        net_provider_id = self.get_net_provider_id(radl)
        if net_provider_id:
            args['ex_network'] = net_provider_id
            self.create_firewall(inf, net_provider_id, radl, driver)
        else:
            net_name = self.get_default_net(driver)
            if net_name:
                args['ex_network'] = net_name
            else:
                net_name = "default"
            self.set_net_provider_id(radl, net_name)
            self.create_firewall(inf, net_name, radl, driver)

        res = []
        if num_vm > 1:
            args['number'] = num_vm
            args['base_name'] = "%s-%s" % (name.lower().replace("_", "-"), str(uuid.uuid1()))
            nodes = driver.ex_create_multiple_nodes(**args)
        else:
            args['name'] = "%s-%s" % (name.lower().replace("_", "-"), str(uuid.uuid1()))
            nodes = [driver.create_node(**args)]

        for node in nodes:
            vm = VirtualMachine(inf, node.extra['name'], self.cloud, radl,
                                requested_radl, self.cloud.getCloudConnector(inf))
            vm.info.systems[0].setValue('instance_id', str(vm.id))
            vm.info.systems[0].setValue('instance_name', str(vm.id))
            inf.add_vm(vm)
            self.log_info("Node successfully created.")

            res.append((True, vm))

        for _ in range(len(nodes), num_vm):
            res.append((False, "Error launching VM."))

        return res

    def finalize(self, vm, last, auth_data):
        try:
            node = self.get_node_with_id(vm.id, auth_data)
        except Exception as ex:
            self.log_exception("Error getting VM: %s. Err: %s." % (vm.id, str(ex)))
            return (False, "Error getting VM: %s. Err: %s." % (vm.id, str(ex)))

        if node:
            success = node.destroy()
            self.delete_disks(node)
            self.del_dns_entries(vm, auth_data)

            if last:
                self.delete_firewall(vm, node.driver)

            if not success:
                return (False, "Error destroying node: " + vm.id)

            self.log_info("VM " + str(vm.id) + " successfully destroyed")
        else:
            self.log_warn("VM " + str(vm.id) + " not found.")
        return (True, "")

    def delete_firewall(self, vm, driver):
        """
        Delete the FW
        """
        net_provider_id = self.get_net_provider_id(vm.info)
        firewall_name = "fw-im-%s" % net_provider_id

        firewall = None
        try:
            firewall = driver.ex_get_firewall(firewall_name)
        except ResourceNotFoundError:
            self.log_info("Firewall %s does not exist. Do not delete." % firewall_name)
        except:
            self.log_exception("Error trying to get FW %s." % firewall_name)

        if firewall:
            try:
                firewall.destroy()
                self.log_info("Firewall %s successfully deleted." % firewall_name)
            except:
                self.log_exception("Error trying to delete FW %s." % firewall_name)

    def delete_disks(self, node):
        """
        Delete the disks of a node

        Arguments:
           - node(:py:class:`libcloud.compute.base.Node`): node object.
        """
        all_ok = True
        for disk in node.extra['disks']:
            try:
                vol_name = os.path.basename(uriparse(disk['source'])[2])
                volume = node.driver.ex_get_volume(vol_name)
                # First try to detach the volume
                if volume:
                    success = volume.detach()
                    if not success:
                        self.log_error(
                            "Error detaching the volume: " + vol_name)
                    else:
                        # wait a bit to detach the disk
                        time.sleep(2)
                    success = volume.destroy()
                    if not success:
                        self.log_error(
                            "Error destroying the volume: " + vol_name)
            except ResourceNotFoundError:
                self.log_info("The volume: " + vol_name + " does not exists. Ignore it.")
                success = True
            except:
                self.log_exception(
                    "Error destroying the volume: " + vol_name + " from the node: " + node.id)
                success = False

            if not success:
                all_ok = False

        return all_ok

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

    def get_node_location(self, node):
        """
        Get the location of a node

        Arguments:
           - node(:py:class:`libcloud.compute.base.Node`): node object.
        Returns: a :py:class:`libcloud.compute.drivers.gce.GCEZone`
        """
        return node.extra['zone']

    def wait_volume(self, volume, state='READY', timeout=60):
        """
        Wait a volume (with the state extra parameter) to be in certain state.

        Arguments:
           - volume(:py:class:`libcloud.compute.base.StorageVolume`): volume object or boolean.
           - state(str): State to wait for (default value 'available').
           - timeout(int): Max time to wait in seconds (default value 60).
        """
        if volume:
            cont = 0
            err_states = ["FAILED"]
            while volume.extra['status'] != state and volume.extra['status'] not in err_states and cont < timeout:
                cont += 2
                time.sleep(2)
                for vol in volume.driver.list_volumes():
                    if vol.id == volume.id:
                        volume = vol
                        break
            return volume.extra['status'] == state
        else:
            return False

    def attach_volumes(self, vm, node):
        """
        Attach a the required volumes (in the RADL) to the launched node

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - node(:py:class:`libcloud.compute.base.Node`): node object.
        """
        try:
            if node.state == NodeState.RUNNING and "volumes" not in vm.__dict__.keys():
                vm.volumes = True
                cont = 1
                while (vm.info.systems[0].getValue("disk." + str(cont) + ".size") and
                        vm.info.systems[0].getValue("disk." + str(cont) + ".device")):
                    disk_size = vm.info.systems[0].getFeature(
                        "disk." + str(cont) + ".size").getValue('G')
                    disk_device = vm.info.systems[0].getValue(
                        "disk." + str(cont) + ".device")
                    self.log_info("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
                    volume_name = "im-%s" % str(uuid.uuid1())

                    location = self.get_node_location(node)
                    volume = node.driver.create_volume(
                        int(disk_size), volume_name, location=location)
                    success = self.wait_volume(volume)
                    if success:
                        self.log_info("Attach the volume ID " + str(volume.id))
                        try:
                            volume.attach(node, disk_device)
                        except:
                            self.log_exception("Error attaching the volume ID " + str(
                                volume.id) + " destroying it.")
                            volume.destroy()
                    else:
                        self.log_error("Error waiting the volume ID " + str(
                            volume.id) + " not attaching to the VM and destroying it.")
                        volume.destroy()

                    cont += 1
            return True
        except Exception:
            self.log_exception(
                "Error creating or attaching the volume to the node")
            return False

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
            if node.state == NodeState.RUNNING or node.state == NodeState.REBOOTING:
                res_state = VirtualMachine.RUNNING
            elif node.state == NodeState.PENDING:
                res_state = VirtualMachine.PENDING
            elif node.state == NodeState.TERMINATED:
                res_state = VirtualMachine.OFF
            elif node.state == NodeState.STOPPED:
                res_state = VirtualMachine.STOPPED
            else:
                res_state = VirtualMachine.UNKNOWN

            vm.state = res_state

            if 'zone' in node.extra:
                vm.info.systems[0].setValue(
                    'availability_zone', node.extra['zone'].name)

            self.update_system_info_from_instance(
                vm.info.systems[0], node.size)

            vm.setIps(node.public_ips, node.private_ips)
            self.attach_volumes(vm, node)
            self.add_dns_entries(vm, auth_data)
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
        driver = self.get_driver(auth_data)

        try:
            node = driver.ex_get_node(vm.id)
        except ResourceNotFoundError:
            return (False, "VM " + str(vm.id) + " does not exist.")
        except Exception as ex:
            self.log_exception("Error getting VM %s" % vm.id)
            return (False, "Error getting VM %s: %s" % (vm.id, str(ex)))

        try:
            driver.ex_start_node(node)
        except Exception as ex:
            self.log_exception("Error starting VM %s" % vm.id)
            return (False, "Error starting VM %s: %s" % (vm.id, str(ex)))

        return (True, "")

    def stop(self, vm, auth_data):
        driver = self.get_driver(auth_data)

        try:
            node = driver.ex_get_node(vm.id)
        except ResourceNotFoundError:
            return (False, "VM " + str(vm.id) + " does not exist.")
        except Exception as ex:
            self.log_exception("Error getting VM %s" % vm.id)
            return (False, "Error getting VM %s: %s" % (vm.id, str(ex)))

        try:
            driver.ex_stop_node(node)
        except Exception as ex:
            self.log_exception("Error stopping VM %s" % vm.id)
            return (False, "Error stopping VM %s: %s" % (vm.id, str(ex)))

        return (True, "")

    def alterVM(self, vm, radl, auth_data):
        return (False, "Not supported")
