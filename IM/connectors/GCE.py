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
import os

from CloudConnector import CloudConnector
from libcloud.compute.base import Node, NodeSize
from libcloud.compute.types import NodeState, Provider
from libcloud.compute.providers import get_driver
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from radl.radl import Feature
from libcloud.common.google import ResourceNotFoundError


class GCECloudConnector(CloudConnector):
    """
    Cloud Launcher to GCE using LibCloud
    """

    type = "GCE"
    """str with the name of the provider."""
    DEFAULT_ZONE = "us-central1"

    def __init__(self, cloud_info):
        self.auth = None
        self.driver = None
        CloudConnector.__init__(self, cloud_info)

    def get_driver(self, auth_data):
        """
        Get the driver from the auth data

        Arguments:
            - auth(Authentication): parsed authentication tokens.

        Returns: a :py:class:`libcloud.compute.base.NodeDriver` or None in case of error
        """
        auths = auth_data.getAuthInfo(self.type)
        if not auths:
            raise Exception("No auth data has been specified to GCE.")
        else:
            auth = auths[0]

        if self.driver and self.auth.compare(auth_data, self.type):
            return self.driver
        else:
            self.auth = auth_data

            if 'username' in auth and 'password' in auth and 'project' in auth:
                cls = get_driver(Provider.GCE)
                # Patch to solve some client problems with \\n
                auth['password'] = auth['password'].replace('\\n', '\n')
                lines = len(auth['password'].replace(" ", "").split())
                if lines < 2:
                    raise Exception("The certificate provided to the GCE plugin has an incorrect format."
                                    " Check that it has more than one line.")

                driver = cls(auth['username'], auth[
                             'password'], project=auth['project'])

                self.driver = driver
                return driver
            else:
                self.logger.error(
                    "No correct auth data has been specified to GCE: username, password and project")
                self.logger.debug(auth)
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

        memory = 1
        memory_op = ">1"
        if radl.getFeature('memory.size'):
            memory = radl.getFeature('memory.size').getValue('M')
            memory_op = radl.getFeature('memory.size').getLogOperator()

        res = None
        for size in sizes:
            # get the node size with the lowest price and memory (in the case
            # of the price is not set)
            if res is None or (size.price <= res.price and size.ram <= res.ram):
                str_compare = "size.ram " + memory_op + " memory"
                if eval(str_compare):
                    if not instance_type_name or size.name == instance_type_name:
                        res = size

        if res is None:
            self.logger.error("No compatible size found")

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
            self.logger.debug("The user requested for a fixed IP")
            if len(requested_ips) > 1:
                self.logger.warn(
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

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        driver = self.get_driver(auth_data)

        system = radl.systems[0]
        region, image_id = self.get_image_data(
            system.getValue("disk.0.image.url"))

        image = driver.ex_get_image(image_id)
        if not image:
            return [(False, "Incorrect image name") for _ in range(num_vm)]

        if system.getValue('availability_zone'):
            region = system.getValue('availability_zone')

        instance_type = self.get_instance_type(
            driver.list_sizes(region), system)

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
            if num_vm:
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
            self.logger.debug("No keys. Generating key pair.")
            (public, private) = self.keygen()
            system.setValue('disk.0.os.credentials.private_key', private)

        metadata = {}
        if private and public:
            metadata = {"sshKeys": username + ":" + public}
            self.logger.debug("Setting ssh for user: " + username)
            self.logger.debug(metadata)

        startup_script = self.get_cloud_init_data(radl)
        if startup_script:
            metadata['startup-script'] = startup_script

        if metadata:
            args['ex_metadata'] = metadata

        net_provider_id = self.get_net_provider_id(radl)
        if net_provider_id:
            args['ex_network'] = net_provider_id
        else:
            net_name = self.get_default_net(driver)
            if net_name:
                args['ex_network'] = net_name
                self.set_net_provider_id(radl, net_name)
            else:
                self.set_net_provider_id(radl, "default")

        res = []
        if num_vm > 1:
            args['number'] = num_vm
            args[
                'base_name'] = "%s-%s" % (name.lower().replace("_", "-"), int(time.time() * 100))
            nodes = driver.ex_create_multiple_nodes(**args)
        else:
            args[
                'name'] = "%s-%s" % (name.lower().replace("_", "-"), int(time.time() * 100))
            nodes = [driver.create_node(**args)]

        for node in nodes:
            vm = VirtualMachine(inf, node.extra[
                                'name'], self.cloud, radl, requested_radl, self.cloud.getCloudConnector())
            vm.info.systems[0].setValue('instance_id', str(vm.id))
            vm.info.systems[0].setValue('instance_name', str(vm.id))
            self.logger.debug("Node successfully created.")
            res.append((True, vm))

        for _ in range(len(nodes), num_vm):
            res.append((False, "Error launching VM."))

        return res

    def finalize(self, vm, auth_data):
        try:
            node = self.get_node_with_id(vm.id, auth_data)
        except:
            self.logger.exception("Error getting VM: %s" % vm.id)
            return (False, "Error getting VM: %s" % vm.id)

        if node:
            success = node.destroy()
            self.delete_disks(node)

            if not success:
                return (False, "Error destroying node: " + vm.id)

            self.logger.debug("VM " + str(vm.id) + " successfully destroyed")
        else:
            self.logger.warn("VM " + str(vm.id) + " not found.")
        return (True, "")

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
                        self.logger.error(
                            "Error detaching the volume: " + vol_name)
                    else:
                        # wait a bit to detach the disk
                        time.sleep(2)
                    success = volume.destroy()
                    if not success:
                        self.logger.error(
                            "Error destroying the volume: " + vol_name)
            except ResourceNotFoundError:
                self.logger.debug("The volume: " + vol_name +
                                  " does not exists. Ignore it.")
                success = True
            except:
                self.logger.exception(
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
            self.logger.warn("VM " + str(node_id) + " does not exist.")

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
                cont = 1
                while (vm.info.systems[0].getValue("disk." + str(cont) + ".size") and
                        vm.info.systems[0].getValue("disk." + str(cont) + ".device")):
                    disk_size = vm.info.systems[0].getFeature(
                        "disk." + str(cont) + ".size").getValue('G')
                    disk_device = vm.info.systems[0].getValue(
                        "disk." + str(cont) + ".device")
                    self.logger.debug(
                        "Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
                    volume_name = "im-%d" % int(time.time() * 100.0)

                    location = self.get_node_location(node)
                    volume = node.driver.create_volume(
                        int(disk_size), volume_name, location=location)
                    success = self.wait_volume(volume)
                    if success:
                        self.logger.debug(
                            "Attach the volume ID " + str(volume.id))
                        volume.attach(node, disk_device)
                    else:
                        self.logger.error("Error waiting the volume ID " + str(
                            volume.id) + " not attaching to the VM and destroying it.")
                        volume.destroy()

                    cont += 1
            return True
        except Exception:
            self.logger.exception(
                "Error creating or attaching the volume to the node")
            return False

    def updateVMInfo(self, vm, auth_data):
        driver = self.get_driver(auth_data)

        node = None
        try:
            node = driver.ex_get_node(vm.id)
        except ResourceNotFoundError:
            self.logger.warn("VM " + str(vm.id) + " does not exist.")
        except Exception, ex:
            self.logger.exception("Error getting VM info: %s" % vm.id)
            return (False, "Error getting VM info: %s. %s" % (vm.id, str(ex)))

        if node:
            if node.state == NodeState.RUNNING:
                res_state = VirtualMachine.RUNNING
            elif node.state == NodeState.REBOOTING:
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
        else:
            vm.state = VirtualMachine.OFF

        return (True, vm)

    def start(self, vm, auth_data):
        driver = self.get_driver(auth_data)

        try:
            node = driver.ex_get_node(vm.id)
        except ResourceNotFoundError:
            return (False, "VM " + str(vm.id) + " does not exist.")
        except Exception, ex:
            self.logger.exception("Error getting VM %s" % vm.id)
            return (False, "Error getting VM %s: %s" % (vm.id, str(ex)))

        try:
            driver.ex_start_node(node)
        except Exception, ex:
            self.logger.exception("Error starting VM %s" % vm.id)
            return (False, "Error starting VM %s: %s" % (vm.id, str(ex)))

        return (True, "")

    def stop(self, vm, auth_data):
        driver = self.get_driver(auth_data)

        try:
            node = driver.ex_get_node(vm.id)
        except ResourceNotFoundError:
            return (False, "VM " + str(vm.id) + " does not exist.")
        except Exception, ex:
            self.logger.exception("Error getting VM %s" % vm.id)
            return (False, "Error getting VM %s: %s" % (vm.id, str(ex)))

        try:
            driver.ex_stop_node(node)
        except Exception, ex:
            self.logger.exception("Error stopping VM %s" % vm.id)
            return (False, "Error stopping VM %s: %s" % (vm.id, str(ex)))

        return (True, "")

    def alterVM(self, vm, radl, auth_data):
        return (False, "Not supported")
