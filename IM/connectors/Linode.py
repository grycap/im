# IM - Infrastructure Manager
# Copyright (C) 2020 - GRyCAP - Universitat Politecnica de Valencia
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
import random
import string
import time
import os.path

try:
    from libcloud.compute.base import NodeImage, NodeLocation
    from libcloud.compute.types import Provider, NodeState
    from libcloud.compute.providers import get_driver
except Exception as ex:
    print("WARN: Linode library not correctly installed. LinodeCloudConnector will not work!.")
    print(ex)

from .LibCloud import LibCloudCloudConnector
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from radl.radl import Feature


class LinodeCloudConnector(LibCloudCloudConnector):
    """
    Cloud Launcher to the Linode Cloud
    """

    type = "Linode"
    """str with the name of the provider."""

    DEFAULT_USER = 'root'
    """ default user to SSH access the VM """
    DEFAULT_LOCATION = 'us-central'
    """ Linode default location """

    VM_STATE_MAP = {
        NodeState.RUNNING: VirtualMachine.RUNNING,
        NodeState.REBOOTING: VirtualMachine.RUNNING,
        NodeState.PENDING: VirtualMachine.PENDING,
        NodeState.STARTING: VirtualMachine.PENDING,
        NodeState.PENDING: VirtualMachine.PENDING,
        NodeState.TERMINATED: VirtualMachine.OFF,
        NodeState.STOPPED: VirtualMachine.STOPPED,
        NodeState.STOPPING: VirtualMachine.RUNNING,
        NodeState.MIGRATING: VirtualMachine.RUNNING,
        NodeState.UPDATING: VirtualMachine.RUNNING,
        NodeState.ERROR: VirtualMachine.FAILED,
        NodeState.REBOOTING: VirtualMachine.RUNNING,
        NodeState.RECONFIGURING: VirtualMachine.PENDING,
        NodeState.UNKNOWN: VirtualMachine.UNKNOWN
    }
    """State map"""

    def __init__(self, cloud_info, inf):
        self.auth = None
        LibCloudCloudConnector.__init__(self, cloud_info, inf)

    def get_driver(self, auth_data):
        """
        Get the driver from the auth data

        Arguments:
                - auth(Authentication): parsed authentication tokens.

        Returns: a :py:class:`libcloud.compute.base.NodeDriver` or None in case of error
        """
        auths = auth_data.getAuthInfo(self.type)
        if not auths:
            raise Exception("No auth data has been specified to Linode.")
        else:
            auth = auths[0]

        if self.driver and self.auth.compare(auth_data, self.type):
            return self.driver
        else:
            self.auth = auth_data
            if 'username' in auth:
                apikey = auth['username']

                Driver = get_driver(Provider.LINODE)
                driver = Driver(key=apikey)
                self.driver = driver

                return driver
            else:
                self.log_error("Incorrect auth data")
                return None

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
        if gpu:
            gpu_op_str = radl.getFeature('gpu.count').getLogOperator()
            gpu_op = self.OPERATORSMAP.get(gpu_op_str)

        # get the node size with the lowest price, vcpus, memory and disk
        sizes.sort(key=lambda x: (x.price, x.extra['vcpus'], x.ram, x.disk))
        for size in sizes:
            comparison = cpu_op(size.extra['vcpus'], cpu)
            comparison = comparison and memory_op(size.ram, memory)
            comparison = comparison and disk_free_op(size.disk, disk_free)

            if gpu:
                comparison = (comparison and 'gpus' in size.extra and
                              size.extra['gpus'] and gpu_op(size.extra['gpus'], gpu))

            if comparison:
                if not instance_type_name or size.id == instance_type_name:
                    return size

        self.log_error("No compatible size found")
        return None

    def update_system_info_from_instance(self, system, instance_type):
        """
        Update the features of the system with the information of the instance_type
        """
        if instance_type:
            LibCloudCloudConnector.update_system_info_from_instance(system, instance_type)
            system.addFeature(Feature("instance_type", "=", instance_type.id),
                              conflict="other", missing="other")
            if 'vcpus' in instance_type.extra and instance_type.extra['vcpus']:
                system.addFeature(Feature("cpu.count", "=", instance_type.extra['vcpus']),
                                  conflict="me", missing="other")

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]

        if protocol == "lin":
            driver = self.get_driver(auth_data)

            res_system = radl_system.clone()
            instance_type = self.get_instance_type(driver.list_sizes(), res_system)
            self.update_system_info_from_instance(res_system, instance_type)

            res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)

            return res_system
        else:
            return None

    def get_node_with_id(self, node_id, auth_data):
        """
        Get the node with the specified ID

        Arguments:
           - node_id(str): ID of the node to get
           - auth(Authentication): parsed authentication tokens.
        Returns: a :py:class:`libcloud.compute.base.Node` with the node info
        """
        driver = self.get_driver(auth_data)
        return driver.ex_get_node(node_id)

    @staticmethod
    def get_location(driver, loc):
        """Return a NodeLocation"""
        for location in driver.list_locations():
            if loc == location.id or loc.lower() in location.name.lower():
                return location
        return None

    @staticmethod
    def get_image_id(path):
        """
        Get the ID of the image to use from the location of the VMI

        Arguments:
           - path(str): URL with the location of the VMI
        Returns: a str with the ID
        """
        url = urlparse(path)
        return "%s%s" % (url[1], url[2])

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        driver = self.get_driver(auth_data)

        system = radl.systems[0]
        image_id = self.get_image_id(system.getValue("disk.0.image.url"))
        image = NodeImage(id=image_id, name=None, driver=driver)

        instance_type = self.get_instance_type(driver.list_sizes(), system)

        instance_name = self.gen_instance_name(system)[:32]
        if instance_name[-1:] == "-":
            instance_name = instance_name[:-1]

        args = {'size': instance_type,
                'image': image,
                'name': instance_name}

        if system.getValue('availability_zone'):
            location = self.get_location(driver, system.getValue('availability_zone'))
            if location:
                args['location'] = location
            else:
                raise Exception('Invalid Linode datacenter specified: %s' % system.getValue('availability_zone'))
        else:
            args['location'] = NodeLocation(self.DEFAULT_LOCATION, '', '', driver)

        public_key = system.getValue("disk.0.os.credentials.public_key")
        private_key = system.getValue('disk.0.os.credentials.private_key')

        if not public_key:
            # We must generate them
            (public_key, private_key) = self.keygen()
            system.setValue('disk.0.os.credentials.private_key', private_key)

        args['ex_authorized_keys'] = [public_key]

        args['root_pass'] = system.getValue('disk.0.os.credentials.new.password')
        if not args['root_pass']:
            args['root_pass'] = system.getValue('disk.0.os.credentials.password')
        if not args['root_pass']:
            args['root_pass'] = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))

        user = system.getValue('disk.0.os.credentials.username')
        if not user:
            user = self.DEFAULT_USER
            system.setValue('disk.0.os.credentials.username', user)

        args['ex_tags'] = self.get_instance_tags(system, auth_data, inf)

        res = []
        i = 0
        while i < num_vm:
            self.log_debug("Creating node")

            vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl, self.cloud.getCloudConnector(inf))
            vm.destroy = True
            inf.add_vm(vm)

            msg = "Error creating the node"
            try:
                node = driver.create_node(**args)
            except Exception as ex:
                msg += ": %s" % str(ex)
                self.log_exception("Error creating node.")
                node = None

            if node:
                vm.id = node.id
                vm.info.systems[0].setValue('instance_id', str(node.id))
                vm.info.systems[0].setValue('instance_name', str(node.name))
                self.log_debug("Node %s successfully created." % node.id)
                vm.destroy = False
                inf.add_vm(vm)
                res.append((True, vm))
            else:
                res.append((False, msg))

            i += 1

        return res

    @staticmethod
    def get_size(node):
        """Get a NodeSize object"""
        for size in node.driver.list_sizes():
            if size.id == node.size:
                return size
        return None

    def updateVMInfo(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            vm.state = self.VM_STATE_MAP.get(node.state, VirtualMachine.UNKNOWN)

            if node.size:
                self.update_system_info_from_instance(vm.info.systems[0], self.get_size(node))
            else:
                self.log_debug("VM " + str(vm.id) + " has no node.size info. Not updating system info.")

            self.setIPsFromInstance(vm, node)
            self.attach_volumes(vm, node)
        else:
            self.log_warn("Error updating the instance %s. VM not found." % vm.id)
            return (False, "Error updating the instance %s. VM not found." % vm.id)

        return (True, vm)

    @staticmethod
    def get_node_volumes(node):
        volumes = []
        for volume in node.driver.list_volumes():
            if str(volume.extra['linode_id']) == str(node.id):
                volumes.append(volume)
        return volumes

    def finalize(self, vm, last, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)

        if node:
            volumes = self.get_node_volumes(node)

            for volume in volumes:
                self.log_debug("Detaching volume id: %s" % volume.id)
                volume.detach()
                volume.extra['linode_id'] = None

            for volume in volumes:
                self.log_debug("Deleting volume id: %s" % volume.id)
                cont = 0
                deleted = False
                while not deleted and cont < 30:
                    try:
                        volume.destroy()
                        deleted = True
                        self.log_debug("volume id: %s, successfully deleted." % volume.id)
                    except Exception as ex:
                        self.log_warn("Error deleting volume id: %s. %s" % (volume.id, str(ex)))
                    cont += 2
                    time.sleep(2)
                if not deleted:
                    return (False, "Error deleting volumes.")

            success = node.destroy()

            if not success:
                return (False, "Error destroying node: " + vm.id)

            self.log_debug("VM " + str(vm.id) + " successfully destroyed")
        else:
            self.log_warn("VM " + str(vm.id) + " not found.")

        return (True, "")

    def create_volume(self, node, system, orig_system, cont):
        disk_size = system.getFeature("disk." + str(cont) + ".size").getValue('G')
        # The minimum size is 10 GB
        if disk_size < 10:
            disk_size = 10
            orig_system.setValue("disk." + str(cont) + ".size", 10, "g")
        self.log_debug("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
        volume_name = ("im-%s" % str(uuid.uuid1()))[:32]
        if volume_name[-1:] == "-":
            volume_name = volume_name[:-1]
        volume = node.driver.create_volume(volume_name, int(disk_size), node=node)
        if 'filesystem_path' in volume.extra and volume.extra['filesystem_path']:
            device = os.path.basename(volume.extra['filesystem_path'])
            orig_system.setValue("disk." + str(cont) + ".device", device)
        return volume

    def attach_volumes(self, vm, node):
        """
        Attach a the required volumes (in the RADL) to the launched node

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - node(:py:class:`libcloud.compute.base.Node`): node object.
        """
        try:
            if node.state == NodeState.RUNNING and "volumes" not in vm.__dict__.keys():
                volumes = self.get_node_volumes(node)
                if volumes:
                    return True
                cont = 1
                while vm.info.systems[0].getValue("disk." + str(cont) + ".size"):
                    self.create_volume(node, vm.info.systems[0], vm.info.systems[0], cont)
                    cont += 1
            return True
        except Exception:
            self.log_exception("Error creating or attaching the volume to the node")
            return False

    def alterVM(self, vm, radl, auth_data):
        success, msg = self.resizeVM(vm, radl, auth_data)
        if not success:
            return (success, msg)

        success, msg = self.add_new_disks(vm, radl, auth_data)
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
                if node.size != instance_type.id:
                    try:
                        self.log_debug("Resizing node: %s" % node.id)
                        success = node.driver.ex_resize_node(node, instance_type)
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
                    self.create_volume(node, system, orig_system, cont)
                    cont += 1
                return (True, "")
            except Exception as ex:
                self.log_exception("Error connecting with Linode")
                return (False, "Error connecting with Linode: " + str(ex))

    def list_images(self, auth_data, filters=None):
        driver = self.get_driver(auth_data)

        images = []
        for image in driver.list_images():
            images.append({"uri": "lin://%s" % image.id, "name": image.name})
        return images
