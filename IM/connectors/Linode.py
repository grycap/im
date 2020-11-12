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

    def __init__(self, cloud_info, inf):
        self.driver = None
        self.auth = None
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
            raise Exception("No auth data has been specified to Linode.")
        else:
            auth = auths[0]

        if self.driver and self.auth.compare(auth_data, self.type, self.cloud.server):
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

    def get_location(self, driver, loc):
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

        args

        if system.getValue('availability_zone'):
            location = self.get_location(driver, system.getValue('availability_zone'))
            if location:
                args['location'] = location
            else:
                raise Exception('Invalid Linode datacenter specified: %s' % system.getValue('availability_zone'))
        else:
            args['location'] = NodeLocation(self.DEFAULT_LOCATION, None, None, None, driver)

        public_key = system.getValue("disk.0.os.credentials.public_key")
        private_key = system.getValue('disk.0.os.credentials.private_key')

        if not public_key:
            # We must generate them
            (public_key, private_key) = self.keygen()
            system.setValue('disk.0.os.credentials.private_key', private_key)

        args['ex_authorized_keys'] = [public_key]

        password = system.getValue('disk.0.os.credentials.new.password')
        if not password:
            password = system.getValue('disk.0.os.credentials.password')
        if not password:
            password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
        args['root_pass'] = password

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
                self.log_debug("Node successfully created.")
                vm.destroy = False
                inf.add_vm(vm)
                res.append((True, vm))
            else:
                res.append((False, msg))

            i += 1

        return res

    def get_size(self, node):
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

    def get_node_volumes(self, node):
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

    def start(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            success = node.start_node()
            if success:
                return (True, "")
            else:
                return (False, "Error in stop operation")
        else:
            return (False, "VM not found with id: " + vm.id)

    def stop(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            success = node.stop_node()
            if success:
                return (True, "")
            else:
                return (False, "Error in stop operation")
        else:
            return (False, "VM not found with id: " + vm.id)

    def reboot(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            success = node.reboot_node()
            if success:
                return (True, "")
            else:
                return (False, "Error in reboot operation")
        else:
            return (False, "VM not found with id: " + vm.id)

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
                    disk_size = vm.info.systems[0].getFeature("disk." + str(cont) + ".size").getValue('G')
                    if disk_size < 10:
                        disk_size = 10
                    self.log_debug("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
                    volume_name = ("im-%s" % str(uuid.uuid1()))[:32]
                    if volume_name[-1:] == "-":
                        volume_name = volume_name[:-1]
                    volume = node.driver.create_volume(volume_name, int(disk_size), node=node)
                    if 'filesystem_path' in volume.extra and volume.extra['filesystem_path']:
                        vm.info.systems[0].setValue("disk." + str(cont) + ".device", volume.extra['filesystem_path'])
                    cont += 1
            return True
        except Exception:
            self.log_exception("Error creating or attaching the volume to the node")
            return False
