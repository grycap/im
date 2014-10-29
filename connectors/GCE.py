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
from libcloud.compute.types import NodeState, Provider
from libcloud.compute.providers import get_driver
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from IM.radl.radl import Feature

class GCECloudConnector(CloudConnector):
    """
    Cloud Launcher to GCE using LibCloud
    """
    
    type = "GCE"
    """str with the name of the provider."""
    
    def get_driver(self, auth_data):
        """
        Get the driver from the auth data

        Arguments:
            - auth(Authentication): parsed authentication tokens.
        
        Returns: a :py:class:`libcloud.compute.base.NodeDriver` or None in case of error
        """
        auth = auth_data.getAuthInfo(self.type)
        
        if auth and 'username' in auth[0] and 'password' in auth[0] and 'project' in auth[0]:            
            cls = get_driver(Provider.GCE)
            driver = cls(auth[0]['username'], auth[0]['password'], project=auth[0]['project']) 
    
            return driver
        else:
            self.logger.error("No correct auth data has been specified to GCE: username, password and project")
            return None

    
    def concreteSystem(self, radl_system, auth_data):
        if radl_system.getValue("disk.0.image.url"):
            url = uriparse(radl_system.getValue("disk.0.image.url"))
            protocol = url[0]
            if protocol == "gce":
                driver = self.get_driver(auth_data)
                
                res_system = radl_system.clone()
                
                if res_system.getValue('availability_zone'):
                    region = res_system.getValue('availability_zone')
                else:
                    region, _ = self.get_image_data(res_system.getValue("disk.0.image.url"))
                    region = res_system.setValue('availability_zone', region)
                
                instance_type = self.get_instance_type(driver.list_sizes(region), res_system)
                
                username = res_system.getValue('disk.0.os.credentials.username')
                if not username:
                    res_system.setValue('disk.0.os.credentials.username','root')
                res_system.addFeature(Feature("memory.size", "=", instance_type.ram, 'M'), conflict="other", missing="other")
                if instance_type.disk:
                    res_system.addFeature(Feature("disk.0.free_size", "=", instance_type.disk , 'G'), conflict="other", missing="other")
                if instance_type.price:
                    res_system.addFeature(Feature("price", "=", instance_type.price), conflict="me", missing="other")
                
                res_system.addFeature(Feature("instance_type", "=", instance_type.name), conflict="other", missing="other")
                res_system.addFeature(Feature("provider.type", "=", self.type), conflict="other", missing="other")                

                return [res_system]
            else:
                return []
        else:
            return [radl_system.clone()]

    def get_instance_type(self, sizes, radl):
        """
        Get the name of the instance type to launch to LibCloud

        Arguments:
           - size(list of :py:class: `libcloud.compute.base.NodeSize`): List of sizes on a provider
           - radl(str): RADL document with the requirements of the VM to get the instance type
        Returns: a :py:class:`libcloud.compute.base.NodeSize` with the instance type to launch    
        """
        instance_type_name = radl.getValue('instance_type')
        
        memory = radl.getFeature('memory.size').getValue('M')
        memory_op = radl.getFeature('memory.size').getLogOperator()

        res = None
        for size in sizes:
            # get the node size with the lowest price and memory (in the case of the price is not set)
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
            net_conn = system.getValue('net_interface.' + str(n) + '.connection')
            if radl.get_network_by_id(net_conn).isPublic():
                fixed_ip = system.getValue("net_interface." + str(n) + ".ip")
                if fixed_ip:
                    requested_ips.append(fixed_ip)
            n += 1
        
        if requested_ips:
            self.logger.debug("The user requested for a fixed IP")
            if len(requested_ips) > 1:
                self.logger.warn("The user has requested more than one fixed IP. Using only the first one")                
            return requested_ips[0]
        else:
            return None

    # el path sera algo asi: gce://us-central1/debian-7
    def get_image_data(self, path):
        """
        Get the region and the image name from an URL of a VMI

        Arguments:
           - path(str): URL of a VMI (some like this: gce://us-central1/debian-7)
        Returns: a tuple (region, image_name) with the region and the AMI ID    
        """
        region = uriparse(path)[1]
        image_name = uriparse(path)[2][1:]
        
        return (region, image_name)

    def launch(self, inf, vm_id, radl, requested_radl, num_vm, auth_data):
        driver = self.get_driver(auth_data)

        system = radl.systems[0]
        region, image_id = self.get_image_data(system.getValue("disk.0.image.url"))

        image = driver.ex_get_image(image_id)
        if not image:
            return [(False, "Incorrect image name") for i in range(num_vm)]

        if system.getValue('availability_zone'):
            region = system.getValue('availability_zone')

        instance_type = self.get_instance_type(driver.list_sizes(region), system)
        
        name = system.getValue("disk.0.image.name")
        if not name:
            name = "userimage"
        
        args = {'size': instance_type,
                'image': image,
                'external_ip': 'ephemeral',
                'location': region,
                'name': "%s-%s" % (name.lower().replace("_","-"), int(time.time()*100))}

        if self.request_external_ip(radl):
            fixed_ip = self.request_external_ip(radl)
            args['external_ip'] = driver.ex_create_address(name="im-" + fixed_ip, region=region, address=fixed_ip)

        # include the SSH_KEYS
        username = system.getValue('disk.0.os.credentials.username')
        private = system.getValue('disk.0.os.credentials.private_key')
        public = system.getValue('disk.0.os.credentials.public_key')
        if private and public:
            #metadata = {"sshKeys": "root:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9i2KyVMk3Cz/rm9pCoIioFm/gMT0EvhobP5PFZnva+WxFeiH41j4shAim/+reyyUgC+hDpo9Pf6ZzvbOOCaWoGzgdEYtItixKmxE3wWoTUXZW4Lwks69+aKS2BXnOPm5z7BV6F72GVc9r7mlq/Xpd9e2EcDa5WyA6ilnBTVnMgWHOgEjQ+AEChswDELF3DSkXmLtQsWup+kVQmktwmC6+4sPztALwhUJiK1jJ+wshPCuJw0nY7t4Keybm2b/A3nLxDlLbJZay0kV70nlwAYSmTa+HcUkbPqgL0UNVlgW2/rdSNo8RSmoF1pFdXb+zii3YCFUnAC2l2FDmxUhRp0bT root@host"}
            metadata = {"sshKeys": username + ":" + public}
            args['ex_metadata'] = metadata
            self.logger.debug("Setting ssh for user: " + username)

        res = []
        i = 0
        while i < num_vm:
            self.logger.debug("Creating node")

            node = driver.create_node(**args)
            
            if node:
                vm = VirtualMachine(inf, vm_id, node.extra['name'], self.cloud, radl, requested_radl)
                self.logger.debug("Node successfully created.")
                res.append((True, vm))
            else:
                res.append((False, "Error creating the node"))
                
            i += 1

        return res
    
    def finalize(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        
        if node:
            success = node.destroy()

            # Delete the volumes
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
                success = volume.destroy()
                if not success:
                    self.logger.error("Error destroying the volume: " + str(disk.id))
            except:
                self.logger.exception("Error destroying the volume: " + str(disk.id) + " from the node: " + node.id)
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
        return driver.ex_get_node(node_id)

    def get_node_location(self, node):
        """
        Get the location of a node

        Arguments:
           - node(:py:class:`libcloud.compute.base.Node`): node object.    
        Returns: a :py:class:`libcloud.compute.drivers.gce.GCEZone`
        """
        return node.extra['zone'] 
    
    def wait_volume(self, volume, state = 'READY', timeout=60):
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
            if node.state == NodeState.RUNNING and not "volumes" in vm.__dict__.keys():
                cont = 1
                while vm.info.systems[0].getValue("disk." + str(cont) + ".size") and vm.info.systems[0].getValue("disk." + str(cont) + ".device"):
                    disk_size = vm.info.systems[0].getFeature("disk." + str(cont) + ".size").getValue('G')
                    disk_device = vm.info.systems[0].getValue("disk." + str(cont) + ".device")
                    self.logger.debug("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
                    volume_name = "im-%d" % int(time.time()*100.0)
                    
                    location = self.get_node_location(node)
                    volume = node.driver.create_volume(int(disk_size), volume_name, location = location)
                    success = self.wait_volume(volume)
                    if success:
                        self.logger.debug("Attach the volume ID " + str(volume.id))
                        volume.attach(node, disk_device)
                    else:
                        self.logger.error("Error waiting the volume ID " + str(volume.id) + " not attaching to the VM and destroying it.")
                        volume.destroy()
                    
                    cont += 1
            return True
        except Exception:
            self.logger.exception("Error creating or attaching the volume to the node")
            return False
   
    def updateVMInfo(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
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
            
            vm.setIps(node.public_ips, node.private_ips)
            self.attach_volumes(vm,node)
        else:
            vm.state = VirtualMachine.OFF
        
        return (True, vm)
        
    def start(self, vm, auth_data):
        return (False, "Not supported")

    def stop(self, vm, auth_data):
        return (False, "Not supported")
    
    def alterVM(self, vm, radl, auth_data):
        return (False, "Not supported")