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

try:
    from libcloud.compute.base import NodeImage, NodeLocation
    from libcloud.compute.types import Provider, NodeState
    from libcloud.compute.providers import get_driver
except Exception as ex:
    print("WARN: CloudStack library not correctly installed. CloudStackCloudConnector will not work!.")
    print(ex)

from .LibCloud import LibCloudCloudConnector
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from radl.radl import Feature


class CloudStackCloudConnector(LibCloudCloudConnector):
    """
    Cloud Launcher to the CloudStack library
    """

    type = "CloudStack"
    """str with the name of the provider."""

    DEFAULT_USER = 'cloudadm'
    """ default user to SSH access the VM """

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
            raise Exception("No auth data has been specified to CloudStack.")
        else:
            auth = auths[0]

        if self.driver and self.auth.compare(auth_data, self.type, self.cloud.server):
            return self.driver
        else:
            self.auth = auth_data
            if 'username' in auth and 'password' in auth:
                apikey = auth['username']
                secretkey = auth['password']

                protocol = self.cloud.protocol
                if not protocol:
                    protocol = "http"
                port = "" if self.cloud.port == -1 else ":" % self.cloud.port
                url = protocol + "://" + self.cloud.server + port + self.cloud.path

                Driver = get_driver(Provider.CLOUDSTACK)
                driver = Driver(key=apikey, secret=secretkey, url=url)
                self.driver = driver

                return driver
            else:
                self.log_error("Incorrect auth data")
                return None

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]
        src_host = url[1].split(':')[0]

        if protocol == "cst" and self.cloud.server == src_host:
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

    def update_system_info_from_instance(self, system, instance_type):
        """
        Update the features of the system with the information of the instance_type
        """
        if instance_type:
            LibCloudCloudConnector.update_system_info_from_instance(system, instance_type)
            if 'cpu' in instance_type.extra:
                system.addFeature(Feature("cpu.count", "=", instance_type.extra['cpu']),
                                  conflict="other", missing="other")

    def _get_security_group(self, driver, sg_name):
        try:
            sg = None
            for elem in driver.ex_list_security_groups():
                if elem['name'] == sg_name:
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
                    sg = driver.ex_create_security_group(sg_name, description="Security group created by the IM")
                res.append(sg['name'])

            try:
                # open always SSH port
                driver.ex_authorize_security_group_ingress(securitygroupname=sg_name,
                                                           protocol='tcp',
                                                           startport=22,
                                                           cidrlist='0.0.0.0/0')

                # open all the ports for the VMs in the security group
#                 usersecuritygrouplist = [{'group': sg['name'], 'account': sg['account'],}]
#                 success = driver.ex_authorize_security_group_ingress(securitygroupname=sg_name,
#                                                      protocol='tcp',
#                                                      startport=1,
#                                                      endport=65535,
#                                                      cidrlist=None,
#                                                      usersecuritygrouplist=usersecuritygrouplist)
#                 success = driver.ex_authorize_security_group_ingress(securitygroupname=sg_name,
#                                                      protocol='udp',
#                                                      startport=1,
#                                                      endport=65535,
#                                                      cidrlist=None,
#                                                      usersecuritygrouplist=usersecuritygrouplist)

            except Exception as addex:
                self.log_warn("Exception adding SG rules. Probably the rules exists:" + str(addex))

            outports = network.getOutPorts()
            if outports:
                for op in outports:
                    if op.is_range():
                        try:
                            driver.ex_authorize_security_group_ingress(securitygroupname=sg_name,
                                                                       protocol=op.get_protocol(),
                                                                       startport=op.get_port_init(),
                                                                       endport=op.get_port_end(),
                                                                       cidrlist='0.0.0.0/0')
                        except Exception as ex:
                            self.log_warn("Exception adding SG rules: " + str(ex))
                    else:
                        if op.get_remote_port() != 22:
                            try:
                                driver.ex_authorize_security_group_ingress(securitygroupname=sg_name,
                                                                           protocol=op.get_protocol(),
                                                                           startport=op.get_remote_port(),
                                                                           cidrlist='0.0.0.0/0')
                            except Exception as ex:
                                self.log_warn("Exception adding SG rules: " + str(ex))

            i += 1

        return res

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        driver = self.get_driver(auth_data)

        system = radl.systems[0]
        image_id = self.get_image_id(system.getValue("disk.0.image.url"))
        image = NodeImage(id=image_id, name=None, driver=driver)

        instance_type = self.get_instance_type(driver.list_sizes(), system)

        sgs = self.create_security_groups(driver, inf, radl)

        args = {'size': instance_type,
                'image': image,
                'ex_security_groups': sgs,
                'ex_start_vm': True,
                'name': self.gen_instance_name(system)}

        if system.getValue('availability_zone'):
            args['location'] = system.getValue('availability_zone')

        keypair = None
        public_key = system.getValue("disk.0.os.credentials.public_key")

        if public_key and public_key.find('-----BEGIN CERTIFICATE-----') == -1:
            keypair = driver.get_key_pair(public_key)
            public_key = None
            if keypair:
                system.setUserKeyCredentials(system.getCredentials().username, None, keypair.private_key)
            else:
                args["ex_keyname"] = keypair.name
        else:
            public_key, private_key = self.keygen()
            system.setUserKeyCredentials(system.getCredentials().username, None, private_key)

        user = system.getValue('disk.0.os.credentials.username')
        if not user:
            user = self.DEFAULT_USER
            system.setValue('disk.0.os.credentials.username', user)

        tags = self.get_instance_tags(system, auth_data, inf)

        res = []
        i = 0
        while i < num_vm:
            self.log_debug("Creating node")

            vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl, self.cloud.getCloudConnector(inf))
            vm.destroy = True
            inf.add_vm(vm)
            cloud_init = self.get_cloud_init_data(radl, vm, public_key, user)

            if cloud_init:
                args['ex_userdata'] = cloud_init

            msg = "Error creating the node"
            try:
                node = driver.create_node(**args)
            except Exception as ex:
                msg += ": %s" % str(ex)
                self.log_exception("Error creating node.")
                node = None

            if node:
                if tags:
                    try:
                        driver.ex_create_tags([node.id], tags)
                    except Exception:
                        self.log_exception("Error adding tags to node %s." % node.id)

                vm.id = node.id
                vm.info.systems[0].setValue('instance_id', str(node.id))
                vm.info.systems[0].setValue('instance_name', str(node.name))
                if 'zone_name' in node.extra:
                    vm.info.systems[0].setValue('availability_zone', node.extra["zone_name"])
                self.log_debug("Node successfully created.")
                vm.destroy = False
                inf.add_vm(vm)
                res.append((True, vm))
            else:
                res.append((False, msg))

            i += 1

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

            if "size_name" in node.extra:
                instance_type = None
                for size in node.driver.list_sizes():
                    if size.name == node.extra["size_name"]:
                        instance_type = size
                        break
                if instance_type:
                    self.update_system_info_from_instance(vm.info.systems[0], instance_type)
            else:
                self.log_debug(
                    "VM " + str(vm.id) + " has no node.size info. Not updating system info.")

            vm.setIps(node.public_ips, node.private_ips)
            self.attach_volumes(vm, node)
        else:
            self.log_warn("Error updating the instance %s. VM not found." % vm.id)
            return (False, "Error updating the instance %s. VM not found." % vm.id)

        return (True, vm)

    def finalize(self, vm, last, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)

        if node:
            success = node.destroy()

            # Delete the EBS volumes
            self.delete_volumes(node.driver, vm)

            if not success:
                return (False, "Error destroying node: " + vm.id)

            self.log_debug("VM " + str(vm.id) + " successfully destroyed")
        else:
            self.log_warn("VM " + str(vm.id) + " not found.")

        try:
            # Delete the SG if this is the last VM
            if last:
                self.delete_security_groups(node.driver, vm.inf)
            else:
                # If this is not the last vm, we skip this step
                self.log_info("There are active instances. Not removing the SG")
        except Exception:
            self.log_exception("Error deleting security groups.")

        return (True, "")

    def delete_security_groups(self, driver, inf, timeout=180, delay=10):
        """
        Delete the SG of this inf
        """
        for net in inf.radl.networks:
            sg_name = "im-%s-%s" % (str(inf.id), net.id)

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
                    try:
                        self.log_info("Deleting SG: %s" % sg['name'])
                        result = driver.ex_delete_security_group(sg['name'])
                        if str(result) == "true":
                            deleted = True
                    except Exception as ex:
                        self.log_warn("Error deleting the SG: %s" % str(ex))

                    if not deleted:
                        time.sleep(delay)
                        cont += delay

            if not deleted:
                self.log_error("Error deleting the SG: Timeout.")

    def start(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            success = node.ex_start()
            if success == "Running":
                return (True, "")
            else:
                return (False, "Error in start operations")
        else:
            return (False, "VM not found with id: " + vm.id)

    def stop(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            success = node.ex_stop()
            if success == "Stopped":
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

    def alterVM(self, vm, radl, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            instance_type = self.get_instance_type(
                node.driver.list_sizes(), radl.systems[0])

            try:
                if node.ex_stop() == "Stopped":
                    error_msg = ""
                    success = False
                    try:
                        node.ex_change_node_size(instance_type)
                        success = True
                    except Exception as ex:
                        self.log_exception("Error resizing VM.")
                        error_msg = "Error resizing VM: %s" % str(ex)
                        success = False
                    finally:
                        if node.ex_start() != "Running":
                            success = False
                            error_msg = "Error restarting VM"

                    return (success, error_msg)
                else:
                    self.log_error("Error stopping the VM.")
                    return (False, "Error stopping VM: %s" % success)
            except Exception as ex:
                self.log_exception("Error resizing VM.")
                return (False, "Error resizing VM: " + str(ex))

            if success:
                return (True, "")
            else:
                return (False, "Error in resize operation")
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
                vm.volumes = []
                cont = 1
                while vm.info.systems[0].getValue("disk." + str(cont) + ".size"):
                    disk_size = vm.info.systems[0].getFeature("disk." + str(cont) + ".size").getValue('G')
                    disk_device = vm.info.systems[0].getValue("disk." + str(cont) + ".device")
                    if disk_device:
                        disk_device = "/dev/" + disk_device
                    self.log_debug("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
                    volume_name = "im-%s" % str(uuid.uuid1())

                    location = NodeLocation(node.extra["zone_id"], node.extra["zone_name"], 'Unknown', node.driver)
                    volume = node.driver.create_volume(int(disk_size), volume_name, location=location)
                    success = self.wait_volume(volume)
                    if success:
                        # Add the volume to the VM to remove it later
                        vm.volumes.append(volume.id)
                        self.log_debug("Attach the volume ID " + str(volume.id))
                        volume.attach(node, disk_device)
                        # wait the volume to be attached
                        self.wait_volume(volume, state='in-use')

                        volume = volume.driver.ex_get_volume(volume.id)
                        if 'attachments' in volume.extra and volume.extra['attachments']:
                            disk_device = volume.extra['attachments'][0]['device']
                            vm.info.systems[0].setValue("disk." + str(cont) + ".device", disk_device)
                    else:
                        self.log_error("Error waiting the volume ID " + str(
                            volume.id) + " not attaching to the VM and destroying it.")
                        volume.destroy()

                    cont += 1
            return True
        except Exception:
            self.log_exception("Error creating or attaching the volume to the node")
            return False
