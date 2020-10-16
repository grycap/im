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

try:
    from pyVim.connect import SmartConnect
    from pyVmomi import vim, vmodl
except Exception as ex:
    print("WARN: VMWare pyVmomi library not correctly installed. vSphereCloudConnector will not work!.")
    print(ex)

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from IM.config import Config
from .CloudConnector import CloudConnector


class vSphereCloudConnector(CloudConnector):
    """
    Cloud Launcher to VMWare vSphere using pyvmomi lib
    https://github.com/vmware/pyvmomi

    This connector is still EXPERIMENTAL!!
    """

    type = "vSphere"
    """str with the name of the provider."""

    VM_STATE_MAP = {
        'poweredOn': VirtualMachine.RUNNING,
        'poweredOff': VirtualMachine.OFF,
        'suspended': VirtualMachine.STOPPED
    }
    """Dictionary with a map with the vSphere VM states to the IM states."""

    def __init__(self, cloud_info, inf):
        self.connection = None
        CloudConnector.__init__(self, cloud_info, inf)

    @staticmethod
    def wait_for_tasks(service_instance, tasks):
        """
        Written by Michael Rice <michael@michaelrice.org>
        Github: https://github.com/michaelrice
        Website: https://michaelrice.github.io/
        Blog: http://www.errr-online.com/
        This code has been released under the terms of the Apache 2 licenses
        http://www.apache.org/licenses/LICENSE-2.0.html
        Helper module for task operations.

        Given the service instance si and tasks, it returns after all the
        tasks are complete
        """
        property_collector = service_instance.content.propertyCollector
        task_list = [str(task) for task in tasks]
        # Create filter
        property_spec = vmodl.query.PropertyCollector.PropertySpec(type=vim.Task,
                                                                   pathSet=[],
                                                                   all=True)
        obj_specs = [vmodl.query.PropertyCollector.ObjectSpec(obj=task) for task in tasks]

        filter_spec = vmodl.query.PropertyCollector.FilterSpec()
        filter_spec.objectSet = obj_specs
        filter_spec.propSet = [property_spec]
        pcfilter = property_collector.CreateFilter(filter_spec, True)
        try:
            version, state = None, None
            # Loop looking for updates till the state moves to a completed state.
            while len(task_list):
                update = property_collector.WaitForUpdates(version)
                for filter_set in update.filterSet:
                    for obj_set in filter_set.objectSet:
                        task = obj_set.obj
                        for change in obj_set.changeSet:
                            if change.name == 'info':
                                state = change.val.state
                            elif change.name == 'info.state':
                                state = change.val
                            else:
                                continue

                            if not str(task) in task_list:
                                continue

                            if state == vim.TaskInfo.State.success:
                                # Remove task from taskList
                                task_list.remove(str(task))
                            elif state == vim.TaskInfo.State.error:
                                raise task.info.error
                # Move to next version
                version = update.version
        finally:
            if pcfilter:
                pcfilter.Destroy()

    def get_connection(self, auth_data):
        """
        Get the vSphere connection object from the auth data

        Arguments:
            - auth(Authentication): parsed authentication tokens.

        Returns: a :py:class:`vim.connect.SmartConnect` or None in case of error
        """
        if self.connection:
            return self.connection
        else:
            auth = auth_data.getAuthInfo(self.type)

            if auth and 'username' in auth[0] and 'password' in auth[0]:

                connection = SmartConnect(host=self.cloud.server,
                                          user=auth[0]['username'],
                                          pwd=auth[0]['password'],
                                          port=self.cloud.port)

                self.connection = connection
                return connection
            else:
                self.log_error("No correct auth data has been specified to vSpere: username, password")
                self.log_debug(auth)
                raise Exception("No correct auth data has been specified to vSpere: username, password")

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]
        src_host = url[1].split(':')[0]

        if protocol == "vsp" and self.cloud.server == src_host:
            # Check the space in image and compare with disks.free_size
            if radl_system.getValue('disks.free_size'):
                disk_free = int(radl_system.getFeature('disks.free_size').getValue('M'))
                # The VMRC specified the value in MB
                disk_size = int(radl_system.getValue("disk.0.size"))

                if disk_size < disk_free:
                    # if the image do not have enough space, discard it
                    return None

            res_system = radl_system.clone()

            res_system.getFeature("cpu.count").operator = "="
            res_system.getFeature("memory.size").operator = "="

            return res_system
        else:
            return None

    @staticmethod
    def gen_nic(num, network):
        """
        Get a nic for the specified network
        """
        nic = vim.vm.device.VirtualDeviceSpec()
        nic.operation = vim.vm.device.VirtualDeviceSpec.Operation.add  # or edit if a device exists
        nic.device = vim.vm.device.VirtualVmxnet3()
        nic.device.wakeOnLanEnabled = True
        nic.device.addressType = 'assigned'
        nic.device.key = 4000  # 4000 seems to be the value to use for a vmxnet3 device
        nic.device.deviceInfo = vim.Description()
        nic.device.deviceInfo.label = "Network Adapter %d" % num
        nic.device.deviceInfo.summary = "Net summary"
        nic.device.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
        nic.device.backing.network = network
        nic.device.backing.deviceName = "Device%d" % num
        nic.device.backing.useAutoDetect = False
        nic.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
        nic.device.connectable.startConnected = True
        nic.device.connectable.allowGuestControl = True

        return nic

    def create_vm(self, radl, vm_name, connection, vm_folder, resource_pool,
                  datastore, template_name, cpu, memory, nets, vm):
        """
        Create a VM from a template

        Arguments:
            - vm_name(str): Name of the VM (must be unique).
            - connection(:py:class:`vim.connect.SmartConnect` ): Connection object.
            - vm_folder(:py:class:`vim.Folder` ): Folder this VM will be a child.
            - resource_pool(:py:class:`vim.ResourcePool`): Resource pool to locate this VM.
            - datastore(:py:class:`vim.Datastore`): Datastore to store this VM.
            - template_name(str): Name of the template used to clone this VM.
            - cpu(int): Number of CPUs of the VM.
            - memory(int): Amount of RAM memory of the VM (in MB).
            - auth(Authentication): parsed authentication tokens.

        Returns: a :py:class:`vim.connect.SmartConnect` or None in case of error
        """
        system = radl.systems[0]
        # set relospec
        relospec = vim.vm.RelocateSpec()
        relospec.datastore = datastore
        relospec.pool = resource_pool

        config = vim.vm.ConfigSpec(name=vm_name,
                                   memoryMB=memory,
                                   numCPUs=cpu)

        devices = []
        adaptermaps = []

        i = 0
        while system.getValue("net_interface." + str(i) + ".connection"):
            net_name = system.getValue("net_interface." + str(i) + ".connection")
            fixed_ip = system.getValue("net_interface." + str(i) + ".ip")

            # get the one network info
            subnet_address = None
            subnet_mask = None
            gateway = None
            net_obj = None
            if nets[net_name]:
                net_obj = nets[net_name][0]
                subnet_address = nets[net_name][2].subnetAddress
                subnet_mask = nets[net_name][2].netmask
                gateway = nets[net_name][2].gateway
                radl.get_network_by_id(net_name).setValue('provider_id', str(net_name))
            else:
                self.log_error("No vSphere network found for network: " + net_name)
                raise Exception("No vSphere network found for network: " + net_name)

            nic = self.gen_nic(i, net_obj)
            devices.append(nic)

            # guest NIC settings, i.e. "adapter map"
            guest_map = vim.vm.customization.AdapterMapping()
            guest_map.adapter = vim.vm.customization.IPSettings()

            if fixed_ip:
                if not subnet_mask:
                    subnet_mask = system.getValue("net_interface." + str(i) + ".subnet")
                if not subnet_mask:
                    raise Exception("net_interface." + str(i) + ".subnet must be defined for this network.")

                if not gateway:
                    gateway = system.getValue("net_interface." + str(i) + ".gateway")
                if not gateway:
                    raise Exception("net_interface." + str(i) + ".gateway must be defined for this network.")

                if not IPAddress(fixed_ip) in IPNetwork(subnet_address + "/" + subnet_mask):
                    raise Exception("IP %s not in the subnet: %s/%s" % (fixed_ip, subnet_address, subnet_mask))

                guest_map.adapter.ip = vim.vm.customization.FixedIp()
                guest_map.adapter.ip.ipAddress = fixed_ip
                guest_map.adapter.subnetMask = subnet_mask
                guest_map.adapter.gateway = gateway
            else:
                guest_map.adapter.ip = vim.vm.customization.DhcpIpGenerator()

            adaptermaps.append(guest_map)
            i += 1

        config.deviceChange = devices

        # Hostname settings
        ident = vim.vm.customization.LinuxPrep()
        (nodename, nodedom) = vm.getRequestedName(default_hostname=Config.DEFAULT_VM_NAME,
                                                  default_domain=Config.DEFAULT_DOMAIN)
        ident.domain = nodedom
        ident.hostName = vim.vm.customization.FixedName()
        ident.hostName.name = nodename

        # DNS settings
        globalip = vim.vm.customization.GlobalIPSettings()
        dns_servers = system.getValue("net_interface.0.dns_servers")
        if dns_servers:
            globalip.dnsServerList = dns_servers.split(",")
        globalip.dnsSuffixList = [nodedom]

        customspec = vim.vm.customization.Specification()
        customspec.nicSettingMap = adaptermaps
        customspec.globalIPSettings = globalip
        customspec.identity = ident

        clonespec = vim.vm.CloneSpec()
        clonespec.location = relospec
        clonespec.powerOn = True
        clonespec.config = config
        clonespec.customization = customspec

        template = self.get_vm_by_name(connection.RetrieveContent(), template_name)

        task = template.Clone(folder=vm_folder, name=vm_name, spec=clonespec)
        return task

    # The path must be: vsp://template_name
    @staticmethod
    def get_template_name(path):
        """
        Get the region and the image name from an URL of a VMI

        Arguments:
           - path(str): URL of a VMI (some like this: vsp://template_name)
        Returns: a str with the template name
        """
        uri = urlparse(path)
        return uri[2][1:]

    @staticmethod
    def get_datastores(content):
        """
        Returns all datastores
        """
        obj = {}
        container = content.viewManager.CreateContainerView(content.rootFolder, [vim.Datastore], True)
        for c in container.view:
            obj[c.name] = c
        return obj

    @staticmethod
    def map_radl_vsphere_networks(radl_nets, vsphere_nets):
        """
        Generate a mapping between the RADL networks and the ONE networks

        Arguments:
           - radl_nets(list of :py:class:`radl.network` objects): RADL networks.
           - vsphere_nets(a list of :py:class:`vim.Network` objects): vSpehere networks

         Returns: a dict with key the RADL network id and value a tuple (one_net_name, one_net_id, is_public)
        """
        # TODO: get the ip and subnet of an interface to select the network
        res = {}

        used_nets = []
        last_net = None
        for radl_net in radl_nets:
            # First check if the user has specified a provider ID
            net_provider_id = radl_net.getValue('provider_id')
            if net_provider_id:
                for net_name, net_values in vsphere_nets.items():
                    is_public = net_values[1]
                    # If the name is the same and have the same "publicity" value
                    if net_name == net_provider_id and radl_net.isPublic() == is_public:
                        res[radl_net.id] = net_values
                        used_nets.append(net_name)
                        break
            else:
                for net_name, net_values in vsphere_nets.items():
                    is_public = net_values[1]
                    if net_name not in used_nets and radl_net.isPublic() == is_public:
                        res[radl_net.id] = net_values
                        used_nets.append(net_name)
                        last_net = net_values
                        break
                if radl_net.id not in res:
                    res[radl_net.id] = last_net

        # In case of there are no private network, use public ones for non mapped networks
        used_nets = []
        for radl_net in radl_nets:
            if not res[radl_net.id]:
                for net_name, net_values in vsphere_nets.items():
                    is_public = net_values[1]
                    if net_name not in used_nets and is_public:
                        res[radl_net.id] = net_values
                        used_nets.append(net_name)
                        last_net = net_values
                        break
                if radl_net.id not in res:
                    res[radl_net.id] = last_net

        return res

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        system = radl.systems[0]

        cpu = system.getValue('cpu.count')
        memory = system.getFeature('memory.size').getValue('M')

        connection = self.get_connection(auth_data)

        content = connection.RetrieveContent()
        datacenter = content.rootFolder.childEntity[0]
        vm_folder = datacenter.vmFolder
        hosts = datacenter.hostFolder.childEntity
        resource_pool = hosts[0].resourcePool

        template = self.get_template_name(system.getValue("disk.0.image.url"))

        datastores = self.get_datastores(content)
        networks = self.get_networks(content, datacenter)

        nets = self.map_radl_vsphere_networks(radl.networks, networks)

        tasks = []
        res = []
        i = 0
        while i < num_vm:
            self.log_debug("Creating node")

            vm_name = self.gen_instance_name(system)
            vm = VirtualMachine(inf, vm_name, self.cloud, radl, requested_radl, self)
            task = self.create_vm(radl, vm_name, connection, vm_folder, resource_pool,
                                  list(datastores.values())[0], template, cpu, memory, nets, vm)
            tasks.append(task)

            i += 1

        for task in tasks:
            try:
                self.wait_for_tasks(connection, [task])
                self.log_debug("Node successfully created.")
                res.append((True, vm))
            except Exception as ex:
                self.log_exception("Error waiting VM creation task.")
                res.append((False, "Error creating the node: " + str(ex)))

        return res

    @staticmethod
    def get_networks(content, datacenter):
        """
        Returns all metworks
        """
        nets = {}
        poolmgr = vim.IpPoolManager()
        ippools = poolmgr.QueryIpPools(datacenter)
        container = content.viewManager.CreateContainerView(content.rootFolder, [vim.Network], True)
        for c in container.view:
            is_public = None
            for ippool in ippools:
                if c.summary.ipPoolName == ippool.name:
                    is_public = not any([IPAddress(ippool.ipv4Config.subnetAddress) in IPNetwork(
                        mask) for mask in Config.PRIVATE_NET_MASKS])
                    break

            nets[c.name] = (c, is_public, ippool.ipv4Config)

        return nets

    @staticmethod
    def get_vm_by_name(content, name):
        """
        Find a virtual machine by it's name and return it
        """
        vm = None
        container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
        for c in container.view:
            # c.summary.config.template
            if c.name == name:
                vm = c
                break
        return vm

    def finalize(self, vm, last, auth_data):
        connection = self.get_connection(auth_data)
        node = self.get_vm_by_name(connection.RetrieveContent(), vm.id)

        if node:
            if format(node.runtime.powerState) == "poweredOn":
                task = node.PowerOff()
                try:
                    self.wait_for_tasks(connection, [task])
                except Exception:
                    self.log_exception("Error powering off VM " + str(vm.id))

            task = node.Destroy()
            try:
                self.wait_for_tasks(connection, [task])
            except Exception as ex:
                self.log_exception("Error destroying the VM " + str(vm.id))
                return (False, "Error destroying the VM: " + str(ex))

            self.log_debug("VM " + str(vm.id) + " successfully destroyed")
        else:
            self.log_warn("VM " + str(vm.id) + " not found.")
        return (True, "")

    @staticmethod
    def setIps(vm, node):
        """
        Set the IPs of the VM from the info obtained from vSphere
        """
        public_ips = []
        private_ips = []

        if node.guest:
            for nic in node.guest.net:
                if nic.ipAddress:
                    ip = nic.ipAddress
                    is_private = any([IPAddress(ip) in IPNetwork(mask) for mask in Config.PRIVATE_NET_MASKS])
                    if is_private:
                        private_ips.append(ip)
                    else:
                        public_ips.append(ip)

        vm.setIps(public_ips, private_ips)

    def updateVMInfo(self, vm, auth_data):
        connection = self.get_connection(auth_data)
        node = self.get_vm_by_name(connection.RetrieveContent(), vm.id)

        if node:
            state = node.summary.runtime.powerState
            vm.state = self.VM_STATE_MAP.get(state, VirtualMachine.UNKNOWN)
            self.setIps(vm, node)
            self.attach_volumes(connection, node, vm)
        else:
            self.log_warn("VM " + str(vm.id) + " does not exist.")
            vm.state = VirtualMachine.OFF

        return (True, vm)

    def start(self, vm, auth_data):
        return self.vm_action(vm, 'start', auth_data)

    def stop(self, vm, auth_data):
        return self.vm_action(vm, 'stop', auth_data)

    def reboot(self, vm, auth_data):
        return self.vm_action(vm, 'reboot', auth_data)

    def vm_action(self, vm, action, auth_data):
        connection = self.get_connection(auth_data)
        node = self.get_vm_by_name(connection.RetrieveContent(), vm.id)

        if node:
            if action == 'stop':
                if format(node.runtime.powerState) != "poweredOn":
                    return (False, "Error stopping the VM. The VM is not running.")
                task = node.Suspend()
            elif action == 'start':
                if format(node.runtime.powerState) != "suspended":
                    return (False, "Error starting the VM. The VM is not suspended.")
                task = node.PowerOn()
            elif action == 'reboot':
                task = node.Reset()

            try:
                self.wait_for_tasks(connection, [task])
            except Exception as ex:
                self.log_exception("Error in VM action " + str(vm.id))
                return (False, "Error in VM action: " + str(ex))

            self.log_debug("VM " + str(vm.id) + " successfully " + action)
        else:
            self.log_warn("VM " + str(vm.id) + " not found.")
        return (True, "")

    def add_disk(self, vm, si, disk_size, disk_type="thin"):
        """
        Written by Dann Bohn
        Github: https://github.com/whereismyjetpack
        Email: dannbohn@gmail.com
        Script to add a Hard disk to an existing VM

        Known issues:
        This will not add more than 15 disks to a VM
        To do that the VM needs an additional scsi controller
        and I have not yet worked through that

        Arguments:
            - vm(:py:class:`vim.VirtualMachine` ): VM to add the disk.
            - si(:py:class:`vim.connect.SmartConnect` ): Connection object.
            - disk_size(str): disk size, in GB, to add to the VM
            - disk_type(str): thick or thin (default value thin).

        Returns: True if the disk is added successfully and False otherwise.
        """
        spec = vim.vm.ConfigSpec()
        # get all disks on a VM, set unit_number to the next available
        for dev in vm.config.hardware.device:
            if hasattr(dev.backing, 'fileName'):
                unit_number = int(dev.unitNumber) + 1
                # unit_number 7 reserved for scsi controller
                if unit_number == 7:
                    unit_number += 1
                if unit_number >= 16:
                    self.log_error("Error adding disks to a VM. We don't support this many disks")
                    return False
            if isinstance(dev, vim.vm.device.VirtualSCSIController):
                controller = dev
        # add disk here
        dev_changes = []
        new_disk_kb = int(disk_size) * 1024 * 1024
        disk_spec = vim.vm.device.VirtualDeviceSpec()
        disk_spec.fileOperation = "create"
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        disk_spec.device = vim.vm.device.VirtualDisk()
        disk_spec.device.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
        if disk_type == 'thin':
            disk_spec.device.backing.thinProvisioned = True
        disk_spec.device.backing.diskMode = 'persistent'
        disk_spec.device.unitNumber = unit_number
        disk_spec.device.capacityInKB = new_disk_kb
        disk_spec.device.controllerKey = controller.key
        dev_changes.append(disk_spec)
        spec.deviceChange = dev_changes
        vm.ReconfigVM(spec=spec)
        self.log_debug("%sGB disk added to %s" % (disk_size, vm.config.name))
        return True

    def attach_volumes(self, conn, node, vm):
        """
        Attach a the required volumes (in the RADL) to the launched instance

        Arguments:
           - conn(:py:class:`vim.connect.SmartConnect` ): Connection object.
           - node(:py:class:`vim.VirtualMachine` ): VM to add the disk.
           - vm(:py:class:`IM.VirtualMachine`): VM information.
        """
        try:
            if node.summary.runtime.powerState == "poweredOn" and "volumes" not in vm.__dict__.keys():
                # Flag to set that this VM has created (or is creating) the
                # volumes
                vm.volumes = True
                cont = 1
                while vm.info.systems[0].getValue("disk." + str(cont) + ".size"):
                    disk_size = vm.info.systems[0].getFeature("disk." + str(cont) + ".size").getValue('G')
                    # disk_device = vm.info.systems[0].getValue("disk." + str(cont) + ".device")
                    self.log_info("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
                    self.add_disk(node, conn, disk_size)
                    cont += 1
        except Exception:
            self.log_exception("Error creating or attaching the volume to the instance")
