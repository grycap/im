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
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from CloudConnector import CloudConnector
from radl.radl import Feature

try:
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.common.credentials import UserPassCredentials
except Exception, ex:
    print "WARN: Python Azure SDK not correctly installed. AzureCloudConnector will not work!."
    print ex


class AzureCloudConnector(CloudConnector):
    """
    Cloud Launcher to the Azure platform
    Azure Resource Manager REST API Reference:
    https://msdn.microsoft.com/en-us/library/azure/dn790568.aspx
    https://azure-sdk-for-python.readthedocs.io/en/latest/
    """

    type = "Azure"
    """str with the name of the provider."""
    INSTANCE_TYPE = 'ExtraSmall'
    """Default instance type."""
    """Port of the server with the Service Management REST API."""
    DEFAULT_LOCATION = "northeurope"
    """Default location to use"""

    PROVISION_STATE_MAP = {
        'Accepted': VirtualMachine.PENDING,
        'Canceled': VirtualMachine.OFF,
        'Created': VirtualMachine.PENDING,
        'Creating': VirtualMachine.PENDING,
        'Deleted': VirtualMachine.OFF,
        'Deleting': VirtualMachine.OFF,
        'Failed': VirtualMachine.FAILED,
        'Notspecified': VirtualMachine.UNKNOWN,
        'Registering': VirtualMachine.PENDING,
        'Running': VirtualMachine.PENDING,
        'Succeeded': VirtualMachine.RUNNING
    }

    POWER_STATE_MAP = {
        'Deallocated': VirtualMachine.OFF,
        'Deallocating': VirtualMachine.OFF,
        'Running': VirtualMachine.RUNNING,
        'Starting': VirtualMachine.PENDING,
        'Started': VirtualMachine.PENDING,
        'Stopped': VirtualMachine.STOPPED
    }

    def __init__(self, cloud_info):
        self.credentials = None
        CloudConnector.__init__(self, cloud_info)

    def get_credentials(self, auth_data):
        auths = auth_data.getAuthInfo(self.type)
        if not auths:
            raise Exception("No auth data has been specified to Azure.")
        else:
            auth = auths[0]

        if 'subscription_id' in auth and 'username' in auth and 'password' in auth:
            subscription_id = auth['subscription_id']
            username = auth['username']
            password = auth['password']
        else:
            raise Exception(
                "No correct auth data has been specified to Azure: subscription_id, username and password.")

        if self.credentials and self.auth.compare(auth_data, self.type):
            return self.credentials, subscription_id
        else:
            self.auth = auth_data
            self.credentials = UserPassCredentials(username, password)

        return self.credentials, subscription_id

    def get_instance_type_by_name(self, instance_name, location, credentials, subscription_id):
        compute_client = ComputeManagementClient(credentials, subscription_id)
        instace_types = compute_client.virtual_machine_sizes.list(location)

        for instace_type in list(instace_types):
            if instace_type.name == instance_name:
                return instace_type

        return None

    def get_instance_type(self, system, credentials, subscription_id):
        """
        Get the name of the instance type to launch to Azure

        Arguments:
           - radl(str): RADL document with the requirements of the VM to get the instance type
        Returns: a str with the name of the instance type to launch to Azure
        """
        instance_type_name = system.getValue('instance_type')

        location = self.DEFAULT_LOCATION
        if system.getValue('availability_zone'):
            location = system.getValue('availability_zone')

        cpu = 1
        cpu_op = ">="
        if system.getFeature('cpu.count'):
            cpu = system.getValue('cpu.count')
            cpu_op = system.getFeature('cpu.count').getLogOperator()

        memory = 1
        memory_op = ">="
        if system.getFeature('memory.size'):
            memory = system.getFeature('memory.size').getValue('M')
            memory_op = system.getFeature('memory.size').getLogOperator()

        disk_free = 0
        disk_free_op = ">="
        if system.getValue('disks.free_size'):
            disk_free = system.getFeature('disks.free_size').getValue('M')
            disk_free_op = system.getFeature('memory.size').getLogOperator()

        compute_client = ComputeManagementClient(credentials, subscription_id)
        instace_types = compute_client.virtual_machine_sizes.list(location)

        res = None
        default = None
        for instace_type in list(instace_types):
            if instace_type.name == self.INSTANCE_TYPE:
                default = instace_type
            # get the instance type with the lowest Memory
            if res is None or (instace_type.memory_in_mb <= res.memory_in_mb):
                str_compare = "instace_type.number_of_cores " + cpu_op + " cpu "
                str_compare += " and instace_type.memory_in_mb " + memory_op + " memory "
                str_compare += " and instace_type.resource_disk_size_in_mb " + \
                    disk_free_op + " disk_free"

                if eval(str_compare):
                    if not instance_type_name or instace_type.name == instance_type_name:
                        res = instace_type

        if res is None:
            return default
        else:
            return res

    def update_system_info_from_instance(self, system, instance_type):
        """
        Update the features of the system with the information of the instance_type
        """
        system.addFeature(Feature("cpu.count", "=", instance_type.number_of_cores),
                          conflict="other", missing="other")
        system.addFeature(Feature("memory.size", "=", instance_type.memory_in_mb, 'M'),
                          conflict="other", missing="other")
        system.addFeature(Feature("disks.free_size", "=", instance_type.resource_disk_size_in_mb, 'M'),
                          conflict="other", missing="other")
        system.addFeature(Feature("instance_type", "=", instance_type.name),
                          conflict="other", missing="other")

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

                protocol = url[0]
                if protocol == "azr":
                    credentials, subscription_id = self.get_credentials(auth_data)

                    res_system = radl_system.clone()
                    instance_type = self.get_instance_type(res_system, credentials, subscription_id)
                    if not instance_type:
                        self.logger.error(
                            "Error generating the RADL of the VM, no instance type available for the requirements.")
                        self.logger.debug(res_system)
                    else:
                        res_system.addFeature(
                            Feature("disk.0.image.url", "=", str_url), conflict="other", missing="other")
                        self.update_system_info_from_instance(res_system, instance_type)
                        res_system.addFeature(
                            Feature("provider.type", "=", self.type), conflict="other", missing="other")

                        username = res_system.getValue('disk.0.os.credentials.username')
                        if not username:
                            res_system.setValue('disk.0.os.credentials.username', 'azureuser')

                        res_system.updateNewCredentialValues()

                        res.append(res_system)
            return res

    def create_ngs(self, location, group_name, nsg_name, outports, network_client):
        """
        Create a Network Security Group
        """
        # Always add SSH port
        security_rules = [{'name': 'sr-Tcp-22-22',
                           'access': 'Allow',
                           'protocol': 'Tcp',
                           'destination_address_prefix': '*',
                           'source_address_prefix': '*',
                           'direction': 'Inbound',
                           'destination_port_range': '22',
                           'source_port_range': '*',
                           'priority': 100
                           }]
        for remote_port, remote_protocol, local_port, local_protocol in outports:
            if local_port != 22:
                protocol = remote_protocol
                if remote_protocol != local_protocol:
                    self.logger.warn("Different protocols used in outports ignoring local port protocol!")

                sr = {'name': 'sr-%s-%d-%d' % (protocol, remote_port, local_port),
                      'access': 'Allow',
                      'protocol': protocol,
                      'destination_address_prefix': '*',
                      'source_address_prefix': '*',
                      'direction': 'Inbound',
                      'destination_port_range': str(local_port),
                      'source_port_range': '*',
                      'priority': 100
                      }
                security_rules.append(sr)

        params = {
            'location': location,
            'security_rules': security_rules
        }

        ngs = None
        try:
            ngs = network_client.network_security_groups.create_or_update(group_name, nsg_name, params).result()
        except:
            self.logger.exception("Error creating NGS")

        return ngs

    def create_nics(self, inf, radl, credentials, subscription_id, group_name, subnets):
        """Create a Network Interface for a VM.
        """
        system = radl.systems[0]
        network_client = NetworkManagementClient(credentials, subscription_id)

        location = self.DEFAULT_LOCATION
        if radl.systems[0].getValue('availability_zone'):
            location = radl.systems[0].getValue('availability_zone')

        i = 0
        res = []
        while system.getValue("net_interface." + str(i) + ".connection"):
            network_name = system.getValue("net_interface." + str(i) + ".connection")
            # TODO: check how to do that
            # fixed_ip = system.getValue("net_interface." + str(i) + ".ip")
            network = radl.get_network_by_id(network_name)
            nic_name = "nic-%d" % i
            ip_config_name = "ip-config-%d" % i

            # Create NIC
            nic_params = {
                'location': location,
                'ip_configurations': [{
                    'name': ip_config_name,
                    'subnet': {'id': subnets[network_name].id}
                }]
            }

            if network.isPublic():
                # Create PublicIP
                public_ip_name = "public-ip-%d" % i
                public_ip_parameters = {
                    'location': location,
                    'public_ip_allocation_method': 'static',
                    'idle_timeout_in_minutes': 4
                }
                async_publicip_creation = network_client.public_ip_addresses.create_or_update(
                    group_name,
                    public_ip_name,
                    public_ip_parameters
                )
                public_ip_info = async_publicip_creation.result()
                nic_params['ip_configurations'][0]['public_ip_address'] = {'id': public_ip_info.id}

                # Create a NSG
                outports = network.getOutPorts()
                if outports:
                    nsg_name = "nsg-%d" % i
                    nsg = self.create_ngs(location, group_name, nsg_name, outports, network_client)
                    if nsg:
                        nic_params['network_security_group'] = {'id': nsg.id}

            async_nic_creation = network_client.network_interfaces.create_or_update(
                group_name, nic_name, nic_params)
            nic = async_nic_creation.result()
            res.append(nic)

            i += 1

        return res

    def get_azure_vm_create_json(self, storage_account, vm_name, nics, radl, instance_type):
        """ Create the VM parameters structure. """
        system = radl.systems[0]
        url = uriparse(system.getValue("disk.0.image.url"))
        # the url has to have the format: azr://publisher/offer/sku/version
        # azr://Canonical/UbuntuServer/16.04.0-LTS/latest
        # azr://MicrosoftWindowsServerEssentials/WindowsServerEssentials/WindowsServerEssentials/latest
        image_values = (url[1] + url[2]).split("/")
        if len(image_values) != 4:
            raise Exception("The Azure image has to have the format: azr://publisher/offer/sku/version")

        location = self.DEFAULT_LOCATION
        if system.getValue('availability_zone'):
            location = system.getValue('availability_zone')

        # Allways use the new credentials
        system.updateNewCredentialValues()
        user_credentials = system.getCredentials()

        os_disk_name = "osdisk-" + str(int(time.time() * 100))

        return {
            'location': location,
            'os_profile': {
                'computer_name': vm_name,
                'admin_username': user_credentials.username,
                'admin_password': user_credentials.password
            },
            'hardware_profile': {
                'vm_size': instance_type.name
            },
            'storage_profile': {
                'image_reference': {
                    'publisher': image_values[0],
                    'offer': image_values[1],
                    'sku': image_values[2],
                    'version': image_values[3]
                },
                'os_disk': {
                    'name': os_disk_name,
                    'caching': 'None',
                    'create_option': 'fromImage',
                    'vhd': {
                        'uri': 'https://{}.blob.core.windows.net/vhds/{}.vhd'.format(
                            storage_account, vm_name + os_disk_name)
                    }
                },
            },
            'network_profile': {
                'network_interfaces': [{'id': nic.id} for nic in nics]
            },
        }

    def get_storage_account(self, group_name, storage_account, credentials, subscription_id):
        """
        Get the information about the Storage Account named "storage_account" or None if it does not exist
        """
        try:
            storage_client = StorageManagementClient(credentials, subscription_id)
            return storage_client.storage_accounts.get_properties(group_name, storage_account)
        except Exception:
            self.logger.exception("Error checking the storage account")
            return None

    def create_storage_account(self, group_name, storage_account, credentials, subscription_id, location):
        """
        Create an storage account with the name specified in "storage_account"
        """
        try:
            storage_client = StorageManagementClient(credentials, subscription_id)
            storage_async_operation = storage_client.storage_accounts.create(group_name,
                                                                             storage_account,
                                                                             {'sku': {'name': 'standard_lrs'},
                                                                              'kind': 'storage',
                                                                              'location': location}
                                                                             )
            return storage_async_operation.result(), ""
        except Exception, ex:
            self.logger.exception("Error creating the storage account")
            return None, str(ex)

    def create_nets(self, inf, radl, credentials, subscription_id, group_name):
        network_client = NetworkManagementClient(credentials, subscription_id)
        location = self.DEFAULT_LOCATION
        if radl.systems[0].getValue('availability_zone'):
            location = radl.systems[0].getValue('availability_zone')
        # check if the vnet exists
        vnet = None
        try:
            vnet = network_client.virtual_networks.get(self, group_name, "privates")
        except Exception:
            pass

        if not vnet:
            # Create VNet in the RG of the Inf
            async_vnet_creation = network_client.virtual_networks.create_or_update(
                group_name,
                "privates",
                {
                    'location': location,
                    'address_space': {
                        'address_prefixes': ['10.0.0.0/16']
                    }
                }
            )
            async_vnet_creation.wait()

            subnets = {}
            for i, net in enumerate(radl.networks):
                subnet_name = net.id
                # Create Subnet in the RG of the Inf
                async_subnet_creation = network_client.subnets.create_or_update(
                    group_name,
                    "privates",
                    subnet_name,
                    {'address_prefix': '10.0.%d.0/24' % i}
                )
                subnets[net.id] = async_subnet_creation.result()
        else:
            subnets = {}
            for i, net in enumerate(radl.networks):
                subnets[net.id] = network_client.subnets.get(group_name, net.id)

        return subnets

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        location = self.DEFAULT_LOCATION
        if radl.systems[0].getValue('availability_zone'):
            location = radl.systems[0].getValue('availability_zone')
        else:
            radl.systems[0].setValue('availability_zone', location)

        credentials, subscription_id = self.get_credentials(auth_data)

        resource_client = ResourceManagementClient(credentials, subscription_id)

        with inf._lock:
            # Create resource group for the Infrastructure
            inf_rg = None
            try:
                inf_rg = resource_client.resource_groups.get("rg-%s" % inf.id)
            except Exception:
                pass
            if not inf_rg:
                resource_client.resource_groups.create_or_update("rg-%s" % inf.id, {'location': location})

            subnets = self.create_nets(inf, radl, credentials, subscription_id, "rg-%s" % inf.id)

        res = []
        i = 0
        while i < num_vm:
            try:
                # Create the VM to get the nodename
                now = int(time.time() * 100)
                vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl, self)
                group_name = "rg-%s-%d" % (inf.id, vm.im_id)
                storage_account_name = "st%d%d" % (now, vm.im_id)

                vm_name = radl.systems[0].getValue("instance_name")
                if vm_name:
                    vm_name = "%s%d" % (vm_name, now)
                else:
                    vm_name = "userimage%d" % now

                # Create resource group for the VM
                resource_client.resource_groups.create_or_update(group_name, {'location': location})

                # Create storage account
                storage_account, error_msg = self.create_storage_account(group_name, storage_account_name,
                                                                         credentials, subscription_id, location)

                if not storage_account:
                    res.append((False, error_msg))
                    resource_client.resource_groups.delete(group_name)
                    break

                nics = self.create_nics(inf, radl, credentials, subscription_id, group_name, subnets)

                instance_type = self.get_instance_type(radl.systems[0], credentials, subscription_id)
                vm_parameters = self.get_azure_vm_create_json(storage_account_name, vm_name, nics, radl, instance_type)

                compute_client = ComputeManagementClient(credentials, subscription_id)
                async_vm_creation = compute_client.virtual_machines.create_or_update(group_name, vm_name, vm_parameters)
                azure_vm = async_vm_creation.result()

                # Set the cloud id to the VM
                vm.id = group_name + '/' + vm_name
                vm.info.systems[0].setValue('instance_id', group_name + '/' + vm_name)

                self.attach_data_disks(vm, storage_account_name, credentials, subscription_id, location)

                res.append((True, vm))
            except Exception, ex:
                self.logger.exception("Error creating the VM")
                res.append((False, "Error creating the VM: " + str(ex)))

                # Delete Resource group and everything in it
                resource_client.resource_groups.delete(group_name)

            i += 1

        return res

    def attach_data_disks(self, vm, storage_account_name, credentials, subscription_id, location):
        """
        Attach the specified RADL disks to the VM
        """
        system = vm.info.systems[0]
        cont = 1
        group_name = vm.id.split('/')[0]
        vm_name = vm.id.split('/')[1]
        compute_client = ComputeManagementClient(credentials, subscription_id)

        while system.getValue("disk." + str(cont) + ".size"):
            disk_size = system.getFeature("disk." + str(cont) + ".size").getValue('G')

            try:
                # Attach data disk
                async_vm_update = compute_client.virtual_machines.create_or_update(
                    group_name,
                    vm_name,
                    {
                        'location': location,
                        'storage_profile': {
                            'data_disks': [{
                                'name': 'mydatadisk%d' % cont,
                                'disk_size_gb': disk_size,
                                'lun': 0,
                                'vhd': {
                                    'uri': "http://{}.blob.core.windows.net/vhds/mydatadisk1.vhd".format(
                                        storage_account_name)
                                },
                                'create_option': 'Empty'
                            }]
                        }
                    }
                )
                async_vm_update.wait()
            except Exception, ex:
                self.logger.exception("Error attaching disk %d to VM %s" % (cont, vm_name))
                return False, "Error attaching disk %d to VM %s: %s" % (cont, vm_name, str(ex))
            cont += 1

        return True, ""

    def updateVMInfo(self, vm, auth_data):
        self.logger.debug("Get the VM info with the id: " + vm.id)
        group_name = vm.id.split('/')[0]
        vm_name = vm.id.split('/')[1]

        try:
            credentials, subscription_id = self.get_credentials(auth_data)
            compute_client = ComputeManagementClient(credentials, subscription_id)
            # Get one the virtual machine by name
            virtual_machine = compute_client.virtual_machines.get(group_name, vm_name)
        except Exception, ex:
            if "NotFound" in str(ex):
                vm.state = VirtualMachine.OFF
                return (True, vm)
            else:
                self.logger.exception("Error getting the VM info: " + vm.id)
                return (False, "Error getting the VM info: " + vm.id + ". " + str(ex))

        self.logger.debug("VM info: " + vm.id + " obtained.")
        vm.state = self.PROVISION_STATE_MAP.get(virtual_machine.provisioning_state, VirtualMachine.UNKNOWN)
        self.logger.debug("The VM state is: " + vm.state)

        instance_type = self.get_instance_type_by_name(virtual_machine.hardware_profile.vm_size,
                                                       virtual_machine.location, credentials, subscription_id)
        self.update_system_info_from_instance(vm.info.systems[0], instance_type)

        # Update IP info
        self.setIPs(vm, virtual_machine.network_profile, credentials, subscription_id)
        return (True, vm)

    def setIPs(self, vm, network_profile, credentials, subscription_id):
        """
        Set the information about the IPs of the VM
        """

        private_ips = []
        public_ips = []

        network_client = NetworkManagementClient(credentials, subscription_id)

        for ni in network_profile.network_interfaces:
            name = " ".join(ni.id.split('/')[-1:])
            sub = "".join(ni.id.split('/')[4])

            ip_conf = network_client.network_interfaces.get(sub, name).ip_configurations

            for ip in ip_conf:
                private_ips.append(ip.private_ip_address)
                name = " ".join(ip.public_ip_address.id.split('/')[-1:])
                sub = "".join(ip.public_ip_address.id.split('/')[4])
                public_ip_info = network_client.public_ip_addresses.get(sub, name)
                public_ips.append(public_ip_info.ip_address)

        vm.setIps(public_ips, private_ips)

    def finalize(self, vm, auth_data):
        try:
            self.logger.debug("Terminate VM: " + vm.id)
            group_name = vm.id.split('/')[0]
            credentials, subscription_id = self.get_credentials(auth_data)

            # Delete Resource group and everything in it
            resource_client = ResourceManagementClient(credentials, subscription_id)
            self.logger.exception("Removing RG: %s" % group_name)
            resource_client.resource_groups.delete(group_name).wait()

            # if it is the last VM delete the RG of the Inf
            if vm.inf.is_last_vm(vm.id):
                self.logger.debug("Removing RG: %s" % "rg-%s" % vm.inf.id)
                resource_client.resource_groups.delete("rg-%s" % vm.inf.id)

        except Exception, ex:
            self.logger.exception("Error terminating the VM")
            return False, "Error terminating the VM: " + str(ex)

        return True, ""

    def stop(self, vm, auth_data):
        try:
            group_name = vm.id.split('/')[0]
            vm_name = vm.id.split('/')[1]
            credentials, subscription_id = self.get_credentials(auth_data)
            compute_client = ComputeManagementClient(credentials, subscription_id)
            compute_client.virtual_machines.power_off(group_name, vm_name)
        except Exception, ex:
            self.logger.exception("Error stopping the VM")
            return False, "Error stopping the VM: " + str(ex)

        return True, ""

    def start(self, vm, auth_data):
        try:
            group_name = vm.id.split('/')[0]
            vm_name = vm.id.split('/')[1]
            credentials, subscription_id = self.get_credentials(auth_data)
            compute_client = ComputeManagementClient(credentials, subscription_id)
            compute_client.virtual_machines.start(group_name, vm_name)
        except Exception, ex:
            self.logger.exception("Error starting the VM")
            return False, "Error starting the VM: " + str(ex)

        return True, ""

    def alterVM(self, vm, radl, auth_data):
        try:
            group_name = vm.id.split('/')[0]
            vm_name = vm.id.split('/')[1]
            credentials, subscription_id = self.get_credentials(auth_data)
            compute_client = ComputeManagementClient(credentials, subscription_id)

            # Deallocating the VM (resize prepare)
            async_vm_deallocate = compute_client.virtual_machines.deallocate(group_name, vm_name)
            async_vm_deallocate.wait()

            instance_type = self.get_instance_type(radl.systems[0], credentials, subscription_id)
            vm_parameters = " { 'hardware_profile': { 'vm_size': %s } } " % instance_type.name

            async_vm_update = compute_client.virtual_machines.create_or_update(group_name,
                                                                               vm_name,
                                                                               vm_parameters)
            async_vm_update.wait()

            # Start the VM
            async_vm_start = compute_client.virtual_machines.start(group_name, vm_name)
            async_vm_start.wait()

            return self.updateVMInfo(vm, auth_data)
        except Exception, ex:
            self.logger.exception("Error altering the VM")
            return False, "Error altering the VM: " + str(ex)

        return (True, "")
