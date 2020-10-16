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
import random
import string
import base64
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from .CloudConnector import CloudConnector
from radl.radl import Feature
from IM.config import Config

try:
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.dns import DnsManagementClient
    from azure.common.credentials import UserPassCredentials
    from azure.common.credentials import ServicePrincipalCredentials
    from msrestazure.azure_exceptions import CloudError
    from azure.mgmt.compute.models import DiskCreateOption, CachingTypes
except Exception as ex:
    print("WARN: Python Azure SDK not correctly installed. AzureCloudConnector will not work!.")
    print(ex)


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
    DEFAULT_LOCATION = "westeurope"
    """Default location to use"""
    DEFAULT_USER = 'azureuser'
    """ default user to SSH access the VM """

    PROVISION_STATE_MAP = {
        'Accepted': VirtualMachine.PENDING,
        'Canceled': VirtualMachine.FAILED,
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
        'PowerState/deallocated': VirtualMachine.OFF,
        'PowerState/deallocating': VirtualMachine.OFF,
        'PowerState/running': VirtualMachine.RUNNING,
        'PowerState/starting': VirtualMachine.PENDING,
        'PowerState/started': VirtualMachine.PENDING,
        'PowerState/stopped': VirtualMachine.STOPPED
    }

    def __init__(self, cloud_info, inf):
        self.credentials = None
        self.auth = None
        CloudConnector.__init__(self, cloud_info, inf)

    def get_credentials(self, auth_data):
        auths = auth_data.getAuthInfo(self.type)
        if not auths:
            raise Exception("No auth data has been specified to Azure.")
        else:
            auth = auths[0]

        if 'subscription_id' in auth and 'username' in auth and 'password' in auth:
            subscription_id = auth['subscription_id']

            if self.credentials and self.auth.compare(auth_data, self.type):
                return self.credentials, subscription_id
            else:
                self.auth = auth_data
                self.credentials = UserPassCredentials(auth['username'], auth['password'])
        elif 'subscription_id' in auth and 'client_id' in auth and 'secret' in auth and 'tenant' in auth:
            subscription_id = auth['subscription_id']

            if self.credentials and self.auth.compare(auth_data, self.type):
                return self.credentials, subscription_id
            else:
                self.auth = auth_data
                self.credentials = ServicePrincipalCredentials(client_id=auth['client_id'],
                                                               secret=auth['secret'],
                                                               tenant=auth['tenant'])
        else:
            raise Exception("No correct auth data has been specified to Azure: "
                            "subscription_id, username and password or"
                            "subscription_id, client_id, secret and tenant")

        return self.credentials, subscription_id

    @staticmethod
    def get_instance_type_by_name(instance_name, location, credentials, subscription_id):
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

        (cpu, cpu_op, memory, memory_op, disk_free, disk_free_op) = self.get_instance_selectors(system)

        compute_client = ComputeManagementClient(credentials, subscription_id)
        instace_types = list(compute_client.virtual_machine_sizes.list(location))
        instace_types.sort(key=lambda x: (x.number_of_cores, x.memory_in_mb, x.resource_disk_size_in_mb))

        default = None
        for instace_type in instace_types:
            if instace_type.name == self.INSTANCE_TYPE:
                default = instace_type

            comparison = cpu_op(instace_type.number_of_cores, cpu)
            comparison = comparison and memory_op(instace_type.memory_in_mb, memory)
            comparison = comparison and disk_free_op(instace_type.resource_disk_size_in_mb, disk_free)

            if comparison:
                if not instance_type_name or instace_type.name == instance_type_name:
                    return instace_type

        return default

    @staticmethod
    def update_system_info_from_instance(system, instance_type):
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

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]

        if protocol == "azr":
            credentials, subscription_id = self.get_credentials(auth_data)

            instance_type = self.get_instance_type(radl_system, credentials, subscription_id)
            if not instance_type:
                self.log_error("Error generating the RADL of the VM, no instance type available for the requirements.")
                self.log_debug(radl_system)
                return None

            res_system = radl_system.clone()
            username = res_system.getValue('disk.0.os.credentials.username')
            if not username:
                res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)

            # In Azure we always need to set a password
            password = res_system.getValue('disk.0.os.credentials.password')
            if not password:
                password = ''.join(random.choice(string.ascii_letters + string.digits + "+-*_$@#=<>[]")
                                   for _ in range(16))
                res_system.setValue('disk.0.os.credentials.password', password)

            res_system.updateNewCredentialValues()

            return res_system
        else:
            return None

    @staticmethod
    def get_rg(group_name, credentials, subscription_id):
        """
        Get the RG named group_name, if it not exists return None
        """
        try:
            resource_client = ResourceManagementClient(credentials, subscription_id)
            return resource_client.resource_groups.get(group_name)
        except CloudError as cex:
            if cex.status_code == 404:
                return None
            else:
                raise cex

    @staticmethod
    def get_storage_account(group_name, storage_name, credentials, subscription_id):
        """
        Get the Storage Account named storage_name in group_name, if it not exists return None
        """
        try:
            storage_client = StorageManagementClient(credentials, subscription_id)
            return storage_client.storage_accounts.get_properties(group_name, storage_name)
        except CloudError as cex:
            if cex.status_code == 404:
                return None
            else:
                raise cex

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
        cont = 200
        for outport in outports:
            sr = {'access': 'Allow',
                  'protocol': outport.get_protocol(),
                  'destination_address_prefix': '*',
                  'source_address_prefix': '*',
                  'direction': 'Inbound',
                  'source_port_range': '*',
                  'priority': cont
                  }
            cont += 100
            if outport.is_range():
                sr['name'] = 'sr-%s-%d-%d' % (outport.get_protocol(),
                                              outport.get_port_init(),
                                              outport.get_port_end())
                sr['destination_port_range'] = "%d-%d" % (outport.get_port_init(), outport.get_port_end())
                security_rules.append(sr)
            elif outport.get_local_port() != 22:
                sr['name'] = 'sr-%s-%d-%d' % (outport.get_protocol(),
                                              outport.get_remote_port(),
                                              outport.get_local_port())
                sr['destination_port_range'] = str(outport.get_local_port())
                security_rules.append(sr)

        params = {
            'location': location,
            'security_rules': security_rules
        }

        ngs = None
        try:
            ngs = network_client.network_security_groups.create_or_update(group_name, nsg_name, params).result()
        except Exception:
            self.log_exception("Error creating NGS")

        return ngs

    def create_nics(self, radl, credentials, subscription_id, group_name, subnets):
        """Create a Network Interface for a VM.
        """
        system = radl.systems[0]
        network_client = NetworkManagementClient(credentials, subscription_id)

        location = self.DEFAULT_LOCATION
        if radl.systems[0].getValue('availability_zone'):
            location = radl.systems[0].getValue('availability_zone')

        i = 0
        hasPublicIP = False
        hasPrivateIP = False
        outports = None
        while system.getValue("net_interface." + str(i) + ".connection"):
            network_name = system.getValue("net_interface." + str(i) + ".connection")
            # TODO: check how to do that
            # fixed_ip = system.getValue("net_interface." + str(i) + ".ip")
            network = radl.get_network_by_id(network_name)

            if network.isPublic():
                hasPublicIP = True
                outports = network.getOutPorts()
            else:
                hasPrivateIP = True

            i += 1

        i = 0
        res = []
        publicAdded = False
        while system.getValue("net_interface." + str(i) + ".connection"):
            network_name = system.getValue("net_interface." + str(i) + ".connection")
            # TODO: check how to do that
            # fixed_ip = system.getValue("net_interface." + str(i) + ".ip")
            network = radl.get_network_by_id(network_name)

            if network.isPublic() and hasPrivateIP:
                # Public nets are not added as nics
                i += 1
                continue

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

            primary = False
            if hasPublicIP and not publicAdded:
                # Create PublicIP
                publicAdded = True
                primary = True
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
                if outports:
                    nsg_name = network.getValue("sg_name")
                    if not nsg_name:
                        nsg_name = "nsg-%d" % i
                    nsg = self.create_ngs(location, group_name, nsg_name, outports, network_client)
                    if nsg:
                        nic_params['network_security_group'] = {'id': nsg.id}

            async_nic_creation = network_client.network_interfaces.create_or_update(
                group_name, nic_name, nic_params)
            nic = async_nic_creation.result()
            res.append((nic, primary))

            i += 1

        return res

    def get_azure_vm_create_json(self, group_name, storage_account, vm_name, nics, radl,
                                 instance_type, custom_data, compute_client, tags):
        """ Create the VM parameters structure. """
        system = radl.systems[0]
        url = urlparse(system.getValue("disk.0.image.url"))
        # the url has to have the format: azr://publisher/offer/sku/version
        # azr://Canonical/UbuntuServer/16.04.0-LTS/latest
        # azr://MicrosoftWindowsServerEssentials/WindowsServerEssentials/WindowsServerEssentials/latest
        image_values = (url[1] + url[2]).split("/")
        if len(image_values) not in [3, 4]:
            raise Exception("The Azure image has to have the format: azr://publisher/offer/sku/version"
                            " or azr://[snapshots|disk]/rgname/diskname")

        location = self.DEFAULT_LOCATION
        if system.getValue('availability_zone'):
            location = system.getValue('availability_zone')

        # Always use the new credentials
        system.updateNewCredentialValues()
        user_credentials = system.getCredentials()

        if custom_data:
            custom_data = base64.b64encode(custom_data.encode()).decode()

        vm = {
            'location': location,
            'hardware_profile': {
                'vm_size': instance_type.name
            },
            'network_profile': {
                'network_interfaces': [{'id': nic.id, 'primary': primary} for nic, primary in nics]
            },
        }

        if len(image_values) == 3:
            os_disk_name = "osdisk-" + str(uuid.uuid1())
            if image_values[0] == "snapshot":
                managed_disk = compute_client.snapshots.get(image_values[1], image_values[2])
            elif image_values[0] == "disk":
                managed_disk = compute_client.disks.get(image_values[1], image_values[2])
            else:
                raise Exception("Incorrect image url: it must be snapshot or disk.")

            async_creation = compute_client.disks.create_or_update(
                group_name,
                os_disk_name,
                {
                    'location': location,
                    'creation_data': {
                        'create_option': DiskCreateOption.copy,
                        'source_resource_id': managed_disk.id
                    }
                }
            )

            os_type = system.getValue("disk.0.os.name")
            os_type = os_type if os_type else "Linux"
            self.log_info("Creating OS disk %s of type %s from disk: %s/%s/%s." % (os_disk_name,
                                                                                   os_type,
                                                                                   image_values[0],
                                                                                   image_values[1],
                                                                                   image_values[2]))
            disk_resource = async_creation.result()

            vm['storage_profile'] = {
                'os_disk': {
                    'create_option': DiskCreateOption.attach,
                    'os_type': os_type,
                    'caching': CachingTypes.read_write,
                    'managed_disk': {
                        'id': disk_resource.id
                    }
                }
            }
        else:
            vm['storage_profile'] = {
                'image_reference': {
                    'publisher': image_values[0],
                    'offer': image_values[1],
                    'sku': image_values[2],
                    'version': image_values[3]
                }
            }
            vm['os_profile'] = {
                'computer_name': vm_name,
                'admin_username': user_credentials.username,
                'admin_password': user_credentials.password,
                'custom_data': custom_data
            }

        if tags:
            vm['tags'] = tags

        cont = 1
        data_disks = []
        while system.getValue("disk." + str(cont) + ".size") or system.getValue("disk." + str(cont) + ".image.url"):
            disk_image = system.getValue("disk." + str(cont) + ".image.url")
            if disk_image:
                disk_parts = disk_image.split("/")
                if len(disk_parts) != 2:
                    raise Exception("Invalid format in disk." + str(cont) + ".image.url: rg_name/disk_name")
                managed_disk = compute_client.disks.get(disk_parts[0], disk_parts[1])
                data_disks.append({
                    'name': managed_disk.name,
                    'lun': cont - 1,
                    'managed_disk': {
                        'id': managed_disk.id
                    },
                    'create_option': DiskCreateOption.attach
                })
            else:
                disk_size = system.getFeature("disk." + str(cont) + ".size").getValue('G')
                self.log_info("Adding a %s GB disk." % disk_size)
                data_disks.append({
                    'name': '%s_disk_%d' % (vm_name, cont),
                    'disk_size_gb': disk_size,
                    'lun': cont - 1,
                    'create_option': DiskCreateOption.empty
                })
            cont += 1

        if data_disks:
            vm['storage_profile']['data_disks'] = data_disks

        return vm

    def create_nets(self, radl, credentials, subscription_id, group_name, inf):
        network_client = NetworkManagementClient(credentials, subscription_id)
        location = self.DEFAULT_LOCATION
        if radl.systems[0].getValue('availability_zone'):
            location = radl.systems[0].getValue('availability_zone')
        # check if the vnet exists
        vnet = None
        try:
            vnet = network_client.virtual_networks.get(group_name, "privates")
        except Exception:
            pass

        if not vnet:
            vnet_cird = self.get_nets_common_cird(radl)
            # Create VNet in the RG of the Inf
            async_vnet_creation = network_client.virtual_networks.create_or_update(
                group_name,
                "privates",
                {
                    'location': location,
                    'address_space': {
                        'address_prefixes': [vnet_cird]
                    }
                }
            )
            async_vnet_creation.wait()

            subnets = {}
            used_cidrs = []
            for net in radl.networks:
                subnet_name = net.id
                net_cidr = self.get_free_cidr(net.getValue('cidr'), used_cidrs, inf)
                used_cidrs.append(net_cidr)

                # Create Subnet in the RG of the Inf
                async_subnet_creation = network_client.subnets.create_or_update(
                    group_name,
                    "privates",
                    subnet_name,
                    {'address_prefix': net_cidr}
                )
                subnets[net.id] = async_subnet_creation.result()
                net.setValue('cidr', net_cidr)
                # Set also the cidr in the inf RADL
                inf.radl.get_network_by_id(net.id).setValue('cidr', net_cidr)
        else:
            subnets = {}
            for i, net in enumerate(radl.networks):
                subnets[net.id] = network_client.subnets.get(group_name, "privates", net.id)

        return subnets

    def create_vms(self, inf, radl, requested_radl, num_vm, location, storage_account_name,
                   subnets, credentials, subscription_id, tags):
        """
        Creates a set of VMs
        """
        resource_client = ResourceManagementClient(credentials, subscription_id)
        vms = []
        i = 0
        while i < num_vm:
            vm_name = self.gen_instance_name(radl.systems[0])
            group_name = "rg-%s" % (vm_name)

            try:
                args = {'location': location}
                if tags:
                    args['tags'] = tags

                # Create resource group for the VM
                resource_client.resource_groups.create_or_update(group_name, args)
                compute_client = ComputeManagementClient(credentials, subscription_id)

                vm = VirtualMachine(inf, group_name + '/' + vm_name, self.cloud, radl, requested_radl, self)
                vm.info.systems[0].setValue('instance_id', group_name + '/' + vm_name)

                nics = self.create_nics(radl, credentials, subscription_id, group_name, subnets)

                custom_data = self.get_cloud_init_data(radl, vm)
                instance_type = self.get_instance_type(radl.systems[0], credentials, subscription_id)
                vm_parameters = self.get_azure_vm_create_json(group_name, storage_account_name, vm_name,
                                                              nics, radl, instance_type, custom_data,
                                                              compute_client, tags)

                async_vm_creation = compute_client.virtual_machines.create_or_update(group_name,
                                                                                     vm_name,
                                                                                     vm_parameters)

                self.log_info("VM ID: %s created." % vm.id)
                inf.add_vm(vm)
                vms.append((True, (vm, async_vm_creation)))
            except Exception as ex:
                vms.append((False, "Error creating the VM: %s" % str(ex)))
                self.log_exception("Error creating the VM")

                # Delete Resource group and everything in it
                if group_name:
                    self.delete_resource_group(group_name, resource_client)

            i += 1

        return vms

    @staticmethod
    def get_storage_account_name(inf_id):
        # Storage account name must be between 3 and 24 characters in length and use
        # numbers and lower-case letters only
        storage_account_name = "s%s" % inf_id
        storage_account_name = storage_account_name.replace("-", "")
        storage_account_name = storage_account_name[:24]
        return storage_account_name

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        location = self.DEFAULT_LOCATION
        if radl.systems[0].getValue('availability_zone'):
            location = radl.systems[0].getValue('availability_zone')
        else:
            radl.systems[0].setValue('availability_zone', location)

        credentials, subscription_id = self.get_credentials(auth_data)

        url = urlparse(radl.systems[0].getValue("disk.0.image.url"))
        # the url has to have the format: azr://publisher/offer/sku/version or
        # azr://[snapshots|disk|image]/rgname/diskname
        # azr://Canonical/UbuntuServer/16.04.0-LTS/latest
        # azr://MicrosoftWindowsServerEssentials/WindowsServerEssentials/WindowsServerEssentials/latest
        image_values = (url[1] + url[2]).split("/")
        if len(image_values) not in [3, 4]:
            raise Exception("The Azure image has to have the format: azr://publisher/offer/sku/version"
                            " or azr://[snapshots|disk|image]/rgname/diskname")
        if len(image_values) == 3 and image_values[0] not in ["snapshot", "disk"]:
            raise Exception("Incorrect image url: it must be snapshot or disk.")

        resource_client = ResourceManagementClient(credentials, subscription_id)
        storage_account_name = self.get_storage_account_name(inf.id)

        tags = self.get_instance_tags(radl.systems[0], auth_data, inf)

        with inf._lock:
            # Create resource group for the Infrastructure if it does not exists
            if not self.get_rg("rg-%s" % inf.id, credentials, subscription_id):
                self.log_info("Creating Inf RG: %s" % "rg-%s" % inf.id)
                resource_client.resource_groups.create_or_update("rg-%s" % inf.id, {'location': location})

            # Create an storage_account per Infrastructure
            storage_account = self.get_storage_account("rg-%s" % inf.id, storage_account_name,
                                                       credentials, subscription_id)

            if not storage_account:
                self.log_info("Creating storage account: %s" % storage_account_name)
                try:
                    storage_client = StorageManagementClient(credentials, subscription_id)
                    storage_client.storage_accounts.create("rg-%s" % inf.id,
                                                           storage_account_name,
                                                           {'sku': {'name': 'standard_lrs'},
                                                            'kind': 'storage',
                                                            'location': location}
                                                           ).wait()
                except Exception:
                    self.log_exception("Error creating storage account: %s" % storage_account)
                    self.delete_resource_group("rg-%s" % inf.id, resource_client)

            subnets = self.create_nets(radl, credentials, subscription_id, "rg-%s" % inf.id, inf)

        res = []
        vms = self.create_vms(inf, radl, requested_radl, num_vm, location,
                              storage_account_name, subnets, credentials, subscription_id, tags)

        remaining_vms = num_vm
        for success, data in vms:
            if success:
                vm, async_vm_creation = data
                try:
                    self.log_debug("Waiting VM ID %s to be created." % vm.id)
                    async_vm_creation.wait()
                    res.append((True, vm))
                    remaining_vms -= 1
                except Exception as ex:
                    self.log_exception("Error waiting the VM %s." % vm.id)

                    # Delete created resources for this VM
                    try:
                        group_name = vm.id.split('/')[0]
                        self.delete_resource_group(group_name, resource_client)
                    except Exception:
                        self.log_exception("Error removing resource group: %s." % group_name)

                    res.append((False, "Error waiting the VM %s: %s" % (vm.id, str(ex))))
            else:
                res.append((False, data))

        if remaining_vms == 0:
            self.log_debug("All VMs created successfully.")

        return res

    def updateVMInfo(self, vm, auth_data):
        self.log_info("Get the VM info with the id: " + vm.id)
        group_name = vm.id.split('/')[0]
        vm_name = vm.id.split('/')[1]

        credentials, subscription_id = self.get_credentials(auth_data)

        try:
            compute_client = ComputeManagementClient(credentials, subscription_id)
            # Get one the virtual machine by name
            virtual_machine = compute_client.virtual_machines.get(group_name, vm_name, expand='instanceView')
        except Exception as ex:
            self.log_warn("The VM does not exists: %s" % str(ex))
            # check if the RG still exists
            if self.get_rg(group_name, credentials, subscription_id):
                self.log_info("But the RG %s does exits. Return OFF." % group_name)
                vm.state = VirtualMachine.OFF
                return (True, vm)

            self.log_exception("Error getting the VM info: " + vm.id)
            return (False, "Error getting the VM info: " + vm.id + ". " + str(ex))

        self.log_info("VM info: " + vm.id + " obtained.")
        vm.state = self.PROVISION_STATE_MAP.get(virtual_machine.provisioning_state, VirtualMachine.UNKNOWN)

        if (vm.state == VirtualMachine.RUNNING and virtual_machine.instance_view and
                len(virtual_machine.instance_view.statuses) > 1):
            vm.state = self.POWER_STATE_MAP.get(virtual_machine.instance_view.statuses[1].code, VirtualMachine.UNKNOWN)

        self.log_debug("The VM state is: " + vm.state)

        instance_type = self.get_instance_type_by_name(virtual_machine.hardware_profile.vm_size,
                                                       virtual_machine.location, credentials, subscription_id)
        self.update_system_info_from_instance(vm.info.systems[0], instance_type)

        # Update IP info
        self.setIPs(vm, virtual_machine.network_profile, credentials, subscription_id)
        self.add_dns_entries(vm, credentials, subscription_id)
        return (True, vm)

    def add_dns_entries(self, vm, credentials, subscription_id):
        """
        Add the required entries in the Azure DNS service

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - credentials, subscription_id: Authentication data to access cloud provider.
        """
        try:
            group_name = vm.id.split('/')[0]
            dns_client = DnsManagementClient(credentials, subscription_id)
            system = vm.info.systems[0]
            for net_name in system.getNetworkIDs():
                num_conn = system.getNumNetworkWithConnection(net_name)
                ip = system.getIfaceIP(num_conn)
                (hostname, domain) = vm.getRequestedNameIface(num_conn,
                                                              default_hostname=Config.DEFAULT_VM_NAME,
                                                              default_domain=Config.DEFAULT_DOMAIN)
                if domain != "localdomain" and ip:
                    zone = None
                    try:
                        zone = dns_client.zones.get(group_name, domain)
                    except Exception:
                        pass
                    if not zone:
                        self.log_info("Creating DNS zone %s" % domain)
                        zone = dns_client.zones.create_or_update(group_name, domain,
                                                                 {'location': 'global'})
                    else:
                        self.log_info("DNS zone %s exists. Do not create." % domain)

                    if zone:
                        record = None
                        try:
                            record = dns_client.record_sets.get(group_name, domain, hostname, 'A')
                        except Exception:
                            pass
                        if not record:
                            self.log_info("Creating DNS record %s." % hostname)
                            record_data = {"ttl": 300, "arecords": [{"ipv4_address": ip}]}
                            dns_client.record_sets.create_or_update(group_name, domain, hostname, 'A', record_data)
                        else:
                            self.log_info("DNS record %s exists. Do not create." % hostname)

            return True
        except Exception:
            self.log_exception("Error creating DNS entries")
            return False

    @staticmethod
    def setIPs(vm, network_profile, credentials, subscription_id):
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
                if ip.private_ip_address:
                    private_ips.append(ip.private_ip_address)
                if ip.public_ip_address:
                    name = " ".join(ip.public_ip_address.id.split('/')[-1:])
                    sub = "".join(ip.public_ip_address.id.split('/')[4])
                    public_ip_info = network_client.public_ip_addresses.get(sub, name)
                    public_ips.append(public_ip_info.ip_address)

        vm.setIps(public_ips, private_ips)

    def finalize(self, vm, last, auth_data):
        credentials, subscription_id = self.get_credentials(auth_data)

        try:
            resource_client = ResourceManagementClient(credentials, subscription_id)

            if vm.id:
                self.log_info("Terminate VM: %s" % vm.id)
                group_name = vm.id.split('/')[0]

                # Delete Resource group and everything in it
                if self.get_rg(group_name, credentials, subscription_id):
                    deleted, msg = self.delete_resource_group(group_name, resource_client)
                    if not deleted:
                        return False, "Error terminating the VM: %s" % msg
                else:
                    self.log_info("RG: %s does not exist. Do not remove." % group_name)
            else:
                self.log_warn("No VM ID. Ignoring")

            # if it is the last VM delete the RG of the Inf
            if last:
                if self.get_rg("rg-%s" % vm.inf.id, credentials, subscription_id):
                    deleted, msg = self.delete_resource_group("rg-%s" % vm.inf.id, resource_client)
                    if not deleted:
                        return False, "Error terminating the VM: %s" % msg
                else:
                    self.log_info("RG: %s does not exist. Do not remove." % "rg-%s" % vm.inf.id)

        except Exception as ex:
            self.log_exception("Error terminating the VM")
            return False, "Error terminating the VM: " + str(ex)

        return True, ""

    def stop(self, vm, auth_data):
        return self.vm_action(vm, 'stop', auth_data)

    def start(self, vm, auth_data):
        return self.vm_action(vm, 'start', auth_data)

    def reboot(self, vm, auth_data):
        return self.vm_action(vm, 'reboot', auth_data)

    def vm_action(self, vm, action, auth_data):
        try:
            group_name = vm.id.split('/')[0]
            vm_name = vm.id.split('/')[1]
            credentials, subscription_id = self.get_credentials(auth_data)
            compute_client = ComputeManagementClient(credentials, subscription_id)
            if action == 'stop':
                compute_client.virtual_machines.power_off(group_name, vm_name)
            elif action == 'start':
                compute_client.virtual_machines.start(group_name, vm_name)
            elif action == 'reboot':
                compute_client.virtual_machines.restart(group_name, vm_name)
        except Exception as ex:
            self.log_exception("Error restarting the VM")
            return False, "Error restarting the VM: " + str(ex)

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
        except Exception as ex:
            self.log_exception("Error altering the VM")
            return False, "Error altering the VM: " + str(ex)

        return (True, "")

    def delete_resource_group(self, group_name, resource_client, max_retries=3):
        """
        Delete a RG with retries
        """
        cont = 0
        msg = ""
        deleted = False

        self.log_info("Delete RG %s." % group_name)
        while cont < max_retries and not deleted:
            cont += 1
            try:
                resource_client.resource_groups.delete(group_name).wait()
                deleted = True
            except Exception as ex:
                msg = str(ex)
                self.log_exception("Error deleting Resource group %s (%d/%d)." % (group_name, cont, max_retries))

        if not deleted:
            self.log_error("Resource group %s cannot be deleted!!!" % group_name)
        else:
            self.log_info("Resource group %s successfully deleted." % group_name)

        return deleted, msg
