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
from netaddr import IPNetwork, IPAddress
from IM.config import Config

try:
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.dns import DnsManagementClient
    from azure.core.exceptions import ResourceNotFoundError
    from azure.mgmt.compute.models import DiskCreateOption, CachingTypes, DeleteOptions
except Exception as ex:
    print("WARN: Python Azure SDK not installed. AzureCloudConnector will not work!.")
    print(ex)

try:
    from azure.common.credentials import UserPassCredentials
    from azure.common.credentials import ServicePrincipalCredentials
except Exception as ex:
    print("WARN: Python azure.common.credentials not installed. AzureCloudConnector may not work properly!.")
    print(ex)

try:
    from azure.identity import ClientSecretCredential
    from azure.identity import UsernamePasswordCredential
    AZURE_IDENTITY_AVAILABLE = True
except Exception as ex:
    AZURE_IDENTITY_AVAILABLE = False
    print("WARN: Python azure-identity not installed. AzureCloudConnector may not work properly!.")
    print(ex)


class AzureInstanceTypeInfo:
    """
    Information about the instance type

    Args:
            - name(str, optional): name of the type of the instance
            - cpu(int, optional): number of cpus
            - mem(int, optional): amount of memory
            - disk_space(int, optional): size of the disks
            - gpu(int, optional): the number of gpus of this instance
            - gpu_model(str, optional): the model of the gpus of this instance
            - gpu_vendor(str, optional): the model of the gpus of this instance
    """

    def __init__(self, name="", cpu=1, mem=0, os_disk_space=0, res_disk_space=0,
                 gpu=0, gpu_model=None, gpu_vendor=None):
        self.name = name
        self.cpu = cpu
        self.mem = mem
        self.os_disk_space = os_disk_space
        self.res_disk_space = res_disk_space
        self.gpu = gpu
        self.gpu_model = gpu_model
        self.gpu_vendor = gpu_vendor

    def set_gpu_models(self):
        """Guess GPU models from instance name"""
        if self.name.startswith('Standard_NC'):
            self.gpu_vendor = "NVIDIA"
            if self.name.endswith('v2'):
                self.gpu_model = "Tesla P100"
            elif self.name.endswith('v3'):
                self.gpu_model = "Tesla V100"
            else:
                self.gpu_model = "Tesla K80"
        elif self.name.startswith('Standard_NCasT4'):
            self.gpu_vendor = "NVIDIA"
            self.gpu_model = "Tesla T4"
        elif self.name.startswith('Standard_ND'):
            self.gpu_vendor = "NVIDIA"
            if self.name.endswith('v2'):
                self.gpu_model = "Tesla V100"
            else:
                self.gpu_model = "Tesla P40"
        elif self.name.startswith('Standard_NV'):
            self.gpu_vendor = "NVIDIA"
            if self.name.endswith('v3'):
                self.gpu_model = "Tesla M60"
            elif self.name.endswith('v4'):
                self.gpu_vendor = "AMD"
                self.gpu_model = "Radeon instinto MI25"
            else:
                self.gpu_model = "Tesla M60"

    @staticmethod
    def fromSKU(sku):
        """Get an instance type object from SKU Json data"""
        gpu = os_disk_space = res_disk_space = mem = cpu = 0
        for elem in sku.capabilities:
            if elem.name == "vCPUs":
                cpu = int(elem.value)
            elif elem.name == "MemoryGB":
                mem = float(elem.value) * 1024
            elif elem.name == "MaxResourceVolumeMB":
                res_disk_space = int(elem.value)
            elif elem.name == "OSVhdSizeMB":
                os_disk_space = int(elem.value)
            elif elem.name == "GPUs":
                gpu = int(elem.value)
        instance_type = AzureInstanceTypeInfo(sku.name, cpu, mem, os_disk_space, res_disk_space, gpu)
        instance_type.set_gpu_models()
        return instance_type


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

        if 'subscription_id' in auth and 'client_id' in auth and 'secret' in auth and 'tenant' in auth:
            subscription_id = auth['subscription_id']

            if self.credentials and self.auth.compare(auth_data, self.type):
                return self.credentials, subscription_id
            else:
                self.auth = auth_data
                if AZURE_IDENTITY_AVAILABLE:
                    self.credentials = ClientSecretCredential(tenant_id=auth['tenant'],
                                                              client_id=auth['client_id'],
                                                              client_secret=auth['secret'])
                else:
                    self.credentials = ServicePrincipalCredentials(client_id=auth['client_id'],
                                                                   secret=auth['secret'],
                                                                   tenant=auth['tenant'])
        elif 'subscription_id' in auth and 'username' in auth and 'password' in auth:
            subscription_id = auth['subscription_id']

            if self.credentials and self.auth.compare(auth_data, self.type):
                return self.credentials, subscription_id
            else:
                self.auth = auth_data
                if AZURE_IDENTITY_AVAILABLE and 'client_id' in auth:
                    self.credentials = UsernamePasswordCredential(client_id=auth['client_id'],
                                                                  username=auth['username'],
                                                                  password=auth['password'])
                else:
                    self.credentials = UserPassCredentials(auth['username'], auth['password'])
        else:
            raise Exception("No correct auth data has been specified to Azure: "
                            "subscription_id, username and password or"
                            "subscription_id, client_id, secret and tenant")

        return self.credentials, subscription_id

    def get_instance_type_by_name(self, instance_name, location, credentials, subscription_id):
        instace_types = self.get_instance_type_list(credentials, subscription_id, location)

        for instace_type in list(instace_types):
            if instace_type.name == instance_name:
                return instace_type

        return None

    def get_instance_type_list(self, credentials, subscription_id, location):
        compute_client = ComputeManagementClient(credentials, subscription_id)

        try:
            skus = list(compute_client.resource_skus.list(filter="location eq '%s'" % location))
            inst_types = [AzureInstanceTypeInfo.fromSKU(sku) for sku in skus if sku.resource_type == "virtualMachines"]
            inst_types.sort(key=lambda x: (x.cpu, x.mem, x.gpu, x.res_disk_space))
            return inst_types
        except Exception:
            self.log_exception("Error getting instance type list.")
            return []

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
        num_gpus = system.getValue('gpu.count')
        gpu_model = system.getValue('gpu.model')
        gpu_vendor = system.getValue('gpu.vendor')

        instace_types = self.get_instance_type_list(credentials, subscription_id, location)

        default = None
        for instace_type in instace_types:
            if instace_type.name == self.INSTANCE_TYPE:
                default = instace_type

            comparison = cpu_op(instace_type.cpu, cpu)
            comparison = comparison and memory_op(instace_type.mem, memory)
            comparison = comparison and disk_free_op(instace_type.res_disk_space, disk_free)

            if num_gpus:
                if num_gpus > instace_type.gpu:
                    continue
                if gpu_vendor and gpu_vendor.lower() != instace_type.gpu_vendor.lower():
                    return False
                if gpu_model and gpu_model.lower() != instace_type.gpu_model.lower():
                    return False

            if comparison:
                if not instance_type_name or instace_type.name == instance_type_name:
                    return instace_type

        return default

    @staticmethod
    def update_system_info_from_instance(system, instance_type):
        """
        Update the features of the system with the information of the instance_type
        """
        system.addFeature(Feature("cpu.count", "=", instance_type.cpu),
                          conflict="other", missing="other")
        system.addFeature(Feature("memory.size", "=", instance_type.mem, 'M'),
                          conflict="other", missing="other")
        system.addFeature(Feature("disks.free_size", "=", instance_type.res_disk_space, 'M'),
                          conflict="other", missing="other")
        system.addFeature(Feature("instance_type", "=", instance_type.name),
                          conflict="other", missing="other")
        if instance_type.gpu:
            system.addFeature(Feature("gpu.count", "=", instance_type.gpu),
                              conflict="other", missing="other")
        if instance_type.gpu_model:
            system.addFeature(Feature("gpu.model", "=", instance_type.gpu_model),
                              conflict="other", missing="other")
        if instance_type.gpu_vendor:
            system.addFeature(Feature("gpu.vendor", "=", instance_type.gpu_vendor),
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
        except ResourceNotFoundError:
            return None

    def create_nsgs(self, radl, location, group_name, credentials, subscription_id, inf):
        """
        Create all needed Network Security Groups (usually only 1)
        """
        i = 0
        res = {}
        network_client = NetworkManagementClient(credentials, subscription_id)
        while radl.systems[0].getValue("net_interface." + str(i) + ".connection"):
            network_name = radl.systems[0].getValue("net_interface." + str(i) + ".connection")
            i += 1
            network = radl.get_network_by_id(network_name)
            if network.isPublic():
                outports = self.add_ssh_port(network.getOutPorts())
                nsg_name = network.getValue("sg_name")
                if not nsg_name:
                    nsg_name = "nsg-%s" % network_name
                nsg = self.create_nsg(location, group_name, nsg_name, outports, network_client, inf)
                res[network_name] = nsg
        return res

    def create_nsg(self, location, group_name, nsg_name, outports, network_client, inf):
        """
        Create a Network Security Group
        """
        security_rules = []
        cont = 200
        for outport in outports:
            sr = {'access': 'Allow',
                  'protocol': outport.get_protocol(),
                  'destination_address_prefix': '*',
                  'source_address_prefix': outport.get_remote_cidr(),
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
            else:
                sr['name'] = 'sr-%s-%d-%d' % (outport.get_protocol(),
                                              outport.get_remote_port(),
                                              outport.get_local_port())
                sr['destination_port_range'] = str(outport.get_local_port())
                security_rules.append(sr)

        params = {
            'location': location,
            'tags': {'InfID': inf.id},
            'security_rules': security_rules
        }

        ngs = None
        try:
            ngs = network_client.network_security_groups.begin_create_or_update(group_name, nsg_name, params).result()
        except Exception:
            self.log_exception("Error creating NGS")

        return ngs

    def create_nics(self, radl, credentials, subscription_id, group_name, subnets, ngss, vm_id, inf):
        """Create a Network Interface for a VM."""
        system = radl.systems[0]
        network_client = NetworkManagementClient(credentials, subscription_id)

        location = self.DEFAULT_LOCATION
        if radl.systems[0].getValue('availability_zone'):
            location = radl.systems[0].getValue('availability_zone')

        i = 0
        hasPublicIP = False
        hasPrivateIP = False
        pub_network_name = None
        publicAdded = False
        while system.getValue("net_interface." + str(i) + ".connection"):
            network_name = system.getValue("net_interface." + str(i) + ".connection")
            network = radl.get_network_by_id(network_name)

            if network.isPublic():
                hasPublicIP = True
                pub_network_name = network_name
            else:
                hasPrivateIP = True

            if not publicAdded and network_name in subnets:
                subnet_network_mask = IPNetwork(subnets[network_name].address_prefix)
                is_private = any([IPAddress(subnet_network_mask.ip) in IPNetwork(mask)
                                  for mask in Config.PRIVATE_NET_MASKS])
                if not is_private:
                    publicAdded = True

            i += 1

        i = 0
        res = []
        while system.getValue("net_interface." + str(i) + ".connection"):
            network_name = system.getValue("net_interface." + str(i) + ".connection")
            fixed_ip = system.getValue("net_interface." + str(i) + ".ip")
            network = radl.get_network_by_id(network_name)

            if network.isPublic() and hasPrivateIP:
                # Public nets are not added as nics
                i += 1
                continue

            nic_name = "nic-%d-%d" % (vm_id, i)
            ip_config_name = "ip-config-%d-%d" % (vm_id, i)

            # Create NIC
            nic_params = {
                'location': location,
                'tags': {'InfID': inf.id},
                'ip_configurations': [{
                    'name': ip_config_name,
                    'subnet': {'id': subnets[network_name].id}
                }]
            }

            primary = False
            public_ip_name = None
            if hasPublicIP and not publicAdded:
                publicAdded = True
                primary = True
                public_ip_info = None
                created = False
                # if fixed ip is set, try to find it
                if fixed_ip:
                    for publicip in list(network_client.public_ip_addresses.list(group_name)):
                        if publicip.ip_address == fixed_ip:
                            if publicip.location != location:
                                self.log_warn("IP %s is not in the same location!!" % fixed_ip)
                                self.error_messages += "IP %s is not in the same location!!" % fixed_ip
                                continue
                            public_ip_info = publicip
                    if not public_ip_info:
                        self.log_warn("IP %s not found. Creating new one!!" % fixed_ip)
                        self.error_messages += "IP %s not found. Creating new one!!" % fixed_ip

                # If not create a PublicIP
                if not public_ip_info:
                    public_ip_name = "public-ip-%d-%d" % (vm_id, i)
                    public_ip_parameters = {
                        'location': location,
                        'tags': {'InfID': inf.id},
                        'public_ip_allocation_method': 'static',
                        'sku': {'name': 'standard'},
                        'idle_timeout_in_minutes': 4,
                        'delete_option': DeleteOptions.DELETE
                    }

                    async_publicip_creation = network_client.public_ip_addresses.begin_create_or_update(
                        group_name,
                        public_ip_name,
                        public_ip_parameters
                    )
                    public_ip_info = async_publicip_creation.result()
                    created = True

                nic_params['ip_configurations'][0]['public_ip_address'] = {'id': public_ip_info.id,
                                                                           'tags': {'InfID': inf.id}}
                if created:
                    nic_params['ip_configurations'][0]['public_ip_address']['delete_option'] = DeleteOptions.DELETE

                if pub_network_name:
                    nic_params['network_security_group'] = {'id': ngss[pub_network_name].id}

            async_nic_creation = network_client.network_interfaces.begin_create_or_update(
                group_name, nic_name, nic_params)
            nic = async_nic_creation.result()
            res.append((nic, primary, public_ip_name))

            i += 1

        return res

    def get_azure_vm_create_json(self, group_name, vm_name, nics, radl,
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
                'network_interfaces': [{'id': nic.id,
                                        'primary': primary,
                                        'delete_option': DeleteOptions.DELETE} for nic, primary, _ in nics]
            },
        }

        os_type = system.getValue("disk.0.os.name")
        os_type = os_type if os_type else "Linux"

        if len(image_values) == 3:
            os_disk_name = "osdisk-" + str(uuid.uuid1())
            if image_values[0] == "snapshot":
                managed_disk = compute_client.snapshots.get(image_values[1], image_values[2])
            elif image_values[0] == "disk":
                managed_disk = compute_client.disks.get(image_values[1], image_values[2])
            else:
                raise Exception("Incorrect image url: it must be snapshot or disk.")

            async_creation = compute_client.disks.begin_create_or_update(
                group_name,
                os_disk_name,
                {
                    'location': location,
                    'creation_data': {
                        'create_option': DiskCreateOption.COPY,
                        'source_resource_id': managed_disk.id
                    }
                }
            )

            self.log_info("Creating OS disk %s of type %s from disk: %s/%s/%s." % (os_disk_name,
                                                                                   os_type,
                                                                                   image_values[0],
                                                                                   image_values[1],
                                                                                   image_values[2]))
            disk_resource = async_creation.result()

            vm['storage_profile'] = {
                'os_disk': {
                    'create_option': DiskCreateOption.ATTACH,
                    'os_type': os_type,
                    'caching': CachingTypes.READ_WRITE,
                    'managed_disk': {
                        'id': disk_resource.id
                    },
                    'delete_option': DeleteOptions.DELETE
                }
            }
        else:
            vm['storage_profile'] = {
                'image_reference': {
                    'publisher': image_values[0],
                    'offer': image_values[1],
                    'sku': image_values[2],
                    'version': image_values[3]
                },
                'os_disk': {
                    'create_option': DiskCreateOption.FROM_IMAGE,
                    'os_type': os_type,
                    'caching': CachingTypes.READ_WRITE,
                    'delete_option': DeleteOptions.DELETE
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
                    'create_option': DiskCreateOption.ATTACH
                })
            else:
                disk_size = system.getFeature("disk." + str(cont) + ".size").getValue('G')
                self.log_info("Adding a %s GB disk." % disk_size)
                data_disks.append({
                    'name': '%s_disk_%d' % (vm_name, cont),
                    'disk_size_gb': disk_size,
                    'lun': cont - 1,
                    'create_option': DiskCreateOption.EMPTY,
                    'delete_option': DeleteOptions.DELETE
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

        has_private = False
        for net in radl.networks:
            if not net.isPublic():
                has_private = True

        subnets = {}
        used_cidrs = []
        for net in radl.networks:
            if net.isPublic() and has_private:
                continue
            subnet_name = net.id
            net_cidr = self.get_free_cidr(net.getValue('cidr'), used_cidrs, inf)
            used_cidrs.append(net_cidr)

            vnet_name = "privates"
            if net.getValue("provider_id"):
                parts = net.getValue("provider_id").split(".")
                if len(parts) != 2:
                    parts = net.getValue("provider_id").split("/")
                    if len(parts) != 2:
                        raise Exception("Invalid provider_id format: net_name.subnet_name")
                vnet_name = parts[0]
                subnet_name = parts[1]

            # check if the vnet exists
            vnet = None
            try:
                vnet = network_client.virtual_networks.get(group_name, vnet_name)
            except ResourceNotFoundError:
                pass

            if not vnet:
                self.log_debug("Creating virtual network %s." % vnet_name)
                vnet_cird = self.get_nets_common_cird(radl)
                # Create VNet in the RG of the Inf
                async_vnet_creation = network_client.virtual_networks.begin_create_or_update(
                    group_name,
                    vnet_name,
                    {
                        'location': location,
                        'tags': {'InfID': inf.id},
                        'address_space': {
                            'address_prefixes': [vnet_cird]
                        }
                    }
                )
                async_vnet_creation.wait()

            # check if the subnet exists
            subnet = None
            try:
                subnet = network_client.subnets.get(group_name, vnet_name, subnet_name)
                subnets[net.id] = subnet
                net.setValue('cidr', subnet.address_prefix)
                inf.radl.get_network_by_id(net.id).setValue('cidr', subnet.address_prefix)
            except ResourceNotFoundError:
                pass

            if not subnet:
                self.log_debug("Creating subnet %s." % subnet_name)
                # Create Subnet in the RG of the Inf
                async_subnet_creation = network_client.subnets.begin_create_or_update(
                    group_name,
                    vnet_name,
                    subnet_name,
                    {'address_prefix': net_cidr,
                     'tags': {'InfID': inf.id}}
                )
                subnets[net.id] = async_subnet_creation.result()
                net.setValue('cidr', net_cidr)
                # Set also the cidr in the inf RADL
                inf.radl.get_network_by_id(net.id).setValue('cidr', net_cidr)

        return subnets

    def create_vms(self, rg_name, inf, radl, requested_radl, num_vm, location,
                   ngss, subnets, credentials, subscription_id, tags):
        """
        Creates a set of VMs
        """
        vms = []
        i = 0
        while i < num_vm:
            vm_name = self.gen_instance_name(radl.systems[0])

            try:
                args = {'location': location}
                if tags:
                    args['tags'] = tags

                # Create resource group for the VM
                compute_client = ComputeManagementClient(credentials, subscription_id)

                vm = VirtualMachine(inf, rg_name + '/' + vm_name, self.cloud, radl, requested_radl, self)
                vm.destroy = True
                inf.add_vm(vm)
                vm.info.systems[0].setValue('instance_id', rg_name + '/' + vm_name)

                nics = self.create_nics(radl, credentials, subscription_id, rg_name, subnets, ngss, vm.im_id, inf)

                custom_data = self.get_cloud_init_data(radl, vm)
                instance_type = self.get_instance_type(radl.systems[0], credentials, subscription_id)
                vm_parameters = self.get_azure_vm_create_json(rg_name, vm_name,
                                                              nics, radl, instance_type, custom_data,
                                                              compute_client, tags)

                async_vm_creation = compute_client.virtual_machines.begin_create_or_update(rg_name,
                                                                                           vm_name,
                                                                                           vm_parameters)

                self.log_info("VM ID: %s created." % vm.id)
                vm.destroy = False
                vms.append((True, (vm, async_vm_creation)))
            except Exception as ex:
                vms.append((False, "Error creating the VM: %s" % str(ex)))
                self.log_exception("Error creating the VM")

                # Delete nics & pub ips
                try:
                    network_client = NetworkManagementClient(credentials, subscription_id)
                    for nic, _, public_ip in nics:
                        network_client.network_interfaces.begin_delete(rg_name, nic.name).wait()
                        if public_ip:
                            network_client.public_ip_addresses.begin_delete(rg_name, public_ip).wait()

                except Exception as delex:
                    self.log_exception("Error deleting NICS %s" % str(delex))

            i += 1

        return vms

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        location = self.DEFAULT_LOCATION
        if radl.systems[0].getValue('availability_zone'):
            location = radl.systems[0].getValue('availability_zone')
        else:
            radl.systems[0].setValue('availability_zone', location)

        credentials, subscription_id = self.get_credentials(auth_data)
        compute_client = ComputeManagementClient(credentials, subscription_id)

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

        if len(image_values) == 4:
            offers = compute_client.virtual_machine_images.list(location,
                                                                image_values[0],
                                                                image_values[1],
                                                                image_values[2])
            if not offers:
                raise Exception("Image url %s: not found" % url)

        resource_client = ResourceManagementClient(credentials, subscription_id)

        tags = self.get_instance_tags(radl.systems[0], auth_data, inf)

        with inf._lock:
            rg_name = radl.systems[0].getValue('rg_name')
            if not rg_name:
                rg_name = "rg-%s" % inf.id
            else:
                if 'rg_name' in inf.extra_info:
                    if rg_name != inf.extra_info['rg_name']:
                        raise Exception("Invalid rg_name. It must be unique per infrastructure.")
                else:
                    inf.extra_info['rg_name'] = rg_name

            # Create resource group for the Infrastructure if it does not exists
            if not self.get_rg(rg_name, credentials, subscription_id):
                self.log_info("Creating Inf RG: %s" % rg_name)
                resource_client.resource_groups.create_or_update(rg_name, {'location': location,
                                                                           'tags': {'InfID': inf.id}})

            subnets = self.create_nets(radl, credentials, subscription_id, rg_name, inf)
            ngss = self.create_nsgs(radl, location, rg_name, credentials, subscription_id, inf)

        res = []
        vms = self.create_vms(rg_name, inf, radl, requested_radl, num_vm, location,
                              ngss, subnets, credentials, subscription_id, tags)

        all_failed = True
        remaining_vms = num_vm
        for success, data in vms:
            if success:
                vm, async_vm_creation = data
                try:
                    self.log_debug("Waiting VM ID %s to be created." % vm.id)
                    async_vm_creation.wait()
                    all_failed = False
                    res.append((True, vm))
                    remaining_vms -= 1
                except Exception as ex:
                    self.log_exception("Error waiting the VM %s." % vm.id)

                    # Delete created resources for this VM
                    try:
                        group_name = vm.id.split('/')[0]
                        vm_name = vm.id.split('/')[1]
                        compute_client.virtual_machines.begin_delete(group_name, vm_name).wait()
                    except Exception:
                        self.log_exception("Error removing errored VM: %s" % vm.id)

                    res.append((False, "Error waiting the VM %s: %s" % (vm.id, str(ex))))
            else:
                res.append((False, data))

        if all_failed:
            try:
                deleted, msg = self.delete_resource_group(inf, rg_name, resource_client, max_retries=1)
                if not deleted:
                    self.log_warn("Error removing errored RG %s: %s" % (rg_name, msg))
            except Exception:
                self.log_exception("Error removing errored RG: %s" % rg_name)

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
        except ResourceNotFoundError:
            self.log_warn("The VM does not exists")
            vm.state = VirtualMachine.OFF
            return (True, vm)
        except Exception as ex:
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
        self.manage_dns_entries("add", vm, auth_data, extra_args={"group_name": group_name})
        return (True, vm)

    def add_dns_entry(self, hostname, domain, ip, auth_data, extra_args=None):
        try:
            group_name = extra_args.get("group_name")
            if not group_name:
                raise Exception("No group name set in DNS creation.")
            credentials, subscription_id = self.get_credentials(auth_data)
            dns_client = DnsManagementClient(credentials, subscription_id)

            domain = domain[:-1]
            zone = None
            try:
                zone = dns_client.zones.get(group_name, domain)
            except Exception:
                pass
            if not zone:
                self.log_info("Creating DNS zone %s" % domain)
                zone = dns_client.zones.create_or_update(group_name, domain, {'location': 'global'})
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
                    is_private = any([IPAddress(ip.private_ip_address) in IPNetwork(mask)
                                      for mask in Config.PRIVATE_NET_MASKS])
                    if is_private:
                        private_ips.append(ip.private_ip_address)
                    else:
                        public_ips.append(ip.private_ip_address)
                if ip.public_ip_address:
                    name = " ".join(ip.public_ip_address.id.split('/')[-1:])
                    sub = "".join(ip.public_ip_address.id.split('/')[4])
                    public_ip_info = network_client.public_ip_addresses.get(sub, name)
                    public_ips.append(public_ip_info.ip_address)

        vm.setIps(public_ips, private_ips)

    def finalize(self, vm, last, auth_data):
        credentials, subscription_id = self.get_credentials(auth_data)

        try:
            compute_client = ComputeManagementClient(credentials, subscription_id)
            resource_client = ResourceManagementClient(credentials, subscription_id)

            if vm.id:
                self.log_info("Terminate VM: %s" % vm.id)
                group_name = vm.id.split('/')[0]
                vm_name = vm.id.split('/')[1]

                # Delete VM
                try:
                    compute_client.virtual_machines.begin_delete(group_name, vm_name).wait()
                except ResourceNotFoundError:
                    self.log_warn("VM ID %s does not exist. Ignoring." % vm.id)
            else:
                self.log_warn("No VM ID. Ignoring")

            # if it is the last VM delete also the RG of the Inf
            if last:
                if vm.id:
                    group_name = vm.id.split('/')[0]
                else:
                    group_name = "rg-%s" % vm.inf.id
                deleted, msg = self.delete_resource_group(vm.inf, group_name, resource_client)
                if not deleted:
                    return False, "Error terminating the RG: %s" % msg

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
        except ResourceNotFoundError:
            self.log_warn("VM ID %s does not exist. Ignoring." % vm.id)
            return False, "VM does not exist."
        except Exception as ex:
            self.log_exception("Error performing action '%s' in the VM" % action)
            return False, "Error performing action '%s' in the VM: %s" % (action, ex)

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

            new_system = self.resize_vm_radl(vm, radl)
            if not new_system:
                return (True, "")

            instance_type = self.get_instance_type(new_system, credentials, subscription_id)
            vm_parameters = " { 'hardware_profile': { 'vm_size': %s } } " % instance_type.name

            async_vm_update = compute_client.virtual_machines.begin_create_or_update(group_name,
                                                                                     vm_name,
                                                                                     vm_parameters)
            async_vm_update.wait()

            # Start the VM
            async_vm_start = compute_client.virtual_machines.start(group_name, vm_name)
            async_vm_start.wait()

            return self.updateVMInfo(vm, auth_data)
        except ResourceNotFoundError:
            self.log_warn("VM ID %s does not exist. Ignoring." % vm.id)
            return False, "VM does not exist."
        except Exception as ex:
            self.log_exception("Error altering the VM")
            return False, "Error altering the VM: " + str(ex)

    def delete_resource_group(self, inf, group_name, resource_client, max_retries=3):
        """
        Delete a RG with retries
        """
        rg = None
        try:
            rg = resource_client.resource_groups.get(group_name)
            rg_delete = False
            if rg.tags and 'InfID' in rg.tags and rg.tags['InfID'] == inf.id:
                rg_delete = True
            else:
                self.log_warn("RG %s was not created by the IM. Only delete resources." % group_name)
        except ResourceNotFoundError:
            self.log_warn("RG %s does not exist. Ignore." % group_name)
            return True, ""

        cont = 0
        msg = ""
        if not rg_delete:
            # Delete all the resources in a RG without deleting the RG
            deleted = False
            while cont < max_retries and not deleted:
                cont += 1

                try:
                    async_deletes = []
                    for resource in list(resource_client.resources.list_by_resource_group(group_name)):
                        if resource.tags and 'InfID' in resource.tags and resource.tags['InfID'] == inf.id:
                            rnamespace = resource.type.split('/')[0]
                            rtype = resource.type.split('/')[1]
                            async_deletes.append(resource_client.resources.begin_delete(group_name,
                                                                                        rnamespace,
                                                                                        "",
                                                                                        rtype,
                                                                                        resource.name,
                                                                                        "2018-05-01"))
                        else:
                            self.log_warn("Resource %s was not created by the IM. Ignore." % resource.name)
                    for async_delete in async_deletes:
                        async_delete.wait()
                    deleted = True
                except Exception as ex:
                    msg = str(ex)
                    self.log_exception("Error deleting Resource from RG %s (%d/%d)." % (group_name,
                                                                                        cont,
                                                                                        max_retries))
        else:
            deleted = False

            self.log_info("Delete RG %s." % group_name)
            while cont < max_retries and not deleted:
                cont += 1
                try:
                    resource_client.resource_groups.begin_delete(group_name).wait()
                    deleted = True
                except Exception as ex:
                    msg = str(ex)
                    self.log_exception("Error deleting Resource group %s (%d/%d)." % (group_name, cont, max_retries))

            if not deleted:
                self.log_error("Resource group %s cannot be deleted!!!" % group_name)
            else:
                self.log_info("Resource group %s successfully deleted." % group_name)

        return deleted, msg

    def list_images(self, auth_data, filters=None):
        location = self.DEFAULT_LOCATION
        offers = ["*"]
        publisher = ['Canonical', 'MicrosoftSQLServer', 'MicrosoftWindowsDesktop',
                     'MicrosoftWindowsServer', 'nvidia', 'Oracle', 'RedHat', 'SUSE']
        if filters and 'location' in filters and filters['location']:
            location = filters['location']
        if filters and 'publisher' in filters and filters['publisher']:
            publisher = filters['publisher'].split(",")
        if filters and 'offer' in filters and filters['offer']:
            offers = filters['offer'].split(",")

        credentials, subscription_id = self.get_credentials(auth_data)
        compute_client = ComputeManagementClient(credentials, subscription_id)

        # If publisher is "*" it means all
        if publisher == ["*"]:
            pubs = compute_client.virtual_machine_images.list_publishers(location)
            publisher = [pub.name for pub in pubs]

        images = []
        for pub in publisher:
            if offers == ["*"]:
                offers = compute_client.virtual_machine_images.list_offers(location, pub)
                offers = [offer.name for offer in offers]
            for offer in offers:
                skus = compute_client.virtual_machine_images.list_skus(location, pub, offer)
                for sku in skus:
                    images.append((pub, offer, sku.name))

        res = []
        for pub, offer, sku in images:
            res.append({"uri": "azr://%s/%s/%s/latest" % (pub, offer, sku),
                               "name": "%s %s %s" % (pub, offer, sku)})
        return res
