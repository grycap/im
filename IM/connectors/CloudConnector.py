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

import logging
import operator
import time
import yaml
import uuid

from radl.radl import Feature, outport
from IM.config import Config
from IM.LoggerMixin import LoggerMixin
from netaddr import IPNetwork, spanning_cidr


class CloudConnector(LoggerMixin):
    """
    Base class to all the Cloud connectors

    Arguments:
            - cloud_info(:py:class:`IM.CloudInfo`): Data about the Cloud Provider
    """

    OPERATORSMAP = {"<": operator.lt, "<=": operator.le, "=": operator.eq,
                    ">=": operator.ge, ">": operator.gt, "==": operator.eq}
    type = "BaseClass"
    """str with the name of the provider."""
    DEFAULT_NET_CIDR = "10.0.*.0/24"

    def __init__(self, cloud_info, inf):
        self.cloud = cloud_info
        """Data about the Cloud Provider."""
        self.inf = inf
        """Infrastructure this CloudConnector is associated with."""
        self.logger = logging.getLogger('CloudConnector')
        """Logger object."""
        self.error_messages = ""
        """String with error messages to be shown to the user."""
        self.verify_ssl = Config.VERIFI_SSL
        """Verify SSL connections """
        if not self.verify_ssl:
            # To avoid errors with host certificates
            try:
                import ssl
                ssl._create_default_https_context = ssl._create_unverified_context
            except Exception:
                pass

            try:
                # To avoid annoying InsecureRequestWarning messages in some Connectors
                import requests.packages
                from requests.packages.urllib3.exceptions import InsecureRequestWarning
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            except Exception:
                pass

    def concreteSystem(self, radl_system, auth_data):
        """
        Return a list of compatible systems with the cloud

        Arguments:

           - radl_system(:py:class:`radl.system`): a system.
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

        Returns(list of system): list of compatible systems.
        """
        image_urls = radl_system.getValue("disk.0.image.url")
        if not image_urls:
            return [radl_system.clone()]
        else:
            if not isinstance(image_urls, list):
                image_urls = [image_urls]

            res = []

            for str_url in image_urls:
                res_system = self.concrete_system(radl_system, str_url, auth_data)
                if res_system:
                    res_system.addFeature(Feature("disk.0.image.url", "=", str_url),
                                          conflict="other", missing="other")
                    res_system.addFeature(Feature("provider.type", "=", self.type),
                                          conflict="other", missing="other")
                    if self.cloud.server:
                        res_system.addFeature(Feature("provider.host", "=", self.cloud.server),
                                              conflict="other", missing="other")
                    if self.cloud.port != -1:
                        res_system.addFeature(Feature("provider.port", "=", self.cloud.port),
                                              conflict="other", missing="other")
                    res.append(res_system)

            return res

    def concrete_system(self, radl_system, str_url, auth_data):
        """
        Return a list of compatible systems with the cloud

        Arguments:

           - radl_system(:py:class:`radl.system`): a system.
           - str_url(string): a VMI url
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

        Returns(:py:class:`radl.system`): a compatible system or none if the url is
        not compatible with the provider.
        """
        return radl_system.clone()

    def updateVMInfo(self, vm, auth_data):
        """
        Updates the information of a VM

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information to update.
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

        Returns: a tuple (success, vm).
           - The first value is True if the operation finished successfully or false otherwise.
           - The second value is a :py:class:`IM.VirtualMachine` with the updated information if
             the operation finished successfully or a str with an error message otherwise.
        """

        raise NotImplementedError("Should have implemented this")

    def alterVM(self, vm, radl, auth_data):
        """
        Modifies the features of a VM

        Arguments:
                - vm(:py:class:`IM.VirtualMachine`): VM to modify.
                - radl(str): RADL document with the VM features to modify.
                - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

        Returns: a tuple (success, vm).
                - The first value is True if the operation finished successfully or false otherwise.
                - The second value is a :py:class:`IM.VirtualMachine` with the modified information if the operation
                  finished successfully or a str with an error message otherwise.
        """

        raise NotImplementedError("Should have implemented this")

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        """
        Launch a set of VMs to the Cloud provider

        Args:

        - inf(InfrastructureInfo): InfrastructureInfo object the VM is part of.
        - radl(RADL): RADL document.
        - num_vm(int): number of instances to deploy.
        - auth_data(Authentication): Authentication data to access cloud provider.

                Returns: a list of tuples with the format (success, vm).
           - The first value is True if the operation finished successfully or false otherwise.
           - The second value is a :py:class:`IM.VirtualMachine` of the launched VMs if the operation
             finished successfully or a str with an error message otherwise.
        """

        raise NotImplementedError("Should have implemented this")

    def launch_with_retry(self, inf, radl, requested_radl, num_vm, auth_data, max_num, delay):
        """
        Launch a set of VMs to the Cloud provider with a set of retries in case of failure

        Args:

        - inf(InfrastructureInfo): InfrastructureInfo object the VM is part of.
        - radl(RADL): RADL document.
        - num_vm(int): number of instances to deploy.
        - auth_data(Authentication): Authentication data to access cloud provider.
        - max_num: Number of retries.
        - delay: a sleep time between retries

                Returns: a list of tuples with the format (success, vm).
           - The first value is True if the operation finished successfully or false otherwise.
           - The second value is a :py:class:`IM.VirtualMachine` of the launched VMs if the operation
             finished successfully or a str with an error message otherwise.
        """
        res_ok = []
        res_err = {}
        retries = 0
        while len(res_ok) < num_vm and retries < max_num:
            if retries != 0:
                time.sleep(delay)
            retries += 1
            err_count = 0
            try:
                vms = self.launch(inf, radl, requested_radl, num_vm - len(res_ok), auth_data)
            except Exception as ex:
                self.log_exception("Error launching some of the VMs")
                vms = []
                for _ in range(num_vm - len(res_ok)):
                    vms.append((False, "Error: %s" % ex))
            for success, vm in vms:
                if success:
                    res_ok.append(vm)
                else:
                    if err_count not in res_err:
                        res_err[err_count] = [vm]
                    else:
                        res_err[err_count].append(vm)
                    err_count += 1

        res = []
        for elem in res_ok:
            res.append((True, elem))

        for i in range(num_vm - len(res_ok)):
            msgs = ""
            for n, msg in enumerate(res_err[i]):
                msgs += "Attempt %d: %s\n" % (n + 1, msg)
            res.append((False, msgs))

        return res

    def finalize(self, vm, last, auth_data):
        """ Terminates a VM

                Arguments:
                - vm(:py:class:`IM.VirtualMachine`): VM to terminate.
                - last(boolean): Flag that specifies that the VM is that last one, to clean all related resources.
                - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

                Returns: a tuple (success, vm).
           - The first value is True if the operation finished successfully or false otherwise.
           - The second value is a str with the ID of the removed VM if the operation finished successfully
             or an error message otherwise.
        """

        raise NotImplementedError("Should have implemented this")

    def start(self, vm, auth_data):
        """ Starts a (previously stopped) VM

                Arguments:
                - vm(:py:class:`IM.VirtualMachine`): VM to start.
                - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

                Returns: a tuple (success, vm).
           - The first value is True if the operation finished successfully or false otherwise.
           - The second value is a str with the ID of the started VM if the operation finished successfully
             or an error message otherwise.
        """

        raise NotImplementedError("Should have implemented this")

    def stop(self, vm, auth_data):
        """ Stops (but not finalizes) a VM

                Arguments:
                - vm(:py:class:`IM.VirtualMachine`): VM to stop.
                - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

                Returns: a tuple (success, vm).
           - The first value is True if the operation finished successfully or false otherwise.
           - The second value is a str with the ID of the stopped VM if the operation finished successfully
             or an error message otherwise.

        """

        raise NotImplementedError("Should have implemented this")

    def reboot(self, vm, auth_data):
        """ Reboots a VM

                Arguments:
                - vm(:py:class:`IM.VirtualMachine`): VM to stop.
                - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

                Returns: a tuple (success, vm).
           - The first value is True if the operation finished successfully or false otherwise.
           - The second value is a str with the ID of the stopped VM if the operation finished successfully
             or an error message otherwise.

        """

        raise NotImplementedError("Should have implemented this")

    def create_snapshot(self, vm, disk_num, image_name, auto_delete, auth_data):
        """
        Create a snapshot of the specified num disk in a virtual machine.

        Arguments:
          - vm(:py:class:`IM.VirtualMachine`): VM to stop.
          - disk_num(int): Number of the disk.
          - image_name(str): Name of the new image.
          - auto_delete(bool): A flag to specify that the snapshot will be deleted when the
            infrastructure is destroyed.
          - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

        Returns: a tuple (success, vm).
          - The first value is True if the operation finished successfully or false otherwise.
          - The second value is a str with the url of the new image if the operation finished successfully
             or an error message otherwise.
        """

        raise NotImplementedError("Should have implemented this")

    def delete_image(self, image_url, auth_data):
        """
        Delete an image on the cloud provider.

        Arguments:
          - image_url(str): URL of the image to delete.
          - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

        Returns: a tuple (success, vm).
          - The first value is True if the operation finished successfully or false otherwise.
          - The second value is an empty str if the operation finished successfully
             or an error message otherwise.
        """
        raise NotImplementedError("Should have implemented this")

    def list_images(self, auth_data, filters=None):
        """
        Get a list of images on the cloud provider using IM URI format.

        Arguments:
          - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
          - filters(:py:class:`dict` of str objects): Pair key value to filter the list of images.
                                                     It is cloud provider specific.

        Returns: a list dicts with at least two fields "uri" and "name".
        """
        raise NotImplementedError("Should have implemented this")

    def get_quotas(self, auth_data):
        """
        Get the number of used and available resources in the cloud provider

        Arguments:
          - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

        Returns: dict with the following structure (if there are no limit in some metric, value is set to 1):
                    {
                        "cores": {"used": 1, "limit": 10},
                        "ram": {"used": 1, "limit": 10},
                        "instances": {"used": 1, "limit": 10},
                        "floating_ips": {"used": 1, "limit": 10},
                        "security_groups": {"used": 1, "limit": 10}
                    }
                 Some providers may provide more elements.
        """
        raise NotImplementedError("Should have implemented this")

    def delete_snapshots(self, vm, auth_data):
        """
        Delete the snapshots created with auto_delete option
        """
        try:
            for image_url in vm.inf.snapshots:
                self.log_debug("Deleting snapshot: %s" % image_url)
                success, msg = self.delete_image(image_url, auth_data)
                if not success:
                    self.log_error("Error deleting snapshot: %s" % msg)
                return success, msg
        except Exception as ex:
            self.log_exception("Error deleting snapshots.")
            return success, str(ex)

    def get_cloud_init_data(self, radl=None, vm=None, public_key=None, user=None):
        """
        Get the cloud init data specified by the user in the RADL
        """
        cloud_config = {}

        if radl:
            configure_name = None
            if radl.contextualize.items:
                system_name = radl.systems[0].name

                for item in radl.contextualize.items.values():
                    if item.system == system_name and item.get_ctxt_tool() == "cloud_init":
                        configure_name = item.configure

            if configure_name:
                cloud_config = yaml.safe_load(radl.get_configure_by_name(configure_name).recipes)
                if not isinstance(cloud_config, dict):
                    # The cloud_init data is a shell script
                    cloud_config = radl.get_configure_by_name(configure_name).recipes.strip()
                    self.log_debug(cloud_config)
                    return cloud_config

        # Only for those VMs with private IP
        if Config.SSH_REVERSE_TUNNELS and vm and not vm.hasPublicNet():
            if 'packages' not in cloud_config:
                cloud_config['packages'] = []
            cloud_config['packages'].extend(["curl", "sshpass"])

            curl_command = vm.get_boot_curl_commands()
            if 'bootcmd' not in cloud_config:
                cloud_config['bootcmd'] = []
            cloud_config['bootcmd'].extend(curl_command)

        if vm and vm.getSSHPort() != 22:
            if 'bootcmd' not in cloud_config:
                cloud_config['bootcmd'] = []
            cloud_config['bootcmd'].append("sed -i '/Port 22/c\\Port %s' /etc/ssh/sshd_config" % vm.getSSHPort())
            cloud_config['bootcmd'].append("service sshd restart")

        if public_key:
            user_data = {}
            user_data['name'] = user
            user_data['sudo'] = "ALL=(ALL) NOPASSWD:ALL"
            user_data['lock-passwd'] = True
            user_data['ssh-import-id'] = user
            # avoid to use default /home dir
            user_data['homedir'] = "/opt/%s" % user
            user_data['ssh-authorized-keys'] = [public_key.strip()]
            if 'users' not in cloud_config:
                cloud_config['users'] = []
            cloud_config['users'].append(user_data)

        if cloud_config:
            if 'merge_how' not in cloud_config:
                cloud_config['merge_how'] = 'list(append)+dict(recurse_array,no_replace)+str()'
            res = yaml.safe_dump(cloud_config, default_flow_style=False, width=512)
            self.log_debug("#cloud-config\n%s" % res)
            return "#cloud-config\n%s" % res
        else:
            return None

    @staticmethod
    def get_instance_tags(system, auth_data=None, inf=None):
        """
        Get the instance_tags value of the system object as a dict
        """
        tags = {}
        if system.getValue('instance_tags'):
            keypairs = system.getValue('instance_tags').split(",")
            for keypair in keypairs:
                parts = keypair.split("=")
                key = parts[0].strip()
                value = parts[1].strip()
                tags[key] = value
        # If available try to set the IM information as tags
        if (Config.VM_TAG_USERNAME and Config.VM_TAG_USERNAME not in tags and
                auth_data and auth_data.getAuthInfo('InfrastructureManager')):
            im_username = auth_data.getAuthInfo('InfrastructureManager')[0]['username']
            tags[Config.VM_TAG_USERNAME] = im_username
        if Config.VM_TAG_INF_ID and Config.VM_TAG_INF_ID not in tags and inf:
            tags[Config.VM_TAG_INF_ID] = inf.id
        from IM.REST import REST_URL
        if Config.VM_TAG_IM_URL and Config.VM_TAG_IM_URL not in tags and REST_URL:
            tags[Config.VM_TAG_IM_URL] = REST_URL
        if Config.VM_TAG_IM and Config.VM_TAG_IM not in tags:
            tags[Config.VM_TAG_IM] = "es.upv.grycap.im"
        return tags

    @staticmethod
    def get_nets_common_cird(radl):
        """
        Get a common CIDR in all the RADL nets
        """
        nets = []
        for num, net in enumerate(radl.networks):
            provider_id = net.getValue('provider_id')
            if net.getValue('create') == 'yes' and not net.isPublic() and not provider_id:
                net_cidr = net.getValue('cidr')
                if not net_cidr:
                    net_cidr = CloudConnector.DEFAULT_NET_CIDR
                net_cidr_0 = IPNetwork(net_cidr.replace("*", "0"))
                if net_cidr_0 not in nets:
                    nets.append(net_cidr_0)
                net_cidr = IPNetwork(net_cidr.replace("*", str(num + 1)))
                nets.append(net_cidr)

        if len(nets) == 0:  # there is no CIDR return the default one
            return "10.0.0.0/16"
        elif len(nets) == 1:  # there is only one, return it
            return nets[0]
        else:  # there are more, get the common CIDR
            return str(spanning_cidr(nets))

    @staticmethod
    def get_instance_selectors(system, mem_unit="M", disk_unit="M"):
        cpu = 1
        cpu_op_str = ">="
        if system.getFeature('cpu.count'):
            cpu = system.getValue('cpu.count')
            cpu_op_str = system.getFeature('cpu.count').getLogOperator()
        cpu_op = CloudConnector.OPERATORSMAP.get(cpu_op_str)

        memory = 0
        memory_op_str = ">="
        if system.getFeature('memory.size'):
            memory = system.getFeature('memory.size').getValue(mem_unit)
            memory_op_str = system.getFeature('memory.size').getLogOperator()
        memory_op = CloudConnector.OPERATORSMAP.get(memory_op_str)

        disk_free = 0
        disk_free_op_str = ">="
        if system.getValue('disks.free_size'):
            disk_free = system.getFeature('disks.free_size').getValue(disk_unit)
            disk_free_op_str = system.getFeature('disks.free_size').getLogOperator()
        disk_free_op = CloudConnector.OPERATORSMAP.get(disk_free_op_str)

        return (cpu, cpu_op, memory, memory_op, disk_free, disk_free_op)

    @staticmethod
    def cidr_wildcard_iterator(cidr, init=0):
        """
        Returns an interator with all the cidr nets that expand the wildcards passed.
        For example: with cidr = 192.168.*.0/24
        it will return:
         - 192.168.1.1/24
         - 192.168.2.1/24
         - 192.168.3.1/24
         - ...
         - 192.168.253.1/24
        """
        if "*" in cidr:
            for val in range(init, 253 + init):
                val = val % 254 + 1
                icidr = cidr.replace("*", str(val), 1)
                if "*" in icidr:
                    for elem in CloudConnector.cidr_wildcard_iterator(icidr):
                        yield elem
                else:
                    yield icidr
            cidr = icidr
        else:
            yield cidr

    @staticmethod
    def get_free_cidr(net_cidr, used_cidrs, inf=None, init=0):
        """
        Get a CIDR that is not used (is not in used_cidrs list)
        """
        if not net_cidr:
            net_cidr = CloudConnector.DEFAULT_NET_CIDR

        if "*" not in net_cidr:
            return net_cidr

        used_cidr_nets = [IPNetwork(net) for net in used_cidrs]

        # add current used cidrs in other inf networks
        if inf:
            # Add the general RADL nets
            for net in inf.radl.networks:
                cidr = net.getValue('cidr')
                if cidr and "*" not in cidr:
                    used_cidr_nets.append(IPNetwork(cidr))

            # and the nets from the VMs
            # Use direct access to the list to avoid lock
            for vm in inf.vm_list:
                for net in vm.info.networks:
                    print(net)
                    cidr = net.getValue('cidr')
                    if cidr and "*" not in cidr:
                        used_cidr_nets.append(IPNetwork(cidr))

        for cidr in CloudConnector.cidr_wildcard_iterator(net_cidr, init):
            if not any([IPNetwork(cidr) in IPNetwork(mask) for mask in used_cidr_nets]):
                return cidr

        return None

    @staticmethod
    def gen_instance_name(system, unique=True, default="im-userimage"):
        name = system.getValue("instance_name")
        if not name:
            name = system.getValue("disk.0.image.name")
        if not name:
            name = system.name
        if not name:
            name = default
        name = name.lower().replace("_", "-")
        if unique:
            return "%s-%s" % (name, str(uuid.uuid1()))
        else:
            return name

    def get_dns_entries(self, vm):
        """
        Get the required entries in the to add in the Cloud provider DNS service

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
        Returns: List of triplets (record, domain, ip)
        """
        res = []
        system = vm.info.systems[0]
        for net_name in system.getNetworkIDs():
            num_conn = system.getNumNetworkWithConnection(net_name)
            ip = system.getIfaceIP(num_conn)
            (hostname, domain) = vm.getRequestedNameIface(num_conn,
                                                          default_hostname=Config.DEFAULT_VM_NAME,
                                                          default_domain=Config.DEFAULT_DOMAIN)
            if not domain.endswith("."):
                domain += "."
            if domain != "localdomain." and ip and hostname:
                res.append((hostname, domain, ip))

            # Also add additional names
            additional_dns_names = system.getValue('net_interface.%d.additional_dns_names' % num_conn)
            if additional_dns_names:
                for dns_name in additional_dns_names:
                    dns_parts = dns_name.split("@")
                    if len(dns_parts) != 2:
                        self.log_error("Invalid format for additional name: %s." % dns_name)
                        self.error_messages = "Invalid format for additional name: %s." % dns_name
                        break
                    hostname = dns_parts[0]
                    domain = dns_parts[1]
                    if not domain.endswith("."):
                        domain += "."
                    if domain != "localdomain." and ip and hostname:
                        res.append((hostname, domain, ip))

        return res

    def resize_vm_radl(self, vm, radl):
        """
        Update the current VM RADL with the new RADL

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - radl(RADL): RADL document.
        Returns: an RADL system or None if no changes are made
        """
        orig_system = vm.info.systems[0].clone()
        new_cpu = radl.systems[0].getValue('cpu.count')
        if new_cpu:
            orig_system.setValue('cpu.count', new_cpu)
        new_memory = radl.systems[0].getValue('memory.size')
        if new_memory:
            orig_system.setValue('memory.size', new_memory)
        instance_type = radl.systems[0].getValue('instance_type')
        if instance_type is not None:
            orig_system.setValue('instance_type', instance_type)
        new_gpu = radl.systems[0].getValue('gpu.count')
        if new_gpu:
            orig_system.setValue('gpu.count', new_gpu)

        if any([new_cpu, new_memory, instance_type, new_gpu]):
            return orig_system
        else:
            self.log_debug("No memory nor cpu nor instance_type nor gpu specified. VM not resized.")
            return None

    @staticmethod
    def add_ssh_port(outports):
        # always open SSH port
        if not outports:
            outports = [outport(22, 22, 'tcp')]
        else:
            ports_list = [op.get_remote_port() for op in outports if op.get_protocol() == "tcp"]
            if 22 not in ports_list:
                outports.append(outport(22, 22, 'tcp'))
        return outports

    def add_dns_entry(self, hostname, domain, ip, auth_data, extra_args=None):
        """
        Add the required entriy in a DNS service

        Arguments:
           - hostname(str): hostname part of the fqdn
           - domain(str): domain name part of the fqdn
           - ip(str): ip to assing to the dns entry
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
           - extra_args(dict): dict with some extra fields needed in some particular Providers
        """
        raise NotImplementedError("Should have implemented this")

    def del_dns_entry(self, hostname, domain, ip, auth_data, extra_args=None):
        """
        Del the required entriy in a DNS service

        Arguments:
           - hostname(str): hostname part of the fqdn
           - domain(str): domain name part of the fqdn
           - ip(str): ip to assing to the dns entry
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
           - extra_args(dict): dict with some extra fields needed in some particular Providers
        """
        raise NotImplementedError("Should have implemented this")

    def manage_dns_entries(self, op, vm, auth_data, extra_args=None):
        """
        Add/Delete the required entries in a DNS service

        Arguments:
           - op(str): Operation to perform ('add' or 'del')
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
           - extra_args(dict): dict with some extra fields needed in some particular Providers
        """
        try:
            if not hasattr(vm, 'dns_entries'):
                vm.dns_entries = []
            if op == "add":
                dns_entries = [entry for entry in self.get_dns_entries(vm) if entry not in vm.dns_entries]
                dns_entries = []
                for entry in self.get_dns_entries(vm):
                    if entry not in vm.dns_entries:
                        dns_entries.append(entry)
            else:
                dns_entries = list(vm.dns_entries)
            if dns_entries:
                for entry in dns_entries:
                    hostname, domain, ip = entry
                    try:
                        if op == "add":
                            success = self.add_dns_entry(hostname, domain, ip, auth_data, extra_args)
                            if success and entry not in vm.dns_entries:
                                vm.dns_entries.append(entry)
                        elif op == "del":
                            self.del_dns_entry(hostname, domain, ip, auth_data, extra_args)
                            if entry in vm.dns_entries:
                                vm.dns_entries.remove(entry)
                        else:
                            raise Exception("Invalid DNS operation.")
                    except NotImplementedError as niex:
                        # Use EC2 as back up for all providers if EC2 credentials are available
                        # TODO: Change it to DyDNS when the full API is available
                        if auth_data.getAuthInfo("EC2"):
                            from IM.connectors.EC2 import EC2CloudConnector
                            if op == "add":
                                success = EC2CloudConnector.add_dns_entry(self, hostname, domain, ip, auth_data)
                                if success and entry not in vm.dns_entries:
                                    vm.dns_entries.append(entry)
                            elif op == "del":
                                EC2CloudConnector.del_dns_entry(self, hostname, domain, ip, auth_data)
                                if entry in vm.dns_entries:
                                    vm.dns_entries.remove(entry)
                            else:
                                raise Exception("Invalid DNS operation.")
                        else:
                            raise niex
            return True
        except Exception as ex:
            self.error_messages += "Error in %s DNS entries %s.\n" % (op, str(ex))
            self.log_exception("Error in %s DNS entries" % op)
            return False
