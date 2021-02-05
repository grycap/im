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
import requests
from netaddr import IPNetwork, spanning_cidr

try:
    import boto.ec2
    import boto.vpc
    import boto.route53
except Exception as ex:
    print("WARN: Boto library not correctly installed. EC2CloudConnector will not work!.")
    print(ex)

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

from IM.VirtualMachine import VirtualMachine
from .CloudConnector import CloudConnector
from radl.radl import Feature
from IM.config import Config


class InstanceTypeInfo:
    """
    Information about the instance type

    Args:
            - name(str, optional): name of the type of the instance
            - cpu_arch(list of str, optional): cpu architectures supported
            - num_cpu(int, optional): number of cpus
            - cores_per_cpu(int, optional): number of cores per cpu
            - mem(int, optional): amount of memory
            - price(int, optional): price per hour
            - cpu_perf(int, optional): performance of the type in ECUs
            - disks(int, optional): number of disks
            - disk_space(int, optional): size of the disks
            - vpc_only(bool, optional): the instance works only on VPC
            - gpu(int, optional): the number of gpus of this instance
    """

    def __init__(self, name="", cpu_arch=None, num_cpu=1, cores_per_cpu=1, mem=0,
                 price=0, cpu_perf=0, disks=0, disk_space=0, vpc_only=None, gpu=0):
        self.name = name
        self.num_cpu = num_cpu
        self.cores_per_cpu = cores_per_cpu
        self.mem = mem
        self.cpu_arch = ["i386"]
        if cpu_arch:
            self.cpu_arch = cpu_arch
        self.price = price
        self.cpu_perf = cpu_perf
        self.disks = disks
        self.disk_space = disk_space
        self.vpc_only = vpc_only
        self.gpu = gpu


class EC2CloudConnector(CloudConnector):
    """
    Cloud Launcher to the EC2 platform
    """

    type = "EC2"
    """str with the name of the provider."""
    INSTANCE_TYPE = 't1.micro'
    """str with the name of the default instance type to launch."""

    VM_STATE_MAP = {
        'pending': VirtualMachine.PENDING,
        'running': VirtualMachine.RUNNING,
        'stopped': VirtualMachine.STOPPED,
        'stopping': VirtualMachine.RUNNING,
        'shutting-down': VirtualMachine.OFF,
        'terminated': VirtualMachine.OFF
    }
    """Dictionary with a map with the EC3 VM states to the IM states."""
    DEFAULT_USER = 'cloudadm'
    """ default user to SSH access the VM """

    instance_type_list = []
    """ Information about the instance types """

    def __init__(self, cloud_info, inf):
        self.connection = None
        self.route53_connection = None
        self.auth = None
        CloudConnector.__init__(self, cloud_info, inf)

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]

        if protocol == "aws":

            instance_type = self.get_instance_type(radl_system)
            if not instance_type:
                self.log_error("Error launching the VM, no instance type available for the requirements.")
                self.log_debug(radl_system)
                return None

            # Currently EC2 plugin only uses private_key credentials
            res_system = radl_system.clone()
            if res_system.getValue('disk.0.os.credentials.private_key'):
                res_system.delValue('disk.0.os.credentials.password')
                res_system.delValue('disk.0.os.credentials.new.password')

            username = res_system.getValue('disk.0.os.credentials.username')
            if not username:
                res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)

            self.update_system_info_from_instance(res_system, instance_type)

            return res_system
        else:
            return None

    @staticmethod
    def update_system_info_from_instance(system, instance_type):
        """
        Update the features of the system with the information of the instance_type
        """
        system.addFeature(Feature("cpu.count", "=", instance_type.num_cpu *
                                  instance_type.cores_per_cpu), conflict="other", missing="other")
        system.addFeature(Feature(
            "memory.size", "=", instance_type.mem, 'M'), conflict="other", missing="other")
        if instance_type.disks > 0:
            system.addFeature(Feature("disks.free_size", "=", instance_type.disks *
                                      instance_type.disk_space, 'G'), conflict="other", missing="other")
            for i in range(1, instance_type.disks + 1):
                system.addFeature(Feature("disk.%d.free_size" % i, "=",
                                          instance_type.disk_space, 'G'), conflict="other", missing="other")
        system.addFeature(Feature("cpu.performance", "=",
                                  instance_type.cpu_perf, 'ECU'), conflict="other", missing="other")
        system.addFeature(
            Feature("price", "=", instance_type.price), conflict="me", missing="other")

        system.addFeature(Feature("instance_type", "=",
                                  instance_type.name), conflict="other", missing="other")

    # Get the EC2 connection object
    def get_connection(self, region_name, auth_data):
        """
        Get a :py:class:`boto.ec2.connection` to interact with.

        Arguments:
           - region_name(str): EC2 region to connect.
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
        Returns: a :py:class:`boto.ec2.connection` or None in case of error
        """
        auths = auth_data.getAuthInfo(self.type)
        if not auths:
            raise Exception("No auth data has been specified to EC2.")
        else:
            auth = auths[0]

        if self.connection and self.auth.compare(auth_data, self.type):
            return self.connection
        else:
            self.auth = auth_data
            conn = None
            try:
                if 'username' in auth and 'password' in auth:
                    region = boto.ec2.get_region(region_name)
                    if region:
                        conn = boto.vpc.VPCConnection(aws_access_key_id=auth['username'],
                                                      aws_secret_access_key=auth['password'],
                                                      region=region)
                    else:
                        raise Exception(
                            "Incorrect region name: " + region_name)
                else:
                    self.log_error("No correct auth data has been specified to EC2: "
                                   "username (Access Key) and password (Secret Key)")
                    raise Exception("No correct auth data has been specified to EC2: "
                                    "username (Access Key) and password (Secret Key)")

            except Exception as ex:
                self.log_exception(
                    "Error getting the region " + region_name)
                raise Exception("Error getting the region " +
                                region_name + ": " + str(ex))

            self.connection = conn
            return conn

    # Get the Route53 connection object
    def get_route53_connection(self, region_name, auth_data):
        """
        Get a :py:class:`boto.route53.connection` to interact with.

        Arguments:
           - region_name(str): AWS region to connect.
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
        Returns: a :py:class:`boto.route53.connection` or None in case of error
        """
        auths = auth_data.getAuthInfo(self.type)
        if not auths:
            raise Exception("No auth data has been specified to EC2.")
        else:
            auth = auths[0]

        if self.route53_connection and self.auth.compare(auth_data, self.type):
            return self.route53_connection
        else:
            self.auth = auth_data
            conn = None
            try:
                if 'username' in auth and 'password' in auth:
                    conn = boto.route53.connect_to_region(region_name,
                                                          aws_access_key_id=auth['username'],
                                                          aws_secret_access_key=auth['password'])
                else:
                    self.log_error("No correct auth data has been specified to EC2: "
                                   "username (Access Key) and password (Secret Key)")
                    raise Exception("No correct auth data has been specified to EC2: "
                                    "username (Access Key) and password (Secret Key)")

            except Exception as ex:
                self.log_exception("Error conneting Route53 in region " + region_name)
                raise Exception("Error conneting Route53 in region" + region_name + ": " + str(ex))

            self.route53_connection = conn
            return conn

    # path format: aws://eu-west-1/ami-00685b74
    @staticmethod
    def getAMIData(path):
        """
        Get the region and the AMI ID from an URL of a VMI

        Arguments:
           - path(str): URL of a VMI (some like this: aws://eu-west-1/ami-00685b74)
        Returns: a tuple (region, ami) with the region and the AMI ID
        """
        region = urlparse(path)[1]
        ami = urlparse(path)[2][1:]

        return (region, ami)

    def get_instance_type(self, radl):
        """
        Get the name of the instance type to launch to EC2

        Arguments:
           - radl(str): RADL document with the requirements of the VM to get the instance type
        Returns: a str with the name of the instance type to launch to EC2
        """
        instance_type_name = radl.getValue('instance_type')

        (cpu, cpu_op, memory, memory_op, disk_free, disk_free_op) = self.get_instance_selectors(radl, disk_unit="G")
        arch = radl.getValue('cpu.arch', 'x86_64')

        performance = 0
        performance_op_str = ">="
        if radl.getValue("cpu.performance"):
            cpu_perf = radl.getFeature("cpu.performance")
            # Assume that GCEU = ECU
            if cpu_perf.unit == "ECU" or cpu_perf.unidad == "GCEU":
                performance = float(cpu_perf.value)
                performance_op_str = cpu_perf.getLogOperator()
            else:
                self.log_warn("Performance unit unknown: " + cpu_perf.unit + ". Ignore it")
        performance_op = CloudConnector.OPERATORSMAP.get(performance_op_str)

        instace_types = self.get_all_instance_types()

        res = None
        for instace_type in instace_types:
            # get the instance type with the lowest price
            if res is None or (instace_type.price <= res.price):

                comparison = arch in instace_type.cpu_arch
                comparison = comparison and cpu_op(instace_type.cores_per_cpu * instace_type.num_cpu, cpu)
                comparison = comparison and memory_op(instace_type.mem, memory)
                comparison = comparison and disk_free_op(instace_type.disks * instace_type.disk_space, disk_free)
                comparison = comparison and performance_op(instace_type.cpu_perf, performance)

                if comparison:
                    if not instance_type_name or instace_type.name == instance_type_name:
                        res = instace_type

        if res is None:
            self.get_instance_type_by_name(self.INSTANCE_TYPE)
        else:
            return res

    @staticmethod
    def set_net_provider_id(radl, vpc, subnet):
        """
        Set the provider ID on all the nets of the system
        """
        system = radl.systems[0]
        for i in range(system.getNumNetworkIfaces()):
            net_id = system.getValue('net_interface.' + str(i) + '.connection')
            net = radl.get_network_by_id(net_id)
            if net:
                net.setValue('provider_id', vpc + "." + subnet)

    @staticmethod
    def _get_security_group(conn, sg_name):
        try:
            return conn.get_all_security_groups(filters={'group-name': sg_name})[0]
        except Exception:
            return None

    def create_security_groups(self, conn, inf, radl, vpc):
        res = []
        try:
            i = 0
            system = radl.systems[0]

            # First create a SG for the entire Infra
            # Use the InfrastructureInfo lock to assure that only one VM create the SG
            with inf._lock:
                sg_name = "im-%s" % str(inf.id)
                sg = self._get_security_group(conn, sg_name)
                if not sg:
                    self.log_info("Creating security group: %s" % sg_name)
                    try:
                        sg = conn.create_security_group(sg_name, "Security group created by the IM", vpc_id=vpc)
                        # open all the ports for the VMs in the security group
                        sg.authorize('tcp', 0, 65535, src_group=sg)
                        sg.authorize('udp', 0, 65535, src_group=sg)
                    except Exception as crex:
                        # First check if the SG does exist
                        sg = self._get_security_group(conn, sg_name)
                        if not sg:
                            # if not raise the exception
                            raise crex
                        else:
                            self.log_info("Security group: " + sg_name + " already created.")

                res.append(sg.id)

            while system.getValue("net_interface." + str(i) + ".connection"):
                network_name = system.getValue("net_interface." + str(i) + ".connection")
                network = radl.get_network_by_id(network_name)

                sg_name = network.getValue("sg_name")
                if not sg_name:
                    sg_name = "im-%s-%s" % (str(inf.id), network_name)

                # Use the InfrastructureInfo lock to assure that only one VM create the SG
                with inf._lock:
                    sg = self._get_security_group(conn, sg_name)
                    if not sg:
                        self.log_info("Creating security group: " + sg_name)
                        try:
                            sg = conn.create_security_group(sg_name, "Security group created by the IM", vpc_id=vpc)
                        except Exception as crex:
                            # First check if the SG does exist
                            sg = self._get_security_group(conn, sg_name)
                            if not sg:
                                # if not raise the exception
                                raise crex
                            else:
                                self.log_info("Security group: " + sg_name + " already created.")

                res.append(sg.id)

                try:
                    # open always SSH port
                    sg.authorize('tcp', 22, 22, '0.0.0.0/0')
                    # open all the ports for the VMs in the security group
                    sg.authorize('tcp', 0, 65535, src_group=sg)
                    sg.authorize('udp', 0, 65535, src_group=sg)
                except Exception as addex:
                    self.log_warn("Exception adding SG rules. Probably the rules exists:" + str(addex))

                outports = network.getOutPorts()
                if outports:
                    for outport in outports:
                        if outport.is_range():
                            try:
                                sg.authorize(outport.get_protocol(), outport.get_port_init(),
                                             outport.get_port_end(), '0.0.0.0/0')
                            except Exception as addex:
                                self.log_warn("Exception adding SG rules. Probably the rules exists:" + str(addex))
                        else:
                            if outport.get_remote_port() != 22 or not network.isPublic():
                                try:
                                    sg.authorize(outport.get_protocol(), outport.get_remote_port(),
                                                 outport.get_remote_port(), '0.0.0.0/0')
                                except Exception as addex:
                                    self.log_warn("Exception adding SG rules. Probably the rules exists:" + str(addex))

                i += 1
        except Exception as ex:
            raise Exception("Error Creating the Security group: " + str(ex))

        if not res:
            raise Exception("Error Creating the Security groups")
        else:
            return res

    @staticmethod
    def get_default_subnet(conn):
        """
        Get the default VPC and the first subnet
        """
        vpc_id = None
        subnet_id = None

        for vpc in conn.get_all_vpcs():
            if vpc.is_default or vpc.tags['Name'] == "default":
                vpc_id = vpc.id
                for subnet in conn.get_all_subnets(filters={"vpcId": vpc_id}):
                    subnet_id = subnet.id
                    break
                break

        return vpc_id, subnet_id

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

        return provider_id

    def get_vpc_cidr(self, radl, conn, inf):
        """
        Get a common CIDR in all the RADL nets
        """
        nets = []
        for i, net in enumerate(radl.networks):
            provider_id = net.getValue('provider_id')
            if net.getValue('create') == 'yes' and not net.isPublic() and not provider_id:
                net_cidr = self.get_free_cidr(net.getValue('cidr'),
                                              [subnet.cidr_block for subnet in conn.get_all_subnets()] + nets,
                                              inf, 127)
                nets.append(net_cidr)

        if len(nets) == 0:  # there is no CIDR return the default one
            return "10.0.0.0/16"
        elif len(nets) == 1:  # there is only one, return it
            return nets[0]
        else:  # there are more, get the common CIDR
            return str(spanning_cidr(nets))

    def create_networks(self, conn, radl, inf):
        """
        Create the requested subnets and VPC
        """
        try:
            common_cird = IPNetwork(self.get_vpc_cidr(radl, conn, inf))
            # EC2 does not accept less that /16 CIDRs
            if common_cird.prefixlen < 16:
                vpc_cird = "%s/16" % str(common_cird.ip)
            else:
                vpc_cird = str(common_cird)
            vpc_id = None
            for i, net in enumerate(radl.networks):
                provider_id = net.getValue('provider_id')
                if net.getValue('create') == 'yes' and not net.isPublic() and not provider_id:
                    net_cidr = self.get_free_cidr(net.getValue('cidr'),
                                                  [subnet.cidr_block for subnet in conn.get_all_subnets()],
                                                  inf, 127)
                    net.delValue('cidr')

                    # First create the VPC
                    if vpc_id is None:
                        # Check if it already exists
                        vpcs = conn.get_all_vpcs(filters={"tag:IM-INFRA-ID": inf.id})
                        if vpcs:
                            vpc_id = vpcs[0].id
                            self.log_debug("VPC %s exists. Do not create." % vpc_id)
                        else:
                            # if not create it
                            self.log_info("Creating VPC with cidr: %s." % vpc_cird)
                            vpc = conn.create_vpc(vpc_cird)
                            time.sleep(1)
                            vpc.add_tag("IM-INFRA-ID", inf.id)
                            vpc_id = vpc.id
                            self.log_info("VPC %s created." % vpc_id)

                            self.log_info("Creating Internet Gateway.")
                            ig = conn.create_internet_gateway()
                            time.sleep(1)
                            ig.add_tag("IM-INFRA-ID", inf.id)
                            self.log_info("Internet Gateway %s created." % ig.id)
                            conn.attach_internet_gateway(ig.id, vpc_id)

                            self.log_info("Adding route to the IG.")
                            for route_table in conn.get_all_route_tables(filters={"vpc-id": vpc_id}):
                                conn.create_route(route_table.id, "0.0.0.0/0", ig.id)

                    # Now create the subnet
                    # Check if it already exists
                    subnets = conn.get_all_subnets(filters={"tag:IM-INFRA-ID": inf.id,
                                                            "tag:IM-SUBNET-ID": net.id})
                    if subnets:
                        subnet = subnets[0]
                        self.log_debug("Subnet %s exists. Do not create." % net.id)
                        net.setValue('cidr', subnet.cidr_block)
                    else:
                        self.log_info("Create subnet for net %s." % net.id)
                        subnet = conn.create_subnet(vpc_id, net_cidr)
                        self.log_info("Subnet %s created." % subnet.id)
                        time.sleep(1)
                        subnet.add_tag("IM-INFRA-ID", inf.id)
                        subnet.add_tag("IM-SUBNET-ID", net.id)
                        net.setValue('cidr', net_cidr)
                        # Set also the cidr in the inf RADL
                        inf.radl.get_network_by_id(net.id).setValue('cidr', net_cidr)

                    net.setValue('provider_id', "%s.%s" % (vpc_id, subnet.id))
        except Exception as ex:
            self.log_exception("Error creating subnets or vpc.")
            try:
                for subnet in conn.get_all_subnets(filters={"tag:IM-INFRA-ID": inf.id}):
                    self.log_info("Deleting subnet: %s" % subnet.id)
                    conn.delete_subnet(subnet.id)
                for vpc in conn.get_all_vpcs(filters={"tag:IM-INFRA-ID": inf.id}):
                    self.log_info("Deleting vpc: %s" % vpc.id)
                    conn.delete_vpc(vpc.id)
                for ig in conn.get_all_internet_gateways(filters={"tag:IM-INFRA-ID": inf.id}):
                    self.log_info("Deleting Internet Gateway: %s" % ig.id)
                    conn.delete_internet_gateways(ig.id)
            except Exception:
                self.log_exception("Error deleting subnets or vpc.")
            raise ex

    def get_networks(self, conn, radl):
        """
        Get VPC and Subnet info
        """
        provider_id = self.get_net_provider_id(radl)
        if provider_id:
            parts = provider_id.split(".")
            if len(parts) == 2 and parts[0].startswith("vpc-") and parts[1].startswith("subnet-"):
                vpc = conn.get_all_vpcs([parts[0]])
                subnet = conn.get_all_subnets([parts[1]])
                if vpc and subnet:
                    return vpc[0].id, subnet[0].id
                elif vpc:
                    raise Exception("Incorrect subnet value in provider_id value: %s" % provider_id)
                else:
                    raise Exception("Incorrect vpc value in provider_id value: %s" % provider_id)
            else:
                raise Exception("Incorrect provider_id value: " +
                                provider_id + ". It must be <vpc-id>.<subnet-id>.")
        else:
            # Check the default VPC and get the first subnet with a connection with a gateway
            # If there are no default VPC, raise error
            vpc, subnet = self.get_default_subnet(conn)
            if vpc and subnet:
                return vpc, subnet
            else:
                raise Exception("No VPC.subnet specified and no VPC default found.")

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):

        system = radl.systems[0]
        placement = system.getValue('availability_zone')

        # Currently EC2 plugin uses first private_key credentials
        if system.getValue('disk.0.os.credentials.private_key'):
            system.delValue('disk.0.os.credentials.password')
            system.delValue('disk.0.os.credentials.new.password')

        (region_name, ami) = self.getAMIData(system.getValue("disk.0.image.url"))

        self.log_info("Connecting with the region: " + region_name)
        conn = self.get_connection(region_name, auth_data)

        res = []
        spot = False
        if system.getValue("spot") == "yes":
            spot = True

        if spot:
            if system.getValue("disk.0.os.name"):
                operative_system = system.getValue("disk.0.os.name")
                if operative_system == "linux":
                    operative_system = 'Linux/UNIX'
                    # TODO: diferenciar entre cuando sea
                    # 'Linux/UNIX', 'SUSE Linux' o 'Windows'
                    # teniendo en cuenta tambien el atributo
                    # "flavour" del RADL
            else:
                for i in range(num_vm):
                    res.append((False, ("Error launching the image: spot instances"
                                        " need the OS defined in the RADL")))
                return res

        if not conn:
            for i in range(num_vm):
                res.append((False, "Error connecting with EC2, check the credentials"))
            return res

        instance_type = self.get_instance_type(system)
        if not instance_type:
            self.log_error("Error no instance type available for the requirements.")
            self.log_debug(system)
            for i in range(num_vm):
                res.append((False, "Error no instance type available for the requirements."))

        image = conn.get_image(ami)
        if not image:
            for i in range(num_vm):
                res.append((False, "Incorrect AMI selected"))
            return res

        block_device_name = None
        for name, device in image.block_device_mapping.items():
            if device.snapshot_id or device.volume_id:
                block_device_name = name

        if not block_device_name:
            self.log_error("Error getting correct block_device name from AMI: " + str(ami))
            for i in range(num_vm):
                res.append((False, "Error getting correct block_device name from AMI: " + str(ami)))
            return res

        with inf._lock:
            self.create_networks(conn, radl, inf)

        vpc, subnet = self.get_networks(conn, radl)

        add_public_ip = True
        if not radl.hasPublicNet(system.name) and system.getValue("ec2.associate_public_ip_address") == "no":
            add_public_ip = False

        sg_ids = self.create_security_groups(conn, inf, radl, vpc)

        public_key = system.getValue("disk.0.os.credentials.public_key")
        private_key = system.getValue('disk.0.os.credentials.private_key')
        keypair_name = None

        if not public_key:
            # We must generate them
            (public_key, private_key) = self.keygen()
            system.setValue('disk.0.os.credentials.private_key', private_key)

        # We assume that if the name key is shorter than 128 is a keypair name
        if len(public_key) < 128:
            keypair_name = public_key
            public_key = None

        user = system.getValue('disk.0.os.credentials.username')
        if not user:
            user = self.DEFAULT_USER
            system.setValue('disk.0.os.credentials.username', user)

        tags = self.get_instance_tags(system, auth_data, inf)

        all_failed = True
        volumes = {}

        i = 0
        while i < num_vm:
            try:
                err_msg = "Launching in region %s with image: %s" % (region_name, ami)
                err_msg += " in VPC: %s-%s " % (vpc, subnet)

                vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl, self)
                vm.destroy = True
                inf.add_vm(vm)
                user_data = self.get_cloud_init_data(radl, vm, public_key, user)

                bdm = boto.ec2.blockdevicemapping.BlockDeviceMapping(conn)
                # Force to use magnetic volumes in root device
                bdm[block_device_name] = boto.ec2.blockdevicemapping.BlockDeviceType(volume_type="standard",
                                                                                     delete_on_termination=True)

                volumes = self.get_volumes(conn, vm)
                for device, (size, snapshot_id, disk_type) in volumes.items():
                    bdm[device] = boto.ec2.blockdevicemapping.BlockDeviceType(snapshot_id=snapshot_id,
                                                                              volume_type=disk_type,
                                                                              size=size, delete_on_termination=True)

                if spot:
                    self.log_info("Launching a spot instance")
                    err_msg += " a spot instance "
                    err_msg += " of type: %s " % instance_type.name
                    price = system.getValue("price")
                    # Realizamos el request de spot instances

                    if system.getValue('availability_zone'):
                        availability_zone = system.getValue('availability_zone')
                    else:
                        availability_zone = 'us-east-1c'
                        historical_price = 1000.0
                        availability_zone_list = conn.get_all_zones()
                        for zone in availability_zone_list:
                            history = conn.get_spot_price_history(instance_type=instance_type.name,
                                                                  product_description=operative_system,
                                                                  availability_zone=zone.name,
                                                                  max_results=1)
                            self.log_debug("Spot price history for the region " + zone.name)
                            self.log_debug(history)
                            if history and history[0].price < historical_price:
                                historical_price = history[0].price
                                availability_zone = zone.name
                    self.log_info("Launching the spot request in the zone " + availability_zone)

                    request = conn.request_spot_instances(price=price, image_id=image.id, count=1,
                                                          type='one-time', instance_type=instance_type.name,
                                                          placement=availability_zone, key_name=keypair_name,
                                                          security_group_ids=sg_ids, block_device_map=bdm,
                                                          subnet_id=subnet, user_data=user_data)

                    if request:
                        ec2_vm_id = region_name + ";" + request[0].id

                        self.log_debug("RADL:")
                        self.log_debug(system)

                        vm.id = ec2_vm_id
                        vm.info.systems[0].setValue('instance_id', str(vm.id))
                        self.log_info("Instance successfully launched.")
                        all_failed = False
                        vm.destroy = False
                        res.append((True, vm))
                    else:
                        res.append((False, "Error %s." % err_msg))
                else:
                    self.log_info("Launching ondemand instance")
                    err_msg += " an ondemand instance "
                    err_msg += " of type: %s " % instance_type.name

                    interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(
                        subnet_id=subnet,
                        groups=sg_ids,
                        associate_public_ip_address=add_public_ip)
                    interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)

                    reservation = conn.run_instances(image.id, min_count=1, max_count=1, key_name=keypair_name,
                                                     instance_type=instance_type.name, network_interfaces=interfaces,
                                                     placement=placement, block_device_map=bdm, user_data=user_data)

                    if len(reservation.instances) == 1:
                        time.sleep(1)
                        instance = reservation.instances[0]
                        instance.add_tag("Name", self.gen_instance_name(system))
                        for key, value in tags.items():
                            instance.add_tag(key, value)
                        ec2_vm_id = region_name + ";" + instance.id

                        self.log_debug("RADL:")
                        self.log_debug(system)

                        vm.id = ec2_vm_id
                        vm.info.systems[0].setValue('instance_id', str(vm.id))
                        self.log_info("Instance successfully launched.")
                        vm.destroy = False
                        res.append((True, vm))
                        all_failed = False
                    else:
                        res.append((False, "Error %s." % err_msg))

            except Exception as ex:
                self.log_exception("Error %s." % err_msg)
                res.append((False, "Error %s. %s" % (err_msg, str(ex))))

            i += 1

        # if all the VMs have failed, remove the sgs
        if all_failed:
            if sg_ids:
                for sgid in sg_ids:
                    self.log_info("Remove the SG: %s" % sgid)
                    try:
                        conn.delete_security_group(group_id=sgid)
                    except Exception:
                        self.log_exception("Error deleting SG.")

        return res

    def create_volume(self, conn, disk_size, placement=None, vol_type=None, timeout=60):
        """
        Create an EBS volume

        Arguments:
           - conn(:py:class:`boto.ec2.connection`): object to connect to EC2 API.
           - disk_size(int): The size of the new volume, in GiB
           - placement(str): The availability zone in which the Volume will be created.
           - type(str): Type of the volume: standard | io1 | gp2.
           - timeout(int): Time needed to create the volume.
        Returns: a :py:class:`boto.ec2.volume.Volume` of the new volume
        """
        if placement is None:
            placement = conn.get_all_zones()[0]
        volume = conn.create_volume(disk_size, placement, volume_type=vol_type)
        cont = 0
        err_states = ["error"]
        while str(volume.status) != 'available' and str(volume.status) not in err_states and cont < timeout:
            self.log_info("State: " + str(volume.status))
            cont += 2
            time.sleep(2)
            volume = conn.get_all_volumes([volume.id])[0]

        if str(volume.status) == 'available':
            return volume
        else:
            self.log_error("Error creating the volume %s, deleting it" % (volume.id))
            conn.delete_volume(volume.id)
            return None

    @staticmethod
    def get_volumes(conn, vm):
        """
        Create the required volumes (in the RADL) for the VM.

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM to modify.
        """
        res = {}

        cont = 1
        while ((vm.info.systems[0].getValue("disk." + str(cont) + ".size") or
                vm.info.systems[0].getValue("disk." + str(cont) + ".image.url")) and
                vm.info.systems[0].getValue("disk." + str(cont) + ".device")):
            disk_url = vm.info.systems[0].getValue("disk." + str(cont) + ".image.url")
            disk_device = vm.info.systems[0].getValue("disk." + str(cont) + ".device")
            disk_type = vm.info.systems[0].getValue("disk." + str(cont) + ".type")
            # Allways use sd as the device prefix
            # https://docs.aws.amazon.com/es_es/AWSEC2/latest/UserGuide/device_naming.html
            disk_device = "sd%s" % disk_device[-1]

            disk_size = None
            snapshot_id = None
            if disk_url:
                _, elem_id = EC2CloudConnector.getAMIData(disk_url)
                if elem_id.startswith('snap-'):
                    snapshot_id = conn.get_all_snapshots([elem_id])[0].id
                else:
                    snapshot = conn.get_all_snapshots(filters={'tag:Name': elem_id})
                    if snapshot:
                        snapshot_id = snapshot[0].id
                    else:
                        raise Exception("No snapshot found with name: %s" % elem_id)
            else:
                disk_size = vm.info.systems[0].getFeature("disk." + str(cont) + ".size").getValue('G')

            # Set standard as default type
            if not disk_type:
                disk_type = "standard"
                vm.info.systems[0].setValue("disk." + str(cont) + ".type", disk_type)

            res["/dev/" + disk_device] = (disk_size, snapshot_id, disk_type)
            cont += 1

        return res

    # Get the EC2 instance object with the specified ID
    def get_instance_by_id(self, instance_id, region_name, auth_data):
        """
        Get the EC2 instance object with the specified ID

        Arguments:
           - id(str): ID of the EC2 instance.
           - region_name(str): Region name to search the instance.
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
        Returns: a :py:class:`boto.ec2.instance` of found instance or None if it was not found
        """
        instance = None

        try:
            conn = self.get_connection(region_name, auth_data)

            reservations = conn.get_all_instances([instance_id])
            instance = reservations[0].instances[0]
        except Exception:
            self.log_error("Error getting instance id: %s" % instance_id)

        return instance

    def add_elastic_ip(self, vm, instance, fixed_ip=None):
        """
        Add an elastic IP to an instance

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - instance(:py:class:`boto.ec2.instance`): object to connect to EC2 instance.
           - fixed_ip(str, optional): specifies a fixed IP to add to the instance.
        Returns: a :py:class:`boto.ec2.address.Address` added or None if some problem occur.
        """
        if vm.state == VirtualMachine.RUNNING and "elastic_ip" not in vm.__dict__.keys():
            # Flag to set that this VM has created (or is creating) the elastic
            # IPs
            vm.elastic_ip = True
            try:
                pub_address = None
                self.log_info("Add an Elastic IP")
                if fixed_ip:
                    for address in instance.connection.get_all_addresses():
                        if str(address.public_ip) == fixed_ip:
                            pub_address = address

                    if pub_address:
                        self.log_info("Setting a fixed allocated IP: " + fixed_ip)
                    else:
                        self.log_warn("Setting a fixed IP NOT ALLOCATED! (" + fixed_ip + "). Ignore it.")
                        return None
                else:
                    provider_id = self.get_net_provider_id(vm.info)
                    if provider_id:
                        pub_address = instance.connection.allocate_address(domain="vpc")
                        instance.connection.associate_address(instance.id, allocation_id=pub_address.allocation_id)
                    else:
                        pub_address = instance.connection.allocate_address()
                        instance.connection.associate_address(instance.id, pub_address.public_ip)

                self.log_debug(pub_address)
                return pub_address
            except Exception:
                self.log_exception("Error adding an Elastic IP to VM ID: " + str(vm.id))
                if pub_address:
                    self.log_exception("The Elastic IP was allocated, release it.")
                    pub_address.release()
                return None
        else:
            self.log_info("The VM is not running, not adding an Elastic IP.")
            return None

    def delete_elastic_ips(self, conn, vm, timeout=240):
        """
        remove the elastic IPs of a VM

        Arguments:
           - conn(:py:class:`boto.ec2.connection`): object to connect to EC2 API.
           - vm(:py:class:`IM.VirtualMachine`): VM information.
        """
        fixed_ips = []
        n = 0
        while vm.getRequestedSystem().getValue("net_interface." + str(n) + ".connection"):
            net_conn = vm.getRequestedSystem().getValue('net_interface.' + str(n) + '.connection')
            if vm.info.get_network_by_id(net_conn).isPublic():
                if vm.getRequestedSystem().getValue("net_interface." + str(n) + ".ip"):
                    fixed_ip = vm.getRequestedSystem().getValue("net_interface." + str(n) + ".ip")
                    fixed_ips.append(fixed_ip)
            n += 1

        pub_ips = []
        n = 0
        while vm.info.systems[0].getValue("net_interface." + str(n) + ".connection"):
            net_conn = vm.info.systems[0].getValue('net_interface.' + str(n) + '.connection')
            if vm.info.get_network_by_id(net_conn).isPublic():
                if vm.info.systems[0].getValue("net_interface." + str(n) + ".ip"):
                    pub_ip = vm.info.systems[0].getValue("net_interface." + str(n) + ".ip")
                    pub_ips.append(pub_ip)
            n += 1

        for pub_ip in pub_ips:
            if pub_ip in fixed_ips:
                self.log_info("%s is a fixed IP, it is not released" % pub_ip)
            else:
                for address in conn.get_all_addresses(filters={"public-ip": pub_ip}):
                    self.log_info("This VM has a Elastic IP %s." % address.public_ip)
                    cont = 0
                    while address.instance_id and cont < timeout:
                        cont += 3
                        try:
                            self.log_debug("Disassociate it.")
                            address.disassociate()
                        except Exception:
                            self.log_debug("Error disassociating the IP.")
                        address = conn.get_all_addresses(filters={"public-ip": pub_ip})[0]
                        self.log_info("It is attached. Wait.")
                        time.sleep(3)

                    address = conn.get_all_addresses(filters={"public-ip": pub_ip})[0]
                    self.log_info("Now release it.")
                    address.release()

    def setIPsFromInstance(self, vm, instance):
        """
        Adapt the RADL information of the VM to the real IPs assigned by EC2

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - instance(:py:class:`boto.ec2.instance`): object to connect to EC2 instance.
        """

        vm_system = vm.info.systems[0]
        num_pub_nets = num_nets = 0
        public_ips = []
        private_ips = []
        if (instance.ip_address is not None and len(instance.ip_address) > 0 and
                instance.ip_address != instance.private_ip_address):
            public_ips = [instance.ip_address]
            num_nets += 1
            num_pub_nets = 1
        if instance.private_ip_address is not None and len(instance.private_ip_address) > 0:
            private_ips = [instance.private_ip_address]
            num_nets += 1

        vm.setIps(public_ips, private_ips)

        for net in vm.info.networks:
            if net.isPublic():
                public_net = net

        elastic_ips = []
        # Get the elastic IPs assigned (there must be only 1)
        for address in instance.connection.get_all_addresses():
            if address.instance_id == instance.id:
                elastic_ips.append(str(address.public_ip))
                # It will be used if it is different to the public IP of the
                # instance
                if str(address.public_ip) != instance.ip_address:
                    vm_system.setValue('net_interface.' + str(num_nets) + '.ip', str(instance.ip_address))
                    vm_system.setValue('net_interface.' + str(num_nets) + '.connection', public_net.id)

                    num_pub_nets += 1
                    num_nets += 1

        n = 0
        requested_ips = []
        while vm.getRequestedSystem().getValue("net_interface." + str(n) + ".connection"):
            net_conn = vm.getRequestedSystem().getValue('net_interface.' + str(n) + '.connection')
            if vm.info.get_network_by_id(net_conn).isPublic():
                fixed_ip = vm.getRequestedSystem().getValue("net_interface." + str(n) + ".ip")
                requested_ips.append(fixed_ip)
            n += 1

        for num, ip in enumerate(sorted(requested_ips, reverse=True)):
            if ip:
                # It is a fixed IP
                if ip not in elastic_ips:
                    # It has not been created yet, do it
                    self.add_elastic_ip(vm, instance, ip)
                    # EC2 only supports 1 elastic IP per instance (without
                    # VPC), so break
                    break
            else:
                # Check if we have enough public IPs
                if num >= num_pub_nets:
                    self.add_elastic_ip(vm, instance)
                    # EC2 only supports 1 elastic IP per instance (without
                    # VPC), so break
                    break

    def addRouterInstance(self, vm, conn):
        """
        Add support for IndigoVR
        """
        success = True
        try:
            route_table_id = None

            i = 0
            while vm.info.systems[0].getValue("net_interface." + str(i) + ".connection"):
                net_name = vm.info.systems[0].getValue("net_interface." + str(i) + ".connection")
                i += 1
                network = vm.info.get_network_by_id(net_name)
                if network.getValue('router'):
                    if not route_table_id:
                        vpc_id = None
                        for vpc in conn.get_all_vpcs(filters={"tag:IM-INFRA-ID": vm.inf.id}):
                            vpc_id = vpc.id
                        if not vpc_id:
                            self.log_error("No VPC found.")
                            return False
                        for rt in conn.get_all_route_tables(filters={"vpc-id": vpc_id}):
                            route_table_id = rt.id

                    if not route_table_id:
                        self.log_error("No Route Table found with name.")
                        return False

                    router_info = network.getValue('router').split(",")
                    if len(router_info) != 2:
                        self.log_error("Incorrect router format.")
                        success = False
                        break

                    system_router = router_info[1]
                    router_cidr = router_info[0]

                    vrouter = None
                    for v in vm.inf.vm_list:
                        if v.info.systems[0].name == system_router:
                            if v.id is None or len(v.id.split(";")) < 2:
                                self.log_warn("Unexpected value in VRouter instance (%s): %s" % (system_router, v.id))
                            else:
                                vrouter = v.id.split(";")[1]
                                break
                    if not vrouter:
                        self.log_error("No VRouter instance found with name %s" % system_router)
                        success = False
                        break

                    reservations = conn.get_all_instances([vrouter])
                    vrouter_instance = reservations[0].instances[0]

                    if vrouter_instance.state != "running":
                        self.log_debug("VRouter instance %s is not running." % system_router)
                        success = False
                        break

                    self.log_info("Adding route %s to instance ID: %s." % (router_cidr, vrouter))
                    conn.create_route(route_table_id, router_cidr, instance_id=vrouter)
                    self.log_debug("Disabling sourceDestCheck to instance ID: %s." % vrouter)
                    conn.modify_instance_attribute(vrouter, attribute='sourceDestCheck', value=False)

                    # once set, delete it to not set it again
                    network.delValue('router')
        except Exception:
            success = False
            self.log_exception("Error adding Router Instance")

        return success

    def updateVMInfo(self, vm, auth_data):
        region = vm.id.split(";")[0]
        instance_id = vm.id.split(";")[1]
        conn = self.get_connection(region, auth_data)

        # Check if the instance_id starts with "sir" -> spot request
        if (instance_id[0] == "s"):
            # Check if the request has been fulfilled and the instance has been
            # deployed
            job_instance_id = None

            self.log_info("Check if the request has been fulfilled and the instance has been deployed")
            job_sir_id = instance_id
            request_list = conn.get_all_spot_instance_requests()
            for sir in request_list:
                # TODO: Check if the request had failed and launch it in
                # another availability zone
                if sir.state == 'failed':
                    vm.state = VirtualMachine.FAILED
                if sir.id == job_sir_id:
                    job_instance_id = sir.instance_id
                    break

            if job_instance_id:
                self.log_info("Request fulfilled, instance_id: " + str(job_instance_id))
                instance_id = job_instance_id
                vm.id = region + ";" + instance_id
                vm.info.systems[0].setValue('instance_id', str(vm.id))
            else:
                vm.state = VirtualMachine.PENDING
                return (True, vm)

        instance = self.get_instance_by_id(instance_id, region, auth_data)
        if instance:
            try:
                # sometime if you try to update a recently created instance
                # this operation fails
                instance.update()
                if "IM-USER" not in instance.tags:
                    im_username = "im_user"
                    if auth_data.getAuthInfo('InfrastructureManager'):
                        im_username = auth_data.getAuthInfo('InfrastructureManager')[0]['username']
                    instance.add_tag("IM-USER", im_username)
            except Exception as ex:
                self.log_exception("Error updating the instance " + instance_id)
                return (False, "Error updating the instance " + instance_id + ": " + str(ex))

            vm.info.systems[0].setValue("virtual_system_type", instance.virtualization_type)
            vm.info.systems[0].setValue("availability_zone", instance.placement)

            vm.state = self.VM_STATE_MAP.get(instance.state, VirtualMachine.UNKNOWN)

            instance_type = self.get_instance_type_by_name(instance.instance_type)
            self.update_system_info_from_instance(vm.info.systems[0], instance_type)

            self.setIPsFromInstance(vm, instance)
            self.add_dns_entries(vm, auth_data)
            self.addRouterInstance(vm, conn)

            try:
                vm.info.systems[0].setValue('launch_time', int(time.mktime(
                    time.strptime(instance.launch_time[:19], '%Y-%m-%dT%H:%M:%S'))))
            except Exception as ex:
                self.log_warn("Error setting the launch_time of the instance. "
                              "Probably the instance is not running:" + str(ex))

        else:
            self.log_warn("Error updating the instance %s. VM not found." % instance_id)
            return (False, "Error updating the instance %s. VM not found." % instance_id)

        return (True, vm)

    def add_dns_entries(self, vm, auth_data):
        """
        Add the required entries in the AWS Route53 service

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
        """
        try:
            region = vm.id.split(";")[0]
            conn = self.get_route53_connection(region, auth_data)
            system = vm.info.systems[0]
            for net_name in system.getNetworkIDs():
                num_conn = system.getNumNetworkWithConnection(net_name)
                ip = system.getIfaceIP(num_conn)
                (hostname, domain) = vm.getRequestedNameIface(num_conn,
                                                              default_hostname=Config.DEFAULT_VM_NAME,
                                                              default_domain=Config.DEFAULT_DOMAIN)
                if domain != "localdomain" and ip:
                    if not domain.endswith("."):
                        domain += "."
                    zone = conn.get_zone(domain)
                    if not zone:
                        self.log_info("Creating DNS zone %s" % domain)
                        zone = conn.create_zone(domain)
                    else:
                        self.log_info("DNS zone %s exists. Do not create." % domain)

                    if zone:
                        fqdn = hostname + "." + domain
                        record = zone.get_a(fqdn)
                        if not record:
                            self.log_info("Creating DNS record %s." % fqdn)
                            changes = boto.route53.record.ResourceRecordSets(conn, zone.id)
                            change = changes.add_change("CREATE", fqdn, "A")
                            change.add_value(ip)
                            changes.commit()
                        else:
                            self.log_info("DNS record %s exists. Do not create." % fqdn)

            return True
        except Exception:
            self.log_exception("Error creating DNS entries")
            return False

    def del_dns_entries(self, vm, auth_data):
        """
        Delete the added entries in the AWS Route53 service

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
        """
        region = vm.id.split(";")[0]
        conn = self.get_route53_connection(region, auth_data)
        system = vm.info.systems[0]
        for net_name in system.getNetworkIDs():
            num_conn = system.getNumNetworkWithConnection(net_name)
            ip = system.getIfaceIP(num_conn)
            (hostname, domain) = vm.getRequestedNameIface(num_conn,
                                                          default_hostname=Config.DEFAULT_VM_NAME,
                                                          default_domain=Config.DEFAULT_DOMAIN)
            if domain != "localdomain" and ip:
                if not domain.endswith("."):
                    domain += "."
                zone = conn.get_zone(domain)
                if not zone:
                    self.log_info("The DNS zone %s does not exists. Do not delete records." % domain)
                else:
                    fqdn = hostname + "." + domain
                    record = zone.get_a(fqdn)
                    if not record:
                        self.log_info("DNS record %s does not exists. Do not delete." % fqdn)
                    else:
                        self.log_info("Deleting DNS record %s." % fqdn)
                        changes = boto.route53.record.ResourceRecordSets(conn, zone.id)
                        change = changes.add_change("DELETE", fqdn, "A")
                        change.add_value(ip)
                        changes.commit()

                    # if there are no A records
                    all_a_records = [r for r in conn.get_all_rrsets(zone.id) if r.type == "A"]
                    if not all_a_records:
                        conn.delete_hosted_zone(zone.id)

    def cancel_spot_requests(self, conn, vm):
        """
        Cancel the spot requests of a VM

        Arguments:
           - conn(:py:class:`boto.ec2.connection`): object to connect to EC2 API.
           - vm(:py:class:`IM.VirtualMachine`): VM information.
        """
        instance_id = vm.id.split(";")[1]
        # Check if the instance_id starts with "sir" -> spot request
        if (instance_id[0] == "s"):
            request_list = conn.get_all_spot_instance_requests([instance_id])
            for sir in request_list:
                conn.cancel_spot_instance_requests(sir.id)
                self.log_info("Spot instance request " + str(sir.id) + " deleted")
                break

    def delete_networks(self, conn, vm, timeout=240):
        """
        Delete the created networks
        """
        for subnet in conn.get_all_subnets(filters={"tag:IM-INFRA-ID": vm.inf.id}):
            self.log_info("Deleting subnet: %s" % subnet.id)
            cont = 0
            deleted = False
            while not deleted and cont < timeout:
                cont += 5
                try:
                    conn.delete_subnet(subnet.id)
                    deleted = True
                except Exception as ex:
                    self.log_warn("Error removing subnet: " + str(ex))

                if not deleted:
                    time.sleep(5)

            if not deleted:
                self.log_error("Timeout (%s) deleting the subnet %s" % (timeout, subnet.id))

        vpc_id = None
        for vpc in conn.get_all_vpcs(filters={"tag:IM-INFRA-ID": vm.inf.id}):
            vpc_id = vpc.id
        ig_id = None
        for ig in conn.get_all_internet_gateways(filters={"tag:IM-INFRA-ID": vm.inf.id}):
            ig_id = ig.id

        if ig_id and vpc_id:
            self.log_info("Detacching Internet Gateway: %s from VPC: %s" % (ig_id, vpc_id))
            conn.detach_internet_gateway(ig_id, vpc_id)
        if ig_id:
            self.log_info("Deleting Internet Gateway: %s" % ig.id)
            conn.delete_internet_gateway(ig_id)
        if vpc_id:
            self.log_info("Deleting vpc: %s" % vpc.id)
            conn.delete_vpc(vpc_id)

    def finalize(self, vm, last, auth_data):

        # first delete the snapshots to avoid problems in EC3 deleting the IM front-end
        if last:
            self.delete_snapshots(vm, auth_data)

        error_msg = ""
        if vm.id is None:
            self.log_info("VM with no ID. Ignore.")
            return True, ""

        region_name = vm.id.split(";")[0]
        instance_id = vm.id.split(";")[1]

        conn = self.get_connection(region_name, auth_data)

        # Terminate the instance
        instance = self.get_instance_by_id(instance_id, region_name, auth_data)
        if instance is not None:
            instance.terminate()

        # Delete the elastic IPs
        try:
            self.delete_elastic_ips(conn, vm)
        except Exception as ex:
            self.log_exception("Error deleting elastic IPs")
            error_msg += "Error deleting elastic IPs: %s. " % ex

        # Delete the spot instance requests
        try:
            self.cancel_spot_requests(conn, vm)
        except Exception as ex:
            self.log_exception("Error canceling spot requests.")
            error_msg += "Error canceling spot requests: %s. " % ex

        # Delete the DNS entries
        try:
            self.del_dns_entries(vm, auth_data)
        except Exception as ex:
            self.log_exception("Error deleting DNS entries")
            error_msg += "Error deleting DNS entries: %s. " % ex

        # if this is the last VM
        if last:
            # Delete the SG
            try:
                self.delete_security_groups(conn, vm)
            except Exception as ex:
                self.log_exception("Error deleting security group.")
                error_msg += "Error deleting security group: %s. " % ex

            # And nets
            try:
                self.delete_networks(conn, vm)
            except Exception as ex:
                self.log_exception("Error deleting networks.")
                error_msg += "Error deleting networks: %s. " % ex

        return (error_msg == "", error_msg)

    def _get_security_groups(self, conn, vm):
        """
        Get all the SGs where the VM is included
        """
        sg_names = ["im-%s" % str(vm.inf.id)]
        for net in vm.inf.radl.networks:
            sg_name = net.getValue("sg_name")
            if not sg_name:
                sg_name = "im-%s-%s" % (str(vm.inf.id), net.id)
            sg_names.append(sg_name)

        sgs = []
        for sg_name in sg_names:
            try:
                sgs.extend(conn.get_all_security_groups(filters={'group-name': sg_name}))
            except Exception:
                self.log_exception("Error getting SG %s" % sg_name)
        return sgs

    def delete_security_groups(self, conn, vm, timeout=90):
        """
        Delete the SG of this infrastructure if this is the last VM

        Arguments:
           - conn(:py:class:`boto.ec2.connection`): object to connect to EC2 API.
           - vm(:py:class:`IM.VirtualMachine`): VirtualMachine information.
        """
        sgs = self._get_security_groups(conn, vm)

        if sgs:
            # Get the default SG to set in the instances
            def_sg_id = conn.get_all_security_groups(filters={'group-name': 'default',
                                                              'vpc-id': sgs[0].vpc_id})[0].id

        for sg in sgs:
            if sg.description != "Security group created by the IM":
                self.log_info("SG %s not created by the IM. Do not delete it." % sg.name)
                continue
            try:
                for instance in sg.instances():
                    instance.modify_attribute("groupSet", [def_sg_id])
            except Exception as ex:
                self.log_warn("Error removing the SG %s from the instance: %s. %s" % (sg.name, instance.id, ex))
                # try to wait some seconds to free the SGs
                time.sleep(5)

            self.log_info("Remove the SG: " + sg.name)
            try:
                sg.revoke('tcp', 0, 65535, src_group=sg)
                sg.revoke('udp', 0, 65535, src_group=sg)
            except Exception as ex:
                self.log_warn("Error revoking self rules: " + str(ex))

            sg.delete()

    def stop(self, vm, auth_data):
        region_name = vm.id.split(";")[0]
        instance_id = vm.id.split(";")[1]

        instance = self.get_instance_by_id(instance_id, region_name, auth_data)
        if (instance is not None):
            instance.update()
            instance.stop()

        return (True, "")

    def start(self, vm, auth_data):
        region_name = vm.id.split(";")[0]
        instance_id = vm.id.split(";")[1]

        instance = self.get_instance_by_id(instance_id, region_name, auth_data)
        if (instance is not None):
            instance.update()
            instance.start()

        return (True, "")

    def reboot(self, vm, auth_data):
        region_name = vm.id.split(";")[0]
        instance_id = vm.id.split(";")[1]

        instance = self.get_instance_by_id(instance_id, region_name, auth_data)
        if (instance is not None):
            instance.update()
            instance.reboot()

        return (True, "")

    @staticmethod
    def waitStop(instance, timeout=120):
        """
        Wait a instance to be stopped
        """
        instance.stop()
        wait = 0
        powered_off = False
        while wait < timeout and not powered_off:
            instance.update()

            powered_off = instance.state == 'stopped'
            if not powered_off:
                time.sleep(2)
                wait += 2

        return powered_off

    def alterVM(self, vm, radl, auth_data):
        region_name = vm.id.split(";")[0]
        instance_id = vm.id.split(";")[1]

        # Terminate the instance
        instance = self.get_instance_by_id(instance_id, region_name, auth_data)
        if instance:
            instance.update()
        else:
            return (False, "The instance has not been found")

        success = True
        if radl.systems:
            instance_type = self.get_instance_type(radl.systems[0])

            if instance_type and instance.instance_type != instance_type.name:
                stopped = self.waitStop(instance)
                if stopped:
                    success = instance.modify_attribute('instanceType', instance_type.name)
                    if success:
                        self.update_system_info_from_instance(vm.info.systems[0], instance_type)
                        instance.start()
                else:
                    return (False, "Error stopping instance: " + instance_id)

        if success:
            _, vm = self.updateVMInfo(vm, auth_data)
            return (success, vm)
        else:
            return (success, "Unknown Error")

    def get_all_instance_types(self, retries=3, delay=5):
        """
        Get all the EC2 instance types

        Returns: a list of :py:class:`InstanceTypeInfo`
        """
        # Get info from http://www.ec2instances.info/
        # https://raw.githubusercontent.com/powdahound/ec2instances.info/master/www/instances.json

        if EC2CloudConnector.instance_type_list:
            return EC2CloudConnector.instance_type_list

        cont = 0
        data = None
        while cont < retries and not data:
            cont += 1
            try:
                info_url = "https://raw.githubusercontent.com/powdahound/ec2instances.info/master/www/instances.json"
                resp = requests.get(info_url)
                if resp.status_code == 200:
                    data = resp.json()
                else:
                    time.sleep(delay)
            except Exception as ex:
                self.log_warn("Error getting ec2instances info: %s. (%s/%s)" % (ex, cont, retries))
                time.sleep(delay)

        instance_list = []
        if not data:
            self.log_error("Error getting ec2instances info.")
        else:
            for instance_type in data:
                price = 50
                if instance_type['pricing'] and 'us-east-1' in instance_type['pricing']:
                    price = float(instance_type['pricing']['us-east-1']['linux']['ondemand'])
                disks = 0
                disk_space = 0
                if instance_type['storage']:
                    disks = instance_type['storage']['devices']
                    disk_space = instance_type['storage']['size']
                cpu_perf = instance_type['ECU']
                if cpu_perf == 'variable':
                    cpu_perf = 0
                instance_list.append(InstanceTypeInfo(name=instance_type['instance_type'],
                                                      cpu_arch=instance_type['arch'],
                                                      num_cpu=instance_type['vCPU'],
                                                      cores_per_cpu=1,
                                                      mem=instance_type['memory'] * 1024,
                                                      price=price,
                                                      cpu_perf=cpu_perf,
                                                      disks=disks,
                                                      disk_space=disk_space,
                                                      vpc_only=instance_type['vpc_only'],
                                                      gpu=instance_type['GPU']))
            EC2CloudConnector.instance_type_list = instance_list

        return instance_list

    def get_instance_type_by_name(self, name):
        """
        Get the EC2 instance type with the specified name

        Returns: an :py:class:`InstanceTypeInfo` or None if the type is not found
        """
        for inst_type in self.get_all_instance_types():
            if inst_type.name == name:
                return inst_type
        return None

    def create_snapshot(self, vm, disk_num, image_name, auto_delete, auth_data):
        """
        Create a snapshot of a virtual machine.
        Arguments:
          - vm(:py:class:`IM.VirtualMachine`): VM to stop.
          - disk_num(int): Number of the disk.
          - image_name(str): Name of the new image.
          - auto_delete(bool): A flag to specify that the snapshot will be deleted when the
            infrastructure is destroyed.
          - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.

        http://boto.readthedocs.io/en/latest/ref/ec2.html#module-boto.ec2.volume
        http://boto.readthedocs.io/en/latest/ref/ec2.html#module-boto.ec2.instance

        Returns: a tuple (success, vm).
          - The first value is True if the operation finished successfully or False otherwise.
          - The second value is a str with the url of the new image if the operation finished successfully
            or an error message otherwise.
        """
        region_name = vm.id.split(";")[0]
        instance_id = vm.id.split(";")[1]
        snapshot_id = ""

        # Obtain the connection object to connect with EC2
        conn = self.get_connection(region_name, auth_data)

        if not conn:
            return (False, "Error connecting with EC2, check the credentials")

        # Create the instance snapshot
        instance = self.get_instance_by_id(instance_id, region_name, auth_data)
        if instance:
            self.log_info("Creating snapshot: " + image_name)
            snapshot_id = instance.create_image(image_name,
                                                description="AMI automatically generated by IM",
                                                no_reboot=True)
            # Add tags to the snapshot to be recognizable
            conn.create_tags(snapshot_id, {'instance_id': instance_id})
        else:
            return (False, "Error obtaining details of the instance")
        if snapshot_id != "":
            new_url = "aws://%s/%s" % (region_name, snapshot_id)
            if auto_delete:
                vm.inf.snapshots.append(new_url)
            return (True, new_url)
        else:
            return (False, "Error generating VM snapshot")

    def delete_image(self, image_url, auth_data):
        (region_name, ami) = self.getAMIData(image_url)

        self.log_info("Deleting image: %s." % image_url)
        conn = self.get_connection(region_name, auth_data)

        success = conn.deregister_image(ami, delete_snapshot=True)  # https://github.com/boto/boto/issues/3019

        if success:
            return (True, "")
        else:
            return (False, "Error deregistering AMI image" + image_url)

    def list_images(self, auth_data, filters=None):
        regions = None
        auth = auth_data.getAuthInfo(self.type)[0]
        if 'region' in auth and auth['region']:
            regions = [auth['region']]
        if filters and 'region' in filters and filters['region']:
            regions = [filters['region']]
            del filters['region']
        if not regions:
            regions = [region.name for region in boto.ec2.regions()]

        images_filter = {'architecture': 'x86_64', 'image-type': 'machine',
                         'virtualization-type': 'hvm', 'state': 'available',
                         'root-device-type': 'ebs'}

        # enable the user to add or overwrite the filters
        if filters:
            images_filter.update(filters)

        images = []
        for region in regions:
            conn = self.get_connection(region, auth_data)
            try:
                for image in conn.get_all_images(owners=['self', 'aws-marketplace'], filters=images_filter):
                    if len(image.id) > 12:  # do not add old images
                        images.append({"uri": "aws://%s/%s" % (region, image.id),
                                       "name": "%s/%s" % (region, image.name)})
            except Exception:
                continue
        return images
