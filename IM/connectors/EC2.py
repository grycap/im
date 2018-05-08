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
import base64
import os
import uuid

try:
    import boto.ec2
    import boto.vpc
    import boto.route53
except Exception as ex:
    print("WARN: Boto library not correctly installed. EC2CloudConnector will not work!.")
    print(ex)

from IM.uriparse import uriparse
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
    """

    def __init__(self, name="", cpu_arch=None, num_cpu=1, cores_per_cpu=1, mem=0,
                 price=0, cpu_perf=0, disks=0, disk_space=0, vpc_only=None):
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


class EC2CloudConnector(CloudConnector):
    """
    Cloud Launcher to the EC2 platform
    """

    type = "EC2"
    """str with the name of the provider."""
    KEYPAIR_DIR = '/tmp'
    """str with a path to store the keypair files."""
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

    def __init__(self, cloud_info, inf):
        self.connection = None
        self.route53_connection = None
        self.auth = None
        CloudConnector.__init__(self, cloud_info, inf)

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
                if protocol == "aws":
                    # Currently EC2 plugin only uses private_key credentials
                    res_system = radl_system.clone()
                    if res_system.getValue('disk.0.os.credentials.private_key'):
                        res_system.delValue('disk.0.os.credentials.password')
                        res_system.delValue('disk.0.os.credentials.new.password')

                    res_system.addFeature(
                        Feature("disk.0.image.url", "=", str_url), conflict="other", missing="other")
                    res_system.addFeature(
                        Feature("provider.type", "=", self.type), conflict="other", missing="other")

                    instance_type = self.get_instance_type(res_system)
                    if not instance_type:
                        self.log_error("Error launching the VM, no instance type available for the requirements.")
                        self.log_debug(res_system)
                        return []
                    else:
                        self.update_system_info_from_instance(
                            res_system, instance_type)
                        res.append(res_system)

            return res

    def update_system_info_from_instance(self, system, instance_type):
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

    # el path sera algo asi: aws://eu-west-1/ami-00685b74
    def getAMIData(self, path):
        """
        Get the region and the AMI ID from an URL of a VMI

        Arguments:
           - path(str): URL of a VMI (some like this: aws://eu-west-1/ami-00685b74)
        Returns: a tuple (region, ami) with the region and the AMI ID
        """
        region = uriparse(path)[1]
        ami = uriparse(path)[2][1:]

        return (region, ami)

    def get_instance_type(self, radl, vpc=None):
        """
        Get the name of the instance type to launch to EC2

        Arguments:
           - radl(str): RADL document with the requirements of the VM to get the instance type
           - vpc(bool): VPC flag that specifies that the instance will be launched using VPC or Classic
        Returns: a str with the name of the instance type to launch to EC2
        """
        instance_type_name = radl.getValue('instance_type')

        cpu = 1
        cpu_op = ">="
        if radl.getFeature('cpu.count'):
            cpu = radl.getValue('cpu.count')
            cpu_op = radl.getFeature('cpu.count').getLogOperator()

        arch = radl.getValue('cpu.arch', 'x86_64')

        memory = 1
        memory_op = ">="
        if radl.getFeature('memory.size'):
            memory = radl.getFeature('memory.size').getValue('M')
            memory_op = radl.getFeature('memory.size').getLogOperator()

        disk_free = 0
        disk_free_op = ">="
        if radl.getValue('disks.free_size'):
            disk_free = radl.getFeature('disks.free_size').getValue('G')
            disk_free_op = radl.getFeature('disks.free_size').getLogOperator()

        performance = 0
        performance_op = ">="
        if radl.getValue("cpu.performance"):
            cpu_perf = radl.getFeature("cpu.performance")
            # Assume that GCEU = ECU
            if cpu_perf.unit == "ECU" or cpu_perf.unidad == "GCEU":
                performance = float(cpu_perf.value)
                performance_op = cpu_perf.getLogOperator()
            else:
                self.log_warn("Performance unit unknown: " + cpu_perf.unit + ". Ignore it")

        instace_types = self.get_all_instance_types()

        res = None
        for instace_type in instace_types:
            # get the instance type with the lowest price
            if res is None or (instace_type.price <= res.price):
                str_compare = "arch in instace_type.cpu_arch "
                str_compare += " and instace_type.cores_per_cpu * instace_type.num_cpu " + cpu_op + " cpu "
                str_compare += " and instace_type.mem " + memory_op + " memory "
                str_compare += " and instace_type.cpu_perf " + performance_op + " performance"
                str_compare += " and instace_type.disks * instace_type.disk_space " + disk_free_op + " disk_free"
                # If the instance will use EC2 classic, get only instances without vpc_only flag
                if vpc is False:
                    str_compare += " and instace_type.vpc_only == False"

                # if arch in instace_type.cpu_arch and
                # instace_type.cores_per_cpu * instace_type.num_cpu >= cpu and
                # instace_type.mem >= memory and instace_type.cpu_perf >=
                # performance and instace_type.disks * instace_type.disk_space
                # >= disk_free:
                if eval(str_compare):
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

        if provider_id:
            parts = provider_id.split(".")
            if len(parts) == 2 and parts[0].startswith("vpc-") and parts[1].startswith("subnet-"):
                # TODO: check that the VPC and subnet, exists
                return parts[0], parts[1]
            else:
                raise Exception("Incorrect provider_id value: " +
                                provider_id + ". It must be <vpc-id>.<subnet-id>.")
        else:
            return None

    @staticmethod
    def _get_security_group(conn, sg_name):
        try:
            return conn.get_all_security_groups(filters={'group-name': sg_name})[0]
        except Exception:
            return None

    def create_security_groups(self, conn, inf, radl, vpc=None):
        res = []
        try:
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

                if vpc:
                    res.append(sg.id)
                else:
                    res.append(sg.name)

                try:
                    # open always SSH port on public nets
                    if network.isPublic():
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
                            if outport.get_remote_port() != 22:
                                try:
                                    sg.authorize(outport.get_protocol(), outport.get_remote_port(),
                                                 outport.get_remote_port(), '0.0.0.0/0')
                                except Exception as addex:
                                    self.log_warn("Exception adding SG rules. Probably the rules exists:" + str(addex))

                i += 1
        except Exception as ex:
            self.log_exception("Error Creating the Security group")
            if vpc:
                raise Exception("Error Creating the Security group: " + str(ex))

        if not res:
            return None
        else:
            return res

    def create_keypair(self, system, conn):
        # create the keypair
        keypair_name = "im-" + str(uuid.uuid1())
        created = False

        try:
            private = system.getValue('disk.0.os.credentials.private_key')
            public = system.getValue('disk.0.os.credentials.public_key')
            if private and public:
                if public.find('-----BEGIN CERTIFICATE-----') != -1:
                    self.log_info("The RADL specifies the PK, upload it to EC2")
                    public_key = base64.b64encode(public)
                    conn.import_key_pair(keypair_name, public_key)
                else:
                    # the public_key nodes specifies the keypair name
                    keypair_name = public
                # Update the credential data
                system.setUserKeyCredentials(
                    system.getCredentials().username, public, private)
            else:
                self.log_info("Creating the Keypair name: %s" % keypair_name)
                keypair_file = self.KEYPAIR_DIR + '/' + keypair_name + '.pem'
                keypair = conn.create_key_pair(keypair_name)
                created = True
                keypair.save(self.KEYPAIR_DIR)
                os.chmod(keypair_file, 0o400)
                with open(keypair_file, "r") as fkeypair:
                    system.setUserKeyCredentials(system.getCredentials().username,
                                                 None, fkeypair.read())
                os.unlink(keypair_file)
        except:
            self.log_exception("Error kreating keypair.")
            keypair_name = None

        return (created, keypair_name)

    def get_default_subnet(self, conn):
        """
        Get the default VPC and the first subnet
        """
        vpc_id = None
        subnet_id = None

        for vpc in conn.get_all_vpcs():
            if vpc.is_default:
                vpc_id = vpc.id
                for subnet in conn.get_all_subnets({"vpcId": vpc_id}):
                    subnet_id = subnet.id
                    break
                break

        return vpc_id, subnet_id

    def get_cloud_init_data(self, radl):
        """
        Get the cloud init data specified by the user in the RADL
        """
        configure_name = None
        if radl.contextualize.items:
            system_name = radl.systems[0].name

            for item in radl.contextualize.items.values():
                if item.system == system_name and item.get_ctxt_tool() == "cloud_init":
                    configure_name = item.configure

        if configure_name:
            return radl.get_configure_by_name(configure_name).recipes
        else:
            return None

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):

        im_username = "im_user"
        if auth_data.getAuthInfo('InfrastructureManager'):
            im_username = auth_data.getAuthInfo(
                'InfrastructureManager')[0]['username']

        system = radl.systems[0]

        user_data = self.get_cloud_init_data(radl)

        # Currently EC2 plugin uses first private_key credentials
        if system.getValue('disk.0.os.credentials.private_key'):
            system.delValue('disk.0.os.credentials.password')
            system.delValue('disk.0.os.credentials.new.password')

        (region_name, ami) = self.getAMIData(
            system.getValue("disk.0.image.url"))

        self.log_info("Connecting with the region: " + region_name)
        conn = self.get_connection(region_name, auth_data)

        res = []
        if not conn:
            for i in range(num_vm):
                res.append(
                    (False, "Error connecting with EC2, check the credentials"))
            return res

        image = conn.get_image(ami)

        if not image:
            for i in range(num_vm):
                res.append((False, "Incorrect AMI selected"))
            return res
        else:
            block_device_name = None
            for name, device in image.block_device_mapping.items():
                if device.snapshot_id or device.volume_id:
                    block_device_name = name

            if not block_device_name:
                self.log_error(
                    "Error getting correct block_device name from AMI: " + str(ami))
                for i in range(num_vm):
                    res.append(
                        (False, "Error getting correct block_device name from AMI: " + str(ami)))
                return res

            # Create the security group for the VMs
            provider_id = self.get_net_provider_id(radl)
            if provider_id:
                vpc, subnet = provider_id
                sg_names = None
                sg_ids = self.create_security_groups(conn, inf, radl, vpc)
                if not sg_ids:
                    vpc = None
                    subnet = None
                    sg_ids = None
                    sg_names = ['default']
            else:
                # Check the default VPC and get the first subnet with a connection with a gateway
                # If there are no default VPC, use EC2-classic
                vpc, subnet = self.get_default_subnet(conn)
                if vpc:
                    self.set_net_provider_id(radl, vpc, subnet)
                    sg_names = None
                    sg_ids = self.create_security_groups(conn, inf, radl, vpc)
                else:
                    sg_ids = None
                    sg_names = self.create_security_groups(conn, inf, radl, vpc)
                    if not sg_names:
                        sg_names = ['default']

            # Now create the keypair
            (created_keypair, keypair_name) = self.create_keypair(system, conn)
            if not keypair_name:
                self.log_error("Error managing the keypair.")
                for i in range(num_vm):
                    res.append((False, "Error managing the keypair."))
                return res

            all_failed = True

            i = 0
            while i < num_vm:
                err_msg = "Launching in region %s with image: %s" % (region_name, ami)
                if vpc:
                    err_msg += " in VPC: %s-%s " % (vpc, subnet)
                else:
                    err_msg += " in EC2 classic "
                try:
                    spot = False
                    if system.getValue("spot") == "yes":
                        spot = True

                    if spot:
                        err_msg += " a spot instance "
                        self.log_info("Launching a spot instance")
                        instance_type = self.get_instance_type(system, vpc is not None)
                        if not instance_type:
                            self.log_error("Error %s, no instance type available for the requirements." % err_msg)
                            self.log_debug(system)
                            res.append(
                                (False, "Error %s, no instance type available for the requirements." % err_msg))
                        else:
                            err_msg += " of type: %s " % instance_type.name
                            price = system.getValue("price")
                            # Realizamos el request de spot instances
                            if system.getValue("disk.0.os.name"):
                                operative_system = system.getValue(
                                    "disk.0.os.name")
                                if operative_system == "linux":
                                    operative_system = 'Linux/UNIX'
                                    # TODO: diferenciar entre cuando sea
                                    # 'Linux/UNIX', 'SUSE Linux' o 'Windows'
                                    # teniendo en cuenta tambien el atributo
                                    # "flavour" del RADL
                            else:
                                res.append((False, ("Error launching the image: spot instances"
                                                    " need the OS defined in the RADL")))
                                # operative_system = 'Linux/UNIX'

                            if system.getValue('availability_zone'):
                                availability_zone = system.getValue(
                                    'availability_zone')
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

                            # Force to use magnetic volumes
                            bdm = boto.ec2.blockdevicemapping.BlockDeviceMapping(
                                conn)
                            bdm[block_device_name] = boto.ec2.blockdevicemapping.BlockDeviceType(
                                volume_type="standard")
                            request = conn.request_spot_instances(price=price, image_id=image.id, count=1,
                                                                  type='one-time', instance_type=instance_type.name,
                                                                  placement=availability_zone, key_name=keypair_name,
                                                                  security_groups=sg_names, security_group_ids=sg_ids,
                                                                  block_device_map=bdm, subnet_id=subnet,
                                                                  user_data=user_data)

                            if request:
                                ec2_vm_id = region_name + ";" + request[0].id

                                self.log_debug("RADL:")
                                self.log_debug(system)

                                vm = VirtualMachine(
                                    inf, ec2_vm_id, self.cloud, radl, requested_radl, self)
                                vm.info.systems[0].setValue(
                                    'instance_id', str(vm.id))
                                # Add the keypair name to remove it later
                                vm.keypair_name = keypair_name
                                self.log_info("Instance successfully launched.")
                                all_failed = False
                                inf.add_vm(vm)
                                res.append((True, vm))
                            else:
                                res.append((False, "Error %s." % err_msg))
                    else:
                        err_msg += " an ondemand instance "
                        self.log_info("Launching ondemand instance")
                        instance_type = self.get_instance_type(system, vpc is not None)
                        if not instance_type:
                            self.log_error("Error %s, no instance type available for the requirements." % err_msg)
                            self.log_debug(system)
                            res.append(
                                (False, "Error %s, no instance type available for the requirements." % err_msg))
                        else:
                            err_msg += " of type: %s " % instance_type.name
                            placement = system.getValue('availability_zone')
                            # Force to use magnetic volumes
                            bdm = boto.ec2.blockdevicemapping.BlockDeviceMapping(conn)
                            bdm[block_device_name] = boto.ec2.blockdevicemapping.BlockDeviceType(volume_type="standard")
                            # Check if the user has specified the net provider
                            # id
                            reservation = image.run(min_count=1, max_count=1, key_name=keypair_name,
                                                    instance_type=instance_type.name, security_groups=sg_names,
                                                    security_group_ids=sg_ids, placement=placement,
                                                    block_device_map=bdm, subnet_id=subnet, user_data=user_data)

                            if len(reservation.instances) == 1:
                                instance = reservation.instances[0]
                                instance.add_tag("IM-USER", im_username)
                                ec2_vm_id = region_name + ";" + instance.id

                                self.log_debug("RADL:")
                                self.log_debug(system)

                                vm = VirtualMachine(
                                    inf, ec2_vm_id, self.cloud, radl, requested_radl, self)
                                vm.info.systems[0].setValue(
                                    'instance_id', str(vm.id))
                                # Add the keypair name to remove it later
                                vm.keypair_name = keypair_name
                                self.log_info("Instance successfully launched.")
                                inf.add_vm(vm)
                                res.append((True, vm))
                                all_failed = False
                            else:
                                res.append((False, "Error %s." % err_msg))

                except Exception as ex:
                    self.log_exception("Error %s." % err_msg)
                    res.append((False, "Error %s. %s" % (err_msg, str(ex))))

                i += 1

        # if all the VMs have failed, remove the sg and keypair
        if all_failed:
            if created_keypair:
                try:
                    conn.delete_key_pair(keypair_name)
                except:
                    self.log_exception("Error deleting keypair.")
            if sg_ids:
                try:
                    for sgid in sg_ids:
                        self.log_info("Remove the SG: %s" % sgid)
                        conn.delete_security_group(group_id=sgid)
                except:
                    self.log_exception("Error deleting SG.")
            if sg_names and sg_names[0] != 'default':
                try:
                    for sgname in sg_names:
                        self.log_info("Remove the SG: %s" % sgname)
                        conn.delete_security_group(sgname)
                except:
                    self.log_exception("Error deleting SG.")

        return res

    def create_volume(self, conn, disk_size, placement, timeout=60):
        """
        Create an EBS volume

        Arguments:
           - conn(:py:class:`boto.ec2.connection`): object to connect to EC2 API.
           - disk_size(:py:class:`boto.ec2.connection`): The size of the new volume, in GiB
           - placement(str): The availability zone in which the Volume will be created.
           - timeout(int): Time needed to create the volume.
        Returns: a :py:class:`boto.ec2.volume.Volume` of the new volume
        """
        volume = conn.create_volume(disk_size, placement)
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

    def attach_volumes(self, instance, vm):
        """
        Attach a the required volumes (in the RADL) to the launched instance

        Arguments:
           - instance(:py:class:`boto.ec2.instance`): object to connect to EC2 instance.
           - vm(:py:class:`IM.VirtualMachine`): VM information.
        """
        try:
            if instance.state == 'running' and "volumes" not in vm.__dict__.keys():
                # Flag to se that this VM has created (or is creating) the
                # volumes
                vm.volumes = True
                conn = instance.connection
                cont = 1
                while (vm.info.systems[0].getValue("disk." + str(cont) + ".size") and
                       vm.info.systems[0].getValue("disk." + str(cont) + ".device")):
                    disk_size = vm.info.systems[0].getFeature(
                        "disk." + str(cont) + ".size").getValue('G')
                    disk_device = vm.info.systems[0].getValue(
                        "disk." + str(cont) + ".device")
                    self.log_info("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
                    volume = self.create_volume(
                        conn, int(disk_size), instance.placement)
                    if volume:
                        self.log_info("Attach the volume ID " + str(volume.id))
                        conn.attach_volume(
                            volume.id, instance.id, "/dev/" + disk_device)
                    cont += 1
        except Exception:
            self.log_exception(
                "Error creating or attaching the volume to the instance")

    def delete_volumes(self, conn, volumes, instance_id, timeout=240):
        """
        Delete the volumes specified in the volumes list

        Arguments:
           - conn(:py:class:`boto.ec2.connection`): object to connect to EC2 API.
           - volumes(list of strings): Volume IDs to delete.
           - timeout(int): Time needed to delete the volume.
        """
        for volume_id in volumes:
            cont = 0
            deleted = False
            while not deleted and cont < timeout:
                cont += 5
                try:
                    curr_vol = conn.get_all_volumes([volume_id])[0]
                except:
                    self.log_warn(
                        "The volume " + volume_id + " does not exist. It cannot be removed. Ignore it.")
                    deleted = True
                    break
                try:
                    curr_vol = conn.get_all_volumes([volume_id])[0]
                    if str(curr_vol.attachment_state()) == "attached":
                        self.log_info("Detaching the volume " + volume_id + " from the instance " + instance_id)
                        conn.detach_volume(volume_id, instance_id, force=True)
                    elif curr_vol.attachment_state() is None:
                        self.log_info("Removing the volume " + volume_id)
                        conn.delete_volume(volume_id)
                        deleted = True
                    else:
                        self.log_info("State: " + str(curr_vol.attachment_state()))
                except Exception as ex:
                    self.log_warn("Error removing the volume: " + str(ex))

                if not deleted:
                    time.sleep(5)

            if not deleted:
                self.log_error("Error removing the volume " + volume_id)

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
        except:
            pass

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
                        pub_address = instance.connection.allocate_address(
                            domain="vpc")
                        instance.connection.associate_address(
                            instance.id, allocation_id=pub_address.allocation_id)
                    else:
                        pub_address = instance.connection.allocate_address()
                        instance.connection.associate_address(
                            instance.id, pub_address.public_ip)

                self.log_debug(pub_address)
                return pub_address
            except Exception:
                self.log_exception(
                    "Error adding an Elastic IP to VM ID: " + str(vm.id))
                if pub_address:
                    self.log_exception(
                        "The Elastic IP was allocated, release it.")
                    pub_address.release()
                return None
        else:
            self.log_info("The VM is not running, not adding an Elastic IP.")
            return None

    def delete_elastic_ips(self, conn, vm):
        """
        remove the elastic IPs of a VM

        Arguments:
           - conn(:py:class:`boto.ec2.connection`): object to connect to EC2 API.
           - vm(:py:class:`IM.VirtualMachine`): VM information.
        """
        try:
            instance_id = vm.id.split(";")[1]
            # Get the elastic IPs
            for address in conn.get_all_addresses():
                if address.instance_id == instance_id:
                    self.log_info("This VM has a Elastic IP, disassociate it")
                    address.disassociate()

                    n = 0
                    found = False
                    while vm.getRequestedSystem().getValue("net_interface." + str(n) + ".connection"):
                        net_conn = vm.getRequestedSystem().getValue('net_interface.' + str(n) + '.connection')
                        if vm.info.get_network_by_id(net_conn).isPublic():
                            if vm.getRequestedSystem().getValue("net_interface." + str(n) + ".ip"):
                                fixed_ip = vm.getRequestedSystem().getValue("net_interface." + str(n) + ".ip")
                                # If it is a fixed IP we must not release it
                                if fixed_ip == str(address.public_ip):
                                    found = True
                        n += 1

                    if not found:
                        self.log_info("Now release it")
                        address.release()
                    else:
                        self.log_info("This is a fixed IP, it is not released")
        except Exception:
            self.log_exception(
                "Error deleting the Elastic IPs to VM ID: " + str(vm.id))

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
                    vm_system.setValue(
                        'net_interface.' + str(num_nets) + '.ip', str(instance.ip_address))
                    vm_system.setValue(
                        'net_interface.' + str(num_nets) + '.connection', public_net.id)

                    num_pub_nets += 1
                    num_nets += 1

        n = 0
        requested_ips = []
        while vm.getRequestedSystem().getValue("net_interface." + str(n) + ".connection"):
            net_conn = vm.getRequestedSystem().getValue(
                'net_interface.' + str(n) + '.connection')
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

    def updateVMInfo(self, vm, auth_data):
        region = vm.id.split(";")[0]
        instance_id = vm.id.split(";")[1]

        try:
            conn = self.get_connection(region, auth_data)
        except:
            pass

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
            self.attach_volumes(instance, vm)
            self.add_dns_entries(vm, auth_data)

            try:
                vm.info.systems[0].setValue('launch_time', int(time.mktime(
                    time.strptime(instance.launch_time[:19], '%Y-%m-%dT%H:%M:%S'))))
            except Exception as ex:
                self.log_warn(
                    "Error setting the launch_time of the instance. Probably the instance is not running:" + str(ex))

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
                            result = changes.commit()
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
        try:
            instance_id = vm.id.split(";")[1]
            request_list = conn.get_all_spot_instance_requests()
            for sir in request_list:
                if sir.instance_id == instance_id:
                    conn.cancel_spot_instance_requests(sir.id)
                    self.log_info("Spot instance request " + str(sir.id) + " deleted")
                    break
        except Exception:
            self.log_exception("Error deleting the spot instance request")

    def finalize(self, vm, last, auth_data):

        # first delete the snapshots to avoid problems in EC3 deleting the IM front-end
        if last:
            self.delete_snapshots(vm, auth_data)

        if vm.id:
            region_name = vm.id.split(";")[0]
            instance_id = vm.id.split(";")[1]

            conn = self.get_connection(region_name, auth_data)

            # Terminate the instance
            volumes = []
            instance = self.get_instance_by_id(instance_id, region_name, auth_data)
            if instance is not None:
                instance.update()
                # Get the volumnes to delete
                for volume in instance.block_device_mapping.values():
                    volumes.append(volume.volume_id)
                instance.terminate()
        else:
            self.log_info("VM with no ID. Ignore.")

        # Delete the SG if this is the last VM
        if last:
            try:
                self.delete_security_groups(conn, vm)
            except:
                self.log_exception("Error deleting security group.")

        public_key = vm.getRequestedSystem().getValue('disk.0.os.credentials.public_key')
        if public_key is None or len(public_key) == 0 or (len(public_key) >= 1 and
                                                          public_key.find('-----BEGIN CERTIFICATE-----') != -1):
            try:
                # only delete in case of the user do not specify the keypair name
                conn.delete_key_pair(vm.keypair_name)
            except:
                self.log_exception("Error deleting keypair.")

        # Delete the DNS entries
        try:
            self.del_dns_entries(vm, auth_data)
        except:
            self.log_exception("Error deleting DNS entries")

        # Delete the elastic IPs
        try:
            self.delete_elastic_ips(conn, vm)
        except:
            self.log_exception("Error deleting elastic IPs.")

        # Delete the  spot instance requests
        try:
            self.cancel_spot_requests(conn, vm)
        except:
            self.log_exception("Error canceling spot requests.")

        # Delete the EBS volumes
        try:
            self.delete_volumes(conn, volumes, instance_id)
        except:
            self.log_exception("Error deleting EBS volumes")

        return (True, "")

    def _get_security_groups(self, conn, vm):
        """
        Get all the SGs where the VM is included
        """
        sgs = []
        for net in vm.info.networks:
            sg_name = "im-%s-%s" % (str(vm.inf.id), net.id)
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

        for sg in sgs:
            some_vm_running = False
            for instance in sg.instances():
                if instance.state == 'running':
                    some_vm_running = True

            # Check that all there are only one active instance (this one)
            if not some_vm_running:
                # wait it to terminate and then remove the SG
                cont = 0
                all_vms_terminated = True
                for instance in sg.instances():
                    while instance.state != 'terminated' and cont < timeout:
                        time.sleep(5)
                        cont += 5
                        instance.update()

                    if instance.state != 'terminated':
                        all_vms_terminated = False

                if all_vms_terminated:
                    self.log_info("Remove the SG: " + sg.name)
                    try:
                        sg.revoke('tcp', 0, 65535, src_group=sg)
                        sg.revoke('udp', 0, 65535, src_group=sg)
                        time.sleep(2)
                    except Exception as ex:
                        self.log_warn("Error revoking self rules: " + str(ex))

                    deleted = False
                    while not deleted and cont < timeout:
                        time.sleep(5)
                        cont += 5
                        try:
                            sg.delete()
                            deleted = True
                        except Exception as ex:
                            # Check if it has been deleted yet
                            sg = self._get_security_group(conn, sg.name)
                            if not sg:
                                self.log_info("Error deleting the SG. But it does not exist. Ignore. " + str(ex))
                                deleted = True
                            else:
                                self.log_exception("Error deleting the SG.")
            else:
                # If there are more than 1, we skip this step
                self.log_info("There are active instances. Not removing the SG")

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

    def waitStop(self, instance, timeout=120):
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

    def get_all_instance_types(self):
        """
        Get all the EC2 instance types

        Returns: a list of :py:class:`InstanceTypeInfo`
        """
        # TODO: use some like Cloudymetrics or CloudHarmony or http://www.ec2instances.info/
        instance_list = []

        t1_micro = InstanceTypeInfo(
            "t1.micro", ["i386", "x86_64"], 1, 1, 613, 0.0031, 0.5, 0, 0, False)
        instance_list.append(t1_micro)

        t2_nano = InstanceTypeInfo(
            "t2.nano", ["i386", "x86_64"], 1, 1, 512, 0.0059, 0.5, 0, 0, True)
        instance_list.append(t2_nano)
        t2_micro = InstanceTypeInfo(
            "t2.micro", ["i386", "x86_64"], 1, 1, 1024, 0.013, 0.5, 0, 0, True)
        instance_list.append(t2_micro)
        t2_small = InstanceTypeInfo(
            "t2.small", ["i386", "x86_64"], 1, 1, 2048, 0.026, 0.5, 0, 0, True)
        instance_list.append(t2_small)
        t2_medium = InstanceTypeInfo(
            "t2.medium", ["i386", "x86_64"], 2, 1, 4096, 0.052, 0.5, 0, 0, True)
        instance_list.append(t2_medium)

        m1_small = InstanceTypeInfo(
            "m1.small", ["i386", "x86_64"], 1, 1, 1740, 0.044, 1, 1, 160, False)
        instance_list.append(m1_small)
        m1_medium = InstanceTypeInfo(
            "m1.medium", ["i386", "x86_64"], 1, 1, 3840, 0.087, 2, 1, 410, False)
        instance_list.append(m1_medium)
        m1_large = InstanceTypeInfo(
            "m1.large", ["x86_64"], 1, 2, 7680, 0.175, 4, 2, 420, False)
        instance_list.append(m1_large)
        m1_xlarge = InstanceTypeInfo(
            "m1.xlarge", ["x86_64"], 1, 4, 15360, 0.35, 8, 4, 420, False)
        instance_list.append(m1_xlarge)

        m2_xlarge = InstanceTypeInfo(
            "m2.xlarge", ["x86_64"], 1, 2, 17510, 0.245, 6.5, 1, 420, False)
        instance_list.append(m2_xlarge)
        m2_2xlarge = InstanceTypeInfo(
            "m2.2xlarge", ["x86_64"], 1, 4, 35020, 0.49, 13, 1, 850, False)
        instance_list.append(m2_2xlarge)
        m2_4xlarge = InstanceTypeInfo(
            "m2.4xlarge", ["x86_64"], 1, 4, 70041, 0.98, 13, 2, 840, False)
        instance_list.append(m2_4xlarge)

        m3_medium = InstanceTypeInfo(
            "m3.medium", ["x86_64"], 1, 1, 3840, 0.048, 3, 1, 4, False)
        instance_list.append(m3_medium)
        m3_large = InstanceTypeInfo(
            "m3.large", ["x86_64"], 2, 1, 7680, 0.095, 6.5, 1, 4, False)
        instance_list.append(m3_large)
        m3_xlarge = InstanceTypeInfo(
            "m3.xlarge", ["x86_64"], 1, 8, 15360, 0.190, 13, 2, 40, False)
        instance_list.append(m3_xlarge)
        m3_2xlarge = InstanceTypeInfo(
            "m3.2xlarge", ["x86_64"], 1, 8, 30720, 0.38, 26, 2, 80, False)
        instance_list.append(m3_2xlarge)

        m4_large = InstanceTypeInfo(
            "m4.large", ["x86_64"], 2, 1, 8192, 0.108, 6.5, 1, 0, True)
        instance_list.append(m4_large)
        m4_xlarge = InstanceTypeInfo(
            "m4.xlarge", ["x86_64"], 4, 1, 16384, 0.215, 13, 1, 0, True)
        instance_list.append(m4_xlarge)
        m4_2xlarge = InstanceTypeInfo(
            "m4.2xlarge", ["x86_64"], 8, 1, 32768, 0.431, 26, 1, 0, True)
        instance_list.append(m4_2xlarge)
        m4_4xlarge = InstanceTypeInfo(
            "m4.4xlarge", ["x86_64"], 16, 1, 65536, 0.862, 53.5, 1, 0, True)
        instance_list.append(m4_4xlarge)
        m4_10xlarge = InstanceTypeInfo(
            "m4.10xlarge", ["x86_64"], 40, 1, 163840, 2.155, 124.5, 1, 0, True)
        instance_list.append(m4_10xlarge)
        m4_16xlarge = InstanceTypeInfo(
            "m4.16xlarge", ["x86_64"], 64, 1, 262144, 3.447, 256, 1, 0, True)
        instance_list.append(m4_16xlarge)

        c1_medium = InstanceTypeInfo(
            "c1.medium", ["i386", "x86_64"], 1, 2, 1740, 0.13, 5, 1, 350, False)
        instance_list.append(c1_medium)
        c1_xlarge = InstanceTypeInfo(
            "c1.xlarge", ["x86_64"], 1, 8, 7680, 0.52, 20, 4, 420, False)
        instance_list.append(c1_xlarge)

        cc2_8xlarge = InstanceTypeInfo(
            "cc2.8xlarge", ["x86_64"], 2, 8, 61952, 2.0, 88, 4, 840, False)
        instance_list.append(cc2_8xlarge)

        cr1_8xlarge = InstanceTypeInfo(
            "cr1.8xlarge", ["x86_64"], 2, 8, 249856, 3.5, 88, 2, 120, False)
        instance_list.append(cr1_8xlarge)

        c3_large = InstanceTypeInfo(
            "c3.large", ["x86_64"], 2, 1, 3840, 0.105, 7, 2, 16, False)
        instance_list.append(c3_large)
        c3_xlarge = InstanceTypeInfo(
            "c3.xlarge", ["x86_64"], 4, 1, 7680, 0.21, 14, 2, 40, False)
        instance_list.append(c3_xlarge)
        c3_2xlarge = InstanceTypeInfo(
            "c3.2xlarge", ["x86_64"], 8, 1, 15360, 0.42, 28, 2, 80, False)
        instance_list.append(c3_2xlarge)
        c3_4xlarge = InstanceTypeInfo(
            "c3.4xlarge", ["x86_64"], 16, 1, 30720, 0.84, 55, 2, 160, False)
        instance_list.append(c3_4xlarge)
        c3_8xlarge = InstanceTypeInfo(
            "c3.8xlarge", ["x86_64"], 32, 1, 61952, 1.68, 108, 2, 320, False)
        instance_list.append(c3_8xlarge)

        r3_large = InstanceTypeInfo(
            "r3.large", ["x86_64"], 2, 1, 15360, 0.166, 6.5, 1, 32, False)
        instance_list.append(r3_large)
        r3_xlarge = InstanceTypeInfo(
            "r3.xlarge", ["x86_64"], 4, 1, 31232, 0.333, 13, 1, 80, False)
        instance_list.append(r3_xlarge)
        r3_2xlarge = InstanceTypeInfo(
            "r3.2xlarge", ["x86_64"], 8, 1, 62464, 0.665, 26, 1, 160, False)
        instance_list.append(r3_2xlarge)
        r3_4xlarge = InstanceTypeInfo(
            "r3.4xlarge", ["x86_64"], 16, 1, 124928, 1.33, 52, 1, 320, False)
        instance_list.append(r3_4xlarge)
        r3_8xlarge = InstanceTypeInfo(
            "r3.8xlarge", ["x86_64"], 32, 1, 249856, 2.66, 104, 2, 320, False)
        instance_list.append(r3_8xlarge)

        r4_large = InstanceTypeInfo(
            "r4.large", ["x86_64"], 2, 1, 15616, 0.133, 7, 1, 0, True)
        instance_list.append(r4_large)
        r4_xlarge = InstanceTypeInfo(
            "r4.xlarge", ["x86_64"], 4, 1, 31232, 0.266, 13.5, 1, 0, True)
        instance_list.append(r4_xlarge)
        r4_2xlarge = InstanceTypeInfo(
            "r4.2xlarge", ["x86_64"], 8, 1, 62464, 0.532, 27, 1, 0, True)
        instance_list.append(r4_2xlarge)
        r4_4xlarge = InstanceTypeInfo(
            "r4.4xlarge", ["x86_64"], 16, 1, 124928, 1.064, 53, 1, 0, True)
        instance_list.append(r4_4xlarge)
        r4_8xlarge = InstanceTypeInfo(
            "r4.8xlarge", ["x86_64"], 32, 1, 249856, 2.128, 99, 1, 0, True)
        instance_list.append(r4_8xlarge)
        r4_16xlarge = InstanceTypeInfo(
            "r4.16xlarge", ["x86_64"], 64, 1, 499712, 4.256, 195, 1, 0, True)
        instance_list.append(r4_16xlarge)

        i2_xlarge = InstanceTypeInfo(
            "i2.xlarge", ["x86_64"], 4, 1, 31232, 0.853, 14, 1, 800, False)
        instance_list.append(i2_xlarge)
        i2_2xlarge = InstanceTypeInfo(
            "i2.2xlarge", ["x86_64"], 8, 1, 62464, 1.705, 27, 2, 800, False)
        instance_list.append(i2_2xlarge)
        i2_4xlarge = InstanceTypeInfo(
            "i2.4xlarge", ["x86_64"], 16, 1, 124928, 3.41, 53, 4, 800, False)
        instance_list.append(i2_4xlarge)
        i2_8xlarge = InstanceTypeInfo(
            "i2.8xlarge", ["x86_64"], 32, 1, 249856, 6.82, 104, 8, 800, False)
        instance_list.append(i2_8xlarge)

        hs1_8xlarge = InstanceTypeInfo(
            "hs1.8xlarge", ["x86_64"], 16, 1, 119808, 4.6, 35, 24, 2048, False)
        instance_list.append(hs1_8xlarge)

        c4_large = InstanceTypeInfo(
            "c4.large", ["x86_64"], 2, 1, 3840, 0.1, 8, 1, 0, True)
        instance_list.append(c4_large)
        c4_xlarge = InstanceTypeInfo(
            "c4.xlarge", ["x86_64"], 4, 1, 7680, 0.199, 16, 1, 0, True)
        instance_list.append(c4_xlarge)
        c4_2xlarge = InstanceTypeInfo(
            "c4.2xlarge", ["x86_64"], 8, 1, 15360, 0.398, 31, 1, 0, True)
        instance_list.append(c4_2xlarge)
        c4_4xlarge = InstanceTypeInfo(
            "c4.4xlarge", ["x86_64"], 16, 1, 30720, 0.796, 62, 1, 0, True)
        instance_list.append(c4_4xlarge)
        c4_8xlarge = InstanceTypeInfo(
            "c4.8xlarge", ["x86_64"], 36, 1, 61952, 1.591, 132, 1, 0, True)
        instance_list.append(c4_8xlarge)

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
