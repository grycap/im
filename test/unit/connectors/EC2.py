#! /usr/bin/env python
#
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

import sys
import unittest

sys.path.append(".")
sys.path.append("..")
from .CloudConn import TestCloudConnectorBase
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
from IM.VirtualMachine import VirtualMachine
from IM.InfrastructureInfo import InfrastructureInfo
from IM.connectors.EC2 import EC2CloudConnector
from mock import patch, MagicMock, call


class TestEC2Connector(TestCloudConnectorBase):
    """
    Class to test the IM connectors
    """

    @staticmethod
    def get_ec2_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "EC2"
        inf = MagicMock()
        inf.id = "1"
        cloud = EC2CloudConnector(cloud_info, inf)
        return cloud

    def test_10_concrete(self):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'aws://us-east-one/ami-id' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        concrete = ec2_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    def test_15_get_all_instance_types(self):
        ec2_cloud = self.get_ec2_cloud()
        instances = ec2_cloud.get_all_instance_types()
        self.assertGreater(len(instances), 20)

        for instance in instances:
            if instance.name == 'm1.small':
                self.assertEqual(instance.cpu_perf, 1.0)
                self.assertEqual(instance.name, 'm1.small')
                self.assertEqual(instance.mem, 1740.8)
                self.assertEqual(instance.price, 0.044)
                self.assertEqual(instance.disks, 1)
                self.assertEqual(instance.cores_per_cpu, 1)
                self.assertEqual(instance.disk_space, 160)

    def get_all_subnets(self, subnet_ids=None, filters=None):
        subnet = MagicMock()
        subnet.id = "subnet-id"
        if filters:
            return []
        elif subnet_ids:
            subnet.cidr_block = "10.10.0.1/24"
            return [subnet]
        subnet.cidr_block = "10.0.1.0/24"
        return [subnet]

    @patch('boto.ec2.get_region')
    @patch('boto.vpc.VPCConnection')
    @patch('boto.ec2.blockdevicemapping.BlockDeviceMapping')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, blockdevicemapping, VPCConnection, get_region):
        radl_data = """
            network net1 (outbound = 'yes' and outports='8080,9000:9100' and sg_name = 'sgname')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            instance_tags = 'key=value,key1=value2' and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'aws://us-east-one/ami-id' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'},
                               {'type': 'InfrastructureManager', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        region = MagicMock()
        get_region.return_value = region

        conn = MagicMock()
        VPCConnection.return_value = conn

        image = MagicMock()
        device = MagicMock()
        reservation = MagicMock()
        instance = MagicMock()
        device.snapshot_id = True
        device.volume_id = True
        image.block_device_mapping = {"device": device}
        instance.add_tag.return_value = True
        instance.id = "iid"
        reservation.instances = [instance]
        image.run.return_value = reservation
        conn.get_image.return_value = image

        subnet = MagicMock()
        subnet.id = "subnet-id"
        conn.get_all_subnets.return_value = [subnet]

        vpc = MagicMock()
        vpc.id = "vpc-id"
        conn.get_all_vpcs.return_value = [vpc]

        sg = MagicMock()
        sg.id = "sgid"
        sg.name = "sgname"
        sg.authorize.return_value = True
        conn.create_security_group.return_value = sg

        conn.get_all_security_groups.return_value = []

        blockdevicemapping.return_value = {'device': ''}

        inf = InfrastructureInfo()
        inf.auth = auth
        inf.radl = radl
        res = ec2_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.assertEquals(len(conn.create_security_group.call_args_list), 3)
        self.assertEquals(conn.create_security_group.call_args_list[0][0][0], "im-%s" % inf.id)
        self.assertEquals(conn.create_security_group.call_args_list[1][0][0], "sgname")
        self.assertEquals(conn.create_security_group.call_args_list[2][0][0], "im-%s-net2" % inf.id)

        # Check the case that we do not use VPC
        radl_data = """
            network net1 (outbound = 'yes' and outports='8080')
            network net2 (create='yes' and cidr='10.0.10.0/24')
            network net3 (create='yes' and cidr='10.0.*.0/24')
            network net4 (create='yes' and cidr='10.0.*.0/24')
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=1g and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'aws://us-east-one/ami-id' and
            disk.0.os.credentials.username = 'user' and
            #disk.0.os.credentials.private_key = 'private' and
            #disk.0.os.credentials.public_key = 'public' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        vpc = MagicMock()
        vpc.id = "vpc-id"
        vpc.is_default = True
        conn.get_all_vpcs.return_value = [vpc]

        subnet = MagicMock()
        subnet.id = "subnet-id"
        subnet.cidr_block = "10.10.0.1/24"
        conn.create_subnet.return_value = subnet
        conn.get_all_subnets.side_effect = self.get_all_subnets

        inf = InfrastructureInfo()
        inf.auth = auth
        inf.radl = radl
        res = ec2_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        # check the instance_type selected is correct
        self.assertEquals(image.run.call_args_list[1][1]["instance_type"], "t3a.micro")
        self.assertEquals(conn.create_subnet.call_args_list[0][0], ('vpc-id', '10.0.10.0/24'))
        self.assertEquals(conn.create_subnet.call_args_list[1][0], ('vpc-id', '10.0.2.0/24'))
        self.assertEquals(conn.create_subnet.call_args_list[2][0], ('vpc-id', '10.0.3.0/24'))

        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('boto.ec2.get_region')
    @patch('boto.vpc.VPCConnection')
    @patch('boto.ec2.blockdevicemapping.BlockDeviceMapping')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_25_launch_spot(self, save_data, blockdevicemapping, VPCConnection, get_region):
        radl_data = """
            network net1 (outbound = 'yes' and provider_id = 'vpc-id.subnet-id')
            network net2 ()
            system test (
            spot = 'yes' and
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'aws://us-east-one/ami-id' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.private_key = 'private' and
            disk.0.os.credentials.public_key = 'public' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'},
                               {'type': 'InfrastructureManager', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        region = MagicMock()
        get_region.return_value = region

        conn = MagicMock()
        VPCConnection.return_value = conn

        image = MagicMock()
        device = MagicMock()
        reservation = MagicMock()
        instance = MagicMock()
        device.snapshot_id = True
        device.volume_id = True
        image.block_device_mapping = {"device": device}
        instance.add_tag.return_value = True
        instance.id = "iid"
        reservation.instances = [instance]
        image.run.return_value = reservation
        conn.get_image.return_value = image

        sg = MagicMock()
        sg.id = "sgid"
        sg.name = "sgname"
        sg.authorize.return_value = True
        conn.create_security_group.return_value = sg

        conn.get_all_security_groups.return_value = []

        blockdevicemapping.return_value = {'device': ''}

        zone = MagicMock()
        zone.name = 'us-east-1'
        conn.get_all_zones.return_value = [zone]
        history = MagicMock()
        history.price = 0.1
        conn.get_spot_price_history.return_value = [history]

        request = MagicMock()
        request.id = "id"
        conn.request_spot_instances.return_value = [request]

        inf = InfrastructureInfo()
        inf.auth = auth
        res = ec2_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.EC2.EC2CloudConnector.get_connection')
    @patch('boto.route53.connect_to_region')
    @patch('boto.route53.record.ResourceRecordSets')
    def test_30_updateVMInfo(self, record_sets, connect_to_region, get_connection):
        radl_data = """
            network net (outbound = 'yes')
            network net2 (router = '10.0.10.0/24,vrouter')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.ip = '158.42.1.1' and
            net_interface.0.dns_name = 'test.domain.com' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'one://server.com/1' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        inf = MagicMock()
        vm1 = MagicMock()
        system1 = MagicMock()
        system1.name = 'vrouter'
        vm1.info.systems = [system1]
        vm1.id = "region;int-id"
        inf.vm_list = [vm1]
        vm = VirtualMachine(inf, "us-east-1;id-1", ec2_cloud.cloud, radl, radl, ec2_cloud, 1)

        conn = MagicMock()
        get_connection.return_value = conn

        reservation = MagicMock()
        instance = MagicMock()
        instance.update.return_value = True
        instance.tags = []
        instance.virtualization_type = "vt"
        instance.placement = "us-east-1"
        instance.state = "running"
        instance.instance_type = "t1.micro"
        instance.launch_time = "2016-12-31T00:00:00"
        instance.ip_address = "158.42.1.1"
        instance.private_ip_address = "10.0.0.1"
        instance.connection = conn
        reservation.instances = [instance]
        conn.get_all_instances.return_value = [reservation]

        address = MagicMock()
        address.public_ip = "158.42.1.1"
        conn.get_all_addresses.return_value = [address]

        dns_conn = MagicMock()
        connect_to_region.return_value = dns_conn

        dns_conn.get_zone.return_value = None
        zone = MagicMock()
        zone.get_a.return_value = None
        dns_conn.create_zone.return_value = zone
        changes = MagicMock()
        record_sets.return_value = changes
        change = MagicMock()
        changes.add_change.return_value = change

        vpc = MagicMock()
        vpc.id = "vpc-id"
        conn.get_all_vpcs.return_value = [vpc]

        subnet = MagicMock()
        subnet.id = "subnet-id"
        conn.get_all_subnets.return_value = [subnet]

        routet = MagicMock()
        routet.id = "routet-id"
        conn.get_all_route_tables.return_value = [routet]

        success, vm = ec2_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        self.assertEquals(dns_conn.create_zone.call_count, 1)
        self.assertEquals(dns_conn.create_zone.call_args_list[0][0][0], "domain.com.")
        self.assertEquals(changes.add_change.call_args_list, [call('CREATE', 'test.domain.com.', 'A')])
        self.assertEquals(change.add_value.call_args_list, [call('158.42.1.1')])
        self.assertEquals(conn.create_route.call_args_list, [call('routet-id', '10.0.10.0/24', instance_id='int-id')])

    @patch('IM.connectors.EC2.EC2CloudConnector.get_connection')
    def test_30_updateVMInfo_spot(self, get_connection):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'one://server.com/1' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "us-east-1;sid-1", ec2_cloud.cloud, radl, radl, ec2_cloud, 1)

        conn = MagicMock()
        get_connection.return_value = conn

        reservation = MagicMock()
        instance = MagicMock()
        instance.update.return_value = True
        instance.tags = []
        instance.virtualization_type = "vt"
        instance.placement = "us-east-1"
        instance.state = "running"
        instance.instance_type = "t1.micro"
        instance.launch_time = "2016-12-31T00:00:00"
        instance.ip_address = "158.42.1.1"
        instance.private_ip_address = "10.0.0.1"
        instance.connection = conn
        reservation.instances = [instance]
        conn.get_all_instances.return_value = [reservation]

        conn.get_all_addresses.return_value = []

        sir = MagicMock()
        sir.state = ""
        sir.id = "id"
        conn.get_all_spot_instance_requests.return_value = [sir]

        volume = MagicMock()
        volume.status = "available"
        volume.id = "volid"
        conn.create_volume.return_value = volume
        conn.attach_volume.return_value = True

        success, vm = ec2_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.EC2.EC2CloudConnector.get_connection')
    def test_40_stop(self, get_connection):
        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "us-east-1;id-1", ec2_cloud.cloud, "", "", ec2_cloud, 1)

        conn = MagicMock()
        get_connection.return_value = conn

        reservation = MagicMock()
        instance = MagicMock()
        instance.update.return_value = True
        instance.stop.return_value = True
        reservation.instances = [instance]
        conn.get_all_instances.return_value = [reservation]

        success, _ = ec2_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.EC2.EC2CloudConnector.get_connection')
    def test_50_start(self, get_connection):
        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "us-east-1;id-1", ec2_cloud.cloud, "", "", ec2_cloud, 1)

        conn = MagicMock()
        get_connection.return_value = conn

        reservation = MagicMock()
        instance = MagicMock()
        instance.update.return_value = True
        instance.stop.return_value = True
        reservation.instances = [instance]
        conn.get_all_instances.return_value = [reservation]

        success, _ = ec2_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.EC2.EC2CloudConnector.get_connection')
    def test_52_reboot(self, get_connection):
        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "us-east-1;id-1", ec2_cloud.cloud, "", "", ec2_cloud, 1)

        conn = MagicMock()
        get_connection.return_value = conn

        reservation = MagicMock()
        instance = MagicMock()
        instance.update.return_value = True
        instance.reboot.return_value = True
        reservation.instances = [instance]
        conn.get_all_instances.return_value = [reservation]

        success, _ = ec2_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.EC2.EC2CloudConnector.get_connection')
    def test_55_alter(self, get_connection):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'one://server.com/1' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        new_radl_data = """
            system test (
            cpu.count>=2 and
            memory.size>=2048m
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "us-east-1;sid-1", ec2_cloud.cloud, radl, radl, ec2_cloud, 1)

        conn = MagicMock()
        get_connection.return_value = conn

        reservation = MagicMock()
        instance = MagicMock()
        instance.update.return_value = True
        instance.stop.return_value = True
        instance.state = "stopped"
        reservation.instances = [instance]
        conn.get_all_instances.return_value = [reservation]

        success, _ = ec2_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.EC2.EC2CloudConnector.get_connection')
    @patch('time.sleep')
    @patch('boto.route53.connect_to_region')
    @patch('boto.route53.record.ResourceRecordSets')
    def test_60_finalize(self, record_sets, connect_to_region, sleep, get_connection):
        radl_data = """
            network net (outbound = 'yes')
            network net2 (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.ip = '158.42.1.1' and
            net_interface.0.dns_name = 'test.domain.com' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'one://server.com/1' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        inf = MagicMock()
        inf.id = "1"
        vm = VirtualMachine(inf, "us-east-1;id-1", ec2_cloud.cloud, radl, radl, ec2_cloud, 1)

        conn = MagicMock()
        get_connection.return_value = conn

        reservation = MagicMock()
        instance = MagicMock()
        device = MagicMock()
        instance.update.return_value = True
        instance.terminate.return_value = True
        instance.block_device_mapping = {"device": device}
        device.volume_id = "volid"
        reservation.instances = [instance]
        conn.get_all_instances.return_value = [reservation]

        address = MagicMock()
        address.public_ip = "158.42.1.1"
        address.instance_id = "id-1"
        address.disassociate.return_value = True
        address.release.return_value = True
        conn.get_all_addresses.return_value = [address]

        conn.get_all_spot_instance_requests.return_value = []

        sg = MagicMock()
        sg.name = "im-1"
        sg.description = "Security group created by the IM"
        sg.instances.return_value = []
        sg.revoke.return_value = True
        sg.delete.return_value = True
        sg1 = MagicMock()
        sg1.name = "im-1-net"
        sg1.description = ""
        sg1.instances.return_value = []
        sg1.revoke.return_value = True
        sg1.delete.return_value = True
        sg2 = MagicMock()
        sg2.name = "im-1-net2"
        sg2.description = "Security group created by the IM"
        sg2.instances.return_value = []
        sg2.revoke.return_value = True
        sg2.delete.return_value = True
        conn.get_all_security_groups.return_value = [sg, sg1, sg2]

        dns_conn = MagicMock()
        connect_to_region.return_value = dns_conn

        zone = MagicMock()
        record = MagicMock()
        zone.id = "zid"
        zone.get_a.return_value = record
        dns_conn.get_all_rrsets.return_value = []
        dns_conn.get_zone.return_value = zone
        changes = MagicMock()
        record_sets.return_value = changes
        change = MagicMock()
        changes.add_change.return_value = change

        subnet = MagicMock()
        subnet.id = "subnet-id"
        conn.get_all_subnets.return_value = [subnet]

        vpc = MagicMock()
        vpc.id = "vpc-id"
        conn.get_all_vpcs.return_value = [vpc]

        ig = MagicMock()
        ig.id = "ig-id"
        conn.get_all_internet_gateways.return_value = [ig]

        success, _ = ec2_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        self.assertEquals(dns_conn.delete_hosted_zone.call_count, 1)
        self.assertEquals(dns_conn.delete_hosted_zone.call_args_list[0][0][0], zone.id)
        self.assertEquals(changes.add_change.call_args_list, [call('DELETE', 'test.domain.com.', 'A')])
        self.assertEquals(change.add_value.call_args_list, [call('158.42.1.1')])
        self.assertEquals(sg.delete.call_args_list, [call()])
        self.assertEquals(sg1.delete.call_args_list, [])
        self.assertEquals(sg2.delete.call_args_list, [call()])
        self.assertEquals(conn.delete_subnet.call_args_list, [call('subnet-id')])
        self.assertEquals(conn.delete_vpc.call_args_list, [call('vpc-id')])
        self.assertEquals(conn.delete_internet_gateway.call_args_list, [call('ig-id')])
        self.assertEquals(conn.detach_internet_gateway.call_args_list, [call('ig-id', 'vpc-id')])

    @patch('IM.connectors.EC2.EC2CloudConnector.get_connection')
    @patch('time.sleep')
    def test_70_create_snapshot(self, sleep, get_connection):
        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "region;id1", ec2_cloud.cloud, "", "", ec2_cloud, 1)

        conn = MagicMock()
        get_connection.return_value = conn

        reservation = MagicMock()
        instance = MagicMock()
        instance.create_image.return_value = "image-ami"
        reservation.instances = [instance]
        conn.get_all_instances.return_value = [reservation]

        success, new_image = ec2_cloud.create_snapshot(vm, 0, "image_name", True, auth)

        self.assertTrue(success, msg="ERROR: creating snapshot: %s" % new_image)
        self.assertEqual(new_image, "aws://region/image-ami")
        self.assertEqual(instance.create_image.call_args_list, [call('image_name',
                                                                     description='AMI automatically generated by IM',
                                                                     no_reboot=True)])
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.EC2.EC2CloudConnector.get_connection')
    @patch('time.sleep')
    def test_80_delete_image(self, sleep, get_connection):
        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        conn = MagicMock()
        get_connection.return_value = conn
        conn.deregister_image.return_value = True

        success, msg = ec2_cloud.delete_image('aws://region/image-ami', auth)

        self.assertTrue(success, msg="ERROR: deleting image. %s" % msg)
        self.assertEqual(conn.deregister_image.call_args_list, [call('image-ami', delete_snapshot=True)])
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
