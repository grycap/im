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
import datetime

sys.path.append(".")
sys.path.append("..")
from .CloudConn import TestCloudConnectorBase
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from IM.config import Config
from IM.VirtualMachine import VirtualMachine
from radl import radl_parse
from IM.InfrastructureInfo import InfrastructureInfo
from IM.connectors.EC2 import EC2CloudConnector
from mock import patch, MagicMock, call


class TestEC2Connector(TestCloudConnectorBase):

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
        self.assertEqual(concrete[0].getValue("instance_type"), "t3a.nano")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            instance_type = 't2.*' and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'aws://us-east-one/ami-id' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        concrete = ec2_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertEqual(concrete[0].getValue("instance_type"), "t2.nano")
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

    def describe_subnets(self, **kwargs):
        subnet = {}
        subnet['SubnetId'] = "subnet-id"
        if 'Filters' in kwargs and kwargs['Filters']:
            return {'Subnets': []}
        elif 'SubnetIds' in kwargs and kwargs['SubnetIds']:
            subnet['CidrBlock'] = "10.10.0.1/24"
        else:
            subnet['CidrBlock'] = "10.0.1.0/24"
        return {'Subnets': [subnet]}

    @patch('IM.connectors.EC2.boto3.client')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, mock_boto_client):
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
            disk.0.image.url = 'aws://us-east-1/ami-id' and
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

        inf = InfrastructureInfo()
        inf.auth = auth
        inf.radl = radl

        mock_conn = MagicMock()
        mock_boto_client.return_value = mock_conn
        mock_conn.describe_security_groups.return_value = {'SecurityGroups': []}
        mock_conn.create_security_group.return_value = {'GroupId': 'sg-id'}
        mock_conn.describe_vpcs.return_value = {'Vpcs': [{'VpcId': 'vpc-id'}]}
        mock_conn.describe_subnets.return_value = {'Subnets': [{'SubnetId': 'subnet-id'}]}
        mock_conn.describe_regions.return_value = {'Regions': [{'RegionName': 'us-east-1'}]}
        mock_conn.describe_images.return_value = {'Images': [{'ImageId': 'ami-id',
                                                              'BlockDeviceMappings': [{'DeviceName': '/dev/sda1',
                                                                                       'Ebs': {
                                                                                           'SnapshotId': 'snap-12345678'
                                                                                       }}]}
                                                             ]}
        mock_conn.run_instances.return_value = {'Instances': [{'InstanceId': 'i-12345678'}]}
        instance = MagicMock()
        mock_conn.Instance.return_value = instance

        res = ec2_cloud.launch(inf, radl, radl, 1, auth)
        success, msg = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM: %s" % msg)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.assertEqual(len(mock_conn.create_security_group.call_args_list), 3)
        self.assertEqual(mock_conn.create_security_group.call_args_list[0][1]['GroupName'], "im-%s" % inf.id)
        self.assertEqual(mock_conn.create_security_group.call_args_list[1][1]['GroupName'], "sgname")
        self.assertEqual(mock_conn.create_security_group.call_args_list[2][1]['GroupName'], "im-%s-net2" % inf.id)
        mock_conn.run_instances.assert_called_once()

    @patch('IM.connectors.EC2.boto3.client')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_25_launch_spot(self, save_data, mock_boto_client):
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
            disk.0.image.url = 'aws://us-east-1/ami-id' and
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

        mock_conn = MagicMock()
        mock_boto_client.return_value = mock_conn
        mock_conn.describe_regions.return_value = {'Regions': [{'RegionName': 'us-east-1'}]}

        mock_conn.run_instances.return_value = {'Instances': [{'InstanceId': 'iid'}]}
        instance = MagicMock()
        mock_conn.Instance.return_value = instance
        instance.id = "iid"
        mock_conn.describe_vpcs.return_value = {'Vpcs': [{'VpcId': 'vpc-id'}]}
        mock_conn.describe_subnets.return_value = {'Subnets': [{'SubnetId': 'subnet-id'}]}
        mock_conn.describe_images.return_value = {'Images': [{'ImageId': 'ami-id',
                                                              'BlockDeviceMappings': [{'DeviceName': '/dev/sda1',
                                                                                       'Ebs': {
                                                                                           'SnapshotId': 'snap-12345678'
                                                                                       }}]}
                                                             ]}
        mock_conn.create_security_group.return_value = {'GroupId': 'sg-id'}
        mock_conn.describe_security_groups.return_value = {'SecurityGroups': []}
        mock_conn.describe_availability_zones.return_value = {'AvailabilityZones': [{'ZoneName': 'us-east-1'}]}
        mock_conn.describe_spot_price_history.return_value = {'SpotPriceHistory': [{'SpotPrice': '0.1'}]}
        mock_conn.request_spot_instances.return_value = {'SpotInstanceRequests': [{'SpotInstanceRequestId': 'sid'}]}

        inf = InfrastructureInfo()
        inf.auth = auth
        res = ec2_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.EC2.boto3.client')
    def test_30_updateVMInfo(self, mock_boto_client):
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
            net_interface.0.additional_dns_names = ['some.test@domain.com'] and
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

        mock_conn = MagicMock()
        mock_boto_client.return_value = mock_conn
        mock_conn.describe_regions.return_value = {'Regions': [{'RegionName': 'us-east-1'}]}
        mock_conn.describe_instances.return_value = {'Reservations': [{'Instances': [{'InstanceId': 'vrid',
                                                                                      'State': {'Name': 'running'}}]}]}
        instance = MagicMock()
        mock_conn.Instance.return_value = instance
        instance.id = "iid"
        instance.tags = []
        instance.virtualization_type = "vt"
        instance.placement = {'AvailabilityZone': 'us-east-1'}
        instance.state = {'Name': 'running'}
        instance.instance_type = "t1.micro"
        instance.launch_time = datetime.datetime.now()
        instance.public_ip_address = "158.42.1.1"
        instance.private_ip_address = "10.0.0.1"
        mock_conn.describe_addresses.return_value = {'Addresses': [{'PublicIp': '158.42.1.1',
                                                                    'InstanceId': 'iid'}]}
        mock_conn.describe_vpcs.return_value = {'Vpcs': [{'VpcId': 'vpc-id'}]}
        mock_conn.describe_subnets.return_value = {'Subnets': [{'SubnetId': 'subnet-id'}]}
        mock_conn.describe_route_tables.return_value = {'RouteTables': [{'RouteTableId': 'routet-id'}]}

        mock_conn.list_hosted_zones_by_name.return_value = {'HostedZones': [{'Name': 'domain.com.',
                                                                             'Id': 'zone-id'}]}
        mock_conn.create_hosted_zone.return_value = {'HostedZone': {'Id': 'zone-idc'}}
        mock_conn.list_resource_record_sets.return_value = {
            'ResourceRecordSets': [{'Name': 'some.test.domain.com.'}]}

        inf = MagicMock()
        vm1 = MagicMock()
        system1 = MagicMock()
        system1.name = 'vrouter'
        vm1.info.systems = [system1]
        vm1.id = "region;int-id"
        inf.vm_list = [vm1]
        vm = VirtualMachine(inf, "us-east-1;id-1", ec2_cloud.cloud, radl, radl, ec2_cloud, 1)

        success, vm = ec2_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.assertEqual(mock_conn.list_hosted_zones_by_name.call_count, 2)
        self.assertEqual(mock_conn.change_resource_record_sets.call_args_list[0][1]['ChangeBatch']['Changes'],
                         [{'Action': 'CREATE',
                           'ResourceRecordSet': {
                               'Name': 'test.domain.com.',
                               'Type': 'A',
                               'TTL': 300,
                               'ResourceRecords': [{'Value': '158.42.1.1'}]}
                           }])
        self.assertEqual(mock_conn.create_route.call_args_list[0][1], {'RouteTableId': 'routet-id',
                                                                       'DestinationCidrBlock': '10.0.10.0/24',
                                                                       'InstanceId': 'int-id'})

        # Test using PRIVATE_NET_MASKS setting 10.0.0.0/8 as public net
        old_priv = Config.PRIVATE_NET_MASKS
        Config.PRIVATE_NET_MASKS = ["172.16.0.0/12", "192.168.0.0/16"]

        instance.public_ip_address = None
        instance.private_ip_address = "10.0.0.1"
        mock_conn.describe_addresses.return_value = {'Addresses': []}

        success, vm = ec2_cloud.updateVMInfo(vm, auth)
        Config.PRIVATE_NET_MASKS = old_priv
        self.assertEqual(vm.getPublicIP(), "10.0.0.1")
        self.assertEqual(vm.getPrivateIP(), None)

    @patch('IM.connectors.EC2.boto3.client')
    @patch('time.sleep')
    def test_60_finalize(self, sleep, mock_boto_client):
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
        vm.dns_entries = [('test', 'domain.com.', '158.42.1.1')]

        mock_conn = MagicMock()
        mock_boto_client.return_value = mock_conn
        mock_conn.describe_regions.return_value = {'Regions': [{'RegionName': 'us-east-1'}]}
        mock_conn.describe_instances.return_value = {'Reservations': [{'Instances': [{'InstanceId': 'vrid',
                                                                                      'State': {'Name': 'running'}}]}]}
        instance = MagicMock()
        mock_conn.Instance.return_value = instance
        instance.block_device_mappings = [{'DeviceName': '/dev/sda1', 'Ebs': {'VolumeId': 'volid'}}]
        mock_conn.describe_addresses.return_value = {'Addresses': [{'PublicIp': '158.42.1.1',
                                                                    'InstanceId': 'id-1'}]}
        mock_conn.describe_spot_instance_requests.return_value = {'SpotInstanceRequests': []}

        mock_conn.describe_security_groups.return_value = {'SecurityGroups': [
            {'GroupId': 'sg1', 'GroupName': 'im-1', 'Description': 'Security group created by the IM',
             'VpcId': 'vpc-id'},
            {'GroupId': 'sg2', 'GroupName': 'im-1-net', 'Description': '',
             'VpcId': 'vpc-id'},
            {'GroupId': 'sg3', 'GroupName': 'im-1-net2', 'Description': 'Security group created by the IM',
             'VpcId': 'vpc-id'}
        ]}
        mock_conn.describe_vpcs.return_value = {'Vpcs': [{'VpcId': 'vpc-id'}]}
        mock_conn.describe_subnets.return_value = {'Subnets': [{'SubnetId': 'subnet-id'}]}

        mock_conn.list_hosted_zones_by_name.return_value = {'HostedZones': [{'Name': 'domain.com.',
                                                                             'Id': 'zone-id'}]}
        mock_conn.list_resource_record_sets.return_value = {
            'ResourceRecordSets': [{'Name': 'test.domain.com.'}]}
        mock_conn.describe_internet_gateways.return_value = {'InternetGateways': [{'InternetGatewayId': 'ig-id'}]}

        success, _ = ec2_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        self.assertEqual(mock_conn.change_resource_record_sets.call_args_list[0][1]['ChangeBatch']['Changes'],
                         [{'Action': 'DELETE',
                           'ResourceRecordSet': {
                               'Name': 'test.domain.com.',
                               'Type': 'A',
                               'TTL': 300,
                               'ResourceRecords': [{'Value': '158.42.1.1'}]}
                           }])
        self.assertEqual(mock_conn.delete_security_group.call_args_list, [call(GroupId='sg1'),
                                                                          call(GroupId='sg3')])
        self.assertEqual(instance.terminate.call_args_list, [call()])
        self.assertEqual(mock_conn.delete_subnet.call_args_list, [call('subnet-id')])
        self.assertEqual(mock_conn.delete_vpc.call_args_list, [call('vpc-id')])
        self.assertEqual(mock_conn.delete_internet_gateway.call_args_list, [call('ig-id')])
        self.assertEqual(mock_conn.detach_internet_gateway.call_args_list, [call('ig-id', 'vpc-id')])


if __name__ == '__main__':
    unittest.main()
