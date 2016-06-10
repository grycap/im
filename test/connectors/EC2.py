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
import os
import logging
import logging.config
from StringIO import StringIO

sys.path.append("..")
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
from IM.VirtualMachine import VirtualMachine
from IM.InfrastructureInfo import InfrastructureInfo
from IM.connectors.EC2 import EC2CloudConnector
from mock import patch, MagicMock, mock_open


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestEC2Connector(unittest.TestCase):
    """
    Class to test the IM connectors
    """

    @classmethod
    def setUpClass(cls):
        cls.log = StringIO()
        ch = logging.StreamHandler(cls.log)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)

        logging.RootLogger.propagate = 0
        logging.root.setLevel(logging.ERROR)

        logger = logging.getLogger('CloudConnector')
        logger.setLevel(logging.DEBUG)
        logger.propagate = 0
        logger.addHandler(ch)

    @classmethod
    def clean_log(cls):
        cls.log = StringIO()

    @staticmethod
    def get_ec2_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "EC2"
        cloud = EC2CloudConnector(cloud_info)
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
        self.clean_log()

    @patch('boto.ec2.get_region')
    @patch('boto.vpc.VPCConnection')
    @patch('boto.ec2.blockdevicemapping.BlockDeviceMapping')
    def test_20_launch(self, blockdevicemapping, VPCConnection, get_region):
        radl_data = """
            network net1 (outbound = 'yes' and outports='8080')
            network net2 ()
            system test (
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

        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
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

        res = ec2_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('boto.ec2.get_region')
    @patch('boto.vpc.VPCConnection')
    @patch('boto.ec2.blockdevicemapping.BlockDeviceMapping')
    def test_25_launch_spot(self, blockdevicemapping, VPCConnection, get_region):
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

        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
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

        res = ec2_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('IM.connectors.EC2.EC2CloudConnector.get_connection')
    def test_30_updateVMInfo(self, get_connection):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.ip = '158.42.1.1' and
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
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "us-east-1;id-1", ec2_cloud.cloud, radl, radl, ec2_cloud)

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

        volume = MagicMock()
        volume.status = "available"
        volume.id = "volid"
        conn.create_volume.return_value = volume
        conn.attach_volume.return_value = True

        success, vm = ec2_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

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
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "us-east-1;sid-1", ec2_cloud.cloud, radl, radl, ec2_cloud)

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
        self.clean_log()

    @patch('IM.connectors.EC2.EC2CloudConnector.get_connection')
    def test_40_stop(self, get_connection):
        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "us-east-1;id-1", ec2_cloud.cloud, "", "", ec2_cloud)

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
        self.clean_log()

    @patch('IM.connectors.EC2.EC2CloudConnector.get_connection')
    def test_50_start(self, get_connection):
        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "us-east-1;id-1", ec2_cloud.cloud, "", "", ec2_cloud)

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
        self.clean_log()

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
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "us-east-1;sid-1", ec2_cloud.cloud, radl, radl, ec2_cloud)

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
        self.clean_log()

    @patch('IM.connectors.EC2.EC2CloudConnector.get_connection')
    @patch('time.sleep')
    def test_60_finalize(self, sleep, get_connection):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.ip = '158.42.1.1' and
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

        auth = Authentication([{'id': 'ec2', 'type': 'EC2', 'username': 'user', 'password': 'pass'}])
        ec2_cloud = self.get_ec2_cloud()

        inf = MagicMock()
        inf.id = "1"
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "us-east-1;id-1", ec2_cloud.cloud, radl, radl, ec2_cloud)
        vm.keypair_name = "key"

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

        conn.delete_key_pair.return_value = True

        address = MagicMock()
        address.public_ip = "158.42.1.1"
        address.instance_id = "id-1"
        address.disassociate.return_value = True
        address.release.return_value = True
        conn.get_all_addresses.return_value = [address]

        conn.get_all_spot_instance_requests.return_value = []

        volume = MagicMock()
        volume.attachment_state.return_value = None
        conn.get_all_volumes.return_value = [volume]
        conn.delete_volume.return_value = True

        sg = MagicMock()
        sg.name = "im-1"
        sg.instances.return_value = []
        sg.revoke.return_value = True
        sg.delete.return_value = True
        conn.get_all_security_groups.return_value = [sg]

        success, _ = ec2_cloud.finalize(vm, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()


if __name__ == '__main__':
    unittest.main()
