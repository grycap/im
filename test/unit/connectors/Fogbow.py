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
import json

sys.path.append(".")
sys.path.append("..")
from .CloudConn import TestCloudConnectorBase
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
from IM.VirtualMachine import VirtualMachine
from IM.InfrastructureInfo import InfrastructureInfo
from IM.connectors.FogBow import FogBowCloudConnector
from mock import patch, MagicMock


class TestFogBowConnector(TestCloudConnectorBase):
    """
    Class to test the IM connectors
    """

    @staticmethod
    def get_fogbow_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "FogBow"
        cloud_info.server = "server.com"
        cloud_info.port = 8182
        inf = MagicMock()
        inf.id = "1"
        cloud = FogBowCloudConnector(cloud_info, inf)
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
            disk.0.image.url = 'fbw://server.com/fogbow-ubuntu' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'fogbow', 'type': 'FogBow', 'token': 'user', 'host': 'server.com'}])
        fogbow_cloud = self.get_fogbow_cloud()

        concrete = fogbow_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    def get_response(self, method, url, verify, headers={}, data=None):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]
        params = parts[4]

        if method not in self.call_count:
            self.call_count[method] = {}
        if url not in self.call_count[method]:
            self.call_count[method][url] = 0
        self.call_count[method][url] += 1

        resp.status_code = 400

        if method == "GET":
            if url == "/computes/1":
                resp.status_code = 200
                resp.json.return_value = {"disk": 0,
                                          "hostName": "hostname",
                                          "id": "1",
                                          "ipAddresses": ["10.0.0.1"],
                                          "memory": 1024,
                                          "state": "READY",
                                          "vCPU": 1}
            elif url == "/volumes/1":
                resp.status_code = 200
                resp.json.return_value = {"id": "1",
                                          "name": "volname",
                                          "size": 1,
                                          "state": "READY"}
            elif url == "/networks/status":
                resp.status_code = 200
                resp.json.return_value = [{"instanceId": "1",
                                           "instanceName": "netname",
                                           "state": "READY"}]
            elif url == "/federatedNetworks/status":
                resp.status_code = 200
                resp.json.return_value = [{"instanceId": "1",
                                           "instanceName": "fednetname",
                                           "state": "READY"}]
            elif url == "/federatedNetworks/1":
                resp.status_code = 200
                resp.json.return_value = {"instanceId": "1",
                                          "cidr": "10.0.1.0/24"}
            elif url == "/publicIps/status":
                resp.status_code = 200
                resp.json.return_value = [{"instanceId": "1",
                                           "instanceName": "ipname",
                                           "state": "READY"}]
            elif url == "/publicIps/1":
                resp.status_code = 200
                resp.json.return_value = {"id": "1",
                                          "ip": "8.8.8.8",
                                          "computeId": "1",
                                          "state": "READY"}
            elif url == "/networks/1":
                resp.status_code = 200
                resp.json.return_value = {"id": "1",
                                          "name": "netname",
                                          "cidr": "192.168.0.0/24",
                                          "gateway": "192.168.0.1",
                                          "allocation": "dynamic",
                                          "state": "READY"}
            elif url == "/attachments/1":
                resp.status_code = 200
                resp.json.return_value = {"id": "1",
                                          "serverId": "1",
                                          "volumeId": "1",
                                          "device": "/dev/sdb",
                                          "state": "READY"}
            elif url == "/publicKey/":
                resp.status_code = 200
                resp.json.return_value = {"publicKey": "publicKey"}
            elif url == "/publicIps/1/securityRules":
                resp.status_code = 200
                resp.json.return_value = []
            elif url == "/networks/1/securityRules":
                resp.status_code = 200
                resp.json.return_value = []
        elif method == "POST":
            if url == "/computes/":
                resp.status_code = 201
                resp.json.return_value = {"id": "1"}
            elif url == "/publicIps/":
                resp.status_code = 201
                resp.json.return_value = {"id": "1"}
            elif url == "/volumes/":
                resp.status_code = 201
                resp.json.return_value = {"id": "1"}
            elif url == "/attachments/":
                resp.status_code = 201
                resp.json.return_value = {"id": "1"}
            elif url == "/networks/":
                resp.status_code = 201
                resp.json.return_value = {"id": "1"}
            elif url == "server1.com/tokens/":
                resp.status_code = 201
                resp.json.return_value = {"token": "token"}
            elif url == "/federatedNetworks/":
                resp.status_code = 201
                resp.json.return_value = {"id": "1"}
            elif url == "/publicIps/1/securityRules":
                resp.status_code = 201
                resp.json.return_value = {"id": "1"}
            elif url == "/networks/1/securityRules":
                resp.status_code = 201
                resp.json.return_value = {"id": "1"}
        elif method == "DELETE":
            if url == "/computes/1":
                resp.status_code = 204
            elif url == "/volumes/1":
                resp.status_code = 204
            elif url == "/networks/1":
                resp.status_code = 204
            elif url == "/publicIps/1":
                resp.status_code = 204
            elif url == "/attachments/1":
                resp.status_code = 204
        elif method == "HEAD":
            if url == "/clouds/":
                resp.status_code = 200

        return resp

    def request(self, method, url, body=None, headers=None):
        self.__class__.last_op = method, url

    @patch('requests.request')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, requests):
        radl_data = """
            network net1 (outbound = 'yes')
            network net2 (outports = '8080,9000/udp')
            network net3 (federated = 'yes' and providers = 'p1,p2')
            network net4 (federated = 'yes' and providers = ['p1','p2'])
            system test (
            gpu.count=1 and
            cpu.sgx.epc_size=8 and
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            net_interface.2.connection = 'net3' and
            net_interface.3.connection = 'net4' and
            availability_zone = 'cloud@site' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'fbw://server.com/fogbow-ubuntu' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'fogbow', 'type': 'FogBow', 'token': 'user', 'host': 'server.com'}])
        fogbow_cloud = self.get_fogbow_cloud()

        requests.side_effect = self.get_response

        inf = InfrastructureInfo()
        inf.auth = auth
        inf.radl = radl
        res = fogbow_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        data = json.loads(requests.call_args_list[4][1]["data"])
        self.assertEqual(data["allocationMode"], "dynamic")

        data = json.loads(requests.call_args_list[7][1]["data"])
        self.assertEqual(data, {"direction": "IN", "protocol": "TCP", "etherType": "IPv4",
                                "portTo": 8080, "portFrom": 8080, "cidr": "0.0.0.0/0"})
        data = json.loads(requests.call_args_list[8][1]["data"])
        self.assertEqual(data, {"direction": "IN", "protocol": "UDP", "etherType": "IPv4",
                                "portTo": 9000, "portFrom": 9000, "cidr": "0.0.0.0/0"})

        data = json.loads(requests.call_args_list[9][1]["data"])
        self.assertEqual(data['cidr'], "10.1.1.0/24")

        data = json.loads(requests.call_args_list[13][1]["data"])
        self.assertEqual(data["compute"]["cloudName"], "cloud")
        self.assertEqual(data["compute"]["provider"], "site")
        self.assertEqual(data["compute"]["vCPU"], 1)
        self.assertEqual(data["compute"]["memory"], 512)
        self.assertEqual(data["compute"]["imageId"], "fogbow-ubuntu")
        self.assertEqual(data["compute"]["requirements"], {'sgx:epc_size': '8', 'gpu': 'true'})
        self.assertEqual(data["federatedNetworkId"], "1")

    @patch('requests.request')
    @patch('time.sleep')
    def test_30_updateVMInfo(self, sleep, requests):
        radl_data = """
            network net (outbound = 'yes' and outports = '8080,9000:9010')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'fbw://server.com/fogbow-ubuntu' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'fogbow', 'type': 'FogBow', 'token': 'user', 'host': 'server.com'}])
        fogbow_cloud = self.get_fogbow_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", fogbow_cloud.cloud, radl, radl, fogbow_cloud, 1)

        requests.side_effect = self.get_response

        success, vm = fogbow_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.assertEquals(vm.info.systems[0].getValue("net_interface.1.ip"), "10.0.0.1")
        self.assertEquals(vm.info.systems[0].getValue("net_interface.0.ip"), "8.8.8.8")
        self.assertEquals(vm.info.systems[0].getValue("memory.size"), 1073741824)
        self.assertEquals(vm.info.systems[0].getValue("disk.1.device"), "/dev/sdb")

        data = json.loads(requests.call_args_list[1][1]["data"])
        self.assertEqual(data["computeId"], '1')
        data = json.loads(requests.call_args_list[4][1]["data"])
        self.assertEqual(data, {'direction': 'IN', 'protocol': 'TCP', 'etherType': 'IPv4',
                                'portTo': 8080, 'portFrom': 8080, 'cidr': '0.0.0.0/0'})
        data = json.loads(requests.call_args_list[5][1]["data"])
        self.assertEqual(data, {'direction': 'IN', 'protocol': 'TCP', 'etherType': 'IPv4',
                                'portTo': 9000, 'portFrom': 9010, 'cidr': '0.0.0.0/0'})
        data = json.loads(requests.call_args_list[6][1]["data"])
        self.assertEqual(data, {'direction': 'IN', 'protocol': 'TCP', 'etherType': 'IPv4',
                                'portTo': 22, 'portFrom': 22, 'cidr': '0.0.0.0/0'})
        data = json.loads(requests.call_args_list[7][1]["data"])
        self.assertEqual(data["size"], 1)
        data = json.loads(requests.call_args_list[9][1]["data"])
        self.assertEqual(data, {"computeId": "1", "device": "/dev/hdb", "volumeId": "1"})

    @patch('requests.request')
    def test_60_finalize(self, requests):
        auth = Authentication([{'id': 'fogbow', 'type': 'FogBow', 'host': 'server.com',
                                'username': 'user', 'password': 'pass', 'as_host': 'server1.com'}])
        fogbow_cloud = self.get_fogbow_cloud()

        radl_data = """
        network public (outbound = 'yes')
        network private ()
        system test ()
        """
        radl = radl_parse.parse_radl(radl_data)
        inf = MagicMock()
        vm = VirtualMachine(inf, "1", fogbow_cloud.cloud, radl, radl, fogbow_cloud, 1)
        vm.volumes = ["1"]
        vm.attachments = ["1"]

        requests.side_effect = self.get_response

        success, _ = fogbow_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        self.assertEqual(requests.call_args_list[6][0], ('DELETE', 'http://server.com:8182/publicIps/1'))
        self.assertEqual(requests.call_args_list[8][0], ('DELETE', 'http://server.com:8182/attachments/1'))
        self.assertEqual(requests.call_args_list[10][0], ('DELETE', 'http://server.com:8182/computes/1'))
        self.assertEqual(requests.call_args_list[12][0], ('DELETE', 'http://server.com:8182/volumes/1'))

        vm.attachments = ["2"]
        vm.volumes = ["2"]
        success, msg = fogbow_cloud.finalize(vm, True, auth)
        self.assertFalse(success, msg="ERROR not detected finalizing VM.")
        self.assertEqual(msg, "Error deleting attachments.\nError deleting Volumes.")


if __name__ == '__main__':
    unittest.main()
