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

import os
import time
import logging
import unittest
import sys
import json
import base64
import yaml
from datetime import datetime
from mock import Mock, patch, MagicMock

sys.path.append("..")
sys.path.append(".")

from IM.config import Config
# To load the ThreadPool class
Config.MAX_SIMULTANEOUS_LAUNCHES = 2

from IM.VirtualMachine import VirtualMachine
from IM.InfrastructureManager import InfrastructureManager as IM
from IM.InfrastructureManager import DisabledFunctionException
from IM.InfrastructureList import InfrastructureList
from IM.auth import Authentication
from radl.radl import RADL, system, deploy, Feature, SoftFeatures
from radl.radl_parse import parse_radl
from radl.radl_json import parse_radl as parse_radl_json
from IM.CloudInfo import CloudInfo
from IM.connectors.CloudConnector import CloudConnector
from IM.SSH import SSH
from IM.InfrastructureInfo import InfrastructureInfo


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    with open(abs_file_path, 'r') as f:
        return f.read()


class TestIM(unittest.TestCase):

    def __init__(self, *args):
        """Init test class."""
        unittest.TestCase.__init__(self, *args)

    def setUp(self):

        Config.DATA_DB = "/tmp/inf.dat"
        InfrastructureList.load_data()
        IM._reinit()

        ch = logging.StreamHandler(sys.stdout)
        log = logging.getLogger('InfrastructureManager')
        log.setLevel(logging.ERROR)
        log.propagate = 0
        log.addHandler(ch)
        log = logging.getLogger('ConfManager')
        log.setLevel(logging.DEBUG)
        log.propagate = 0
        log.addHandler(ch)

    def tearDown(self):
        IM.stop()

    @staticmethod
    def getAuth(im_users=[], vmrc_users=[], clouds=[]):
        return Authentication([
            {'id': 'im%s' % i, 'type': 'InfrastructureManager', 'username': 'user%s' % i,
             'password': 'pass%s' % i} for i in im_users] + [
            {'id': 'vmrc%s' % i, 'type': 'VMRC', 'username': 'vmrcuser%s' % i,
             'password': 'pass%s' % i, 'host': 'hostname'} for i in vmrc_users] + [
            {'id': 'cloud%s' % i, 'type': c, 'username': 'user%s' % i,
             'password': 'pass%s' % i, 'host': 'http://server.com:80/path'} for c, i in clouds])

    @staticmethod
    def register_cloudconnector(name, cloud_connector):
        sys.modules['IM.connectors.' + name] = type('MyConnector', (object,),
                                                    {name + 'CloudConnector': cloud_connector})

    @staticmethod
    def get_dummy_ssh(retry=False, auto_close=True):
        ssh = SSH("", "", "")
        ssh.test_connectivity = Mock(return_value=True)
        ssh.execute = Mock(return_value=("10", "", 0))
        ssh.sftp_put_files = Mock(return_value=True)
        ssh.sftp_mkdir = Mock(return_value=True)
        ssh.sftp_put_dir = Mock(return_value=True)
        ssh.sftp_put = Mock(return_value=True)
        ssh.sftp_list = Mock(return_value=["", "", "", "", ""])
        return ssh

    def gen_launch_res(self, inf, radl, requested_radl, num_vm, auth_data):
        res = []
        for _ in range(num_vm):
            cloud = CloudInfo()
            cloud.type = "Dummy"
            vm = VirtualMachine(inf, "1234", cloud, radl, requested_radl)
            vm.get_ssh = Mock(side_effect=self.get_dummy_ssh)
            vm.state = VirtualMachine.RUNNING
            res.append((True, vm))
        return res

    def sleep_and_create_vm(self, inf, radl, requested_radl, num_vm, auth_data):
        res = []
        time.sleep(5)
        for _ in range(num_vm):
            cloud = CloudInfo()
            cloud.type = "Dummy"
            vm = VirtualMachine(inf, "1234", cloud, radl, requested_radl)
            vm.get_ssh = Mock(side_effect=self.get_dummy_ssh)
            vm.state = VirtualMachine.RUNNING
            res.append((True, vm))
        return res

    def get_cloud_connector_mock(self, name="MyMock0"):
        cloud = type(name, (CloudConnector, object), {})
        cloud.launch = Mock(side_effect=self.gen_launch_res)
        return cloud

    @staticmethod
    def gen_token(aud=None, exp=None, user_sub="user_sub", groups=None):
        data = {
            "sub": user_sub,
            "iss": "https://iam-test.indigo-datacloud.eu/",
            "exp": 1465471354,
            "iat": 1465467755,
            "jti": "jti",
        }
        if aud:
            data["aud"] = aud
        if exp:
            data["exp"] = int(time.time()) + exp
        if groups:
            data["groups"] = groups
        return ("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.%s.ignored" %
                base64.urlsafe_b64encode(json.dumps(data).encode("utf-8")).decode("utf-8"))

    def test_inf_creation0(self):
        """Create infrastructure with empty RADL."""
        auth0 = self.getAuth([0])
        infId = IM.CreateInfrastructure("", auth0)
        IM.DestroyInfrastructure(infId, auth0)

    def test_inf_creation1(self):
        """Create infrastructure with an incorrect RADL in two cloud providers."""
        radl = """"
            network publica (outbound = 'yes')
            network privada ()

            system front (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'publica' and
            net_interface.1.connection = 'privada' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'yoyoyo' and
            disk.0.os.name = 'linux'
            )

            system wn (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'privada' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'yoyoyo' and
            disk.0.os.name = 'linux'
            )

            deploy front 1 cloud0
            deploy wn 1 cloud1
        """

        auth0 = self.getAuth([0])
        with self.assertRaises(Exception) as ex:
            _ = IM.CreateInfrastructure(radl, auth0)
        self.assertIn("Two deployments that have to be launched in the same cloud provider"
                      " are asked to be deployed in different cloud providers",
                      str(ex.exception))

    def test_inf_creation_addition_clouds(self):
        """Add resources infrastructure with an incorrect RADL with 2 clouds."""
        radl = """"
            network publica (outbound = 'yes')
            network privada ()
            system front (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'publica' and
            net_interface.1.connection = 'privada' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'yoyoyo' and
            disk.0.os.name = 'linux'
            )
            system wn (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'privada' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'yoyoyo' and
            disk.0.os.name = 'linux'
            )
            deploy front 1 cloud0
            deploy wn 1
        """

        auth0 = self.getAuth([0], [], [("Dummy", 0), ("Dummy", 1)])
        infId = IM.CreateInfrastructure(radl, auth0)

        radl = """
            network privada
            system wn
            deploy wn 1 cloud1
        """

        with self.assertRaises(Exception) as ex:
            _ = IM.AddResource(infId, radl, auth0)
        self.assertIn("Two deployments that have to be launched in the same cloud provider"
                      " are asked to be deployed in different cloud providers",
                      str(ex.exception))

    def test_inf_creation_errors(self):
        """Create infrastructure with errors."""
        radl = """"
            network publica (outbound = 'yes')
            network privada ()
            system front (
            net_interface.0.connection = 'publica' and
            net_interface.1.connection = 'privada' and
            disk.0.image.url = ['one://localhost/image', 'http://localhost:443/image'] and
            disk.0.os.credentials.username = 'ubuntu'
            )
            system wn (
            net_interface.0.connection = 'privada' and
            disk.0.image.url = ['one://localhost/image', 'http://localhost:443/image'] and
            disk.0.os.credentials.username = 'ubuntu'
            )
            deploy front 1
            deploy wn 1
        """

        # this case raises an exception
        auth0 = Authentication([{'type': 'InfrastructureManager', 'password': 'tests'}])
        with self.assertRaises(Exception) as ex:
            IM.CreateInfrastructure(radl, auth0)

        self.assertEqual(str(ex.exception), "No username nor token for the InfrastructureManager.")

        # this case raises an exception
        auth0 = Authentication([{'type': 'InfrastructureManager', 'username': 'test',
                                 'password': 'tests'}])
        with self.assertRaises(Exception) as ex:
            IM.CreateInfrastructure(radl, auth0)

        self.assertEqual(str(ex.exception), "No cloud provider available")

        # this case must fail with "no concrete system" error
        auth0 = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                 'password': 'pass', 'tenant': 'ten', 'host': 'localhost:5000'},
                                {'type': 'InfrastructureManager', 'username': 'test',
                                 'password': 'tests'}])

        with self.assertRaises(Exception) as ex:
            IM.CreateInfrastructure(radl, auth0)
        self.assertIn('Error launching the VMs of type front to cloud ID ost of type OpenStack.'
                      ' Error, no concrete system to deploy: front in cloud: ost. '
                      'Check if a correct image is being used', str(ex.exception))

        # this case must work OK
        auth0 = Authentication([{'id': 'dummy', 'type': 'Dummy'},
                                {'type': 'InfrastructureManager', 'username': 'test',
                                 'password': 'tests'}])
        IM.CreateInfrastructure(radl, auth0)

        Config.MAX_VM_FAILS = 3
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s0", 1))
        cloud = type("MyMock0", (CloudConnector, object), {})
        cloud.launch = Mock(return_value=[(False, "e1")])
        cloud.finalize = Mock(return_value=(True, ""))
        self.register_cloudconnector("Mock", cloud)
        auth0 = self.getAuth([0], [], [("Mock", 0)])

        with self.assertRaises(Exception) as ex:
            IM.CreateInfrastructure(str(radl), auth0)

        self.assertIn(("Error launching the VMs of type s0 to cloud ID cloud0 of type Mock. "
                       "Attempt 1: e1\nAttempt 2: e1\nAttempt 3: e1"), str(ex.exception))

        self.assertEqual(cloud.finalize.call_count, 1)

        # test error in the async case to get the whole error
        Config.MAX_VM_FAILS = 1
        inf_id = IM.CreateInfrastructure(str(radl), auth0, True)
        cont_msg = ""
        wait = 0
        while cont_msg == "" and wait < 20:
            cont_msg = IM.GetInfrastructureContMsg(inf_id, auth0)
            time.sleep(1)
            wait += 1
        self.assertIn("Error launching the VMs of type s0 to cloud ID cloud0 of type Mock. Attempt 1: e1", cont_msg)

    @patch("IM.InfrastructureManager.OpenIDClient")
    def test_access_no_own_inf(self, oidc_client_mock):
        """Try to access not owned Infs."""
        auth0, auth1 = self.getAuth([0]), self.getAuth([1])
        infId0 = IM.CreateInfrastructure("", auth0)
        infId1 = IM.CreateInfrastructure("", auth1)
        with self.assertRaises(Exception) as ex:
            IM.DestroyInfrastructure(infId0, auth1)
        self.assertEqual(str(ex.exception),
                         "Access to this infrastructure not granted.")
        with self.assertRaises(Exception) as ex:
            IM.DestroyInfrastructure(infId1, auth0)
        self.assertEqual(str(ex.exception),
                         "Access to this infrastructure not granted.")

        Config.ADMIN_USER = {"username": "admin", "password": "adminpass"}
        autha = Authentication([{'id': 'im', 'type': 'InfrastructureManager',
                                'username': 'admin', 'password': 'adminpass'}])
        IM.GetInfrastructureInfo(infId0, autha)
        IM.GetInfrastructureInfo(infId1, autha)

        Config.ADMIN_USER = None

        oidc_client_mock.get_user_info_request.return_value = True, {
            "preferred_username": "username",
            "sub": "user_sub",
            "groups": ["admin", "other"]
        }
        oidc_client_mock.is_access_token_expired.return_value = False, ""
        Config.OIDC_ISSUERS = ["https://iam-test.indigo-datacloud.eu/"]
        Config.OIDC_ADMIN_GROUPS = [{"issuer": "https://iam-test.indigo-datacloud.eu/", "group": "admin"}]
        token = self.gen_token()
        autha = Authentication([{'id': 'im', 'type': 'InfrastructureManager', 'token': token}])
        IM.GetInfrastructureInfo(infId0, autha)

        Config.OIDC_ADMIN_GROUPS = []

        IM.DestroyInfrastructure(infId0, auth0)

    def test_inf_auth_with_userdb(self):
        """Test access im with user db."""
        Config.USER_DB = os.path.dirname(os.path.realpath(__file__)) + '/../files/users.txt'

        auth0 = self.getAuth([0])
        infId0 = IM.CreateInfrastructure("", auth0)
        IM.DestroyInfrastructure(infId0, auth0)

        auth1 = self.getAuth([1])
        with self.assertRaises(Exception) as ex:
            IM.CreateInfrastructure("", auth1)
        self.assertEqual(str(ex.exception),
                         "Invalid InfrastructureManager credentials")
        Config.USER_DB = None

    def test_inf_addresources0(self):
        """Deploy single virtual machines and test reference."""
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s0", 1))

        auth0 = self.getAuth([0], [], [("Dummy", 0)])
        infId = IM.CreateInfrastructure("", auth0)

        vms = IM.AddResource(infId, str(radl), auth0)
        self.assertEqual(vms, [0])

        # Test references
        radl = RADL()
        radl.add(system("s0", reference=True))
        radl.add(deploy("s0", 1))
        vms = IM.AddResource(infId, str(radl), auth0)
        self.assertEqual(vms, [1])

        IM.DestroyInfrastructure(infId, auth0)

    def test_inf_addresources1(self):
        """Deploy n independent virtual machines."""
        n = 20  # Machines to deploy
        Config.MAX_SIMULTANEOUS_LAUNCHES = int(n / 2)  # Test the pool
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s0", n))
        cloud = self.get_cloud_connector_mock()
        self.register_cloudconnector("Mock", cloud)
        auth0 = self.getAuth([0], [], [("Mock", 0)])
        infId = IM.CreateInfrastructure("", auth0)
        vms = IM.AddResource(infId, str(radl), auth0)
        self.assertEqual(len(vms), n)
        self.assertEqual(cloud.launch.call_count, n)
        for call, _ in cloud.launch.call_args_list:
            self.assertEqual(call[3], 1)
        IM.DestroyInfrastructure(infId, auth0)

    def test_inf_addresources2(self):
        """Deploy independent virtual machines in two cloud providers."""
        n0, n1 = 2, 5  # Machines to deploy
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(system("s1", [Feature("disk.0.image.url", "=", "mock1://wind.ows.suc.kz"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.private_key", "=", "private_key")]))
        radl.add(deploy("s0", n0))
        radl.add(deploy("s1", n1))

        Config.MAX_SIMULTANEOUS_LAUNCHES = 10

        def concreteSystem(s, cloud_id):
            url = s.getValue("disk.0.image.url")
            return [s.clone()] if url.partition(":")[0] == cloud_id else []
        cloud0 = self.get_cloud_connector_mock("MyMock0")
        cloud0.concreteSystem = lambda _0, s, _1: concreteSystem(s, "mock0")
        self.register_cloudconnector("Mock0", cloud0)
        cloud1 = self.get_cloud_connector_mock("MyMock1")
        cloud1.concreteSystem = lambda _0, s, _1: concreteSystem(s, "mock1")
        self.register_cloudconnector("Mock1", cloud1)
        auth0 = self.getAuth([0], [], [("Mock0", 0), ("Mock1", 1)])
        infId = IM.CreateInfrastructure("", auth0)
        vms = IM.AddResource(infId, str(radl), auth0)
        self.assertEqual(len(vms), n0 + n1)
        self.assertEqual(cloud0.launch.call_count, n0)
        self.assertEqual(cloud1.launch.call_count, n1)
        for call, _ in cloud0.launch.call_args_list + cloud1.launch.call_args_list:
            self.assertEqual(call[3], 1)
        IM.DestroyInfrastructure(infId, auth0)

    @patch('IM.VMRC.Client')
    def test_inf_addresources3(self, suds_cli):
        """Test cloud selection."""
        n0, n1 = 2, 5  # Machines to deploy
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               SoftFeatures(10, [Feature("memory.size", "<=", 500)]),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(system("s1", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               SoftFeatures(10, [Feature("memory.size", ">=", 800)]),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s0", n0))
        radl.add(deploy("s1", n1))

        Config.MAX_SIMULTANEOUS_LAUNCHES = 10

        def concreteSystem(s, mem):
            return [system(s.name, [Feature("memory.size", "=", mem)])]
        cloud0 = self.get_cloud_connector_mock("MyMock0")
        cloud0.concreteSystem = lambda _0, s, _1: concreteSystem(s, 500)
        self.register_cloudconnector("Mock0", cloud0)
        cloud1 = self.get_cloud_connector_mock("MyMock1")
        cloud1.concreteSystem = lambda _0, s, _1: concreteSystem(s, 1000)
        self.register_cloudconnector("Mock1", cloud1)
        auth0 = self.getAuth([0], [0], [("Mock0", 0), ("Mock1", 1)])
        infId = IM.CreateInfrastructure("", auth0)
        vms = IM.AddResource(infId, str(radl), auth0)
        self.assertEqual(len(vms), n0 + n1)
        self.assertEqual(cloud0.launch.call_count, n0)
        self.assertEqual(cloud1.launch.call_count, n1)
        for call, _ in cloud0.launch.call_args_list + cloud1.launch.call_args_list:
            self.assertEqual(call[3], 1)
        IM.DestroyInfrastructure(infId, auth0)

    def test_inf_addresources_parallel(self):
        """Deploy parallel virtual machines."""
        radl = """"
            network publica (outbound = 'yes')
            network privada ()

            system front (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'publica' and
            net_interface.1.connection = 'privada' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'yoyoyo' and
            disk.0.os.name = 'linux'
            )

            system wn (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'privada' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'yoyoyo' and
            disk.0.os.name = 'linux'
            )

            deploy front 1
            deploy wn 3
            deploy wn 2
        """
        cloud = type("MyMock0", (CloudConnector, object), {})
        cloud.launch = Mock(side_effect=self.sleep_and_create_vm)
        self.register_cloudconnector("Mock", cloud)
        auth0 = self.getAuth([0], [], [("Mock", 0)])
        infId = IM.CreateInfrastructure("", auth0)

        # in this case it will take aprox 15 secs
        before = int(time.time())
        Config.MAX_SIMULTANEOUS_LAUNCHES = 1
        vms = IM.AddResource(infId, str(radl), auth0)
        delay = int(time.time()) - before
        self.assertLess(delay, 21)
        self.assertGreater(delay, 14)

        self.assertEqual(vms, [0, 1, 2, 3, 4, 5])
        self.assertEqual(cloud.launch.call_count, 3)
        self.assertEqual(cloud.launch.call_args_list[0][0][3], 1)
        self.assertEqual(cloud.launch.call_args_list[1][0][3], 3)
        self.assertEqual(cloud.launch.call_args_list[2][0][3], 2)

        cloud = type("MyMock0", (CloudConnector, object), {})
        cloud.launch = Mock(side_effect=self.sleep_and_create_vm)
        self.register_cloudconnector("Mock", cloud)

        # in this case it will take aprox 5 secs
        before = int(time.time())
        Config.MAX_SIMULTANEOUS_LAUNCHES = 3  # Test the pool
        vms = IM.AddResource(infId, str(radl), auth0)
        delay = int(time.time()) - before
        # self.assertLess(delay, 17)
        # self.assertGreater(delay, 14)
        self.assertLess(delay, 12)
        self.assertGreater(delay, 4)
        Config.MAX_SIMULTANEOUS_LAUNCHES = 1

        self.assertEqual(vms, [6, 7, 8, 9, 10, 11])
        self.assertEqual(cloud.launch.call_count, 3)
        total = cloud.launch.call_args_list[0][0][3]
        total += cloud.launch.call_args_list[1][0][3]
        total += cloud.launch.call_args_list[2][0][3]
        self.assertEqual(total, 6)

        IM.DestroyInfrastructure(infId, auth0)

    @patch('IM.VMRC.Client')
    def test_inf_cloud_order(self, suds_cli):
        """Test cloud selection in base of the auth data order."""
        n0, n1 = 1, 1  # Machines to deploy
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("cpu.count", "=", 1),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s0", n0))
        radl.add(system("s1", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("cpu.count", "=", 1),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s1", n1))

        cloud0 = self.get_cloud_connector_mock("MyMock0")
        self.register_cloudconnector("Mock0", cloud0)
        cloud1 = self.get_cloud_connector_mock("MyMock1")
        self.register_cloudconnector("Mock1", cloud1)
        auth0 = self.getAuth([0], [0], [("Mock0", 0), ("Mock1", 1)])
        infId = IM.CreateInfrastructure(str(radl), auth0)
        self.assertEqual(cloud0.launch.call_count, n0 + n1)
        IM.DestroyInfrastructure(infId, auth0)

    def test_get_infrastructure_list(self):
        """Get infrastructure List."""
        radl_str = """"
            system front (
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'pass' and
            disk.0.applications contains (name = 'ansible.roles.micafer.hadoop')
            )
            deploy front 1"""
        radl = parse_radl(radl_str)
        auth0 = self.getAuth([0], [], [("Dummy", 0)])
        infId = IM.CreateInfrastructure(radl, auth0)
        inf_ids = IM.GetInfrastructureList(auth0)
        self.assertEqual(inf_ids, [infId])

        inf_ids = IM.GetInfrastructureList(auth0, ".*hadoop.*")
        self.assertEqual(inf_ids, [infId])

        inf_ids = IM.GetInfrastructureList(auth0, ".*nonexist.*")
        self.assertEqual(inf_ids, [])

        auth1 = self.getAuth([1], [], [("Dummy", 0)])
        infId1 = IM.CreateInfrastructure(radl, auth1)

        auth = self.getAuth([0, 1], [], [("Dummy", 0)])
        inf_ids = IM.GetInfrastructureList(auth)
        self.assertEqual(len(inf_ids), 2)
        inf_ids = IM.GetInfrastructureList(auth0)
        self.assertEqual(len(inf_ids), 1)

        IM.DestroyInfrastructure(infId, auth)
        IM.DestroyInfrastructure(infId1, auth)

    def test_reconfigure(self):
        """Reconfigure."""
        radl_str = """"
            system front (
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'pass' and
            disk.0.applications contains (name = 'ansible.roles.micafer.hadoop')
            )
            deploy front 1"""
        radl = parse_radl(radl_str)

        auth0 = self.getAuth([0], [], [("Dummy", 0)])
        infId = IM.CreateInfrastructure(str(radl), auth0)

        reconf_radl = """configure test (\n@begin\n---\n  - tasks:\n      - debug: msg="RECONFIGURERADL"\n@end\n)"""
        IM.Reconfigure(infId, reconf_radl, auth0)
        IM.Reconfigure(infId, reconf_radl, auth0, ['0'])
        inf = IM.get_infrastructure(infId, auth0)
        self.assertEqual(inf.radl.configures[0].recipes, '\n---\n  - tasks:\n      - debug: msg="RECONFIGURERADL"\n')

        reconf_radl = """"
            system front (
            disk.0.applications contains (name = 'ansible.roles.micafer.hadoop,version') and
            disk.0.applications contains (name = 'ansible.roles.micafer.hadoop1')
            )"""
        IM.Reconfigure(infId, reconf_radl, auth0)
        inf = IM.get_infrastructure(infId, auth0)
        self.assertIn("ansible.roles.micafer.hadoop,version", inf.radl.systems[0].getValue("disk.0.applications"))
        self.assertIn("ansible.roles.micafer.hadoop1", inf.radl.systems[0].getValue("disk.0.applications"))

        reconf_radl = """"
            system front (
            disk.0.applications contains (name = 'ansible.roles.micafer.hadoop,version') and
            disk.0.applications contains (name = 'ansible.roles.micafer.hadoop1')
            )"""
        IM.Reconfigure(infId, reconf_radl, auth0)
        inf = IM.get_infrastructure(infId, auth0)
        self.assertIn("ansible.roles.micafer.hadoop,version", inf.radl.systems[0].getValue("disk.0.applications"))
        self.assertIn("ansible.roles.micafer.hadoop1", inf.radl.systems[0].getValue("disk.0.applications"))

        IM.DestroyInfrastructure(infId, auth0)

    def test_inf_removeresources(self):
        """Deploy 4 VMs and remove 2"""
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s0", 4))

        auth0 = self.getAuth([0], [], [("Dummy", 0)])
        infId = IM.CreateInfrastructure(str(radl), auth0)
        cont = IM.RemoveResource(infId, ['0', '1'], auth0)
        self.assertEqual(cont, 2)
        vms = IM.GetInfrastructureInfo(infId, auth0)
        self.assertEqual(sorted(vms), ['2', '3'])

        IM.DestroyInfrastructure(infId, auth0)

    def test_get_vm_info(self):
        """
        Test GetVMInfo and GetVMProperty and GetVMContMsg and GetInfrastructureRADL and
        GetInfrastructureContMsg and GetInfrastructureState.
        """
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s0", 1))

        auth0 = self.getAuth([0], [], [("Dummy", 0)])
        infId = IM.CreateInfrastructure(str(radl), auth0)

        radl_info = IM.GetVMInfo(infId, "0", auth0)
        parsed_radl_info = parse_radl(str(radl_info))
        self.assertEqual(parsed_radl_info.systems[0].getValue("state"), "running")

        radl_info = IM.GetVMInfo(infId, "0", auth0, True)
        parsed_radl_info = parse_radl_json(radl_info)
        self.assertEqual(parsed_radl_info.systems[0].getValue("state"), "running")

        state = IM.GetVMProperty(infId, "0", "state", auth0)
        self.assertEqual(state, "running")

        contmsg = IM.GetVMContMsg(infId, "0", auth0)
        self.assertEqual(contmsg, "")

        InfrastructureList.infrastructure_list[infId].cont_out = "Header"
        InfrastructureList.infrastructure_list[infId].vm_list[0].cloud_connector = MagicMock()
        InfrastructureList.infrastructure_list[infId].vm_list[0].cloud_connector.error_messages = "TESTMSG"
        contmsg = IM.GetInfrastructureContMsg(infId, auth0)
        header_contmsg = IM.GetInfrastructureContMsg(infId, auth0, True)
        InfrastructureList.infrastructure_list[infId].vm_list[0].cloud_connector = None

        self.assertIn("TESTMSG", contmsg)
        self.assertNotIn("TESTMSG", header_contmsg)
        self.assertIn("Header", header_contmsg)

        state = IM.GetInfrastructureState(infId, auth0)
        self.assertEqual(state["state"], "running")
        self.assertEqual(state["vm_states"]["0"], "running")

        radl_info = IM.GetInfrastructureRADL(infId, auth0)
        parsed_radl_info = parse_radl(str(radl_info))
        self.assertEqual(parsed_radl_info.systems[0].getValue("disk.0.os.credentials.username"), "user")

        IM.DestroyInfrastructure(infId, auth0)

    @patch('IM.InfrastructureList.InfrastructureList.get_inf_ids')
    def test_get_inf_state(self, get_inf_ids):
        """Test GetInfrastructureState."""
        auth0 = self.getAuth([0], [], [("Dummy", 0)])

        inf = MagicMock()
        get_inf_ids.return_value = ["1"]
        InfrastructureList.infrastructure_list = {"1": inf}
        inf.id = "1"
        inf.auth = auth0
        inf.deleted = False
        inf.deleting = False
        inf.has_expired.return_value = False
        vm1 = MagicMock()
        vm1.im_id = 0
        vm1.state = VirtualMachine.RUNNING
        vm2 = MagicMock()
        vm2.im_id = 1
        vm2.state = VirtualMachine.RUNNING
        vm3 = MagicMock()
        vm3.im_id = 2
        vm3.state = VirtualMachine.RUNNING
        inf.get_vm_list.return_value = [vm1, vm2, vm3]

        state = IM.GetInfrastructureState("1", auth0)
        self.assertEqual(state["state"], "running")

        vm1.state = VirtualMachine.FAILED
        vm2.state = VirtualMachine.RUNNING
        vm3.state = VirtualMachine.UNKNOWN

        state = IM.GetInfrastructureState("1", auth0)
        self.assertEqual(state["state"], "failed")

        vm1.state = VirtualMachine.PENDING
        vm2.state = VirtualMachine.RUNNING
        vm3.state = VirtualMachine.CONFIGURED

        state = IM.GetInfrastructureState("1", auth0)
        self.assertEqual(state["state"], "pending")

        vm1.state = VirtualMachine.PENDING
        vm2.state = VirtualMachine.CONFIGURED
        vm3.state = VirtualMachine.UNCONFIGURED

        state = IM.GetInfrastructureState("1", auth0)
        self.assertEqual(state["state"], "pending")

        vm1.state = VirtualMachine.RUNNING
        vm2.state = VirtualMachine.CONFIGURED
        vm3.state = VirtualMachine.UNCONFIGURED

        state = IM.GetInfrastructureState("1", auth0)
        self.assertEqual(state["state"], "running")

        vm1.state = VirtualMachine.RUNNING
        vm2.state = VirtualMachine.CONFIGURED
        vm3.state = VirtualMachine.STOPPED

        state = IM.GetInfrastructureState("1", auth0)
        self.assertEqual(state["state"], "running")

        inf.get_vm_list.return_value = []
        inf.configured = None
        state = IM.GetInfrastructureState("1", auth0)
        self.assertEqual(state["state"], "pending")

    def test_altervm(self):
        """Test AlterVM."""
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("cpu.count", "=", 1),
                               Feature("memory.size", "=", 512, "M"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s0", 1))

        auth0 = self.getAuth([0], [], [("Dummy", 0)])
        infId = IM.CreateInfrastructure(str(radl), auth0)

        radl = RADL()
        radl.add(system("s1", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("cpu.count", "=", 1),
                               Feature("memory.size", "=", 512, "M"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("cpu.count", "=", 2),
                               Feature("memory.size", "=", 1024, "M"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s1", 1))
        radl.add(deploy("s0", 1))

        radl_info = IM.AlterVM(infId, "0", str(radl), auth0)
        parsed_radl_info = parse_radl(str(radl_info))
        self.assertEqual(parsed_radl_info.systems[0].getValue("cpu.count"), 2)
        self.assertEqual(parsed_radl_info.systems[0].getFeature('memory.size').getValue('M'), 1024)

        radl = RADL()
        radl.add(system("s1", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("cpu.count", "=", 2),
                               Feature("memory.size", "=", 1024, "M"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s1", 1))

        with self.assertRaises(Exception) as ex:
            IM.AlterVM(infId, "0", str(radl), auth0)
        self.assertEqual(str(ex.exception), 'Incorrect RADL no system with name s0 provided.')

        IM.DestroyInfrastructure(infId, auth0)

    def test_start_stop(self):
        """Test Start and Stop operations."""
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s0", 1))

        auth0 = self.getAuth([0], [], [("Dummy", 0)])
        infId = IM.CreateInfrastructure(str(radl), auth0)

        res = IM.StopInfrastructure(infId, auth0)
        self.assertEqual(res, "")
        res = IM.StartInfrastructure(infId, auth0)
        self.assertEqual(res, "")

        res = IM.StartVM(infId, "0", auth0)
        self.assertEqual(res, "")
        res = IM.StopVM(infId, "0", auth0)
        self.assertEqual(res, "")
        res = IM.RebootVM(infId, "0", auth0)
        self.assertEqual(res, "")

        IM.DestroyInfrastructure(infId, auth0)

    def test_export_import(self):
        """Test ExportInfrastructure and ImportInfrastructure operations."""
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s0", 1))

        auth0 = self.getAuth([0], [], [("Dummy", 0)])
        infId = IM.CreateInfrastructure(str(radl), auth0)

        res = IM.ExportInfrastructure(infId, True, auth0)
        new_inf_id = IM.ImportInfrastructure(res, auth0)

        IM.DestroyInfrastructure(new_inf_id, auth0)

    def test_create_disk_snapshot(self):
        """Test CreateDiskSnapshot"""
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s0", 1))

        new_url = "mock0://linux.for.ev.er/test"

        cloud0 = self.get_cloud_connector_mock("MyMock0")
        cloud0.create_snapshot = Mock(return_value=(True, new_url))
        self.register_cloudconnector("Mock0", cloud0)
        auth0 = self.getAuth([0], [], [("Mock0", 0)])

        infId = IM.CreateInfrastructure(str(radl), auth0)

        InfrastructureList.infrastructure_list[infId].vm_list[0].cloud_connector = cloud0

        res = IM.CreateDiskSnapshot(infId, 0, 0, "test", True, auth0)
        self.assertEqual(res, new_url)

        self.assertEqual(cloud0.create_snapshot.call_count, 1)

    def test_contextualize(self):
        """Test Contextualization process."""
        radl = """"
            network publica (outbound = 'yes')

            system front (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'publica' and
            net_interface.0.dns_name = 'test' and
            net_interface.0.ip = '10.0.0.1' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'yoyoyo' and
            disk.0.os.name = 'linux' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.fstype='ext4' and
            disk.1.mount_path='/mnt/disk' and
            disk.0.applications contains (name = 'ansible.roles.micafer.hadoop') and
            disk.0.applications contains (name='gmetad') and
            disk.0.applications contains (name='wget')
            )

configure step1 (
@begin
---
  - tasks:
      - shell:  echo "Hi"

@end
)

configure step2 (
@begin
---
  - tasks:
      - shell:  echo "Hi"

@end
)

            contextualize (
                system front configure step1 step 1
                system front configure step2 step 2
            )

            deploy front 1
        """

        auth0 = self.getAuth([0], [], [("Mock", 0)])
        IM._reinit()
        Config.PLAYBOOK_RETRIES = 1
        Config.CONTEXTUALIZATION_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../contextualization"
        Config.CONFMAMAGER_CHECK_STATE_INTERVAL = 0.01
        Config.UPDATE_CTXT_LOG_INTERVAL = 1
        Config.CHECK_CTXT_PROCESS_INTERVAL = 1
        cloud0 = self.get_cloud_connector_mock("MyMock")
        self.register_cloudconnector("Mock", cloud0)

        infId = IM.CreateInfrastructure(str(radl), auth0)

        time.sleep(20)

        state = IM.GetInfrastructureState(infId, auth0)
        self.assertEqual(state["state"], "unconfigured")

        IM.Reconfigure(infId, "", auth0)

        InfrastructureList.infrastructure_list[infId].ansible_configured = True
        InfrastructureList.infrastructure_list[infId].vm_list[0].get_ctxt_log = MagicMock()
        InfrastructureList.infrastructure_list[infId].vm_list[0].get_ctxt_log.return_value = "OK"

        time.sleep(5)

        state = IM.GetInfrastructureState(infId, auth0)
        self.assertEqual(state["state"], "running")

        contmsg = IM.GetInfrastructureContMsg(infId, auth0)
        self.assertGreater(len(contmsg), 150)

        IM.DestroyInfrastructure(infId, auth0)

    def test_contextualize_timeout(self):
        """Test Contextualization process timeout."""
        radl = """"
            network publica (outbound = 'yes')

            system front (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'publica' and
            net_interface.0.dns_name = 'test' and
            net_interface.0.ip = '10.0.0.1' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'pass' and
            disk.0.os.name = 'linux'
            )

configure step1 (
@begin
---
  - tasks:
      - shell:  echo "Hi"

@end
)

configure step2 (
@begin
---
  - tasks:
      - shell:  echo "Hi"

@end
)

            contextualize 2 (
                system front configure step1 step 1
                system front configure step2 step 2
            )

            deploy front 1
        """

        auth0 = self.getAuth([0], [], [("Mock", 0)])
        IM._reinit()
        Config.PLAYBOOK_RETRIES = 1
        Config.CONTEXTUALIZATION_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../contextualization"
        Config.CONFMAMAGER_CHECK_STATE_INTERVAL = 1
        Config.UPDATE_CTXT_LOG_INTERVAL = 1
        Config.CHECK_CTXT_PROCESS_INTERVAL = 1
        cloud0 = self.get_cloud_connector_mock("MyMock")
        self.register_cloudconnector("Mock", cloud0)

        infId = IM.CreateInfrastructure(str(radl), auth0)

        time.sleep(4)

        state = IM.GetInfrastructureState(infId, auth0)
        self.assertEqual(state["state"], "unconfigured")

        contmsg = IM.GetInfrastructureContMsg(infId, auth0)
        self.assertIn("ERROR: Max contextualization time passed.", contmsg)

        IM.DestroyInfrastructure(infId, auth0)

    @patch('requests.request')
    def test_check_oidc_invalid_token(self, request):
        im_auth = {"token": self.gen_token()}

        Config.OIDC_ISSUERS = ["https://iam-test.indigo-datacloud.eu/"]
        with self.assertRaises(Exception) as ex:
            IM.check_oidc_token(im_auth)
        self.assertEqual(str(ex.exception),
                         'Invalid InfrastructureManager credentials. OIDC auth Token expired.')

        im_auth_aud = {"token": self.gen_token(aud="test1,test2")}

        Config.OIDC_AUDIENCE = "test"
        with self.assertRaises(Exception) as ex:
            IM.check_oidc_token(im_auth_aud)
        self.assertEqual(str(ex.exception),
                         'Invalid InfrastructureManager credentials. Audience not accepted.')

        Config.OIDC_AUDIENCE = "test2"
        with self.assertRaises(Exception) as ex:
            IM.check_oidc_token(im_auth_aud)
        self.assertEqual(str(ex.exception),
                         'Invalid InfrastructureManager credentials. OIDC auth Token expired.')
        Config.OIDC_AUDIENCE = None

        Config.OIDC_SCOPES = ["scope1", "scope2"]
        Config.OIDC_CLIENT_ID = "client"
        Config.OIDC_CLIENT_SECRET = "secret"
        response = MagicMock()
        response.status_code = 200
        response.text = '{ "scope": "profile scope1" }'
        request.return_value = response
        with self.assertRaises(Exception) as ex:
            IM.check_oidc_token(im_auth_aud)
        self.assertEqual(str(ex.exception),
                         'Invalid InfrastructureManager credentials. '
                         'Scopes scope1 scope2 not in introspection scopes: profile scope1')

        response.status_code = 200
        response.text = '{ "scope": "address profile scope1 scope2" }'
        request.return_value = response
        with self.assertRaises(Exception) as ex:
            IM.check_oidc_token(im_auth_aud)
        self.assertEqual(str(ex.exception),
                         'Invalid InfrastructureManager credentials. '
                         'OIDC auth Token expired.')

        Config.OIDC_SCOPES = []
        Config.OIDC_CLIENT_ID = None
        Config.OIDC_CLIENT_SECRET = None

        Config.OIDC_ISSUERS = ["https://other_issuer"]

        with self.assertRaises(Exception) as ex:
            IM.check_oidc_token(im_auth)
        self.assertEqual(str(ex.exception),
                         "Invalid InfrastructureManager credentials. Issuer not accepted.")

    @patch('IM.InfrastructureManager.OpenIDClient')
    def test_check_oidc_valid_token(self, openidclient):
        im_auth = {"token": (self.gen_token())}

        user_info = json.loads(read_file_as_string('../files/iam_user_info.json'))

        openidclient.is_access_token_expired.return_value = False, "Valid Token for 100 seconds"
        openidclient.get_user_info_request.return_value = True, user_info

        Config.OIDC_ISSUERS = ["https://iam-test.indigo-datacloud.eu/"]
        Config.OIDC_AUDIENCE = None

        IM.check_oidc_token(im_auth)

        self.assertEqual(im_auth['username'], InfrastructureInfo.OPENID_USER_PREFIX + "micafer")
        self.assertEqual(im_auth['password'], "https://iam-test.indigo-datacloud.eu/sub")

    @patch('IM.InfrastructureManager.OpenIDClient')
    def test_check_oidc_groups(self, openidclient):
        im_auth = {"token": (self.gen_token())}

        user_info = json.loads(read_file_as_string('../files/iam_user_info.json'))

        openidclient.is_access_token_expired.return_value = False, "Valid Token for 100 seconds"
        openidclient.get_user_info_request.return_value = True, user_info

        Config.OIDC_ISSUERS = ["https://iam-test.indigo-datacloud.eu/"]
        Config.OIDC_AUDIENCE = None
        Config.OIDC_GROUPS = ["urn:mace:egi.eu:group:demo.fedcloud.egi.eu:role=member#aai.egi.eu"]
        Config.OIDC_GROUPS_CLAIM = "eduperson_entitlement"

        IM.check_oidc_token(im_auth)

        self.assertEqual(im_auth['username'], InfrastructureInfo.OPENID_USER_PREFIX + "micafer")
        self.assertEqual(im_auth['password'], "https://iam-test.indigo-datacloud.eu/sub")

        Config.OIDC_GROUPS = ["urn:mace:egi.eu:group:demo.fedcloud.egi.eu:role=INVALID#aai.egi.eu"]

        with self.assertRaises(Exception) as ex:
            IM.check_oidc_token(im_auth)
        self.assertEqual(str(ex.exception),
                         "Error trying to validate OIDC auth token: Invalid InfrastructureManager" +
                         " credentials. User not in configured groups.")

        Config.OIDC_GROUPS = []

    @patch('IM.InfrastructureManager.OpenIDClient.get_user_info_request')
    def test_inf_auth_with_token(self, get_user_info_request):
        im_auth = {"token": (self.gen_token(exp=120))}
        im_auth['username'] = InfrastructureInfo.OPENID_USER_PREFIX + "micafer"
        im_auth['password'] = "https://iam-test.indigo-datacloud.eu/user_sub"
        # Check that a user/pass cred cannot access OpenID ones
        user_auth = Authentication([{'id': 'im', 'type': 'InfrastructureManager',
                                     'username': im_auth['username'],
                                     'password': im_auth['password']}])

        with self.assertRaises(Exception) as ex:
            IM.check_auth_data(user_auth)
        self.assertEqual(str(ex.exception), "Invalid username used for the InfrastructureManager.")

        Config.FORCE_OIDC_AUTH = True
        with self.assertRaises(Exception) as ex:
            IM.check_auth_data(user_auth)
        self.assertEqual(str(ex.exception), "No token provided for the InfrastructureManager.")
        Config.FORCE_OIDC_AUTH = False

        Config.OIDC_ISSUERS = ["https://iam-test.indigo-datacloud.eu/"]
        user_auth = Authentication([{'id': 'im', 'type': 'InfrastructureManager',
                                     'token': im_auth['token']}])
        get_user_info_request.return_value = True, {'sub': 'micafer'}
        inf = InfrastructureInfo()
        inf.id = "1"
        inf.auth = user_auth
        user_auth = IM.check_auth_data(user_auth)
        res = inf.is_authorized(user_auth)
        self.assertTrue(res)

        get_user_info_request.return_value = True, {'sub': 'user_sub'}
        user_auth1 = Authentication([{'id': 'im', 'type': 'InfrastructureManager',
                                      'token': self.gen_token(user_sub="user_sub", exp=120)}])
        user_auth1 = IM.check_auth_data(user_auth1)
        res = inf.is_authorized(user_auth1)
        self.assertFalse(res)

        inf.auth = user_auth1
        Config.ADMIN_USER = [{"username": "__OPENID__admin_user",
                              "password": "https://iam-test.indigo-datacloud.eu/admin_user",
                              "token": ""}]
        get_user_info_request.return_value = True, {'sub': 'admin_user'}
        admin_auth = Authentication([{'id': 'im', 'type': 'InfrastructureManager',
                                      'token': self.gen_token(user_sub="admin_user", exp=120)}])
        admin_auth = IM.check_auth_data(admin_auth)
        res = inf.is_authorized(admin_auth)
        self.assertTrue(res)

    def test_db(self):
        """ Test DB data access."""
        inf = InfrastructureInfo()
        inf.id = "1"
        inf.auth = self.getAuth([0], [], [("Dummy", 0)])
        cloud = CloudInfo()
        cloud.type = "Dummy"
        self.assertEqual(str(cloud), "type = Dummy, ")
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er")]))
        radl.add(deploy("s0", 1))
        vm1 = VirtualMachine(inf, "1", cloud, radl, radl, None, 1)
        vm2 = VirtualMachine(inf, "2", cloud, radl, radl, None, 2)
        inf.vm_list = [vm1, vm2]
        inf.vm_master = vm1
        # first create the DB table
        Config.DATA_DB = "sqlite:///tmp/ind.dat"
        InfrastructureList.load_data()

        success = InfrastructureList._save_data_to_db(Config.DATA_DB, {"1": inf})
        self.assertTrue(success)

        res = InfrastructureList._get_data_from_db(Config.DATA_DB)
        self.assertEqual(len(res), 1)
        self.assertEqual(len(res['1'].vm_list), 2)
        self.assertEqual(res['1'].vm_list[0], res['1'].vm_master)
        self.assertEqual(res['1'].vm_master.info.systems[0].getValue("disk.0.image.url"), "mock0://linux.for.ev.er")
        self.assertTrue(res['1'].auth.compare(inf.auth, "InfrastructureManager"))

    def test_inf_remove_two_clouds(self):
        """Test remove VMs from 2 cloud providers."""
        radl = """"
            network publica (outbound = 'yes')
            system front (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'publica' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'aaaaa' and
            disk.0.os.name = 'linux'
            )
            contextualize ()
            deploy front 2 cloud0
            deploy front 2 cloud1
        """

        cloud0 = self.get_cloud_connector_mock("MyMock0")
        cloud0.finalize = Mock(return_value=(True, ""))
        self.register_cloudconnector("Mock0", cloud0)
        cloud1 = self.get_cloud_connector_mock("MyMock1")
        cloud1.finalize = Mock(return_value=(True, ""))
        self.register_cloudconnector("Mock1", cloud1)
        auth0 = self.getAuth([0], [], [("Mock1", 1), ("Mock0", 0)])

        infId = IM.CreateInfrastructure(radl, auth0)

        InfrastructureList.infrastructure_list[infId].vm_list[0].cloud.server = "server0"
        InfrastructureList.infrastructure_list[infId].vm_list[0].cloud_connector = cloud0
        InfrastructureList.infrastructure_list[infId].vm_list[1].cloud.server = "server0"
        InfrastructureList.infrastructure_list[infId].vm_list[1].cloud_connector = cloud0
        InfrastructureList.infrastructure_list[infId].vm_list[2].cloud.server = "server1"
        InfrastructureList.infrastructure_list[infId].vm_list[2].cloud_connector = cloud1
        InfrastructureList.infrastructure_list[infId].vm_list[3].cloud.server = "server1"
        InfrastructureList.infrastructure_list[infId].vm_list[3].cloud_connector = cloud1

        cont = IM.RemoveResource(infId, ['0', '1'], auth0)

        InfrastructureList.infrastructure_list[infId].vm_list[2].cloud_connector = cloud1
        InfrastructureList.infrastructure_list[infId].vm_list[3].cloud_connector = cloud1

        self.assertEqual(cont, 2)
        self.assertEqual(cloud0.finalize.call_args_list[0][0][1], False)
        self.assertEqual(cloud0.finalize.call_args_list[1][0][1], True)
        self.assertEqual(cloud0.finalize.call_count, 2)
        self.assertEqual(cloud1.finalize.call_count, 0)

        IM.DestroyInfrastructure(infId, auth0)

        self.assertEqual(cloud0.finalize.call_count, 2)
        self.assertEqual(cloud1.finalize.call_count, 2)
        self.assertEqual(cloud1.finalize.call_args_list[0][0][1], False)
        self.assertEqual(cloud1.finalize.call_args_list[1][0][1], True)

    def test_create_async(self):
        """Create Inf. async."""
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s0", 1))

        cloud = type("MyMock0", (CloudConnector, object), {})
        cloud.launch = Mock(side_effect=self.sleep_and_create_vm)
        cloud.finalize = Mock(return_value=(True, ""))
        self.register_cloudconnector("Mock", cloud)
        auth0 = self.getAuth([0], [], [("Mock", 0)])

        before = int(time.time())
        infId = IM.CreateInfrastructure(str(radl), auth0, True)
        delay = int(time.time()) - before

        self.assertLess(delay, 2)

        time.sleep(6)

        IM.DestroyInfrastructure(infId, auth0)

    def test_inf_delete_force(self):
        """Force a DestroyInfrastructure."""
        auth0 = self.getAuth([0])
        infId = IM.CreateInfrastructure("", auth0)
        inf = IM.get_infrastructure(infId, auth0)
        inf.destroy_vms = Mock(side_effect=Exception())
        with self.assertRaises(Exception):
            IM.DestroyInfrastructure(infId, auth0)
        self.assertEqual(inf.deleted, False)
        IM.DestroyInfrastructure(infId, auth0, True)
        self.assertEqual(inf.deleted, True)

    def sleep_5(self, _):
        time.sleep(5)

    def test_inf_delete_async(self):
        """DestroyInfrastructure async."""
        auth0 = self.getAuth([0])
        infId = IM.CreateInfrastructure("", auth0)
        inf = IM.get_infrastructure(infId, auth0)
        inf.destroy_vms = Mock(side_effect=self.sleep_5)
        IM.DestroyInfrastructure(infId, auth0, False, True)
        self.assertEqual(inf.deleted, False)
        state = IM.GetInfrastructureState(infId, auth0)
        self.assertEqual(state["state"], VirtualMachine.DELETING)
        time.sleep(10)
        self.assertEqual(inf.deleted, True)

    def test_boot_modes(self):
        """Test boot modes."""
        auth0 = self.getAuth([0], [], [("Dummy", 0), ("Dummy", 1)])
        infId = IM.CreateInfrastructure('', auth0)

        Config.BOOT_MODE = 1
        with self.assertRaises(DisabledFunctionException):
            IM.DestroyInfrastructure(infId, auth0)
        with self.assertRaises(DisabledFunctionException):
            IM.CreateInfrastructure('', auth0)
        IM.GetInfrastructureList(auth0)

        Config.BOOT_MODE = 2
        with self.assertRaises(DisabledFunctionException):
            IM.CreateInfrastructure('', auth0)
        IM.DestroyInfrastructure(infId, auth0)
        IM.GetInfrastructureList(auth0)

        Config.BOOT_MODE = 0

    @patch('IM.InfrastructureManager.FedcloudInfo')
    def test_get_cloud_info(self, appdbis):
        auth = self.getAuth([0], [], [("Dummy", 0), ("Dummy", 1)])
        res = IM.GetCloudImageList("cloud1", auth)

        self.assertEqual(res, [{'name': 'Image Name1', 'uri': 'mock0://linux.for.ev.er/image1'},
                               {'name': 'Image Name2', 'uri': 'mock0://linux.for.ev.er/image2'}])
        res = IM.GetCloudQuotas("cloud0", auth)
        self.assertEqual(res, {"cores": {"used": 1, "limit": 10},
                               "ram": {"used": 1, "limit": 10},
                               "instances": {"used": 1, "limit": 10},
                               "floating_ips": {"used": 1, "limit": 10},
                               "security_groups": {"used": 1, "limit": 10}})

        with self.assertRaises(Exception):
            IM.GetCloudQuotas("cloud2", auth)

        auth = Authentication([{'id': 'im', 'type': 'InfrastructureManager', 'username': 'user', 'password': 'pass'},
                               {'id': 'app', 'type': 'AppDBIS', 'token': 'atoken'}])

        appdbis.list_images.return_value = [{'uri': 'ost://site/imageid', 'name': 'Image Name'}]

        res = IM.GetCloudImageList("app", auth, {"distribution": "Ubuntu", "version": "20.04"})
        self.assertEqual(res, [{'uri': 'ost://site/imageid', 'name': 'Image Name'}])
        self.assertEqual(appdbis.list_images.call_args_list[0][0][0],
                         {'distribution': 'Ubuntu', 'version': '20.04'})

    @patch('IM.InfrastructureManager.VMRC')
    @patch('IM.InfrastructureManager.FedcloudInfo')
    def test_systems_with_iis(self, egiis, vmrc):
        auth = self.getAuth([0], [0])
        auth.auth_list.append({"type": "EGIIS", "host": "https://is.cloud.egi.eu"})
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.os.name", "=", "linux"),
                               Feature("disk.0.os.flavour", "=", "ubuntu"),
                               Feature("disk.0.os.version", "=", "18.04")]))
        radl.add(deploy("s0", 1))
        inf = InfrastructureInfo()
        inf.id = "1"

        sys_egi = system("s0", [Feature("disk.0.os.name", "=", "linux"),
                                Feature("disk.0.os.flavour", "=", "ubuntu"),
                                Feature("disk.0.os.version", "=", "18.04"),
                                Feature("disk.0.image.url", "=", "https://fedcloud.eu"),
                                Feature("disk.0.image.vo", "=", "fedcloud.egi.eu")])

        egiis.search_vm.return_value = [sys_egi]

        sys_vmrc = system("s0", [Feature("disk.0.os.name", "=", "linux"),
                                 Feature("disk.0.os.flavour", "=", "ubuntu"),
                                 Feature("disk.0.os.version", "=", "18.04"),
                                 Feature("disk.0.image.url", "=", "one://server.com/1"),
                                 Feature("disk.0.os.credentials.password", "=", "pass"),
                                 Feature("disk.0.os.credentials.username", "=", "user")])

        vmrc_mock = MagicMock()
        vmrc.return_value = vmrc_mock
        vmrc_mock.search_vm.return_value = [sys_vmrc]

        res = IM.systems_with_iis(inf, radl, auth)

        self.assertEqual(len(res['s0']), 2)
        self.assertEqual(res['s0'][0].getValue("disk.0.image.url"), "one://server.com/1")
        self.assertEqual(res['s0'][0].getValue("disk.0.os.credentials.password"), "pass")
        self.assertEqual(res['s0'][0].getValue("disk.0.os.credentials.username"), "user")

        self.assertEqual(res['s0'][1].getValue("disk.0.image.url"), "https://fedcloud.eu")
        self.assertEqual(res['s0'][1].getValue("disk.0.image.vo"), "fedcloud.egi.eu")

    @patch('IM.InfrastructureManager.VaultCredentials')
    def test_get_auth_from_vault(self, vault):
        vault_mock = MagicMock()
        vault_mock.get_creds.return_value = [{'id': 'cloud1', 'type': 'OpenNebula', 'username': 'user',
                                              'password': 'pass'}]
        vault.return_value = vault_mock
        auth = Authentication([{'type': 'Vault', 'host': 'http://vault.com:8200/', 'token': 'atoken'},
                               {'type': 'InfrastructureManager', 'token': 'atoken'}])
        res = IM.get_auth_from_vault(auth)
        self.assertIn({'id': 'cloud1', 'type': 'OpenNebula', 'username': 'user', 'password': 'pass'}, res.auth_list)
        self.assertIn({'type': 'InfrastructureManager', 'token': 'atoken'}, res.auth_list)

    def test_change_inf_auth(self):
        """Try to access not owned Infs."""
        auth0, auth1, auth2 = self.getAuth([0]), self.getAuth([1]), self.getAuth([2])
        infId0 = IM.CreateInfrastructure("", auth0)
        users = IM.GetInfrastructureOwners(infId0, auth0)
        self.assertEqual(users, ['user0'])
        # Test append auth
        IM.ChangeInfrastructureAuth(infId0, auth1, False, auth0)
        IM.GetInfrastructureInfo(infId0, auth1)
        IM.GetInfrastructureInfo(infId0, auth0)
        with self.assertRaises(Exception) as ex:
            IM.GetInfrastructureInfo(infId0, auth2)
        self.assertEqual(str(ex.exception), "Access to this infrastructure not granted.")
        users = IM.GetInfrastructureOwners(infId0, auth0)
        self.assertEqual(users, ['user0', 'user1'])
        # Test overwrite auth
        IM.ChangeInfrastructureAuth(infId0, auth1, True, auth0)
        IM.GetInfrastructureInfo(infId0, auth1)
        with self.assertRaises(Exception) as ex:
            IM.GetInfrastructureInfo(infId0, auth0)
        self.assertEqual(str(ex.exception), "Access to this infrastructure not granted.")
        users = IM.GetInfrastructureOwners(infId0, auth1)
        self.assertEqual(users, ['user1'])
        # Test with invalid auth
        with self.assertRaises(Exception) as ex:
            IM.ChangeInfrastructureAuth(infId0, auth2, True, auth0)
        self.assertEqual(str(ex.exception), "Access to this infrastructure not granted.")
        # Test with invalid new auth
        auth3 = self.getAuth([], [0])
        with self.assertRaises(Exception) as ex:
            IM.ChangeInfrastructureAuth(infId0, auth3, True, auth1)
        self.assertEqual(str(ex.exception), ("Invalid new infrastructure data provided: No credentials"
                                             " provided for the InfrastructureManager."))

    @patch("IM.connectors.Dummy.DummyCloudConnector")
    def test_search_vm(self, dummycc):
        auth = self.getAuth([0], [], [("Dummy", 0), ("Dummy", 0)])
        radl_sys = system("s0", [Feature("disk.0.os.flavour", "=", "Ubuntu"),
                                 Feature("disk.0.os.version", "=", "20.04")])
        inf = MagicMock()
        dummy = MagicMock(["list_images"])
        dummycc.return_value = dummy
        dummy.list_images.side_effect = [[{"name": "ubuntu-20.04-raw", "uri": "imageuri"}],
                                         [{"name": "ubuntu-22.04-raw", "uri": "imageuri2"},
                                          {"name": "ubuntu-20.04-raw", "uri": "imageuri3"},
                                          {"name": "ubuntu-20.04-raw", "uri": "imageuri4"}]]
        msg, res = IM.search_vm(inf, radl_sys, auth)
        self.assertEqual(msg, "")
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0].name, "s0")
        self.assertEqual(res[0].getValue("disk.0.image.url"), "imageuri")
        self.assertEqual(res[1].name, "s0")
        self.assertEqual(res[1].getValue("disk.0.image.url"), "imageuri2")

    @patch('IM.InfrastructureManager.FedcloudInfo')
    def test_translate_egi_to_ost(self, appdb):
        appdb.get_site_url.return_value = 'https://ostsite.com:5000'
        appdb.get_project_ids.return_value = {'vo_name': 'projectid'}

        auth = Authentication([{'id': 'egi', 'type': 'EGI', 'host': 'SITE_NAME', 'vo': 'vo_name', 'token': 'atoken'},
                               {'type': 'InfrastructureManager', 'token': 'atoken'}])
        res = IM.translate_egi_to_ost(auth)
        self.assertIn({'id': 'egi', 'type': 'OpenStack', 'username': 'egi.eu', 'password': 'atoken',
                       'tenant': 'openid', 'auth_version': '3.x_oidc_access_token', 'vo': 'vo_name',
                       'host': 'https://ostsite.com:5000', 'domain': 'projectid'}, res.auth_list)
        self.assertIn({'type': 'InfrastructureManager', 'token': 'atoken'}, res.auth_list)

    def test_estimate_resources(self):
        radl = """"
            network publica (outbound = 'yes')
            network privada

            system front (
            cpu.count>=2 and
            gpu.count>=1 and
            memory.size>=4g and
            net_interface.0.connection = 'publica' and
            net_interface.1.connection = 'privada' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.size = 20GB and
            disk.0.free_size >= 20GB and
            disk.0.os.name = 'linux' and
            disk.1.size=100GB and
            disk.1.device='hdb' and
            disk.1.fstype='ext4' and
            disk.1.mount_path='/mnt/disk'
            )

            system wn (
            cpu.count>=1 and
            memory.size>=2g and
            net_interface.0.connection = 'privada' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.free_size >= 10GB and
            disk.0.os.name = 'linux' and
            disk.1.size=20GB and
            disk.1.device='hdb' and
            disk.1.fstype='ext4' and
            disk.1.mount_path='/mnt/disk'
            )

            deploy front 1
            deploy wn 2
        """
        res = IM.EstimateResouces(radl, self.getAuth([0], [], [("Dummy", 0)]))
        self.assertEqual(res, {
            'cloud0': {
                'cloudType': 'Dummy',
                'cloudEndpoint': 'http://server.com:80/path',
                'compute': [{'cpuCores': 2, 'memoryInMegabytes': 4000, 'diskSizeInGigabytes': 40,
                             'publicIP': 1, "GPU": 1},
                            {'cpuCores': 1, 'memoryInMegabytes': 2000, 'diskSizeInGigabytes': 10},
                            {'cpuCores': 1, 'memoryInMegabytes': 2000, 'diskSizeInGigabytes': 10}],
                'storage': [{'sizeInGigabytes': 20},
                            {'sizeInGigabytes': 100},
                            {'sizeInGigabytes': 20},
                            {'sizeInGigabytes': 20}]
            }})

    @patch('IM.Stats.DataBase')
    @patch('IM.InfrastructureManager.InfrastructureManager.check_auth_data')
    def test_get_stats(self, check_auth_data, DataBase):
        radl = """
            system node (
            memory.size = 512M and
            cpu.count = 2
            )"""

        auth = Authentication([{'type': 'InfrastructureManager', 'token': 'atoken',
                                'username': '__OPENID__mcaballer', 'password': 'pass'}])
        check_auth_data.return_value = auth

        db = MagicMock()
        inf_data = {
            "id": "1",
            "auth": auth.serialize(),
            "creation_date": 1646655374,
            "extra_info": {"TOSCA": yaml.dump({"metadata": {"icon": "kubernetes.png"}})},
            "vm_list": [
                {"cloud": {"type": "OSCAR", "server": "sharp-elbakyan5.im.grycap.net"}, "info": radl},
                json.dumps({"cloud": '{"type": "OSCAR", "server": "sharp-elbakyan5.im.grycap.net"}', "info": radl})
            ]
        }
        db.select.return_value = [(json.dumps(inf_data), '2022-03-23', '1')]
        DataBase.return_value = db

        stats = IM.GetStats('2001-01-01', '2122-01-01', auth)
        expected_res = [{'creation_date': '2022-03-07 12:16:14',
                         'tosca_name': 'kubernetes',
                         'vm_count': 2,
                         'cpu_count': 4,
                         'memory_size': 1024,
                         'cloud_type': 'OSCAR',
                         'cloud_host': 'sharp-elbakyan5.im.grycap.net',
                         'hybrid': False,
                         'deleted': False,
                         'im_user': '__OPENID__mcaballer',
                         'inf_id': '1',
                         'last_date': '2022-03-23 00:00:00'}]
        self.assertEqual(stats, expected_res)
        db.select.assert_called_with('select data, date, id from inf_list where '
                                     '((auth like \'%%"__OPENID__mcaballer"%%\')) order by rowid desc')

        auth = Authentication([{'type': 'InfrastructureManager', 'token': 'atoken',
                                'username': 'micafer', 'password': 'pass'}])
        check_auth_data.return_value = auth
        stats = IM.GetStats('2001-01-01', '2122-01-01', auth)
        self.assertEqual(db.select.call_args_list[1][0][0],
                         ('select data, date, id from inf_list where '
                          '((auth like \'%%"micafer"%%\' and auth like \'%%"pass"%%\')) '
                          'order by rowid desc'))

        db.find.return_value = [{'data': json.dumps(inf_data),
                                 'date': datetime.strptime('2022-03-23', "%Y-%m-%d"),
                                 'id': '1'}]
        DataBase.MONGO = "MONGO"
        db.db_type = "MONGO"
        stats = IM.GetStats('2001-01-01', '2122-01-01', auth)
        db.find.assert_called_with('inf_list',
                                   {
                                       '$or': [{'auth': {'$elemMatch': {'username': 'micafer', 'password': 'pass'}}}],
                                       'data.creation_date': {'$gte': 978307200.0, '$lte': 4796668800.0}
                                   },
                                   {'id': True, 'data': True, 'date': True}, [('id', -1)])


if __name__ == "__main__":
    unittest.main()
