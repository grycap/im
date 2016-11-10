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

from mock import Mock, patch, MagicMock

sys.path.append("..")
sys.path.append(".")

from IM.config import Config
# To load the ThreadPool class
Config.MAX_SIMULTANEOUS_LAUNCHES = 2

from IM.VirtualMachine import VirtualMachine
from IM.InfrastructureManager import InfrastructureManager as IM
from IM.auth import Authentication
from radl.radl import RADL, system, deploy, Feature, SoftFeatures
from radl.radl_parse import parse_radl
from IM.CloudInfo import CloudInfo
from IM.connectors.CloudConnector import CloudConnector
from IM.SSH import SSH
from IM.InfrastructureInfo import InfrastructureInfo
from IM.tosca.Tosca import Tosca


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestIM(unittest.TestCase):

    def __init__(self, *args):
        unittest.TestCase.__init__(self, *args)

    def setUp(self):

        IM._reinit()
        # Patch save_data
        IM.save_data = staticmethod(lambda *args: None)

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

    def register_cloudconnector(self, name, cloud_connector):
        sys.modules['IM.connectors.' + name] = type('MyConnector', (object,),
                                                    {name + 'CloudConnector': cloud_connector})

    def get_dummy_ssh(self, retry=False):
        ssh = SSH("", "", "")
        ssh.test_connectivity = Mock(return_value=True)
        ssh.execute = Mock(return_value=("10", "", 0))
        ssh.sftp_put_files = Mock(return_value=True)
        ssh.sftp_mkdir = Mock(return_value=True)
        ssh.sftp_put_dir = Mock(return_value=True)
        ssh.sftp_put = Mock(return_value=True)
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

    def get_cloud_connector_mock(self, name="MyMock0"):
        cloud = type(name, (CloudConnector, object), {})
        cloud.launch = Mock(side_effect=self.gen_launch_res)
        return cloud

    def test_inf_creation0(self):
        """Create infrastructure with empty RADL."""

        auth0 = self.getAuth([0])
        infId = IM.CreateInfrastructure("", auth0)
        IM.DestroyInfrastructure(infId, auth0)

    def test_inf_creation1(self):
        """Create infrastructure with empty RADL."""

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

    def test_inf_auth(self):
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
        IM.DestroyInfrastructure(infId0, auth0)
        IM.DestroyInfrastructure(infId1, auth1)

    def test_inf_addresources_without_credentials(self):
        """Deploy single virtual machine without credentials to check that it raises the correct exception."""

        radl = RADL()
        radl.add(
            system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er")]))
        radl.add(deploy("s0", 1))

        auth0 = self.getAuth([0], [], [("Dummy", 0)])
        infId = IM.CreateInfrastructure("", auth0)

        with self.assertRaises(Exception) as ex:
            IM.AddResource(infId, str(radl), auth0)

        self.assertIn("No username", ex.exception.message)

        IM.DestroyInfrastructure(infId, auth0)

    def test_inf_auth_with_userdb(self):
        """Test access im with user db"""

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
        Config.MAX_SIMULTANEOUS_LAUNCHES = n / 2  # Test the pool
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

    def test_inf_addresources3(self):
        """Test cloud selection."""

        n0, n1 = 2, 5  # Machines to deploy
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               SoftFeatures(
                                   10, [Feature("memory.size", "<=", 500)]),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(system("s1", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               SoftFeatures(
                                   10, [Feature("memory.size", ">=", 800)]),
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

    def test_inf_cloud_order(self):
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

        auth0 = self.getAuth([0])
        infId = IM.CreateInfrastructure("", auth0)
        inf_ids = IM.GetInfrastructureList(auth0)
        self.assertEqual(inf_ids, [infId])
        IM.DestroyInfrastructure(infId, auth0)

    def test_reconfigure(self):
        """Reconfigure."""
        radl = RADL()
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s0", 1))

        auth0 = self.getAuth([0], [], [("Dummy", 0)])
        infId = IM.CreateInfrastructure(str(radl), auth0)

        reconf_radl = """configure test (\n@begin\n---\n  - tasks:\n      - debug: msg="RECONFIGURERADL"\n@end\n)"""
        IM.Reconfigure(infId, reconf_radl, auth0)
        IM.Reconfigure(infId, reconf_radl, auth0, ['0'])

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

        state = IM.GetVMProperty(infId, "0", "state", auth0)
        self.assertEqual(state, "running")

        contmsg = IM.GetVMContMsg(infId, "0", auth0)
        self.assertEqual(contmsg, "")

        contmsg = IM.GetInfrastructureContMsg(infId, auth0)

        state = IM.GetInfrastructureState(infId, auth0)
        self.assertEqual(state["state"], "running")
        self.assertEqual(state["vm_states"]["0"], "running")

        radl_info = IM.GetInfrastructureRADL(infId, auth0)
        parsed_radl_info = parse_radl(str(radl_info))
        self.assertEqual(parsed_radl_info.systems[0].getValue("disk.0.os.credentials.username"), "user")

        IM.DestroyInfrastructure(infId, auth0)

    def test_get_inf_state(self):
        """
        Test GetInfrastructureState.
        """
        auth0 = self.getAuth([0], [], [("Dummy", 0)])

        inf = MagicMock()
        IM.infrastructure_list = {"1": inf}
        inf.id = "1"
        inf.auth = auth0
        inf.deleted = False
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

    def test_altervm(self):
        """Test AlterVM"""
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
        radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                               Feature("disk.0.os.credentials.username", "=", "user"),
                               Feature("cpu.count", "=", 2),
                               Feature("memory.size", "=", 1024, "M"),
                               Feature("disk.0.os.credentials.password", "=", "pass")]))
        radl.add(deploy("s0", 1))

        radl_info = IM.AlterVM(infId, "0", str(radl), auth0)
        parsed_radl_info = parse_radl(str(radl_info))
        self.assertEqual(parsed_radl_info.systems[0].getValue("cpu.count"), 2)
        self.assertEqual(parsed_radl_info.systems[0].getFeature('memory.size').getValue('M'), 1024)

        IM.DestroyInfrastructure(infId, auth0)

    def test_start_stop(self):
        """Test Start and Stop operations"""
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

        IM.DestroyInfrastructure(infId, auth0)

    def test_export_import(self):
        """Test ExportInfrastructure and ImportInfrastructure operations"""
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

    def test_contextualize(self):
        """Test Contextualization process"""
        radl = """"
            network publica (outbound = 'yes')

            system front (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'publica' and
            net_interface.0.ip = '10.0.0.1' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'yoyoyo' and
            disk.0.os.name = 'linux' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.fstype='ext4' and
            disk.1.mount_path='/mnt/disk' and
            disk.0.applications contains (name = 'ansible.modules.micafer.hadoop') and
            disk.0.applications contains (name='gmetad') and
            disk.0.applications contains (name='wget')
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

        time.sleep(15)

        state = IM.GetInfrastructureState(infId, auth0)
        self.assertEqual(state["state"], "unconfigured")

        IM.infrastructure_list[infId].ansible_configured = True
        IM.infrastructure_list[infId].vm_list[0].get_ctxt_log = MagicMock()
        IM.infrastructure_list[infId].vm_list[0].get_ctxt_log.return_value = "OK"

        IM.Reconfigure(infId, "", auth0)

        time.sleep(5)

        state = IM.GetInfrastructureState(infId, auth0)
        self.assertEqual(state["state"], "running")

        contmsg = IM.GetInfrastructureContMsg(infId, auth0)
        self.assertGreater(len(contmsg), 150)

        IM.DestroyInfrastructure(infId, auth0)

    def test_tosca_to_radl(self):
        """Test TOSCA RADL translation"""
        tosca_data = read_file_as_string('../files/tosca_long.yml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        parse_radl(str(radl))

    def test_tosca_get_outputs(self):
        """Test TOSCA get_outputs function"""
        tosca_data = read_file_as_string('../files/tosca_create.yml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        radl.systems[0].setValue("net_interface.0.ip", "158.42.1.1")
        radl.systems[0].setValue("disk.0.os.credentials.username", "ubuntu")
        radl.systems[0].setValue("disk.0.os.credentials.password", "pass")
        inf = InfrastructureInfo()
        vm = VirtualMachine(inf, "1", None, radl, radl, None)
        vm.requested_radl = radl
        inf.vm_list = [vm]
        outputs = tosca.get_outputs(inf)
        self.assertEqual(outputs, {'server_url': ['158.42.1.1'],
                                   'server_creds': {'token_type': 'password',
                                                    'token': 'pass',
                                                    'user': 'ubuntu'}})

    @patch('httplib.HTTPSConnection')
    def test_check_oidc_token(self, connection):
        im_auth = {"token": ("eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkYzVkNWFiNy02ZGI5LTQwNzktOTg1Yy04MGF"
                             "jMDUwMTcwNjYiLCJpc3MiOiJodHRwczpcL1wvaWFtLXRlc3QuaW5kaWdvLWRhdGFjbG91ZC5ldVwvIiwiZXhwI"
                             "joxNDY1NDcxMzU0LCJpYXQiOjE0NjU0Njc3NTUsImp0aSI6IjA3YjlkYmE4LTc3NWMtNGI5OS1iN2QzLTk4Njg"
                             "5ODM1N2FiYSJ9.DwpZizVaYtvIj7fagQqDFpDh96szFupf6BNMIVLcopqQtZ9dBvwN9lgZ_w7Htvb3r-erho_hc"
                             "me5mqDMVbSKwsA2GiHfiXSnh9jmNNVaVjcvSPNVGF8jkKNxeSSgoT3wED8xt4oU4s5MYiR075-RAkt6AcWqVbXU"
                             "z5BzxBvANko")}

        user_info = read_file_as_string('../files/iam_user_info.json')

        conn = MagicMock()
        connection.return_value = conn

        resp = MagicMock()
        resp.status = 200
        resp.read.return_value = user_info
        conn.getresponse.return_value = resp

        IM.check_oidc_token(im_auth)

        self.assertEqual(im_auth['username'], "micafer")
        self.assertEqual(im_auth['password'], "https://iam-test.indigo-datacloud.eu/sub")
        
        Config.OIDC_ISSUERS = ["https://other_issuer"]
        
        with self.assertRaises(Exception) as ex:
            IM.check_oidc_token(im_auth)
        self.assertEqual(str(ex.exception),
                         ("Error trying to validate OIDC auth token: Invalid "
                          "InfrastructureManager credentials. Issuer not accepted."))

    @patch('IM.InfrastructureManager.DataBase.connect')
    @patch('IM.InfrastructureManager.DataBase.table_exists')
    @patch('IM.InfrastructureManager.DataBase.select')
    @patch('IM.InfrastructureManager.DataBase.execute')
    def test_db(self, execute, select, table_exists, connect):

        table_exists.return_value = True
        select.return_value = [["1", "", read_file_as_string("../files/data.pkl")]]
        execute.return_value = True

        res = IM.get_data_from_db("mysql://username:password@server/db_name")
        self.assertEqual(len(res), 1)

        inf = InfrastructureInfo()
        inf.id = "1"
        success = IM.save_data_to_db("mysql://username:password@server/db_name", {"1": inf})
        self.assertTrue(success)

if __name__ == "__main__":
    unittest.main()
