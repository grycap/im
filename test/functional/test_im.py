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

from mock import Mock

sys.path.append("..")
sys.path.append(".")

from IM.config import Config
# To load the ThreadPool class
Config.MAX_SIMULTANEOUS_LAUNCHES = 2

from IM.VirtualMachine import VirtualMachine
from IM.InfrastructureManager import InfrastructureManager as IM
from IM.InfrastructureList import InfrastructureList
from IM.auth import Authentication
from radl.radl import RADL, system, deploy, Feature
from IM.CloudInfo import CloudInfo
from IM.connectors.CloudConnector import CloudConnector
from IM.SSH import SSH


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestIM(unittest.TestCase):

    def __init__(self, *args):
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

    def test_inf_lifecycle(self):
        """Test Infrastructure lifecycle"""
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
        Config.CONFMAMAGER_CHECK_STATE_INTERVAL = 0.001
        cloud0 = self.get_cloud_connector_mock("MyMock")
        self.register_cloudconnector("Mock", cloud0)

        infId = IM.CreateInfrastructure(str(radl), auth0)

        time.sleep(15)

        state = IM.GetInfrastructureState(infId, auth0)
        self.assertEqual(state["state"], "unconfigured")

        InfrastructureList.infrastructure_list[infId].ansible_configured = True

        IM.Reconfigure(infId, "", auth0)

        time.sleep(2)

        state = IM.GetInfrastructureState(infId, auth0)
        self.assertEqual(state["state"], "running")

        add_radl = RADL()
        add_radl.add(system("s0", [Feature("disk.0.image.url", "=", "mock0://linux.for.ev.er"),
                                   Feature("disk.0.os.credentials.username", "=", "user"),
                                   Feature("disk.0.os.credentials.password", "=", "pass")]))
        add_radl.add(deploy("s0", 1))

        vms = IM.AddResource(infId, str(add_radl), auth0)
        self.assertEqual(vms, [1])

        state = IM.GetVMProperty(infId, "1", "state", auth0)
        self.assertEqual(state, "running")

        contmsg = IM.GetVMContMsg(infId, "1", auth0)
        self.assertEqual(contmsg, "")

        cont = IM.RemoveResource(infId, ['1'], auth0)
        self.assertEqual(cont, 1)

        IM.DestroyInfrastructure(infId, auth0)

if __name__ == "__main__":
    unittest.main()
