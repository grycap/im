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

import unittest
import xmlrpclib
import time

from IM.auth import Authentication
from IM.VirtualMachine import VirtualMachine
from IM.radl import radl_parse

RADL_ADD = "network publica\nnetwork privada\nsystem wn\ndeploy wn 1 one"
RADL_ADD_ERROR = "system wnno deploy wnno 1"
TESTS_PATH = '/home/micafer/codigo/git_im/im/test'
RADL_FILE = TESTS_PATH + '/test.radl'
#RADL_FILE =  TESTS_PATH + '/test_ec2.radl'
AUTH_FILE = TESTS_PATH + '/auth.dat'
HOSTNAME = "localhost"
TEST_PORT = 8899

class TestIM(unittest.TestCase):

    server = None
    auth_data = None
    inf_id = 0

    @classmethod
    def setUpClass(cls):
        cls.server = xmlrpclib.ServerProxy("http://" + HOSTNAME + ":" + str(TEST_PORT),allow_none=True)
        cls.auth_data = Authentication.read_auth_data(AUTH_FILE)
        cls.inf_id = 0

    @classmethod
    def tearDownClass(cls):
        # Assure that the infrastructure is destroyed
        try:
            cls.server.DestroyInfrastructure(cls.inf_id, cls.auth_data)
        except Exception:
            pass

    def wait_inf_state(self, state, timeout, incorrect_states = []):
        """
        Wait for an infrastructure to have a specific state
        """
        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR calling the GetInfrastructureInfo function:" + str(res))
        self.assertEqual(len(res), 2, msg="ERROR calling the GetInfrastructureInfo function: Incorrect number of VMs(" + str(len(res)) + ") deberia ser 2")

        vm_ids = res['vm_list']

        err_states = [VirtualMachine.FAILED, VirtualMachine.OFF]
        err_states.extend(incorrect_states)

        wait = 0
        all_ok = False
        while not all_ok and wait < timeout:
            all_ok = True
            for vm_id in vm_ids:
                (success, vm_state)  = self.server.GetVMProperty(self.inf_id, vm_id, "state", self.auth_data)
                self.assertTrue(success, msg="ERROR getting VM info:" + str(res))

                self.assertFalse(vm_state in err_states, msg="ERROR waiting for a state. '" + vm_state + "' was obtained in the VM: " + str(vm_id) + " err_states = " + str(err_states))
                
                if vm_state in err_states:
                    return False
                elif vm_state != state:
                    all_ok = False

            if not all_ok:
                wait += 5
                time.sleep(5)

        return all_ok

    def test_10_list(self):
        """
        Test the GetInfrastructureList IM function
        """
        (success, res) = self.server.GetInfrastructureList(self.auth_data)
        self.assertTrue(success, msg="ERROR calling GetInfrastructureList: " + str(res))

    def test_11_create(self):
        """
        Test the CreateInfrastructure IM function
        """
        f = open(RADL_FILE)
        radl = ""
        for line in f.readlines():
            radl += line
        f.close()

        (success, inf_id) = self.server.CreateInfrastructure(radl, self.auth_data)
        self.assertTrue(success, msg="ERROR calling CreateInfrastructure: " + str(inf_id))
        self.__class__.inf_id = inf_id

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 900)
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_13_getcontmsg(self):
        """
        Test the GetInfrastructureInfo IM function
        """
        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR calling GetInfrastructureInfo: " + str(res))
        cont_out = res['cont_out']
        self.assertGreater(len(cont_out), 100, msg="Incorrect contextualization message: " + cont_out)

    def test_14_get_vm_info(self):
        """
        Test the GetVMInfo IM function
        """
        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR calling GetInfrastructureInfo: " + str(res))
        vm_ids = res['vm_list']
        (success, info)  = self.server.GetVMInfo(self.inf_id, vm_ids[0], self.auth_data)
        self.assertTrue(success, msg="ERROR calling GetVMInfo: " + str(info))
        try:
            radl_parse.parse_radl(info)
        except Exception, ex:
            self.assertTrue(False, msg="ERROR parsing the RADL returned by GetVMInfo: " + str(ex))       
            
    def test_15_get_vm_property(self):
        """
        Test the GetVMProperty IM function
        """
        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR calling GetInfrastructureInfo: " + str(res))
        vm_ids = res['vm_list']
        (success, info)  = self.server.GetVMProperty(self.inf_id, vm_ids[0], "state", self.auth_data)
        self.assertTrue(success, msg="ERROR calling GetVMProperty: " + str(info))
        self.assertNotEqual(info, None, msg="ERROR in the value returned by GetVMProperty: " + info)
        self.assertNotEqual(info, "", msg="ERROR in the value returned by GetVMPropert: " + info)    

    def test_16_get_ganglia_info(self):
        """
        Test the Ganglia IM information integration
        """
        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR calling GetInfrastructureInfo: " + str(res))
        vm_ids = res['vm_list']
        (success, info)  = self.server.GetVMInfo(self.inf_id, vm_ids[1], self.auth_data)
        self.assertTrue(success, msg="ERROR calling GetVMInfo: " + str(info))
        info_radl = radl_parse.parse_radl(info)
        prop_usage = info_radl.systems[0].getValue("cpu.usage")
        self.assertIsNotNone(prop_usage, msg="ERROR getting ganglia VM info (cpu.usage = None) of VM " + str(vm_ids[1]))

    def test_17_error_addresource(self):
        """
        Test to get error when adding a resource with an incorrect RADL
        """
        (success, res) = self.server.AddResource(self.inf_id, RADL_ADD_ERROR, self.auth_data)
        self.assertFalse(success, msg="Incorrect RADL in AddResource not returned error")
        pos = res.find("Unknown reference in RADL")
        self.assertGreater(pos, -1, msg="Incorrect RADL in AddResource not returned the expected error: " + res)

    def test_18_addresource(self):
        """
        Test AddResource function
        """
        (success, res) = self.server.AddResource(self.inf_id, RADL_ADD, self.auth_data)
        self.assertTrue(success, msg="ERROR calling AddResource: " + str(res))

        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR calling GetInfrastructureInfo:" + str(res))
        vm_ids = res['vm_list']
        self.assertEqual(len(vm_ids), 3, msg="ERROR getting infrastructure info: Incorrect number of VMs(" + str(len(vm_ids)) + "). It must be 3")

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 900)
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_19_removeresource(self):
        """
        Test RemoveResource function
        """
        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR calling GetInfrastructureInfo: " + str(res))
        vm_ids = res['vm_list']

        (success, res) = self.server.RemoveResource(self.inf_id, vm_ids[2], self.auth_data)
        self.assertTrue(success, msg="ERROR calling RemoveResource: " + str(res))

        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR calling GetInfrastructureInfo:" + str(res))
        vm_ids = res['vm_list']
        self.assertEqual(len(vm_ids), 2, msg="ERROR getting infrastructure info: Incorrect number of VMs(" + str(len(vm_ids)) + "). It must be 2")

        (success, vm_state)  = self.server.GetVMProperty(self.inf_id, vm_ids[0], "state", self.auth_data)
        self.assertTrue(success, msg="ERROR getting VM state:" + str(res))
        self.assertEqual(vm_state, VirtualMachine.RUNNING, msg="ERROR unexpected state. Expected 'running' and obtained " + vm_state)

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_20_stop(self):
        """
        Test StopInfrastructure function
        """
        (success, res) = self.server.StopInfrastructure(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR calling StopInfrastructure: " + str(res))

        all_stopped = self.wait_inf_state(VirtualMachine.STOPPED, 120, [VirtualMachine.RUNNING])
        self.assertTrue(all_stopped, msg="ERROR waiting the infrastructure to be stopped (timeout).")

    def test_21_start(self):
        """
        Test StartInfrastructure function
        """
        (success, res) = self.server.StartInfrastructure(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR calling StartInfrastructure: " + str(res))

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 120, [VirtualMachine.RUNNING])
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be started (timeout).")

    def test_50_destroy(self):
        """
        Test DestroyInfrastructure function
        """
        (success, res) = self.server.DestroyInfrastructure(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR calling DestroyInfrastructure: " + str(res))

if __name__ == '__main__':
    unittest.main()
