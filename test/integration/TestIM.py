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
import sys
import os

sys.path.append("..")
sys.path.append(".")

from IM.auth import Authentication
from IM.VirtualMachine import VirtualMachine
from radl import radl_parse
from IM import __version__ as version

RADL_ADD_WIN = "network publica\nnetwork privada\nsystem windows\ndeploy windows 1 one"
RADL_ADD = "network publica\nnetwork privada\nsystem wn\ndeploy wn 1 one"
RADL_ADD_ERROR = "system wnno deploy wnno 1"
HOSTNAME = "localhost"
TEST_PORT = 8899


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestIM(unittest.TestCase):

    server = None
    auth_data = None
    inf_id = None

    @classmethod
    def setUpClass(cls):
        cls.server = xmlrpclib.ServerProxy(
            "http://" + HOSTNAME + ":" + str(TEST_PORT), allow_none=True)
        tests_path = os.path.dirname(os.path.realpath(__file__))
        auth_file = tests_path + '/../auth.dat'
        cls.auth_data = Authentication.read_auth_data(auth_file)

    @classmethod
    def tearDownClass(cls):
        # Assure that the infrastructure is destroyed
        try:
            if cls.inf_id:
                if isinstance(cls.inf_id, list):
                    for inf_id in cls.inf_id:
                        cls.server.DestroyInfrastructure(inf_id, cls.auth_data)
                else:
                    cls.server.DestroyInfrastructure(cls.inf_id, cls.auth_data)
        except Exception:
            pass

    def wait_inf_state(self, inf_id, state, timeout, incorrect_states=None, vm_ids=None):
        """
        Wait for an infrastructure to have a specific state
        """
        if not vm_ids:
            (success, vm_ids) = self.server.GetInfrastructureInfo(inf_id, self.auth_data)
            self.assertTrue(
                success, msg="ERROR calling the GetInfrastructureInfo function:" + str(vm_ids))

        err_states = [VirtualMachine.FAILED, VirtualMachine.UNCONFIGURED]
        if incorrect_states:
            err_states.extend(incorrect_states)

        wait = 0
        all_ok = False
        while not all_ok and wait < timeout:
            all_ok = True
            for vm_id in vm_ids:
                (success, vm_state) = self.server.GetVMProperty(inf_id, vm_id, "state", self.auth_data)
                self.assertTrue(success, msg="ERROR getting VM info:" + str(vm_state))

                if vm_state == VirtualMachine.UNCONFIGURED:
                    _, cont_msg = self.server.GetVMContMsg(inf_id, vm_id, self.auth_data)
                    print(cont_msg)

                self.assertFalse(vm_state in err_states, msg="ERROR waiting for a state. '" + vm_state +
                                 "' was obtained in the VM: " + str(vm_id) + " err_states = " + str(err_states))

                if vm_state in err_states:
                    return False
                elif vm_state != state:
                    all_ok = False

            if not all_ok:
                wait += 5
                if wait >= timeout:
                    _, cont_msg = self.server.GetInfrastructureContMsg(inf_id, self.auth_data)
                    print(cont_msg)
                else:
                    time.sleep(5)

        return all_ok

    def test_05_getversion(self):
        """
        Test the GetVersion IM function
        """
        (success, res) = self.server.GetVersion()
        self.assertTrue(success, msg="ERROR calling GetVersion: " + str(res))
        self.assertEqual(
            res, version, msg="Incorrect version. Expected %s, obtained: %s" % (version, res))

    def test_10_list(self):
        """
        Test the GetInfrastructureList IM function
        """
        (success, res) = self.server.GetInfrastructureList(self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureList: " + str(res))
        (success, res) = self.server.GetInfrastructureList(self.auth_data, "*.")
        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureList: " + str(res))

    def test_11_create(self):
        """
        Test the CreateInfrastructure IM function
        """
        radl = read_file_as_string("../files/test.radl")

        (success, inf_id) = self.server.CreateInfrastructure(radl, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling CreateInfrastructure: " + str(inf_id))
        self.__class__.inf_id = inf_id

        all_configured = self.wait_inf_state(
            inf_id, VirtualMachine.CONFIGURED, 900)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_12_getradl(self):
        """
        Test the GetInfrastructureRADL IM function
        """
        (success, res) = self.server.GetInfrastructureRADL(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureRADL: " + str(res))
        try:
            radl_parse.parse_radl(res)
        except Exception as ex:
            self.assertTrue(
                False, msg="ERROR parsing the RADL returned by GetInfrastructureRADL: " + str(ex))

    def test_13_getcontmsg(self):
        """
        Test the GetInfrastructureContMsg IM function
        """
        (success, cont_out) = self.server.GetInfrastructureContMsg(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR calling GetInfrastructureContMsg: " + str(cont_out))
        self.assertGreater(len(cont_out), 100, msg="Incorrect contextualization message: " + cont_out)
        self.assertIn("Select master VM", cont_out)
        self.assertIn("NODENAME = front", cont_out)
        # Check vault task
        self.assertIn("VAULTOK", cont_out)

        (success, cont_out) = self.server.GetInfrastructureContMsg(self.inf_id, self.auth_data, True)
        self.assertTrue(success, msg="ERROR calling GetInfrastructureContMsg: " + str(cont_out))
        self.assertGreater(len(cont_out), 100, msg="Incorrect contextualization message: " + cont_out)
        self.assertIn("Select master VM", cont_out)
        self.assertNotIn("NODENAME = front", cont_out)

    def test_14_getvmcontmsg(self):
        """
        Test the GetVMContMsg IM function
        """
        (success, res) = self.server.GetVMContMsg(
            self.inf_id, 0, self.auth_data)
        self.assertTrue(success, msg="ERROR calling GetVMContMsg: " + str(res))
        self.assertGreater(
            len(res), 100, msg="Incorrect VM contextualization message: " + res)

    def test_15_get_vm_info(self):
        """
        Test the GetVMInfo IM function
        """
        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureInfo: " + str(vm_ids))
        (success, info) = self.server.GetVMInfo(
            self.inf_id, vm_ids[0], self.auth_data)
        self.assertTrue(success, msg="ERROR calling GetVMInfo: " + str(info))
        try:
            radl_parse.parse_radl(info)
        except Exception as ex:
            self.assertTrue(
                False, msg="ERROR parsing the RADL returned by GetVMInfo: " + str(ex))

    def test_16_get_vm_property(self):
        """
        Test the GetVMProperty IM function
        """
        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureInfo: " + str(vm_ids))
        (success, info) = self.server.GetVMProperty(
            self.inf_id, vm_ids[0], "state", self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling GetVMProperty: " + str(info))
        self.assertNotEqual(
            info, None, msg="ERROR in the value returned by GetVMProperty: " + info)
        self.assertNotEqual(
            info, "", msg="ERROR in the value returned by GetVMPropert: " + info)

    def test_17_create_snapshot(self):
        """
        Test CreateDiskSnapshot function
        """
        (success, res) = self.server.CreateDiskSnapshot(self.inf_id, "0", 0,
                                                        "im-test-image", True,
                                                        self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling CreateDiskSnapshot: " + str(res))

    def test_18_error_addresource(self):
        """
        Test to get error when adding a resource with an incorrect RADL
        """
        (success, res) = self.server.AddResource(
            self.inf_id, RADL_ADD_ERROR, self.auth_data)
        self.assertFalse(
            success, msg="Incorrect RADL in AddResource not returned error")
        pos = res.find("Unknown reference in RADL")
        self.assertGreater(
            pos, -1, msg="Incorrect RADL in AddResource not returned the expected error: " + res)

    def test_19_addresource(self):
        """
        Test AddResource function
        """
        (success, res) = self.server.AddResource(
            self.inf_id, RADL_ADD_WIN, self.auth_data)
        self.assertTrue(success, msg="ERROR calling AddResource: " + str(res))

        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureInfo:" + str(vm_ids))
        self.assertEqual(len(vm_ids), 4, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 4"))

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 900)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_20_getstate(self):
        """
        Test the GetInfrastructureState IM function
        """
        (success, res) = self.server.GetInfrastructureState(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureState: " + str(res))
        state = res['state']
        self.assertEqual(state, "configured", msg="Unexpected inf state: " +
                         state + ". It must be 'configured'.")
        vm_states = res['vm_states']
        self.assertEqual(len(vm_states), 4, msg="ERROR getting infrastructure state: Incorrect number of VMs(" +
                         str(len(vm_states)) + "). It must be 4")
        for vm_id, vm_state in vm_states.items():
            self.assertEqual(vm_state, "configured", msg="Unexpected vm state: " +
                             vm_state + " in VM ID " + str(vm_id) + ". It must be 'configured'.")

    def test_21_addresource_noconfig(self):
        """
        Test AddResource function with the contex option to False
        """
        (success, res) = self.server.AddResource(
            self.inf_id, RADL_ADD, self.auth_data, False)
        self.assertTrue(success, msg="ERROR calling AddResource: " + str(res))

        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureInfo:" + str(vm_ids))
        self.assertEqual(len(vm_ids), 5, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 5"))

    def test_22_removeresource(self):
        """
        Test RemoveResource function
        """
        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureInfo: " + str(vm_ids))

        (success, res) = self.server.RemoveResource(
            self.inf_id, vm_ids[2], self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling RemoveResource: " + str(res))

        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureInfo:" + str(vm_ids))
        self.assertEqual(len(vm_ids), 4, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 4"))

        (success, vm_state) = self.server.GetVMProperty(
            self.inf_id, vm_ids[0], "state", self.auth_data)
        self.assertTrue(success, msg="ERROR getting VM state:" + str(res))
        self.assertEqual(vm_state, VirtualMachine.RUNNING,
                         msg="ERROR unexpected state. Expected 'running' and obtained " + vm_state)

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 600)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_23_removeresource_noconfig(self):
        """
        Test RemoveResource function with the context option to False
        """
        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureInfo: " + str(vm_ids))

        (success, res) = self.server.RemoveResource(
            self.inf_id, vm_ids[2], self.auth_data, False)
        self.assertTrue(
            success, msg="ERROR calling RemoveResource: " + str(res))

        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureInfo:" + str(vm_ids))
        self.assertEqual(len(vm_ids), 3, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 3"))

        (success, vm_state) = self.server.GetVMProperty(
            self.inf_id, vm_ids[0], "state", self.auth_data)
        self.assertTrue(success, msg="ERROR getting VM state:" + str(res))
        self.assertEqual(vm_state, VirtualMachine.CONFIGURED,
                         msg="ERROR unexpected state. Expected 'running' and obtained " + vm_state)

    def test_24_reconfigure(self):
        """
        Test Reconfigure function
        """
        (success, res) = self.server.Reconfigure(
            self.inf_id, "", self.auth_data)
        self.assertTrue(success, msg="ERROR calling Reconfigure: " + str(res))

        all_stopped = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 600)
        self.assertTrue(
            all_stopped, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_25_reconfigure_vmlist(self):
        """
        Test Reconfigure function specifying a list of VMs
        """
        (success, res) = self.server.Reconfigure(
            self.inf_id, "", self.auth_data, [0])
        self.assertTrue(success, msg="ERROR calling Reconfigure: " + str(res))

        all_stopped = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 600)
        self.assertTrue(
            all_stopped, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_26_reconfigure_radl(self):
        """
        Test Reconfigure function specifying a new RADL
        """
        radl = """configure test (\n@begin\n---\n  - tasks:\n      - debug: msg="RECONFIGURERADL"\n@end\n)"""
        (success, res) = self.server.Reconfigure(
            self.inf_id, radl, self.auth_data)
        self.assertTrue(success, msg="ERROR calling Reconfigure: " + str(res))

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 600)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

        (success, cont_out) = self.server.GetInfrastructureContMsg(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureContMsg: " + str(cont_out))
        self.assertIn("RECONFIGURERADL", cont_out,
                      msg="Incorrect contextualization message: " + cont_out)

    def test_30_stop(self):
        """
        Test StopInfrastructure function
        """
        time.sleep(30)
        (success, res) = self.server.StopInfrastructure(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling StopInfrastructure: " + str(res))
        time.sleep(30)

        all_stopped = self.wait_inf_state(
            self.inf_id, VirtualMachine.STOPPED, 120, [VirtualMachine.RUNNING])
        self.assertTrue(
            all_stopped, msg="ERROR waiting the infrastructure to be stopped (timeout).")

    def test_31_start(self):
        """
        Test StartInfrastructure function
        """
        # Assure the VM to be stopped
        time.sleep(30)
        (success, res) = self.server.StartInfrastructure(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling StartInfrastructure: " + str(res))
        time.sleep(30)

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 150, [VirtualMachine.RUNNING])
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be started (timeout).")

    def test_32_stop_vm(self):
        """
        Test StopVM function
        """
        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        time.sleep(30)
        (success, res) = self.server.StopVM(self.inf_id, vm_ids[0], self.auth_data)
        self.assertTrue(success, msg="ERROR calling StopVM: " + str(res))
        time.sleep(30)

        all_stopped = self.wait_inf_state(self.inf_id, VirtualMachine.STOPPED, 120, [
                                          VirtualMachine.RUNNING], [vm_ids[0]])
        self.assertTrue(
            all_stopped, msg="ERROR waiting the vm to be stopped (timeout).")

    def test_33_start_vm(self):
        """
        Test StartVM function
        """
        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        # Assure the VM to be stopped
        time.sleep(30)
        (success, res) = self.server.StartVM(self.inf_id, vm_ids[0], self.auth_data)
        self.assertTrue(success, msg="ERROR calling StartVM: " + str(res))
        time.sleep(30)

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 150, [VirtualMachine.RUNNING], [vm_ids[0]])
        self.assertTrue(
            all_configured, msg="ERROR waiting the vm to be started (timeout).")

    def test_34_reboot_vm(self):
        """
        Test RebootVM function
        """
        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)

        (success, res) = self.server.RebootVM(self.inf_id, vm_ids[0], self.auth_data)
        self.assertTrue(success, msg="ERROR calling RebootVM: " + str(res))

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 60, [VirtualMachine.RUNNING], [vm_ids[0]])
        self.assertTrue(
            all_configured, msg="ERROR waiting the vm to be rebooted (timeout).")

    def test_40_export_import(self):
        """
        Test ExportInfrastructure and ImportInfrastructure functions
        """
        (success, res) = self.server.ExportInfrastructure(
            self.inf_id, True, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling ExportInfrastructure: " + str(res))

        (success, res) = self.server.ImportInfrastructure(res, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling ImportInfrastructure: " + str(res))

    def test_50_destroy(self):
        """
        Test DestroyInfrastructure function
        """
        (success, res) = self.server.DestroyInfrastructure(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling DestroyInfrastructure: " + str(res))

    def test_60_create_no_context(self):
        """
        Test the CreateInfrastructure IM function without context
        """
        radl = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            disk.0.os.flavour='ubuntu' and
            disk.0.os.version>='14.04'
            )

            deploy test 1

            contextualize ()
            """

        (success, inf_id) = self.server.CreateInfrastructure(radl, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling CreateInfrastructure: " + str(inf_id))
        self.__class__.inf_id = inf_id

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 300)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_65_destroy(self):
        """
        Test DestroyInfrastructure function
        """
        (success, res) = self.server.DestroyInfrastructure(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling DestroyInfrastructure: " + str(res))

    def test_70_create_cloud_init(self):
        """
        Test the CreateInfrastructure IM function with cloud init ctxt
        """
        radl = """
            network net ()

            system node (
             cpu.arch='x86_64' and
             cpu.count>=1 and
             memory.size>=512m and
             net_interface.0.connection = 'net' and
             disk.0.os.flavour='ubuntu' and
             disk.0.os.version>='14.04'
            )

            deploy node 1

            configure node (
@begin
#!/bin/bash
echo "Hello World" >> /tmp/data.txt
@end
            )

            contextualize (
              system node configure node with cloud_init
            )
            """

        radl_parse.parse_radl(radl)
        (success, inf_id) = self.server.CreateInfrastructure(radl, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling CreateInfrastructure: " + str(inf_id))
        self.__class__.inf_id = inf_id

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 300)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_75_destroy(self):
        """
        Test DestroyInfrastructure function
        """
        (success, res) = self.server.DestroyInfrastructure(
            self.inf_id, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling DestroyInfrastructure: " + str(res))

    def test_80_create_ansible_host(self):
        """
        Test the CreateInfrastructure IM function using an external ansible host
        """
        ansible_radl = """
            network publicnet (outbound = 'yes')
            network net ()

            system node (
             cpu.arch='x86_64' and
             cpu.count>=1 and
             memory.size>=512m and
             net_interface.0.connection = 'publicnet' and
             net_interface.1.connection = 'net' and
             disk.0.os.flavour='ubuntu' and
             disk.0.os.version>='14.04'
            )

            deploy node 1
            """

        (success, inf_id) = self.server.CreateInfrastructure(
            ansible_radl, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling CreateInfrastructure to create ansible master: " + str(inf_id))
        self.__class__.inf_id = [inf_id]

        all_configured = self.wait_inf_state(
            inf_id, VirtualMachine.CONFIGURED, 600)
        self.assertTrue(
            all_configured, msg="ERROR waiting the ansible master to be configured (timeout).")

        (success, info) = self.server.GetVMInfo(inf_id, "0", self.auth_data)
        self.assertTrue(
            success, msg="ERROR getting ansible master info: " + str(info))
        master_radl = radl_parse.parse_radl(info)

        host = master_radl.systems[0].getValue("net_interface.0.ip")
        username = master_radl.systems[0].getValue(
            "disk.0.os.credentials.username")
        password = master_radl.systems[0].getValue(
            "disk.0.os.credentials.password")

        radl = """
            ansible ansible_master (host = '%s' and credentials.username='%s' and credentials.password='%s')
            network net ()

            system node (
             cpu.arch='x86_64' and
             cpu.count>=1 and
             memory.size>=512m and
             net_interface.0.connection = 'net' and
             disk.0.os.flavour='ubuntu' and
             disk.0.os.version>='14.04'
            )

            deploy node 1
            """ % (host, username, password)

        (success, inf_id) = self.server.CreateInfrastructure(radl, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling CreateInfrastructure: " + str(inf_id))
        self.__class__.inf_id.append(inf_id)

        all_configured = self.wait_inf_state(
            inf_id, VirtualMachine.CONFIGURED, 450)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_85_destroy(self):
        """
        Test DestroyInfrastructure function
        """
        for inf_id in self.inf_id:
            (success, res) = self.server.DestroyInfrastructure(
                inf_id, self.auth_data)
            self.assertTrue(
                success, msg="ERROR calling DestroyInfrastructure: " + str(res))

    def test_90_create(self):
        """
        Test the CreateInfrastructure IM function with ctxt dist
        """
        radl = read_file_as_string("../files/test_cont_dist.radl")

        (success, inf_id) = self.server.CreateInfrastructure(radl, self.auth_data)
        self.assertTrue(
            success, msg="ERROR calling CreateInfrastructure: " + str(inf_id))
        self.__class__.inf_id = [inf_id]

        all_configured = self.wait_inf_state(
            inf_id, VirtualMachine.CONFIGURED, 1200)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_95_destroy(self):
        """
        Test DestroyInfrastructure function
        """
        for inf_id in self.inf_id:
            (success, res) = self.server.DestroyInfrastructure(
                inf_id, self.auth_data)
            self.assertTrue(
                success, msg="ERROR calling DestroyInfrastructure: " + str(res))

#     It does not work in the jenkins env.
#     def test_97_create(self):
#         """
#         Test the CreateInfrastructure IM function with reverse SSH support
#         """
#         radl = read_file_as_string("../files/reverse.radl")
#
#         (success, inf_id) = self.server.CreateInfrastructure(radl, self.auth_data)
#         self.assertTrue(
#             success, msg="ERROR calling CreateInfrastructure: " + str(inf_id))
#         self.__class__.inf_id = [inf_id]
#
#         all_configured = self.wait_inf_state(
#             inf_id, VirtualMachine.CONFIGURED, 600)
#         self.assertTrue(
#             all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")
#
#     def test_99_destroy(self):
#         """
#         Test DestroyInfrastructure function
#         """
#         for inf_id in self.inf_id:
#             (success, res) = self.server.DestroyInfrastructure(
#                 inf_id, self.auth_data)
#             self.assertTrue(
#                 success, msg="ERROR calling DestroyInfrastructure: " + str(res))


if __name__ == '__main__':
    unittest.main()
