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
import time
import sys
import os
import requests
import json

from urllib.parse import urlparse

sys.path.append("..")
sys.path.append(".")

from IM.VirtualMachine import VirtualMachine
from radl import radl_parse
from IM import __version__ as version

RADL_ADD_WIN = "network publica\nnetwork privada\nsystem windows\ndeploy windows 1 one"
RADL_ADD = "network publica\nnetwork privada\nsystem wn\ndeploy wn 1 one"
RADL_ADD_ERROR = "system wnno deploy wnno 1"
HOSTNAME = "localhost"
TEST_PORT = 8800


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    with open(abs_file_path, 'r') as f:
        return f.read()


class TestIM(unittest.TestCase):
    auth_data = None
    inf_id = None

    @classmethod
    def setUpClass(cls):
        cls.auth_data = read_file_as_string('../auth.dat').replace("\n", "\\n")
        cls.inf_id = "0"

    def create_request(self, method, path, headers=None, body=None):
        if headers is None:
            headers = {'AUTHORIZATION': self.auth_data}
        elif headers != {} and 'AUTHORIZATION' not in headers:
            headers['AUTHORIZATION'] = self.auth_data
        url = "http://%s:%d%s" % (HOSTNAME, TEST_PORT, path)
        return requests.request(method, url, headers=headers, data=body)

    @staticmethod
    def _extract_vm_ids(uri_list_text):
        vm_ids = []
        for vm_uri in uri_list_text.splitlines():
            vm_uri = vm_uri.strip()
            if not vm_uri:
                continue
            vm_path = urlparse(vm_uri).path
            vm_ids.append(vm_path.rsplit('/', 1)[-1])
        return vm_ids

    @classmethod
    def tearDownClass(cls):
        # Assure that the infrastructure is destroyed
        try:
            if cls.inf_id:
                if isinstance(cls.inf_id, list):
                    for inf_id in cls.inf_id:
                        headers = {'AUTHORIZATION': cls.auth_data}
                        url = "http://%s:%d%s" % (HOSTNAME, TEST_PORT, "/infrastructures/" + inf_id)
                        requests.request("DELETE", url, headers=headers)
                else:
                    headers = {'AUTHORIZATION': cls.auth_data}
                    url = "http://%s:%d%s" % (HOSTNAME, TEST_PORT, "/infrastructures/" + cls.inf_id)
                    requests.request("DELETE", url, headers=headers)
        except Exception:
            pass

    def wait_inf_state(self, inf_id, state, timeout, incorrect_states=None, vm_ids=None):
        """
        Wait for an infrastructure to have a specific state
        """
        if not vm_ids:
            resp = self.create_request("GET", "/infrastructures/%s" % inf_id)
            self.assertEqual(resp.status_code, 200,
                             msg="ERROR calling the GetInfrastructureInfo function:" + resp.text)
            vm_ids = self._extract_vm_ids(resp.text)

        err_states = [VirtualMachine.FAILED, VirtualMachine.UNCONFIGURED]
        if incorrect_states:
            err_states.extend(incorrect_states)

        wait = 0
        all_ok = False
        while not all_ok and wait < timeout:
            all_ok = True
            for vm_id in vm_ids:
                resp = self.create_request("GET", "/infrastructures/%s/vms/%s/state" % (inf_id, vm_id))
                vm_state = resp.text
                self.assertEqual(resp.status_code, 200, msg="ERROR getting VM info:" + str(vm_state))

                if vm_state == VirtualMachine.UNCONFIGURED:
                    cont_msg = self.create_request("GET", "/infrastructures/%s/contmsg?headeronly=true" % inf_id).text
                    print(cont_msg)
                    cont_msg = self.create_request("GET", "/infrastructures/%s/vms/%s/contmsg" % (inf_id, vm_id)).text
                    print(cont_msg)

                self.assertNotIn(vm_state, err_states, msg="ERROR waiting for a state. '" + vm_state +
                                 "' was obtained in the VM: " + str(vm_id) + " err_states = " + str(err_states))

                if vm_state in err_states:
                    return False
                elif vm_state != state:
                    all_ok = False

            if not all_ok:
                wait += 5
                if wait >= timeout:
                    cont_msg = self.create_request("GET", "/infrastructures/%s/contmsg" % inf_id).text
                    print(cont_msg)
                else:
                    time.sleep(5)

        return all_ok

    def test_05_getversion(self):
        """
        Test the GetVersion IM function
        """
        resp = self.create_request("GET", "/version", headers={})
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetVersion: " + resp.text)
        res = resp.text
        self.assertEqual(
            res, version, msg="Incorrect version. Expected %s, obtained: %s" % (version, res))

    def test_10_list(self):
        """
        Test the GetInfrastructureList IM function
        """
        resp = self.create_request("GET", "/infrastructures")
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureList: " + resp.text)
        resp = self.create_request("GET", "/infrastructures?filter=.*")
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureList: " + resp.text)

    def test_11_create(self):
        """
        Test the CreateInfrastructure IM function
        """
        radl = read_file_as_string("../files/test.radl")

        resp = self.create_request("POST", "/infrastructures", body=radl)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling CreateInfrastructure: " + resp.text)
        inf_id = str(os.path.basename(resp.text))
        self.__class__.inf_id = inf_id

        all_configured = self.wait_inf_state(
            inf_id, VirtualMachine.CONFIGURED, 2700)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_12_getradl(self):
        """
        Test the GetInfrastructureRADL IM function
        """
        resp = self.create_request("GET", "/infrastructures/%s/radl" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureRADL: " + resp.text)
        res = resp.text
        try:
            radl_parse.parse_radl(res)
        except Exception as ex:
            self.fail("ERROR parsing the RADL returned by GetInfrastructureRADL: " + str(ex))

    def test_13_getcontmsg(self):
        """
        Test the GetInfrastructureContMsg IM function
        """
        resp = self.create_request("GET", "/infrastructures/%s/contmsg" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureContMsg: " + resp.text)
        cont_out = resp.text
        self.assertGreater(len(cont_out), 100, msg="Incorrect contextualization message: " + cont_out)
        self.assertIn("Select master VM", cont_out)
        self.assertIn("NODENAME = front", cont_out)
        # Check vault task
        self.assertIn("VAULTOK", cont_out)

        resp = self.create_request("GET", "/infrastructures/%s/contmsg?headeronly=true" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureContMsg: " + resp.text)
        cont_out = resp.text
        self.assertGreater(len(cont_out), 100, msg="Incorrect contextualization message: " + cont_out)
        self.assertIn("Select master VM", cont_out)
        self.assertNotIn("NODENAME = front", cont_out)

    def test_14_getvmcontmsg(self):
        """
        Test the GetVMContMsg IM function
        """
        resp = self.create_request("GET", "/infrastructures/%s/vms/0/contmsg" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetVMContMsg: " + resp.text)
        res = resp.text
        self.assertGreater(
            len(res), 100, msg="Incorrect VM contextualization message: " + res)

    def test_15_get_vm_info(self):
        """
        Test the GetVMInfo IM function
        """
        resp = self.create_request("GET", "/infrastructures/%s" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureInfo: " + resp.text)
        vm_ids = self._extract_vm_ids(resp.text)
        resp = self.create_request("GET", "/infrastructures/%s/vms/%s" % (self.inf_id, vm_ids[0]))
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetVMInfo: " + resp.text)
        info = resp.text
        try:
            radl_parse.parse_radl(info)
        except Exception as ex:
            self.fail("ERROR parsing the RADL returned by GetVMInfo: " + str(ex))

    def test_16_get_vm_property(self):
        """
        Test the GetVMProperty IM function
        """
        resp = self.create_request("GET", "/infrastructures/%s" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureInfo: " + resp.text)
        vm_ids = self._extract_vm_ids(resp.text)
        resp = self.create_request("GET", "/infrastructures/%s/vms/%s/state" % (self.inf_id, vm_ids[0]))
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetVMProperty: " + resp.text)
        info = resp.text
        self.assertNotEqual(
            info, None, msg="ERROR in the value returned by GetVMProperty: " + info)
        self.assertNotEqual(
            info, "", msg="ERROR in the value returned by GetVMPropert: " + info)

    def test_17_create_snapshot(self):
        """
        Test CreateDiskSnapshot function
        """
        path = "/infrastructures/%s/vms/0/disks/0/snapshot?image_name=im-test-image&auto_delete=yes" % self.inf_id
        resp = self.create_request("PUT", path)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling CreateDiskSnapshot: " + resp.text)

    def test_18_error_addresource(self):
        """
        Test to get error when adding a resource with an incorrect RADL
        """
        resp = self.create_request("POST", "/infrastructures/%s" % self.inf_id, body=RADL_ADD_ERROR)
        self.assertNotEqual(resp.status_code, 200, msg="Incorrect RADL in AddResource not returned error")
        res = resp.text
        pos = res.find("Unknown reference in RADL")
        self.assertGreater(
            pos, -1, msg="Incorrect RADL in AddResource not returned the expected error: " + res)

    def test_19_addresource(self):
        """
        Test AddResource function
        """
        resp = self.create_request("POST", "/infrastructures/%s" % self.inf_id, body=RADL_ADD)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling AddResource: " + resp.text)

        resp = self.create_request("GET", "/infrastructures/%s" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureInfo:" + resp.text)
        vm_ids = self._extract_vm_ids(resp.text)
        self.assertEqual(len(vm_ids), 4, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 4"))

        all_configured = self.wait_inf_state(self.inf_id, VirtualMachine.CONFIGURED, 2400)
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_20_getstate(self):
        """
        Test the GetInfrastructureState IM function
        """
        resp = self.create_request("GET", "/infrastructures/%s/state" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureState: " + resp.text)
        res = json.loads(resp.text)
        res = res.get('state', res)
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
        resp = self.create_request("POST", "/infrastructures/%s?context=0" % self.inf_id, body=RADL_ADD)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling AddResource: " + resp.text)

        resp = self.create_request("GET", "/infrastructures/%s" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureInfo:" + resp.text)
        vm_ids = self._extract_vm_ids(resp.text)
        self.assertEqual(len(vm_ids), 5, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 5"))

    def test_22_removeresource(self):
        """
        Test RemoveResource function
        """
        resp = self.create_request("GET", "/infrastructures/%s" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureInfo: " + resp.text)
        vm_ids = self._extract_vm_ids(resp.text)

        resp = self.create_request("DELETE", "/infrastructures/%s/vms/%s" % (self.inf_id, vm_ids[2]))
        self.assertEqual(resp.status_code, 200, msg="ERROR calling RemoveResource: " + resp.text)

        resp = self.create_request("GET", "/infrastructures/%s" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureInfo:" + resp.text)
        vm_ids = self._extract_vm_ids(resp.text)
        self.assertEqual(len(vm_ids), 4, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 4"))

        resp = self.create_request("GET", "/infrastructures/%s/vms/%s/state" % (self.inf_id, vm_ids[0]))
        self.assertEqual(resp.status_code, 200, msg="ERROR getting VM state:" + resp.text)
        vm_state = resp.text
        self.assertEqual(vm_state, VirtualMachine.RUNNING,
                         msg="ERROR unexpected state. Expected 'running' and obtained " + vm_state)

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 2400)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_23_removeresource_noconfig(self):
        """
        Test RemoveResource function with the context option to False
        """
        resp = self.create_request("GET", "/infrastructures/%s" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureInfo: " + resp.text)
        vm_ids = self._extract_vm_ids(resp.text)

        resp = self.create_request("DELETE", "/infrastructures/%s/vms/%s?context=0" % (self.inf_id, vm_ids[2]))
        self.assertEqual(resp.status_code, 200, msg="ERROR calling RemoveResource: " + resp.text)

        resp = self.create_request("GET", "/infrastructures/%s" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureInfo:" + resp.text)
        vm_ids = self._extract_vm_ids(resp.text)
        self.assertEqual(len(vm_ids), 3, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 3"))

        resp = self.create_request("GET", "/infrastructures/%s/vms/%s/state" % (self.inf_id, vm_ids[0]))
        self.assertEqual(resp.status_code, 200, msg="ERROR getting VM state:" + resp.text)
        vm_state = resp.text
        self.assertEqual(vm_state, VirtualMachine.CONFIGURED,
                         msg="ERROR unexpected state. Expected 'running' and obtained " + vm_state)

    def test_24_reconfigure(self):
        """
        Test Reconfigure function
        """
        resp = self.create_request("PUT", "/infrastructures/%s/reconfigure" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling Reconfigure: " + resp.text)

        all_stopped = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 900)
        self.assertTrue(
            all_stopped, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_25_reconfigure_vmlist(self):
        """
        Test Reconfigure function specifying a list of VMs
        """
        resp = self.create_request("PUT", "/infrastructures/%s/reconfigure?vm_list=0" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling Reconfigure: " + resp.text)

        all_stopped = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 900)
        self.assertTrue(
            all_stopped, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_26_reconfigure_radl(self):
        """
        Test Reconfigure function specifying a new RADL
        """
        radl = """configure test (\n@begin\n---\n  - tasks:\n      - debug: msg="RECONFIGURERADL"\n@end\n)"""
        resp = self.create_request("PUT", "/infrastructures/%s/reconfigure" % self.inf_id, body=radl)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling Reconfigure: " + resp.text)

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 900)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

        resp = self.create_request("GET", "/infrastructures/%s/contmsg" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureContMsg: " + resp.text)
        cont_out = resp.text
        self.assertIn("RECONFIGURERADL", cont_out,
                      msg="Incorrect contextualization message: " + cont_out)

    def test_30_stop(self):
        """
        Test StopInfrastructure function
        """
        time.sleep(30)
        resp = self.create_request("PUT", "/infrastructures/%s/stop" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling StopInfrastructure: " + resp.text)
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
        time.sleep(60)
        resp = self.create_request("PUT", "/infrastructures/%s/start" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling StartInfrastructure: " + resp.text)
        time.sleep(30)

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 150, [VirtualMachine.RUNNING])
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be started (timeout).")

    def test_32_stop_vm(self):
        """
        Test StopVM function
        """
        resp = self.create_request("GET", "/infrastructures/%s" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureInfo: " + resp.text)
        vm_ids = self._extract_vm_ids(resp.text)
        time.sleep(30)
        resp = self.create_request("PUT", "/infrastructures/%s/vms/%s/stop" % (self.inf_id, vm_ids[0]))
        self.assertEqual(resp.status_code, 200, msg="ERROR calling StopVM: " + resp.text)
        time.sleep(30)

        all_stopped = self.wait_inf_state(self.inf_id, VirtualMachine.STOPPED, 120, [
                                          VirtualMachine.RUNNING], [vm_ids[0]])
        self.assertTrue(
            all_stopped, msg="ERROR waiting the vm to be stopped (timeout).")

    def test_33_start_vm(self):
        """
        Test StartVM function
        """
        resp = self.create_request("GET", "/infrastructures/%s" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureInfo: " + resp.text)
        vm_ids = self._extract_vm_ids(resp.text)
        # Assure the VM to be stopped
        time.sleep(60)
        resp = self.create_request("PUT", "/infrastructures/%s/vms/%s/start" % (self.inf_id, vm_ids[0]))
        self.assertEqual(resp.status_code, 200, msg="ERROR calling StartVM: " + resp.text)
        time.sleep(30)

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 150, [VirtualMachine.RUNNING], [vm_ids[0]])
        self.assertTrue(
            all_configured, msg="ERROR waiting the vm to be started (timeout).")

    def test_34_reboot_vm(self):
        """
        Test RebootVM function
        """
        resp = self.create_request("GET", "/infrastructures/%s" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetInfrastructureInfo: " + resp.text)
        vm_ids = self._extract_vm_ids(resp.text)

        resp = self.create_request("PUT", "/infrastructures/%s/vms/%s/reboot" % (self.inf_id, vm_ids[0]))
        self.assertEqual(resp.status_code, 200, msg="ERROR calling RebootVM: " + resp.text)

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 60, [VirtualMachine.RUNNING], [vm_ids[0]])
        self.assertTrue(
            all_configured, msg="ERROR waiting the vm to be rebooted (timeout).")

    def test_40_export_import(self):
        """
        Test ExportInfrastructure and ImportInfrastructure functions
        """
        resp = self.create_request("GET", "/infrastructures/%s/data?delete=true" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling ExportInfrastructure: " + resp.text)
        inf_data = resp.text

        resp = self.create_request("PUT", "/infrastructures",
                                   headers={'AUTHORIZATION': self.auth_data,
                                            'Content-Type': 'application/json'},
                                   body=inf_data)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling ImportInfrastructure: " + resp.text)

    def test_45_stats(self):
        resp = self.create_request("GET", "/stats")
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetStats: " + resp.text)
        data = json.loads(resp.text)
        res = data.get('stats', data)
        self.assertEqual(len(res), 4, msg="ERROR getting stats: Incorrect number of infrastructures")

    def test_50_destroy(self):
        """
        Test DestroyInfrastructure function
        """
        resp = self.create_request("DELETE", "/infrastructures/%s" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling DestroyInfrastructure: " + resp.text)

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
            disk.0.os.version>='20.04'
            )

            deploy test 1

            contextualize ()
            """

        resp = self.create_request("POST", "/infrastructures", body=radl)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling CreateInfrastructure: " + resp.text)
        inf_id = str(os.path.basename(resp.text))
        self.__class__.inf_id = inf_id

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 300)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_65_destroy(self):
        """
        Test DestroyInfrastructure function
        """
        resp = self.create_request("DELETE", "/infrastructures/%s" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling DestroyInfrastructure: " + resp.text)

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
             disk.0.os.name='linux' and
             disk.0.image.url = 'one://ramses.i3m.upv.es/1593'
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
        resp = self.create_request("POST", "/infrastructures", body=radl)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling CreateInfrastructure: " + resp.text)
        inf_id = str(os.path.basename(resp.text))
        self.__class__.inf_id = inf_id

        all_configured = self.wait_inf_state(
            self.inf_id, VirtualMachine.CONFIGURED, 300)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_75_destroy(self):
        """
        Test DestroyInfrastructure function
        """
        resp = self.create_request("DELETE", "/infrastructures/%s" % self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling DestroyInfrastructure: " + resp.text)

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
             memory.size>=1g and
             net_interface.0.connection = 'publicnet' and
             net_interface.1.connection = 'net' and
             disk.0.os.flavour='ubuntu' and
             disk.0.os.version>='20.04'
            )

            deploy node 1
            """

        resp = self.create_request("POST", "/infrastructures", body=ansible_radl)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR calling CreateInfrastructure to create ansible master: " + resp.text)
        inf_id = str(os.path.basename(resp.text))
        self.__class__.inf_id = [inf_id]

        all_configured = self.wait_inf_state(
            inf_id, VirtualMachine.CONFIGURED, 1200)
        self.assertTrue(
            all_configured, msg="ERROR waiting the ansible master to be configured (timeout).")

        resp = self.create_request("GET", "/infrastructures/%s/vms/0" % inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR getting ansible master info: " + resp.text)
        info = resp.text
        master_radl = radl_parse.parse_radl(info)

        host = master_radl.systems[0].getValue("net_interface.0.ip")
        username = master_radl.systems[0].getValue(
            "disk.0.os.credentials.username")
        private_key = master_radl.systems[0].getValue(
            "disk.0.os.credentials.private_key")

        radl = """
            ansible ansible_master (host = '%s' and credentials.username='%s' and credentials.private_key ='%s')
            network net ()

            system node (
             cpu.arch='x86_64' and
             cpu.count>=1 and
             memory.size>=1g and
             net_interface.0.connection = 'net' and
             disk.0.os.flavour='ubuntu' and
             disk.0.os.version>='20.04'
            )

            deploy node 1
            """ % (host, username, private_key)

        resp = self.create_request("POST", "/infrastructures", body=radl)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling CreateInfrastructure: " + resp.text)
        inf_id = str(os.path.basename(resp.text))
        self.__class__.inf_id.append(inf_id)

        all_configured = self.wait_inf_state(
            inf_id, VirtualMachine.CONFIGURED, 1200)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_85_destroy(self):
        """
        Test DestroyInfrastructure function
        """
        for inf_id in self.inf_id:
            resp = self.create_request("DELETE", "/infrastructures/%s" % inf_id)
            self.assertEqual(resp.status_code, 200, msg="ERROR calling DestroyInfrastructure: " + resp.text)

    def test_90_create(self):
        """
        Test the CreateInfrastructure IM function with ctxt dist
        """
        radl = read_file_as_string("../files/test_cont_dist.radl")

        resp = self.create_request("POST", "/infrastructures", body=radl)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling CreateInfrastructure: " + resp.text)
        inf_id = str(os.path.basename(resp.text))
        self.__class__.inf_id = [inf_id]

        all_configured = self.wait_inf_state(
            inf_id, VirtualMachine.CONFIGURED, 2100)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_95_destroy(self):
        """
        Test DestroyInfrastructure function
        """
        for inf_id in self.inf_id:
            resp = self.create_request("DELETE", "/infrastructures/%s" % inf_id)
            self.assertEqual(resp.status_code, 200, msg="ERROR calling DestroyInfrastructure: " + resp.text)

    def test_96_create(self):
        """
        Test the CreateInfrastructure IM function setting Ansible version
        """
        radl = read_file_as_string("../files/test_ansible.radl")

        resp = self.create_request("POST", "/infrastructures", body=radl)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling CreateInfrastructure: " + resp.text)
        inf_id = str(os.path.basename(resp.text))
        self.__class__.inf_id = [inf_id]

        all_configured = self.wait_inf_state(inf_id, VirtualMachine.CONFIGURED, 1200)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_97_destroy(self):
        """
        Test DestroyInfrastructure function
        """
        for inf_id in self.inf_id:
            resp = self.create_request("DELETE", "/infrastructures/%s" % inf_id)
            self.assertEqual(resp.status_code, 200, msg="ERROR calling DestroyInfrastructure: " + resp.text)

    def test_98_proxy(self):
        """
        Test connecting a VM using a proxy host
        """
        radl = """
            network net (outbound = 'yes')
            network priv (provider_id = '16')
            system test (
            cpu.count>=1 and
            memory.size>=1g and
            net_interface.0.connection = 'net' and
            net_interface.1.connection = 'priv' and
            disk.0.os.name='linux' and
            disk.0.image.url = 'one://ramses.i3m.upv.es/1593'
            )

            deploy test 1
            """

        resp = self.create_request("POST", "/infrastructures", body=radl)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling CreateInfrastructure: " + resp.text)
        inf_id = str(os.path.basename(resp.text))
        self.__class__.inf_id = [inf_id]

        all_configured = self.wait_inf_state(inf_id, VirtualMachine.CONFIGURED, 1200)
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

        resp = self.create_request("GET", "/infrastructures/%s/vms/0" % inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling GetVMInfo: " + resp.text)
        vminfo = resp.text

        vm = radl_parse.parse_radl(vminfo)
        proxy_ip = vm.systems[0].getValue("net_interface.0.ip")
        proxy_user = vm.systems[0].getValue("disk.0.os.credentials.username")
        proxy_key = vm.systems[0].getValue("disk.0.os.credentials.private_key")
        proxy_host = "%s@%s" % (proxy_user, proxy_ip)

        radl = """
            network net (proxy_host = '%s' and provider_id = '16' and proxy_key='%s')
            system test (
            cpu.count>=1 and
            memory.size>=1g and
            net_interface.0.connection = 'net' and
            disk.0.os.name='linux' and
            disk.0.image.url = 'one://ramses.i3m.upv.es/1593'
            )

            deploy test 1
            """ % (proxy_host, proxy_key)
        resp = self.create_request("POST", "/infrastructures", body=radl)
        self.assertEqual(resp.status_code, 200, msg="ERROR calling CreateInfrastructure: " + resp.text)
        inf_id2 = str(os.path.basename(resp.text))
        self.__class__.inf_id.append(inf_id2)

        all_configured = self.wait_inf_state(inf_id2, VirtualMachine.CONFIGURED, 1200)
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_99_destroy(self):
        """
        Test DestroyInfrastructure function
        """
        for inf_id in self.inf_id:
            resp = self.create_request("DELETE", "/infrastructures/%s" % inf_id)
            self.assertEqual(resp.status_code, 200, msg="ERROR calling DestroyInfrastructure: " + resp.text)


if __name__ == '__main__':
    unittest.main()
