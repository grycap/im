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
import os
import requests
import time
import sys
import json

sys.path.append("..")
sys.path.append(".")

from IM.VirtualMachine import VirtualMachine
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from radl import radl_parse
from IM import __version__ as version

PID = None
RADL_ADD = "network privada\nsystem front\ndeploy front 1"
RADL_ADD_ERROR = "system wnno deploy wnno 1"
HOSTNAME = "localhost"
TEST_PORT = 8800


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestIM(unittest.TestCase):

    server = None
    auth_data = None
    inf_id = 0

    @classmethod
    def setUpClass(cls):
        cls.auth_data = read_file_as_string('../auth.dat').replace("\n", "\\n")
        cls.inf_id = "0"

    @classmethod
    def tearDownClass(cls):
        # Assure that the infrastructure is destroyed
        try:
            headers = {'AUTHORIZATION': cls.auth_data}
            url = "http://%s:%d%s" % (HOSTNAME, TEST_PORT, "/infrastructures/" + cls.inf_id)
            requests.request("DELETE", url, headers=headers)
        except Exception:
            pass

    def create_request(self, method, path, headers=None, body=None):
        if headers is None:
            headers = {'AUTHORIZATION': self.auth_data}
        elif headers != {}:
            if 'AUTHORIZATION' not in headers:
                headers['AUTHORIZATION'] = self.auth_data
        url = "http://%s:%d%s" % (HOSTNAME, TEST_PORT, path)
        return requests.request(method, url, headers=headers, data=body)

    def wait_inf_state(self, state, timeout, incorrect_states=None, vm_ids=None):
        """
        Wait for an infrastructure to have a specific state
        """
        if not vm_ids:
            resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
            self.assertEqual(resp.status_code, 200,
                             msg="ERROR getting infrastructure info:" + resp.text)

            vm_ids = resp.text.split("\n")
        else:
            pass

        err_states = [VirtualMachine.FAILED, VirtualMachine.UNCONFIGURED]
        if incorrect_states:
            err_states.extend(incorrect_states)

        wait = 0
        all_ok = False
        while not all_ok and wait < timeout:
            all_ok = True
            for vm_id in vm_ids:
                vm_uri = urlparse(vm_id)
                resp = self.create_request("GET", vm_uri[2] + "/state")
                vm_state = resp.text

                self.assertEqual(resp.status_code, 200,
                                 msg="ERROR getting VM info:" + vm_state)

                if vm_state == VirtualMachine.UNCONFIGURED:
                    resp = self.create_request("GET", "/infrastructures/" + self.inf_id + "/contmsg")
                    print(resp.text)

                self.assertFalse(vm_state in err_states, msg=("ERROR waiting for a state. '%s' state was expected "
                                                              "and '%s' was obtained in the VM %s" % (state,
                                                                                                      vm_state,
                                                                                                      vm_uri)))

                if vm_state in err_states:
                    return False
                elif vm_state != state:
                    all_ok = False

            if not all_ok:
                wait += 5
                time.sleep(5)

        if wait >= timeout:
            # There is a timeout, print the contmsg
            resp = self.create_request("GET", "/infrastructures/" + self.inf_id + "/contmsg")
            print(resp.text)

        return all_ok

    def test_05_version(self):
        resp = self.create_request("GET", "/version")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting IM version:" + resp.text)
        self.assertEqual(
            resp.text, version, msg="Incorrect version. Expected %s, obtained: %s" % (version, resp.text))

    def test_10_list(self):
        resp = self.create_request("GET", "/infrastructures")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR listing user infrastructures:" + resp.text)

        resp = self.create_request("GET", "/infrastructures?filter=.*")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR listing user infrastructures:" + resp.text)

    def test_12_list_with_incorrect_token(self):
        auth_data_lines = read_file_as_string('../auth.dat').split("\n")
        token = ("eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkYzVkNWFiNy02ZGI5LTQwNzktOTg1Yy04MGFjMDUwMTcwNjYi"
                 "LCJpc3MiOiJodHRwczpcL1wvaWFtLXRlc3QuaW5kaWdvLWRhdGFjbG91ZC5ldVwvIiwiZXhwIjoxNDYyODY5MjgxLCJpYXQiOjE"
                 "0NjI4NjU2ODEsImp0aSI6Ijc1M2M4ZTI1LWU3MGMtNGI5MS05YWJhLTcxNDI5NTg3MzUzOSJ9.iA9nv7QdkmfgJPSQ_77_eKrvh"
                 "P1xwZ1Z91xzrZ0Bzue0ark4qRMlHCdZvad1tunURaSsHHMsFYQ3H7oQj-ZSYWOfr1KxMaIo4pWaVHrW8qsCMLmqdNfubR54GmTh"
                 "M4cA2ZdNZa8neVT8jUvzR1YX-5cz7sp2gWbW9LAwejoXDtk")
        auth_data = "type = InfrastructureManager; token = %s\\n" % token
        for line in auth_data_lines:
            if line.find("type = InfrastructureManager") == -1:
                auth_data += line.strip() + "\\n"

        resp = self.create_request("GET", "/infrastructures", headers={'AUTHORIZATION': auth_data})
        self.assertEqual(resp.status_code, 401,
                         msg="ERROR using an invalid token. A 401 error is expected:" + resp.text)

    def test_15_get_incorrect_info(self):
        resp = self.create_request("GET", "/infrastructures/999999")
        self.assertEqual(resp.status_code, 404,
                         msg="Incorrect error code: %d" % resp.status_code)

    def test_16_get_incorrect_info_json(self):
        resp = self.create_request("GET", "/infrastructures/999999", headers={'Accept': 'application/json'})
        self.assertEqual(resp.status_code, 404,
                         msg="Incorrect error code: %d" % resp.status_code)
        res = json.loads(resp.text)
        self.assertEqual(res['code'], 404,
                         msg="Incorrect error message: " + resp.text)

    def test_18_get_info_without_auth_data(self):
        resp = self.create_request("GET", "/infrastructures/0", headers={})
        self.assertEqual(resp.status_code, 401,
                         msg="Incorrect error code: %d" % resp.status_code)

    def test_20_create(self):
        radl = read_file_as_string('../files/test_simple.radl')
        resp = self.create_request("POST", "/infrastructures", body=radl)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR creating the infrastructure:" + resp.text)

        self.__class__.inf_id = str(os.path.basename(resp.text))

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_22_get_forbidden_info(self):
        resp = self.create_request("GET", "/infrastructures/" + self.inf_id,
                                   headers={'AUTHORIZATION': ("type = InfrastructureManager; "
                                                              "username = some; password = other")})

        self.assertEqual(resp.status_code, 403,
                         msg="Incorrect error code: %d" % resp.status_code)

    def test_30_get_vm_info(self):
        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")

        vm_uri = urlparse(vm_ids[0])
        resp = self.create_request("GET", vm_uri[2])
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting VM info:" + resp.text)

    def test_32_get_vm_contmsg(self):
        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200, msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")

        vm_uri = urlparse(vm_ids[0])
        resp = self.create_request("GET", vm_uri[2] + "/contmsg")
        self.assertEqual(resp.status_code, 200, msg="ERROR getting VM contmsg:" + resp.text)
        self.assertEqual(len(resp.text), 0, msg="Incorrect VM contextualization message: " + resp.text)

        resp2 = self.create_request("GET", vm_uri[2] + "/contmsg?headeronly=true")
        self.assertEqual(resp2.status_code, 200, msg="ERROR getting VM contmsg:" + resp.text)

    def test_33_get_contmsg(self):
        resp = self.create_request("GET", "/infrastructures/" + self.inf_id + "/contmsg")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        self.assertGreater(
            len(resp.text), 30, msg="Incorrect contextualization message: " + resp.text)

    def test_34_get_radl(self):
        resp = self.create_request("GET", "/infrastructures/" + self.inf_id + "/radl")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure RADL:" + resp.text)
        try:
            radl_parse.parse_radl(resp.text)
        except Exception as ex:
            self.assertTrue(
                False, msg="ERROR parsing the RADL returned by GetInfrastructureRADL: " + str(ex))

    def test_35_get_vm_property(self):
        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")

        vm_uri = urlparse(vm_ids[0])
        resp = self.create_request("GET", vm_uri[2] + "/state")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting VM property:" + resp.text)

    def test_37_create_snapshot(self):
        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")

        vm_uri = urlparse(vm_ids[0])
        resp = self.create_request("PUT", vm_uri[2] + "/disks/0/snapshot?"
                                   "image_name=im-rest-test-image&auto_delete=yes")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR creating snapshot:" + resp.text)
        self.assertTrue(resp.text.startswith("one://"))

    def test_40_addresource(self):
        resp = self.create_request("POST", "/infrastructures/" + self.inf_id, body=RADL_ADD)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR adding resources:" + resp.text)

        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")
        self.assertEqual(len(vm_ids), 2, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 2"))
        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_45_getstate(self):
        resp = self.create_request("GET", "/infrastructures/" + self.inf_id + "/state")
        self.assertEqual(
            resp.status_code, 200, msg="ERROR getting the infrastructure state:" + resp.text)
        res = json.loads(resp.text)
        state = res['state']['state']
        vm_states = res['state']['vm_states']
        self.assertEqual(state, "configured", msg="Unexpected inf state: " +
                         state + ". It must be 'configured'.")
        for vm_id, vm_state in vm_states.items():
            self.assertEqual(vm_state, "configured", msg="Unexpected vm state: " +
                             vm_state + " in VM ID " + str(vm_id) + ". It must be 'configured'.")

    def test_46_removeresource(self):
        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")

        vm_uri = urlparse(vm_ids[1])
        resp = self.create_request("DELETE", vm_uri[2])
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR removing resources:" + resp.text)

        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")
        self.assertEqual(len(vm_ids), 1, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 1"))

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 300)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_47_addresource_noconfig(self):
        resp = self.create_request("POST", "/infrastructures/" + self.inf_id + "?context=0", body=RADL_ADD)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR adding resources:" + resp.text)

        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")
        self.assertEqual(len(vm_ids), 2, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 2"))

    def test_50_removeresource_noconfig(self):
        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")

        vm_uri = urlparse(vm_ids[1])
        resp = self.create_request("DELETE", vm_uri[2] + "?context=0")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR removing resources:" + resp.text)

        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")
        self.assertEqual(len(vm_ids), 1, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 1"))

    def test_55_reconfigure(self):
        resp = self.create_request("PUT", "/infrastructures/" + self.inf_id + "/reconfigure")
        self.assertEqual(resp.status_code, 200, msg="ERROR reconfiguring:" + resp.text)

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 300)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_57_reconfigure_list(self):
        resp = self.create_request("PUT", "/infrastructures/" + self.inf_id + "/reconfigure?vm_list=0")
        self.assertEqual(resp.status_code, 200, msg="ERROR reconfiguring:" + resp.text)

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 300)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_60_stop(self):
        time.sleep(10)
        resp = self.create_request("PUT", "/infrastructures/" + self.inf_id + "/stop")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR stopping the infrastructure:" + resp.text)
        time.sleep(10)

        all_stopped = self.wait_inf_state(
            VirtualMachine.STOPPED, 120, [VirtualMachine.RUNNING])
        self.assertTrue(
            all_stopped, msg="ERROR waiting the infrastructure to be stopped (timeout).")

    def test_70_start(self):
        # To assure the VM is stopped
        time.sleep(30)
        resp = self.create_request("PUT", "/infrastructures/" + self.inf_id + "/start")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR starting the infrastructure:" + resp.text)
        time.sleep(10)

        all_configured = self.wait_inf_state(
            VirtualMachine.CONFIGURED, 120, [VirtualMachine.RUNNING])
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be started (timeout).")

    def test_80_stop_vm(self):
        time.sleep(30)
        resp = self.create_request("PUT", "/infrastructures/" + self.inf_id + "/vms/0/stop")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR stopping the vm:" + resp.text)
        time.sleep(10)

        all_stopped = self.wait_inf_state(VirtualMachine.STOPPED, 120, [
                                          VirtualMachine.RUNNING], ["/infrastructures/" + self.inf_id + "/vms/0"])
        self.assertTrue(
            all_stopped, msg="ERROR waiting the infrastructure to be stopped (timeout).")

    def test_90_start_vm(self):
        # To assure the VM is stopped
        time.sleep(30)
        resp = self.create_request("PUT", "/infrastructures/" + self.inf_id + "/vms/0/start")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR starting the vm:" + resp.text)
        time.sleep(10)

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 120, [
                                             VirtualMachine.RUNNING], ["/infrastructures/" + self.inf_id + "/vms/0"])
        self.assertTrue(
            all_configured, msg="ERROR waiting the vm to be started (timeout).")

    def test_91_reboot_vm(self):
        # To assure the VM is rebooted
        time.sleep(10)

        resp = self.create_request("PUT", "/infrastructures/" + self.inf_id + "/vms/0/reboot")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR rebooting the vm:" + resp.text)

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 60, [
                                             VirtualMachine.RUNNING], ["/infrastructures/" + self.inf_id + "/vms/0"])
        self.assertTrue(
            all_configured, msg="ERROR waiting the vm to be rebooted (timeout).")

    def test_92_destroy(self):
        resp = self.create_request("DELETE", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR destroying the infrastructure:" + resp.text)

    def test_93_create_tosca(self):
        """
        Test the CreateInfrastructure IM function with a TOSCA document
        """
        tosca = read_file_as_string('../files/tosca_create.yml')

        resp = self.create_request("POST", "/infrastructures", headers={'Content-Type': 'text/yaml'}, body=tosca)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR creating the infrastructure:" + resp.text)

        self.__class__.inf_id = str(os.path.basename(resp.text))

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 900)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_94_get_outputs(self):
        resp = self.create_request("GET", "/infrastructures/" + self.inf_id + "/outputs")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting TOSCA outputs:" + resp.text)
        res = json.loads(resp.text)
        server_url = str(res['outputs']['server_url'][0])
        self.assertRegexpMatches(
            server_url, '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', msg="Unexpected outputs: " + resp.text)

    def test_95_add_tosca(self):
        """
        Test the AddResource IM function with a TOSCA document
        """
        tosca = read_file_as_string('../files/tosca_add.yml')

        resp = self.create_request("POST", "/infrastructures/" + self.inf_id,
                                   headers={'Content-Type': 'text/yaml'}, body=tosca)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR adding resources:" + resp.text)

        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")
        self.assertEqual(len(vm_ids), 3, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 2"))
        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_96_remove_tosca(self):
        """
        Test the RemoveResource IM function with a TOSCA document
        """
        tosca = read_file_as_string('../files/tosca_remove.yml')

        resp = self.create_request("POST", "/infrastructures/" + self.inf_id,
                                   headers={'Content-Type': 'text/yaml'}, body=tosca)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR removing resources:" + resp.text)

        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")
        self.assertEqual(len(vm_ids), 2, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 2"))
        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_98_destroy(self):
        resp = self.create_request("DELETE", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR destroying the infrastructure:" + resp.text)


if __name__ == '__main__':
    unittest.main()
