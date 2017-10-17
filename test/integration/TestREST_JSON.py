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
from IM.uriparse import uriparse
from radl.radl_json import parse_radl as parse_radl_json

PID = None
RADL_ADD = """[{"class":"network","reference":true,"id":"publica"},
{"class":"system","reference":true,"id":"front"},{"vm_number":1,"class":"deploy","system":"front"}]"""
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
                vm_uri = uriparse(vm_id)
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

        return all_ok

    def test_20_create(self):
        radl = read_file_as_string('../files/test_simple.json')
        resp = self.create_request("POST", "/infrastructures",
                                   headers={'Content-type': 'application/json'},
                                   body=radl)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR creating the infrastructure:" + resp.text)

        self.__class__.inf_id = str(os.path.basename(resp.text))

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 900)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_30_get_vm_info(self):
        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")

        vm_uri = uriparse(vm_ids[0])
        resp = self.create_request("GET", vm_uri[2], headers={'Accept': 'application/json'})
        ct = resp.headers['Content-type']
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting VM info:" + resp.text)
        self.assertEqual(ct, "application/json",
                         msg="ERROR getting VM info: Incorrect Content-type: %s" % ct)
        res = json.loads(resp.text)
        radl = res["radl"]
        parse_radl_json(radl)

    def test_40_addresource(self):
        resp = self.create_request("POST", "/infrastructures/" + self.inf_id,
                                   headers={'Content-type': 'application/json'},
                                   body=RADL_ADD)
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

    def test_55_reconfigure(self):
        new_config = """
[
{
"class": "configure",
"id": "front",
"recipes": "---\\n  - tasks:\\n    - debug: msg=RECONTEXTUALIZAMOS!\\n\\n"
}
]
        """

        resp = self.create_request("PUT", "/infrastructures/" + self.inf_id + "/reconfigure",
                                   headers={'Content-type': 'application/json'},
                                   body=new_config)
        self.assertEqual(resp.status_code, 200, msg="ERROR reconfiguring:" + resp.text)

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 300)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

        resp = self.create_request("GET", "/infrastructures/" + self.inf_id + "/contmsg")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure contextualization message:" + resp.text)
        self.assertNotEqual(resp.text.find("RECONTEXTUALIZAMOS"), -1,
                            msg="Incorrect contextualization message: " + resp.text)

    def test_95_destroy(self):
        resp = self.create_request("DELETE", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR destroying the infrastructure:" + resp.text)

if __name__ == '__main__':
    unittest.main()
