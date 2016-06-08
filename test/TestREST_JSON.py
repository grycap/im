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
import httplib
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
TESTS_PATH = os.path.dirname(os.path.realpath(__file__))
RADL_FILE = TESTS_PATH + '/files/test_simple.json'
AUTH_FILE = TESTS_PATH + '/files/auth.dat'

HOSTNAME = "localhost"
TEST_PORT = 8800


class TestIM(unittest.TestCase):

    server = None
    auth_data = None
    inf_id = 0

    @classmethod
    def setUpClass(cls):
        cls.server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        f = open(AUTH_FILE)
        cls.auth_data = ""
        for line in f.readlines():
            cls.auth_data += line.strip() + "\\n"
        f.close()
        cls.inf_id = "0"

    @classmethod
    def tearDownClass(cls):
        # Assure that the infrastructure is destroyed
        try:
            cls.server.request('DELETE', "/infrastructures/" +
                               cls.inf_id, headers={'Authorization': cls.auth_data})
            cls.server.getresponse()
        except Exception:
            pass

    def wait_inf_state(self, state, timeout, incorrect_states=[], vm_ids=None):
        """
        Wait for an infrastructure to have a specific state
        """
        if not vm_ids:
            self.server.request('GET', "/infrastructures/" + self.inf_id,
                                headers={'AUTHORIZATION': self.auth_data})
            resp = self.server.getresponse()
            output = str(resp.read())
            self.assertEqual(resp.status, 200,
                             msg="ERROR getting infrastructure info:" + output)

            vm_ids = output.split("\n")
        else:
            pass

        err_states = [VirtualMachine.FAILED,
                      VirtualMachine.OFF, VirtualMachine.UNCONFIGURED]
        err_states.extend(incorrect_states)

        wait = 0
        all_ok = False
        while not all_ok and wait < timeout:
            all_ok = True
            for vm_id in vm_ids:
                vm_uri = uriparse(vm_id)
                self.server.request(
                    'GET', vm_uri[2] + "/state", headers={'AUTHORIZATION': self.auth_data})
                resp = self.server.getresponse()
                vm_state = str(resp.read())
                self.assertEqual(resp.status, 200,
                                 msg="ERROR getting VM info:" + vm_state)

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
        f = open(RADL_FILE)
        radl = ""
        for line in f.readlines():
            radl += line
        f.close()

        self.server.request('POST', "/infrastructures", body=radl, headers={
                            'AUTHORIZATION': self.auth_data, 'Content-Type': 'application/json'})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200,
                         msg="ERROR creating the infrastructure:" + output)

        self.__class__.inf_id = str(os.path.basename(output))

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_30_get_vm_info(self):
        self.server.request('GET', "/infrastructures/" + self.inf_id,
                            headers={'AUTHORIZATION': self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")

        vm_uri = uriparse(vm_ids[0])
        self.server.request('GET', vm_uri[2], headers={
                            'AUTHORIZATION': self.auth_data, 'Accept': 'application/json'})
        resp = self.server.getresponse()
        ct = resp.getheader('Content-type')
        output = str(resp.read())
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting VM info:" + output)
        self.assertEqual(ct, "application/json",
                         msg="ERROR getting VM info: Incorrect Content-type: %s" % ct)
        res = json.loads(output)
        radl = res["radl"]
        parse_radl_json(radl)

    def test_40_addresource(self):
        self.server.request('POST', "/infrastructures/" + self.inf_id, body=RADL_ADD,
                            headers={'AUTHORIZATION': self.auth_data, 'Content-Type': 'application/json'})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200,
                         msg="ERROR adding resources:" + output)

        self.server.request('GET', "/infrastructures/" + self.inf_id,
                            headers={'AUTHORIZATION': self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")
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

        self.server.request('PUT', "/infrastructures/" + self.inf_id + "/reconfigure", body=new_config,
                            headers={'AUTHORIZATION': self.auth_data, 'Content-Type': 'application/json'})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR reconfiguring:" + output)

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 300)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

        self.server.request('GET', "/infrastructures/" + self.inf_id +
                            "/contmsg", headers={'AUTHORIZATION': self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting the infrastructure info:" + output)
        self.assertNotEqual(output.find("RECONTEXTUALIZAMOS"), -1,
                            msg="Incorrect contextualization message: " + output)

    def test_95_destroy(self):
        self.server.request('DELETE', "/infrastructures/" +
                            self.inf_id, headers={'Authorization': self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200,
                         msg="ERROR destroying the infrastructure:" + output)

if __name__ == '__main__':
    unittest.main()
