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

from multiprocessing import Process
import unittest
import time
import sys
import os
import random
import datetime
import requests
import json

sys.path.append("..")
sys.path.append(".")

from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from radl import radl_parse
from IM import __version__ as version

RADL_ADD = "network publica\nnetwork privada\nsystem wn\ndeploy wn 1"
TESTS_PATH = os.path.dirname(os.path.realpath(__file__))
RADL_FILE = TESTS_PATH + '/load-test.radl'
AUTH_FILE = TESTS_PATH + '/auth.dat'
HOSTNAME = "imservice"
TEST_PORT = 8800
MIN_SLEEP = 1
MAX_SLEEP = 10


class LoadTest(unittest.TestCase):

    server = None
    auth_data = None
    inf_id = 0
    response_times = []

    @classmethod
    def setUpClass(cls):
        cls.auth_data = open(AUTH_FILE, 'r').read().replace("\n", "\\n")
        cls.inf_id = 0

    @classmethod
    def tearDownClass(cls):
        # Assure that the infrastructure is destroyed
        try:
            headers = {'AUTHORIZATION': cls.auth_data}
            url = "http://%s:%d%s" % (HOSTNAME, TEST_PORT, "/infrastructures/" + cls.inf_id)
            requests.request("DELETE", url, headers=headers)
        except Exception:
            pass

    @staticmethod
    def wait(mint=MIN_SLEEP, maxt=MAX_SLEEP):
        delay = random.uniform(mint, maxt)
        time.sleep(delay)

    def create_request(self, method, path, headers=None, body=None):
        before = time.time()

        if headers is None:
            headers = {'AUTHORIZATION': self.auth_data}
        elif headers != {}:
            if 'AUTHORIZATION' not in headers:
                headers['AUTHORIZATION'] = self.auth_data
        url = "http://%s:%d%s" % (HOSTNAME, TEST_PORT, path)

        resp = requests.request(method, url, headers=headers, data=body)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        return resp

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

        err_states = [VirtualMachine.FAILED,
                      VirtualMachine.OFF, VirtualMachine.UNCONFIGURED]
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
        radl = open(RADL_FILE, 'r').read()
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

        vm_uri = uriparse(vm_ids[0])
        resp = self.create_request("GET", vm_uri[2])
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting VM info:" + resp.text)

    def test_32_get_vm_contmsg(self):
        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")

        vm_uri = uriparse(vm_ids[0])
        resp = self.create_request("GET", vm_uri[2] + "/contmsg")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting VM contmsg:" + resp.text)

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

        vm_uri = uriparse(vm_ids[0])
        resp = self.create_request("GET", vm_uri[2] + "/state")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting VM property:" + resp.text)

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

        vm_uri = uriparse(vm_ids[1])
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

        vm_uri = uriparse(vm_ids[1])
        resp = self.create_request("DELETE", vm_uri[2] + "?context=0")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR removing resources:" + resp.text)

        resp = self.create_request("GET", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)
        vm_ids = resp.text.split("\n")
        self.assertEqual(len(vm_ids), 1, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 1"))

    def test_95_destroy(self):
        resp = self.create_request("DELETE", "/infrastructures/" + self.inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR destroying the infrastructure:" + resp.text)


def test(num_client):
    now = datetime.datetime.now()
    print(now, ": Launch client num: %d" % num_client)
    unittest.main()
    now = datetime.datetime.now()
    print(now, ": End client num: %d" % num_client)

if __name__ == '__main__':
    MAX_THREADS = 1
    MAX_CLIENTS = 1
    DELAY = 1

    if len(sys.argv) > 3:
        DELAY = int(sys.argv[3])
        del sys.argv[3]

    if len(sys.argv) > 2:
        MAX_CLIENTS = int(sys.argv[1])
        MAX_THREADS = int(sys.argv[2])
        del sys.argv[1]
        del sys.argv[1]
    elif len(sys.argv) > 1:
        MAX_CLIENTS = MAX_THREADS = int(sys.argv[1])
        del sys.argv[1]

    processes = []
    remaining = MAX_CLIENTS
    while remaining > 0:
        now = datetime.datetime.now()
        while len(processes) < MAX_THREADS:
            p = Process(target=test, args=(MAX_CLIENTS - remaining,))
            p.start()
            processes.append(p)
            remaining -= 1

        while len(processes) >= MAX_THREADS:
            new_processes = []
            for p in processes:
                if p.is_alive():
                    new_processes.append(p)
            processes = new_processes
            if len(processes) >= MAX_THREADS:
                time.sleep(DELAY)
