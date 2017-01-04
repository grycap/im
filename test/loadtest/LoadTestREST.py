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
import xmlrpclib
import time
import sys
import os
import random
import datetime
import httplib
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
        cls.server = xmlrpclib.ServerProxy(
            "http://" + HOSTNAME + ":" + str(TEST_PORT), allow_none=True)
        cls.auth_data = open(AUTH_FILE, 'r').read().replace("\n", "\\n")
        cls.inf_id = 0

    @classmethod
    def tearDownClass(cls):
        # Assure that the infrastructure is destroyed
        try:
            cls.server.DestroyInfrastructure(cls.inf_id, cls.auth_data)
        except Exception:
            pass

    @staticmethod
    def wait(mint=MIN_SLEEP, maxt=MAX_SLEEP):
        delay = random.uniform(mint, maxt)
        time.sleep(delay)

    def wait_inf_state(self, state, timeout, incorrect_states=[], vm_ids=None):
        """
        Wait for an infrastructure to have a specific state
        """
        if not vm_ids:
            before = time.time()
            server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
            server.request('GET', "/infrastructures/" + self.inf_id,
                           headers={'AUTHORIZATION': self.auth_data})
            resp = server.getresponse()
            output = str(resp.read())
            server.close()
            self.assertEqual(resp.status, 200,
                             msg="ERROR getting infrastructure info:" + output)

            vm_ids = output.split("\n")
            resp_time = time.time() - before
            self.__class__.response_times.append(resp_time)
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
                server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
                before = time.time()
                server.request(
                    'GET', vm_uri[2] + "/state", headers={'AUTHORIZATION': self.auth_data})
                resp = server.getresponse()
                vm_state = str(resp.read())
                server.close()
                resp_time = time.time() - before
                self.__class__.response_times.append(resp_time)
                self.assertEqual(resp.status, 200,
                                 msg="ERROR getting VM info:" + vm_state)

                if vm_state == VirtualMachine.UNCONFIGURED:
                    server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
                    server.request('GET', "/infrastructures/" + self.inf_id + "/contmsg",
                                   headers={'AUTHORIZATION': self.auth_data})
                    resp = server.getresponse()
                    output = str(resp.read())
                    server.close()
                    print output

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
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/version")
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting IM version:" + output)
        self.assertEqual(
            output, version, msg="Incorrect version. Expected %s, obtained: %s" % (version, output))

    def test_10_list(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures",
                       headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR listing user infrastructures:" + output)

    def test_15_get_incorrect_info(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/999999",
                       headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        resp.read()
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 404,
                         msg="Incorrect error message: " + str(resp.status))

    def test_16_get_incorrect_info_json(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/999999",
                       headers={'AUTHORIZATION': self.auth_data, 'Accept': 'application/json'})
        resp = server.getresponse()
        output = resp.read()
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 404,
                         msg="Incorrect error message: " + str(resp.status))
        res = json.loads(output)
        self.assertEqual(res['code'], 404,
                         msg="Incorrect error message: " + output)

    def test_18_get_info_without_auth_data(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/0")
        resp = server.getresponse()
        resp.read()
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 401,
                         msg="Incorrect error message: " + str(resp.status))

    def test_20_create(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        radl = open(RADL_FILE, 'r').read()

        server.request('POST', "/infrastructures", body=radl,
                       headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR creating the infrastructure:" + output)

        self.__class__.inf_id = str(os.path.basename(output))

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_22_get_forbidden_info(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/" + self.inf_id,
                       headers={'AUTHORIZATION': ("type = InfrastructureManager; "
                                                  "username = some; password = other")})
        resp = server.getresponse()
        resp.read()
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 403,
                         msg="Incorrect error message: " + str(resp.status))

    def test_30_get_vm_info(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/" + self.inf_id,
                       headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")

        vm_uri = uriparse(vm_ids[0])
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', vm_uri[2], headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting VM info:" + output)

    def test_32_get_vm_contmsg(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/" + self.inf_id,
                       headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")

        vm_uri = uriparse(vm_ids[0])
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', vm_uri[2] + "/contmsg", headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting VM contmsg:" + output)

    def test_33_get_contmsg(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/" + self.inf_id + "/contmsg",
                       headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting the infrastructure info:" + output)
        self.assertGreater(
            len(output), 30, msg="Incorrect contextualization message: " + output)

    def test_34_get_radl(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/" + self.inf_id + "/radl",
                       headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting the infrastructure RADL:" + output)
        try:
            radl_parse.parse_radl(output)
        except Exception, ex:
            self.assertTrue(
                False, msg="ERROR parsing the RADL returned by GetInfrastructureRADL: " + str(ex))

    def test_35_get_vm_property(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/" + self.inf_id,
                       headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")

        vm_uri = uriparse(vm_ids[0])
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request(
            'GET', vm_uri[2] + "/state", headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting VM property:" + output)

    def test_40_addresource(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('POST', "/infrastructures/" + self.inf_id,
                       body=RADL_ADD, headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR adding resources:" + output)

        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/" + self.inf_id,
                       headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")
        self.assertEqual(len(vm_ids), 2, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 2"))
        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_45_getstate(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/" + self.inf_id + "/state",
                       headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(
            resp.status, 200, msg="ERROR getting the infrastructure state:" + output)
        res = json.loads(output)
        state = res['state']['state']
        vm_states = res['state']['vm_states']
        self.assertEqual(state, "configured", msg="Unexpected inf state: " +
                         state + ". It must be 'configured'.")
        for vm_id, vm_state in vm_states.items():
            self.assertEqual(vm_state, "configured", msg="Unexpected vm state: " +
                             vm_state + " in VM ID " + str(vm_id) + ". It must be 'configured'.")

    def test_46_removeresource(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/" + self.inf_id,
                       headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")

        vm_uri = uriparse(vm_ids[1])
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('DELETE', vm_uri[2], headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR removing resources:" + output)

        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/" + self.inf_id,
                       headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")
        self.assertEqual(len(vm_ids), 1, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 1"))

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 300)
        self.assertTrue(
            all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_47_addresource_noconfig(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('POST', "/infrastructures/" + self.inf_id + "?context=0",
                       body=RADL_ADD, headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR adding resources:" + output)

    def test_50_removeresource_noconfig(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/" + self.inf_id + "?context=0",
                       headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")

        vm_uri = uriparse(vm_ids[1])
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('DELETE', vm_uri[2], headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR removing resources:" + output)

        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('GET', "/infrastructures/" + self.inf_id,
                       headers={'AUTHORIZATION': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")
        self.assertEqual(len(vm_ids), 1, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 1"))

    def test_95_destroy(self):
        before = time.time()
        server = httplib.HTTPConnection(HOSTNAME, TEST_PORT)
        server.request('DELETE', "/infrastructures/" + self.inf_id,
                       headers={'Authorization': self.auth_data})
        resp = server.getresponse()
        output = str(resp.read())
        server.close()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)
        self.assertEqual(resp.status, 200,
                         msg="ERROR destroying the infrastructure:" + output)


def test(num_client):
    now = datetime.datetime.now()
    print now, ": Launch client num: %d" % num_client
    unittest.main()
    now = datetime.datetime.now()
    print now, ": End client num: %d" % num_client

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

    cont = 0
    while cont < MAX_CLIENTS:
        num_treads = min(MAX_CLIENTS - cont, MAX_THREADS)
        processes = []
        now = datetime.datetime.now()
        print now, ": Launch %d threads. " % num_treads
        for num in range(num_treads):
            p = Process(target=test, args=(cont + num,))
            p.start()
            processes.append(p)
            time.sleep(DELAY)
        for p in processes:
            p.join()
        cont += num_treads
        now = datetime.datetime.now()
        print now, ": End %d threads. " % num_treads
