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
try:
    from xmlrpclib import ServerProxy
except ImportError:
    from xmlrpc.client import ServerProxy

sys.path.append("..")
sys.path.append(".")

from IM.auth import Authentication
from IM.VirtualMachine import VirtualMachine
from radl import radl_parse
from IM import __version__ as version

RADL_ADD = "network publica\nnetwork privada\nsystem wn\ndeploy wn 1"
TESTS_PATH = os.path.dirname(os.path.realpath(__file__))
RADL_FILE = TESTS_PATH + '/load-test.radl'
AUTH_FILE = TESTS_PATH + '/auth.dat'
HOSTNAME = "imservice"
TEST_PORT = 8899
MIN_SLEEP = 1
MAX_SLEEP = 10


class LoadTest(unittest.TestCase):

    server = None
    auth_data = None
    inf_id = 0
    response_times = []

    @classmethod
    def setUpClass(cls):
        cls.server = ServerProxy("http://" + HOSTNAME + ":" + str(TEST_PORT), allow_none=True)
        cls.auth_data = Authentication.read_auth_data(AUTH_FILE)
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

    def wait_inf_state(self, states, timeout, incorrect_states=None, vm_ids=None):
        """
        Wait for an infrastructure to have a specific state
        """
        if not vm_ids:
            before = time.time()
            (success, vm_ids) = self.server.GetInfrastructureInfo(
                self.inf_id, self.auth_data)
            resp_time = time.time() - before
            self.__class__.response_times.append(resp_time)

            self.assertTrue(
                success, msg="ERROR calling the GetInfrastructureInfo function:" + str(vm_ids))

        err_states = [VirtualMachine.FAILED, VirtualMachine.OFF]
        if incorrect_states:
            err_states.extend(incorrect_states)

        wait = 0
        all_ok = False
        while not all_ok and wait < timeout:
            all_ok = True
            for vm_id in vm_ids:
                before = time.time()
                (success, vm_state) = self.server.GetVMProperty(
                    self.inf_id, vm_id, "state", self.auth_data)
                resp_time = time.time() - before
                self.__class__.response_times.append(resp_time)

                self.assertTrue(
                    success, msg="ERROR getting VM info:" + str(vm_state))

                self.assertFalse(vm_state in err_states, msg="ERROR waiting for a state. '" + vm_state +
                                 "' was obtained in the VM: " + str(vm_id) + " err_states = " + str(err_states))

                if vm_state in err_states:
                    return False
                elif vm_state not in states:
                    all_ok = False

            if not all_ok:
                wait += 5
                time.sleep(5)

        return all_ok

    def test_05_getversion(self):
        """
        Test the GetVersion IM function
        """
        before = time.time()
        (success, res) = self.server.GetVersion()
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(success, msg="ERROR calling GetVersion: " + str(res))
        self.assertEqual(
            res, version, msg="Incorrect version. Expected %s, obtained: %s" % (version, res))
        self.wait()

    def test_10_list(self):
        """
        Test the GetInfrastructureList IM function
        """
        before = time.time()
        (success, res) = self.server.GetInfrastructureList(self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureList: " + str(res))
        self.wait()

    def test_11_create(self):
        """
        Test the CreateInfrastructure IM function
        """
        f = open(RADL_FILE)
        radl = ""
        for line in f.readlines():
            radl += line
        f.close()

        before = time.time()
        (success, inf_id) = self.server.CreateInfrastructure(radl, self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(
            success, msg="ERROR calling CreateInfrastructure: " + str(inf_id))
        self.__class__.inf_id = inf_id

        self.wait_inf_state([VirtualMachine.CONFIGURED], 900)

    def test_12_getradl(self):
        """
        Test the GetInfrastructureRADL IM function
        """
        before = time.time()
        (success, res) = self.server.GetInfrastructureRADL(
            self.inf_id, self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureRADL: " + str(res))
        try:
            radl_parse.parse_radl(res)
        except Exception as ex:
            self.assertTrue(
                False, msg="ERROR parsing the RADL returned by GetInfrastructureRADL: " + str(ex))
        self.wait()

    def test_13_getcontmsg(self):
        """
        Test the GetInfrastructureContMsg IM function
        """
        before = time.time()
        (success, cont_out) = self.server.GetInfrastructureContMsg(
            self.inf_id, self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureContMsg: " + str(cont_out))
        self.wait()

    def test_14_getvmcontmsg(self):
        """
        Test the GetVMContMsg IM function
        """
        before = time.time()
        (success, res) = self.server.GetVMContMsg(
            self.inf_id, 0, self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(success, msg="ERROR calling GetVMContMsg: " + str(res))
        self.wait()

    def test_15_get_vm_info(self):
        """
        Test the GetVMInfo IM function
        """
        before = time.time()
        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureInfo: " + str(vm_ids))

        before = time.time()
        (success, info) = self.server.GetVMInfo(
            self.inf_id, vm_ids[0], self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(success, msg="ERROR calling GetVMInfo: " + str(info))
        try:
            radl_parse.parse_radl(info)
        except Exception as ex:
            self.assertTrue(
                False, msg="ERROR parsing the RADL returned by GetVMInfo: " + str(ex))
        self.wait()

    def test_16_get_vm_property(self):
        """
        Test the GetVMProperty IM function
        """
        before = time.time()
        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureInfo: " + str(vm_ids))

        before = time.time()
        (success, info) = self.server.GetVMProperty(
            self.inf_id, vm_ids[0], "state", self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(
            success, msg="ERROR calling GetVMProperty: " + str(info))
        self.assertNotEqual(
            info, None, msg="ERROR in the value returned by GetVMProperty: " + info)
        self.assertNotEqual(
            info, "", msg="ERROR in the value returned by GetVMPropert: " + info)
        self.wait()

    def test_19_addresource(self):
        """
        Test AddResource function
        """
        before = time.time()
        (success, res) = self.server.AddResource(
            self.inf_id, RADL_ADD, self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(success, msg="ERROR calling AddResource: " + str(res))

        before = time.time()
        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureInfo:" + str(vm_ids))
        self.assertEqual(len(vm_ids), 2, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 2"))

        self.wait_inf_state([VirtualMachine.CONFIGURED], 300)

    def test_20_getstate(self):
        """
        Test the GetInfrastructureState IM function
        """
        before = time.time()
        (success, res) = self.server.GetInfrastructureState(
            self.inf_id, self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureState: " + str(res))
        self.wait()

    def test_23_removeresource(self):
        """
        Test RemoveResource function
        """
        before = time.time()
        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureInfo: " + str(vm_ids))

        before = time.time()
        (success, res) = self.server.RemoveResource(
            self.inf_id, vm_ids[-1], self.auth_data, False)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(
            success, msg="ERROR calling RemoveResource: " + str(res))

        before = time.time()
        (success, vm_ids) = self.server.GetInfrastructureInfo(
            self.inf_id, self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureInfo:" + str(vm_ids))
        self.assertEqual(len(vm_ids), 1, msg=("ERROR getting infrastructure info: Incorrect number of VMs(" +
                                              str(len(vm_ids)) + "). It must be 1"))

        self.wait_inf_state([VirtualMachine.CONFIGURED], 300)

    def print_response_times(self):
        total = 0.0
        for time in self.response_times:
            total += time
        print("Mean Time: %.4f" % (total / len(self.response_times)))

    def test_50_destroy(self):
        """
        Test DestroyInfrastructure function
        """
        before = time.time()
        (success, res) = self.server.DestroyInfrastructure(
            self.inf_id, self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.print_response_times()

        self.assertTrue(
            success, msg="ERROR calling DestroyInfrastructure: " + str(res))

        self.wait()


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

    cont = 0
    while cont < MAX_CLIENTS:
        num_treads = min(MAX_CLIENTS - cont, MAX_THREADS)
        processes = []
        now = datetime.datetime.now()
        print(now, ": Launch %d threads. " % num_treads)
        for num in range(num_treads):
            p = Process(target=test, args=(cont + num,))
            p.start()
            processes.append(p)
            time.sleep(DELAY)
        for p in processes:
            p.join()
        cont += num_treads
        now = datetime.datetime.now()
        print(now, ": End %d threads. " % num_treads)
