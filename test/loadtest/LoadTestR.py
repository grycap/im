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

TESTS_PATH = os.path.dirname(os.path.realpath(__file__))
AUTH_FILE = TESTS_PATH + '/auth.dat'
HOSTNAME = "imservice"
TEST_PORT = 8899
MIN_SLEEP = 1
MAX_SLEEP = 10


class LoadTest(unittest.TestCase):

    server = None
    auth_data = None
    response_times = []

    @classmethod
    def setUpClass(cls):
        cls.server = ServerProxy("http://" + HOSTNAME + ":" + str(TEST_PORT), allow_none=True)
        cls.auth_data = Authentication.read_auth_data(AUTH_FILE)

    @staticmethod
    def wait(mint=MIN_SLEEP, maxt=MAX_SLEEP):
        delay = random.uniform(mint, maxt)
        time.sleep(delay)

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

        for inf_id in res:
            self.getinfo(inf_id)
            self.getstate(inf_id)

        self.print_response_times()

    def getinfo(self, inf_id):
        """
        Test the GetVMInfo IM function
        """
        before = time.time()
        (success, vm_ids) = self.server.GetInfrastructureInfo(
            inf_id, self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureInfo: " + str(vm_ids))

        self.wait()

    def getstate(self, inf_id):
        """
        Test the GetInfrastructureState IM function
        """
        before = time.time()
        (success, res) = self.server.GetInfrastructureState(
            inf_id, self.auth_data)
        resp_time = time.time() - before
        self.__class__.response_times.append(resp_time)

        self.assertTrue(
            success, msg="ERROR calling GetInfrastructureState: " + str(res))
        self.wait()

    def print_response_times(self):
        total = 0.0
        for time in self.response_times:
            total += time
        print("Mean Time: %.4f" % (total / len(self.response_times)))


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
