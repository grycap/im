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

    def test_10_list(self):
        resp = self.create_request("GET", "/infrastructures")
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR listing user infrastructures:" + resp.text)

        if resp.text:
            for inf_id in resp.text.split("\n"):
                inf_id = os.path.basename(inf_id)
                self.getinfo(inf_id)
                self.getstate(inf_id)

    def getinfo(self, inf_id):
        resp = self.create_request("GET", "/infrastructures/" + inf_id)
        self.assertEqual(resp.status_code, 200,
                         msg="ERROR getting the infrastructure info:" + resp.text)

    def getstate(self, inf_id):
        resp = self.create_request("GET", "/infrastructures/" + inf_id + "/state")
        self.assertEqual(
            resp.status_code, 200, msg="ERROR getting the infrastructure state:" + resp.text)
        res = json.loads(resp.text)
        state = res['state']['state']
        vm_states = res['state']['vm_states']
        print(inf_id, " ", state)


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
        DELAY = float(sys.argv[3])
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
