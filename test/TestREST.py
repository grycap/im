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
import json

from IM.VirtualMachine import VirtualMachine
from IM.uriparse import uriparse
from IM.radl import radl_parse

PID = None
RADL_ADD = "network publica\nsystem front\ndeploy front 1"
RADL_ADD_ERROR = "system wnno deploy wnno 1"
TESTS_PATH = '/home/micafer/codigo/git_im/im/test'
RADL_FILE = TESTS_PATH + '/test_simple.radl'
AUTH_FILE = TESTS_PATH + '/auth.dat'

HOSTNAME = "jonsu.i3m.upv.es"
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
        try:
            cls.server.request('DELETE', "/infrastructures/" + cls.inf_id, headers = {'Authorization' : cls.auth_data})
            cls.server.getresponse()
        except Exception, ex:
            print "Error deleting the infrastructure: ", ex

    def wait_inf_state(self, state, timeout):
        self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertIs(resp.status, 200, msg="ERROR al obtener la informacion de la infraestructura:" + output)
        
        output_obj = json.loads(output)
        
        self.assertIs(len(output_obj), 2, msg="ERROR al obtener la informacion de la infraestructura: Numero incorrecto de VMs(" + str(len(output_obj)) + ") deberia ser 2")

        vm_ids = output_obj['vm_list']

        err_states = [VirtualMachine.FAILED, VirtualMachine.OFF]

        wait = 0
        all_ok = False
        while not all_ok and wait < timeout:
            all_ok = True
            for vm_id in vm_ids:
                vm_uri = uriparse(vm_id)
                self.server.request('GET', vm_uri[2], headers = {'AUTHORIZATION' : self.auth_data})
                resp = self.server.getresponse()
                output = str(resp.read())
                self.assertIs(resp.status, 200, msg="ERROR al obtener la informacion de la VM:" + output)
                info_radl = radl_parse.parse_radl(output)
                vm_state = info_radl.systems[0].getValue('state')

                if vm_state in err_states:
                    return False
                elif vm_state != state:
                    all_ok = False

            if not all_ok:
                wait += 5
                time.sleep(5)

        return all_ok

    def test_10_list(self):
        self.server.request('GET', "/infrastructures", headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertIs(resp.status, 200, msg="ERROR al listar las infraestructuras:" + output)

    def test_11_create(self):
        f = open(RADL_FILE)
        radl = ""
        for line in f.readlines():
            radl += line
        f.close()

        self.server.request('POST', "/infrastructures", body = radl, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertIs(resp.status, 200, msg="ERROR creating the infrastructure:" + output)

        self.__class__.inf_id = str(os.path.basename(output))
        
        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(all_configured, msg="ERROR al esperar la creacion de la Infraestructura.")

    def test_14_get_vm_info(self):
        self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertIs(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        output_obj = json.loads(output)
        vm_ids = output_obj['vm_list']

        vm_uri = uriparse(vm_ids[0])
        self.server.request('GET', vm_uri[2], headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertIs(resp.status, 200, msg="ERROR al obtener la informacion de la VM:" + output)

    def test_18_addresource(self):
        self.server.request('POST', "/infrastructures/" + self.inf_id, body = RADL_ADD, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertIs(resp.status, 200, msg="ERROR al anaydir recursos a la infraestructura:" + output)

        self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertIs(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        output_obj = json.loads(output)
        vm_ids = output_obj['vm_list']
        self.assertIs(len(vm_ids), 2, msg="ERROR al obtener la informacion de la infraestructura: Numero incorrecto de VMs(" + str(len(vm_ids)) + ") deberia ser 3")
        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(all_configured, msg="ERROR al esperar la creacion de la Infraestructura.")

    def test_19_removeresource(self):
        self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertIs(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        output_obj = json.loads(output)
        vm_ids = output_obj['vm_list']
        
        vm_uri = uriparse(vm_ids[1])
        self.server.request('DELETE', vm_uri[2], headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertIs(resp.status, 200, msg="ERROR al borrar recursos de la infraestructura:" + output)

        self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertIs(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        output_obj = json.loads(output)
        vm_ids = output_obj['vm_list']
        self.assertIs(len(vm_ids), 1, msg="ERROR al obtener la informacion de la infraestructura: Numero incorrecto de VMs(" + str(len(vm_ids)) + ") deberia ser 2")

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 300)
        self.assertTrue(all_configured, msg="ERROR al esperar la eliminacion de un nodo a la Infraestructura.")

    def test_20_stop(self):
        self.server.request('PUT', "/infrastructures/" + self.inf_id + "/stop", headers = {"Content-type": "application/x-www-form-urlencoded", 'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertIs(resp.status, 200, msg="ERROR al parar la infraestructura:" + output)

        all_stopped = self.wait_inf_state(VirtualMachine.STOPPED, 120)
        self.assertTrue(all_stopped, msg="ERROR al esperar la parada de la Infraestructura.")

    def test_21_start(self):
        self.server.request('PUT', "/infrastructures/" + self.inf_id + "/start", headers = {"Content-type": "application/x-www-form-urlencoded", 'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertIs(resp.status, 200, msg="ERROR al parar la infraestructura:" + output)

        all_stopped = self.wait_inf_state(VirtualMachine.CONFIGURED, 120)
        self.assertTrue(all_stopped, msg="ERROR al esperar la parada de la Infraestructura.")

    def test_50_destroy(self):
        self.server.request('DELETE', "/infrastructures/" + self.inf_id, headers = {'Authorization' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertIs(resp.status, 200, msg="ERROR al borrar la infraestructura:" + output)

if __name__ == '__main__':
    unittest.main()
