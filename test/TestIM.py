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
import xmlrpclib
import time

from IM.auth import Authentication
from IM.VirtualMachine import VirtualMachine
from IM.radl import radl_parse

RADL_ADD = "network publica\nnetwork privada\nsystem wn\ndeploy wn 1 one"
RADL_ADD_ERROR = "system wnno deploy wnno 1"
TESTS_PATH = '/home/micafer/codigo/git_im/im/test'
RADL_FILE = TESTS_PATH + '/test.radl'
#RADL_FILE =  TESTS_PATH + '/test_ec2.radl'
AUTH_FILE = TESTS_PATH + '/auth.dat'

HOSTNAME = "localhost"
TEST_PORT = 8899

class TestIM(unittest.TestCase):

    server = None
    auth_data = None
    inf_id = 0

    @classmethod
    def setUpClass(cls):
        cls.server = xmlrpclib.ServerProxy("http://" + HOSTNAME + ":" + str(TEST_PORT),allow_none=True)
        cls.auth_data = Authentication.read_auth_data(AUTH_FILE)
        cls.inf_id = 0

    @classmethod
    def tearDownClass(cls):
        # Por si acaso la borro
        try:
            cls.server.DestroyInfrastructure(cls.inf_id, cls.auth_data)
        except Exception, ex:
            print "Error al matar el servicio: ", ex

    def wait_inf_state(self, state, timeout):
        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR al obtener la informacion de la infraestructura:" + str(res))
        self.assertEqual(len(res), 2, msg="ERROR al obtener la informacion de la infraestructura: Numero incorrecto de VMs(" + str(len(res)) + ") deberia ser 2")

        vm_ids = res['vm_list']

        err_states = [VirtualMachine.FAILED, VirtualMachine.OFF]

        wait = 0
        all_ok = False
        while not all_ok and wait < timeout:
            all_ok = True
            for vm_id in vm_ids:
                (success, info)  = self.server.GetVMInfo(self.inf_id, vm_id, self.auth_data)
                self.assertTrue(success, msg="ERROR al obtener la informacion de la VM:" + str(res))
                
                info_radl = radl_parse.parse_radl(info)
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
        (success, res) = self.server.GetInfrastructureList(self.auth_data)
        self.assertTrue(success, msg="ERROR al listar las infraestructuras: " + str(res))

    def test_11_create(self):
        f = open(RADL_FILE)
        radl = ""
        for line in f.readlines():
            radl += line
        f.close()

        (success, inf_id) = self.server.CreateInfrastructure(radl, self.auth_data)
        self.assertTrue(success, msg="ERROR creating the infrastructure: " + str(inf_id))
        self.__class__.inf_id = inf_id

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 900)
        self.assertTrue(all_configured, msg="ERROR al esperar la creacion de la Infraestructura.")

    def test_13_getcontmsg(self):
        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR getting the infrastructure info: " + str(res))
        cont_out = res['cont_out']
        self.assertGreater(len(cont_out), 100, msg="Mensaje que contextualizacion incorrecto: " + cont_out)

    def test_14_get_vm_info(self):
        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR getting the infrastructure info: " + str(res))
        vm_ids = res['vm_list']
        (success, info)  = self.server.GetVMInfo(self.inf_id, vm_ids[0], self.auth_data)
        self.assertTrue(success, msg="ERROR al obtener la informacion de la VM: " + str(info))
        try:
            radl_parse.parse_radl(info)
        except Exception, ex:
            self.assertTrue(False, msg="ERROR al parsear el RADL con la informacion de la VM: " + str(ex))            

    def test_15_get_ganglia_info(self):
        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR getting the infrastructure info: " + str(res))
        vm_ids = res['vm_list']
        (success, info)  = self.server.GetVMInfo(self.inf_id, vm_ids[0], self.auth_data)
        self.assertEqual(success, True, msg="ERROR al obtener la informacion de la VM: " + str(info))
        info_radl = radl_parse.parse_radl(info)
        prop_usage = info_radl.systems[0].getValue("cpu.usage")
        self.assertIsNotNone(prop_usage, msg="ERROR al obtener la informacion de ganglia de la VM (cpu.usage = None)")

    def test_17_error_addresource(self):
        (success, res) = self.server.AddResource(self.inf_id, RADL_ADD_ERROR, self.auth_data)
        self.assertFalse(success, msg="No da error al anaydir recursos incorrectamenta a la infraestructura")
        pos = res.find("Unknown reference in RADL")
        self.assertGreater(pos, -1, msg="Mensaje de error incorrecto: " + res)

    def test_18_addresource(self):
        (success, res) = self.server.AddResource(self.inf_id, RADL_ADD, self.auth_data)
        self.assertTrue(success, msg="ERROR al anaydir recursos a la infraestructura: " + str(res))

        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR al obtener la informacion de la infraestructura:" + str(res))
        vm_ids = res['vm_list']
        self.assertEqual(len(vm_ids), 3, msg="ERROR al obtener la informacion de la infraestructura: Numero incorrecto de VMs(" + str(len(vm_ids)) + ") deberia ser 3")

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 900)
        self.assertTrue(all_configured, msg="ERROR al esperar la adicion de un nodo a la Infraestructura.")

    def test_19_removeresource(self):
        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        vm_ids = res['vm_list']

        (success, res) = self.server.RemoveResource(self.inf_id, vm_ids[2], self.auth_data)
        self.assertTrue(success, msg="ERROR al borrar recursos de la infraestructura: " + str(res))

        (success, res) = self.server.GetInfrastructureInfo(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR al obtener la informacion de la infraestructura:" + str(res))
        vm_ids = res['vm_list']
        self.assertEqual(len(vm_ids), 2, msg="ERROR al obtener la informacion de la infraestructura: Numero incorrecto de VMs(" + str(len(vm_ids)) + ") deberia ser 2")

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(all_configured, msg="ERROR al esperar la eliminacion de un nodo a la Infraestructura.")

    def test_20_stop(self):
        (success, res) = self.server.StopInfrastructure(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR al parar la infraestructura: " + str(res))

        all_stopped = self.wait_inf_state(VirtualMachine.STOPPED, 120)
        self.assertTrue(all_stopped, msg="ERROR al esperar la parada de la Infraestructura.")

    def test_21_start(self):
        (success, res) = self.server.StartInfrastructure(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR al iniciar la infraestructura: " + str(res))

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 120)
        self.assertTrue(all_configured, msg="ERROR al esperar la iniciada de la Infraestructura.")

    def test_50_destroy(self):
        (success, res) = self.server.DestroyInfrastructure(self.inf_id, self.auth_data)
        self.assertTrue(success, msg="ERROR al borrar la infraestructura: " + str(res))

if __name__ == '__main__':
    unittest.main()
