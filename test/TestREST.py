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
from IM.radl import radl_parse

PID = None
RADL_ADD = "network publica\nsystem front\ndeploy front 1"
RADL_ADD_ERROR = "system wnno deploy wnno 1"
TESTS_PATH = os.path.dirname(os.path.realpath(__file__))
RADL_FILE = TESTS_PATH + '/test_simple.radl'
AUTH_FILE = TESTS_PATH + '/auth.dat'

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
            cls.server.request('DELETE', "/infrastructures/" + cls.inf_id, headers = {'Authorization' : cls.auth_data})
            cls.server.getresponse()
        except Exception:
            pass

    def wait_inf_state(self, state, timeout, incorrect_states = [], vm_ids = None):
        """
        Wait for an infrastructure to have a specific state
        """
        if not vm_ids:
            self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
            resp = self.server.getresponse()
            output = str(resp.read())
            self.assertEqual(resp.status, 200, msg="ERROR getting infrastructure info:" + output)
            
            vm_ids = output.split("\n")
        else:
            pass

        err_states = [VirtualMachine.FAILED, VirtualMachine.OFF, VirtualMachine.UNCONFIGURED]
        err_states.extend(incorrect_states)

        wait = 0
        all_ok = False
        while not all_ok and wait < timeout:
            all_ok = True
            for vm_id in vm_ids:
                vm_uri = uriparse(vm_id)
                self.server.request('GET', vm_uri[2] + "/state", headers = {'AUTHORIZATION' : self.auth_data})
                resp = self.server.getresponse()
                vm_state = str(resp.read())
                self.assertEqual(resp.status, 200, msg="ERROR getting VM info:" + vm_state)

                self.assertFalse(vm_state in err_states, msg="ERROR waiting for a state. '%s' state was expected and '%s' was obtained in the VM %s" % (state, vm_state, vm_uri))

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
        self.assertEqual(resp.status, 200, msg="ERROR listing user infrastructures:" + output)
        
    def test_15_get_incorrect_info(self):
        self.server.request('GET', "/infrastructures/999999", headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404, msg="Incorrect error message: " + str(resp.status))

    def test_18_get_info_without_auth_data(self):
        self.server.request('GET', "/infrastructures/0")
        resp = self.server.getresponse()
        resp.read()
        self.assertEqual(resp.status, 401, msg="Incorrect error message: " + str(resp.status))

    def test_20_create(self):
        f = open(RADL_FILE)
        radl = ""
        for line in f.readlines():
            radl += line
        f.close()

        self.server.request('POST', "/infrastructures", body = radl, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR creating the infrastructure:" + output)

        self.__class__.inf_id = str(os.path.basename(output))
        
        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_30_get_vm_info(self):
        self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")

        vm_uri = uriparse(vm_ids[0])
        self.server.request('GET', vm_uri[2], headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting VM info:" + output)
        
    def test_32_get_vm_contmsg(self):
        self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")

        vm_uri = uriparse(vm_ids[0])
        self.server.request('GET', vm_uri[2] + "/contmsg", headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting VM contmsg:" + output)
        self.assertEqual(len(output), 0, msg="Incorrect VM contextualization message: " + output)
        
    def test_33_get_contmsg(self):
        self.server.request('GET', "/infrastructures/" + self.inf_id + "/contmsg", headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        self.assertGreater(len(output), 30, msg="Incorrect contextualization message: " + output)
        
    def test_34_get_radl(self):
        self.server.request('GET', "/infrastructures/" + self.inf_id + "/radl", headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting the infrastructure RADL:" + output)
        try:
            radl_parse.parse_radl(output)
        except Exception, ex:
            self.assertTrue(False, msg="ERROR parsing the RADL returned by GetInfrastructureRADL: " + str(ex))
        
    def test_35_get_vm_property(self):
        self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")

        vm_uri = uriparse(vm_ids[0])
        self.server.request('GET', vm_uri[2] + "/state", headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting VM property:" + output)

    def test_40_addresource(self):
        self.server.request('POST', "/infrastructures/" + self.inf_id, body = RADL_ADD, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR adding resources:" + output)

        self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")
        self.assertEqual(len(vm_ids), 2, msg="ERROR getting infrastructure info: Incorrect number of VMs(" + str(len(vm_ids)) + "). It must be 2")
        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")
        
    def test_45_getstate(self):
        self.server.request('GET', "/infrastructures/" + self.inf_id + "/state", headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting the infrastructure state:" + output)
        res = json.loads(output)
        state = res['state']
        vm_states = res['vm_states']
        self.assertEqual(state, "configured", msg="Unexpected inf state: " + state + ". It must be 'configured'.")
        for vm_id, vm_state in vm_states.iteritems():
            self.assertEqual(vm_state, "configured", msg="Unexpected vm state: " + vm_state + " in VM ID " + str(vm_id) + ". It must be 'configured'.")

    def test_46_removeresource(self):
        self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")
        
        vm_uri = uriparse(vm_ids[1])
        self.server.request('DELETE', vm_uri[2], headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR removing resources:" + output)

        self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")
        self.assertEqual(len(vm_ids), 1, msg="ERROR getting infrastructure info: Incorrect number of VMs(" + str(len(vm_ids)) + "). It must be 1")

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 300)
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_47_addresource_noconfig(self):
        self.server.request('POST', "/infrastructures/" + self.inf_id + "?context=0", body = RADL_ADD, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR adding resources:" + output)

    def test_50_removeresource_noconfig(self):
        self.server.request('GET', "/infrastructures/" + self.inf_id + "?context=0", headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")
        
        vm_uri = uriparse(vm_ids[1])
        self.server.request('DELETE', vm_uri[2], headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR removing resources:" + output)

        self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")
        self.assertEqual(len(vm_ids), 1, msg="ERROR getting infrastructure info: Incorrect number of VMs(" + str(len(vm_ids)) + "). It must be 1")

    def test_55_reconfigure(self):
        self.server.request('PUT', "/infrastructures/" + self.inf_id + "/reconfigure", headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR reconfiguring:" + output)
        
        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 300)
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_57_reconfigure_list(self):
        self.server.request('PUT', "/infrastructures/" + self.inf_id + "/reconfigure?vm_list=0", headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR reconfiguring:" + output)
        
        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 300)
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_60_stop(self):
        time.sleep(10)
        self.server.request('PUT', "/infrastructures/" + self.inf_id + "/stop", headers = {"Content-type": "application/x-www-form-urlencoded", 'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR stopping the infrastructure:" + output)
        time.sleep(10)

        all_stopped = self.wait_inf_state(VirtualMachine.STOPPED, 120, [VirtualMachine.RUNNING])
        self.assertTrue(all_stopped, msg="ERROR waiting the infrastructure to be stopped (timeout).")

    def test_70_start(self):
        # To assure the VM is stopped 
        time.sleep(10)
        self.server.request('PUT', "/infrastructures/" + self.inf_id + "/start", headers = {"Content-type": "application/x-www-form-urlencoded", 'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR starting the infrastructure:" + output)
        time.sleep(10)

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 120, [VirtualMachine.RUNNING])
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be started (timeout).")
        
    def test_80_stop_vm(self):
        time.sleep(10)
        self.server.request('PUT', "/infrastructures/" + self.inf_id + "/vms/0/stop", headers = {"Content-type": "application/x-www-form-urlencoded", 'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR stopping the vm:" + output)
        time.sleep(10)

        all_stopped = self.wait_inf_state(VirtualMachine.STOPPED, 120, [VirtualMachine.RUNNING], ["/infrastructures/" + self.inf_id + "/vms/0"])
        self.assertTrue(all_stopped, msg="ERROR waiting the infrastructure to be stopped (timeout).")
        
    def test_90_start_vm(self):
        # To assure the VM is stopped 
        time.sleep(10)
        self.server.request('PUT', "/infrastructures/" + self.inf_id + "/vms/0/start", headers = {"Content-type": "application/x-www-form-urlencoded", 'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR starting the vm:" + output)
        time.sleep(10)

        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 120, [VirtualMachine.RUNNING], ["/infrastructures/" + self.inf_id + "/vms/0"])
        self.assertTrue(all_configured, msg="ERROR waiting the vm to be started (timeout).")

    def test_92_destroy(self):
        self.server.request('DELETE', "/infrastructures/" + self.inf_id, headers = {'Authorization' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR destroying the infrastructure:" + output)
        
    def test_93_create_tosca(self):
        """
        Test the CreateInfrastructure IM function with a TOSCA document
        """
        tosca = """
tosca_definitions_version: tosca_simple_yaml_1_0
 
description: TOSCA test for the IM

repositories:
  indigo_repository:
    description: INDIGO Custom types repository
    url: https://raw.githubusercontent.com/indigo-dc/tosca-types/master/

imports:
  - indigo_custom_types:
      file: custom_types.yaml
      repository: indigo_repository

topology_template:
  inputs:
    db_name:
      type: string
      default: world
    db_user:
      type: string
      default: dbuser
    db_password:
      type: string
      default: pass
    mysql_root_password:
      type: string
      default: mypass

  node_templates:
  
    apache:
      type: tosca.nodes.WebServer.Apache
      requirements:
        - host: web_server
 
    web_server:
      type: tosca.nodes.indigo.Compute
      properties:
        public_ip: yes
      capabilities:
        # Host container properties
        host:
         properties:
           num_cpus: 1
           mem_size: 1 GB
        # Guest Operating System properties
        os:
          properties:
            # host Operating System image properties
            type: linux 
            distribution: ubuntu 
 
    test_db:
      type: tosca.nodes.indigo.Database.MySQL
      properties:
        name: { get_input: db_name }
        user: { get_input: db_user }
        password: { get_input: db_password }
        root_password: { get_input: mysql_root_password }
      artifacts:
        db_content:
          file: http://downloads.mysql.com/docs/world.sql.gz
          type: tosca.artifacts.File
      requirements:
        - host:
            node: mysql
      interfaces:
        Standard:
          configure:
            implementation: mysql/mysql_db_import.yml
            inputs:
              db_name: { get_property: [ SELF, name ] }
              db_data: { get_artifact: [ SELF, db_content ] }
              db_name: { get_property: [ SELF, name ] }
              db_user: { get_property: [ SELF, user ] }
 
    mysql:
      type: tosca.nodes.DBMS.MySQL
      properties:
        root_password: { get_input: mysql_root_password }
      requirements:
        - host:
            node: db_server
 
    db_server:
      type: tosca.nodes.Compute
      capabilities:
        # Host container properties
        host:
         properties:
           num_cpus: 1
           disk_size: 10 GB
           mem_size: 4 GB
        os:
         properties:
           architecture: x86_64
           type: linux
           distribution: ubuntu
           

  outputs:
    server_url:
      value: { get_attribute: [ web_server, public_address ] }
            """

        self.server.request('POST', "/infrastructures", body = tosca, headers = {'AUTHORIZATION' : self.auth_data, 'Content-Type':'text/yaml'})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR creating the infrastructure:" + output)

        self.__class__.inf_id = str(os.path.basename(output))
        
        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_94_get_outputs(self):
        self.server.request('GET', "/infrastructures/" + self.inf_id + "/outputs", headers = {'Authorization' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting TOSCA outputs:" + output)
        res = json.loads(output)
        server_url = str(res['server_url'][0])
        self.assertRegexpMatches(server_url, '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', msg="Unexpected outputs: " + output)

    def test_95_add_tosca(self):
        """
        Test the AddResource IM function with a TOSCA document
        """
        tosca = """
tosca_definitions_version: tosca_simple_yaml_1_0
 
description: TOSCA test for the IM

repositories:
  indigo_repository:
    description: INDIGO Custom types repository
    url: https://raw.githubusercontent.com/indigo-dc/tosca-types/master/

imports:
  - indigo_custom_types:
      file: custom_types.yaml
      repository: indigo_repository

topology_template:
  inputs:
    db_name:
      type: string
      default: world
    db_user:
      type: string
      default: dbuser
    db_password:
      type: string
      default: pass
    mysql_root_password:
      type: string
      default: mypass

  node_templates:
  
    apache:
      type: tosca.nodes.WebServer.Apache
      requirements:
        - host: web_server
 
    web_server:
      type: tosca.nodes.indigo.Compute
      properties:
        public_ip: yes
      capabilities:
        scalable:
          properties:
           count: 2
        # Host container properties
        host:
         properties:
           num_cpus: 1
           mem_size: 1 GB
        # Guest Operating System properties
        os:
          properties:
            # host Operating System image properties
            type: linux 
            distribution: ubuntu 
 
    test_db:
      type: tosca.nodes.indigo.Database.MySQL
      properties:
        name: { get_input: db_name }
        user: { get_input: db_user }
        password: { get_input: db_password }
        root_password: { get_input: mysql_root_password }
      artifacts:
        db_content:
          file: http://downloads.mysql.com/docs/world.sql.gz
          type: tosca.artifacts.File
      requirements:
        - host:
            node: mysql
      interfaces:
        Standard:
          configure:
            implementation: mysql/mysql_db_import.yml
            inputs:
              db_name: { get_property: [ SELF, name ] }
              db_data: { get_artifact: [ SELF, db_content ] }
              db_name: { get_property: [ SELF, name ] }
              db_user: { get_property: [ SELF, user ] }
 
    mysql:
      type: tosca.nodes.DBMS.MySQL
      properties:
        root_password: { get_input: mysql_root_password }
      requirements:
        - host:
            node: db_server
 
    db_server:
      type: tosca.nodes.Compute
      capabilities:
        # Host container properties
        host:
         properties:
           num_cpus: 1
           disk_size: 10 GB
           mem_size: 4 GB
        os:
         properties:
           architecture: x86_64
           type: linux
           distribution: ubuntu
           

  outputs:
    server_url:
      value: { get_attribute: [ web_server, public_address ] }
            """

        self.server.request('POST', "/infrastructures/" + self.inf_id, body = tosca, headers = {'AUTHORIZATION' : self.auth_data, 'Content-Type':'text/yaml'})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR adding resources:" + output)

        self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")
        self.assertEqual(len(vm_ids), 3, msg="ERROR getting infrastructure info: Incorrect number of VMs(" + str(len(vm_ids)) + "). It must be 2")
        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_96_remove_tosca(self):
        """
        Test the AddResource IM function with a TOSCA document
        """
        tosca = """
tosca_definitions_version: tosca_simple_yaml_1_0
 
description: TOSCA test for the IM

repositories:
  indigo_repository:
    description: INDIGO Custom types repository
    url: https://raw.githubusercontent.com/indigo-dc/tosca-types/master/

imports:
  - indigo_custom_types:
      file: custom_types.yaml
      repository: indigo_repository

topology_template:
  inputs:
    db_name:
      type: string
      default: world
    db_user:
      type: string
      default: dbuser
    db_password:
      type: string
      default: pass
    mysql_root_password:
      type: string
      default: mypass

  node_templates:
  
    apache:
      type: tosca.nodes.WebServer.Apache
      requirements:
        - host: web_server
 
    web_server:
      type: tosca.nodes.indigo.Compute
      properties:
        public_ip: yes
      capabilities:
        scalable:
          properties:
           count: 1
           removal_list: ['2']
        # Host container properties
        host:
         properties:
           num_cpus: 1
           mem_size: 1 GB
        # Guest Operating System properties
        os:
          properties:
            # host Operating System image properties
            type: linux 
            distribution: ubuntu 
 
    test_db:
      type: tosca.nodes.indigo.Database.MySQL
      properties:
        name: { get_input: db_name }
        user: { get_input: db_user }
        password: { get_input: db_password }
        root_password: { get_input: mysql_root_password }
      artifacts:
        db_content:
          file: http://downloads.mysql.com/docs/world.sql.gz
          type: tosca.artifacts.File
      requirements:
        - host:
            node: mysql
      interfaces:
        Standard:
          configure:
            implementation: mysql/mysql_db_import.yml
            inputs:
              db_name: { get_property: [ SELF, name ] }
              db_data: { get_artifact: [ SELF, db_content ] }
              db_name: { get_property: [ SELF, name ] }
              db_user: { get_property: [ SELF, user ] }
 
    mysql:
      type: tosca.nodes.DBMS.MySQL
      properties:
        root_password: { get_input: mysql_root_password }
      requirements:
        - host:
            node: db_server
 
    db_server:
      type: tosca.nodes.Compute
      capabilities:
        # Host container properties
        host:
         properties:
           num_cpus: 1
           disk_size: 10 GB
           mem_size: 4 GB
        os:
         properties:
           architecture: x86_64
           type: linux
           distribution: ubuntu
           

  outputs:
    server_url:
      value: { get_attribute: [ web_server, public_address ] }
            """

        self.server.request('POST', "/infrastructures/" + self.inf_id, body = tosca, headers = {'AUTHORIZATION' : self.auth_data, 'Content-Type':'text/yaml'})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR removing resources:" + output)

        self.server.request('GET', "/infrastructures/" + self.inf_id, headers = {'AUTHORIZATION' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR getting the infrastructure info:" + output)
        vm_ids = output.split("\n")
        self.assertEqual(len(vm_ids), 2, msg="ERROR getting infrastructure info: Incorrect number of VMs(" + str(len(vm_ids)) + "). It must be 2")
        all_configured = self.wait_inf_state(VirtualMachine.CONFIGURED, 600)
        self.assertTrue(all_configured, msg="ERROR waiting the infrastructure to be configured (timeout).")

    def test_98_destroy(self):
        self.server.request('DELETE', "/infrastructures/" + self.inf_id, headers = {'Authorization' : self.auth_data})
        resp = self.server.getresponse()
        output = str(resp.read())
        self.assertEqual(resp.status, 200, msg="ERROR destroying the infrastructure:" + output)

if __name__ == '__main__':
    unittest.main()
