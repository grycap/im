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

import sys
import unittest
import time
import logging
import logging.config

sys.path.append("..")
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
from IM.VirtualMachine import VirtualMachine
from IM.VMRC import VMRC
from IM.InfrastructureInfo import InfrastructureInfo

TESTS_PATH = '/home/micafer/codigo/git_im/im/test'
AUTH_FILE = TESTS_PATH + '/auth.dat'

auth = Authentication(Authentication.read_auth_data(AUTH_FILE))
cloud_list = dict([(c.id, c.getCloudConnector())
                   for c in CloudInfo.get_cloud_list(auth)])


class TestConnectors(unittest.TestCase):
    """
    Class to test the IM connectors
    """

    vm_list = []
    """ List of VMs launched in the test """

    # connectors_to_test = "all"
    connectors_to_test = ["fogbow"]
    """ Specify the connectors to test: "all": All the connectors specified in the auth file or a list with the IDs"""

    @classmethod
    def setUpClass(cls):
        ch = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)

        logging.RootLogger.propagate = 0
        logging.root.setLevel(logging.ERROR)

        logger = logging.getLogger('CloudConnector')
        logger.setLevel(logging.DEBUG)
        logger.propagate = 0
        logger.addHandler(ch)

    def concrete_systems_with_vmrc(self, radl):
        # Get VMRC credentials
        vmrc_list = []
        for vmrc_elem in auth.getAuthInfo('VMRC'):
            if ('host' in vmrc_elem and 'username' in vmrc_elem and
                    'password' in vmrc_elem):
                vmrc_list.append(VMRC(vmrc_elem['host'], vmrc_elem['username'],
                                      vmrc_elem['password']))

        # Concrete systems using VMRC
        res = []
        for vmrc in vmrc_list:
            vmrc_res = vmrc.search_vm(radl)
            res.extend([radl.clone().applyFeatures(s0, conflict="other", missing="other")
                        for s0 in vmrc_res])

        return res

    def test_10_concrete(self):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            #disks.free_size>=2g and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.flavour='ubuntu' and
            disk.0.os.version>='12.04'
            #disk.0.os.flavour='centos' and
            #disk.0.os.version>='6'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        for cloud_id, cloud in cloud_list.items():
            if self.connectors_to_test == "all" or cloud_id in self.connectors_to_test:
                systems = self.concrete_systems_with_vmrc(radl_system)
                concrete_systems = []
                for s in systems:
                    concrete_systems.extend(cloud.concreteSystem(s, auth))
                self.assertTrue(len(
                    concrete_systems) > 0, msg="ERROR: no system returned by concreteSystems for cloud: " + cloud_id)

    def test_20_launch(self):
        radl_data = """
            network net (outbound='yes' and outports='8899/tcp,22/tcp-22/tcp')
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            #memory.size>=1024m and
            #disks.free_size>=2g and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.flavour='ubuntu' and
            disk.0.os.version>='12.04' and
            disk.0.os.credentials.new.password = 'Passtest+01' and
            #disk.0.os.flavour='centos' and
            #disk.0.os.version>='6' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()
        radl_system = radl.systems[0]

        for cloud_id, cloud in cloud_list.items():
            if self.connectors_to_test == "all" or cloud_id in self.connectors_to_test:
                systems = self.concrete_systems_with_vmrc(radl_system)
                concrete_systems = []
                for s in systems:
                    concrete_systems.extend(cloud.concreteSystem(s, auth))
                self.assertTrue(len(
                    concrete_systems) > 0, msg="ERROR: no system returned by concreteSystems for cloud: " + cloud_id)

                launch_radl = radl.clone()
                launch_radl.systems = [concrete_systems[0]]
                res = cloud.launch(InfrastructureInfo(),
                                   launch_radl, launch_radl, 1, auth)
                for success, vm in res:
                    self.assertTrue(
                        success, msg="ERROR: launching a VM for cloud: " + cloud_id)
                    self.__class__.vm_list.append(vm)

    def test_30_updateVMInfo(self):
        for vm in self.vm_list:
            cl = vm.cloud.getCloudConnector()
            (success, new_vm) = cl.updateVMInfo(vm, auth)
            self.assertTrue(
                success, msg="ERROR: getting VM info for cloud: " + vm.cloud.id + ": " + str(new_vm))

    def wait_vm_state(self, cl, vm, state, timeout):
        # wait the VM to be stopped
        errors = 0
        max_errors = 3
        wait = 0
        err_states = [VirtualMachine.FAILED,
                      VirtualMachine.OFF, VirtualMachine.UNCONFIGURED]
        while vm.state != state and wait < timeout:

            self.assertFalse(vm.state in err_states, msg="ERROR waiting for a state. '" + vm.state +
                             "' was obtained in the VM: " + str(vm.id) + " err_states = " + str(err_states))

            try:
                (success, new_vm) = cl.updateVMInfo(vm, auth)
            except:
                success = False
                pass
            if success:
                vm = new_vm
                wait += 5
                time.sleep(5)
            elif errors < max_errors:
                errors += 1
                wait += 5
                time.sleep(5)
            else:
                return False

        return vm.state == state

    def test_40_stop(self):
        for vm in self.vm_list:
            cl = vm.cloud.getCloudConnector()

            # wait the VM to be running
            wait_ok = self.wait_vm_state(cl, vm, VirtualMachine.RUNNING, 240)

            self.assertTrue(
                wait_ok, msg="ERROR: waiting stop op VM for cloud: " + vm.cloud.id)

            (success, msg) = cl.stop(vm, auth)
            self.assertTrue(
                success, msg="ERROR: stopping VM for cloud: " + vm.cloud.id + ": " + str(msg))

            # wait the VM to be stopped
            wait_ok = self.wait_vm_state(cl, vm, VirtualMachine.STOPPED, 240)

            self.assertTrue(
                wait_ok, msg="ERROR: waiting stop op VM for cloud: " + vm.cloud.id)

    def test_50_start(self):
        for vm in self.vm_list:
            cl = vm.cloud.getCloudConnector()
            (success, msg) = cl.start(vm, auth)
            self.assertTrue(
                success, msg="ERROR: starting VM for cloud: " + vm.cloud.id + ": " + str(msg))
            # wait the VM to be running again
            wait_ok = self.wait_vm_state(cl, vm, VirtualMachine.RUNNING, 180)
            self.assertTrue(
                wait_ok, msg="ERROR: waiting start op VM for cloud: " + vm.cloud.id)

    def test_55_alter(self):
        radl_data = """
            system test (
            cpu.count>=2 and
            memory.size>=2048m
            )"""
        radl = radl_parse.parse_radl(radl_data)
        for vm in self.vm_list:
            cl = vm.cloud.getCloudConnector()
            (success, msg) = cl.alterVM(vm, radl, auth)
            self.assertTrue(
                success, msg="ERROR: updating VM for cloud: " + vm.cloud.id + ": " + str(msg))
            # wait the VM to resize
            time.sleep(30)
            # get the updated vm
            (success, new_vm) = cl.updateVMInfo(vm, auth)
            new_cpu = new_vm.info.systems[0].getValue('cpu.count')
            new_memory = new_vm.info.systems[
                0].getFeature('memory.size').getValue('M')
            self.assertGreaterEqual(
                new_cpu, 2, msg="ERROR: updating VM for cloud: " + vm.cloud.id + ". CPU num must at least 2.")
            self.assertGreaterEqual(new_memory, 1024, msg="ERROR: updating VM for cloud: " +
                                    vm.cloud.id + ". Memory must be at least 1024M.")

    def test_60_finalize(self):
        for vm in self.vm_list:
            cl = vm.cloud.getCloudConnector()
            (success, msg) = cl.finalize(vm, auth)
            self.assertTrue(
                success, msg="ERROR: finalizing VM for cloud: " + vm.cloud.id + ": " + str(msg))


if __name__ == '__main__':
    unittest.main()
