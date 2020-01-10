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
import tempfile

from IM.VirtualMachine import VirtualMachine
from radl import radl_parse
from mock import patch, MagicMock


class TestVirtualMachine(unittest.TestCase):
    """
    Class to test the VirtualMachineclass
    """

    def test_apps_to_install(self):
        radl_data = """
            system test (
            disk.0.applications contains (name = 'ansible.modules.grycap.clues') and
            disk.0.applications contains (name = 'java' and version='1.9')
            )"""
        radl = radl_parse.parse_radl(radl_data)
        vm = VirtualMachine(None, "1", None, radl, radl)
        apps = vm.getAppsToInstall()
        self.assertEqual(apps[0].getValue("name"), "java")
        self.assertEqual(apps[0].getValue("version"), "1.9")

        modules = vm.getModulesToInstall()
        self.assertEqual(modules[0], "grycap.clues")

    def test_get_remote_port(self):
        radl_data = """
            system test (
            disk.0.os.name = 'linux'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        vm = VirtualMachine(None, "1", None, radl, radl)
        port = vm.getRemoteAccessPort()
        self.assertEqual(port, 22)

        radl_data = """
            network net1 (outbound = 'yes' and
                          outports = '1022-22')
            system test (
            net_interface.0.connection = 'net1' and
            disk.0.os.name = 'linux'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        vm = VirtualMachine(None, "1", None, radl, radl)
        port = vm.getRemoteAccessPort()
        self.assertEqual(port, 1022)

        radl_data = """
            system test (
            disk.0.os.name = 'windows'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        vm = VirtualMachine(None, "1", None, radl, radl)
        port = vm.getRemoteAccessPort()
        self.assertEqual(port, 5986)

        radl_data = """
            network net1 (outbound = 'yes' and
                          outports = '105986-5986')
            system test (
            net_interface.0.connection = 'net1' and
            disk.0.os.name = 'windows'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        vm = VirtualMachine(None, "1", None, radl, radl)
        port = vm.getRemoteAccessPort()
        self.assertEqual(port, 105986)

    @patch("tempfile.mkdtemp")
    def test_get_ctxt_log(self, mkdtemp):
        ssh = MagicMock()
        mkdtemp.return_value = "/tmp/test_get_ctxt"
        os.mkdir("/tmp/test_get_ctxt")
        with open('/tmp/test_get_ctxt/ctxt_agent.log', 'w+') as f:
            f.write("cont_log")

        inf = MagicMock()
        inf.id = "1"
        vm = VirtualMachine(inf, "1", None, None, None)
        cont_log = vm.get_ctxt_log("", ssh, delete=True)
        self.assertEqual(cont_log, "cont_log")

    @patch("tempfile.mkdtemp")
    def test_get_ctxt_output(self, mkdtemp):
        ssh = MagicMock()
        tmp_dir = "%s/test_get_ctxt" % tempfile.gettempdir()
        mkdtemp.return_value = tmp_dir
        os.mkdir(tmp_dir)
        with open('%s/ctxt_agent.out' % tmp_dir, 'w+') as f:
            f.write('{"OK": true, "CHANGE_CREDS": true}')

        radl_data = """
            system test (
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass' and
            disk.0.os.credentials.new.password = 'newpass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        inf = MagicMock()
        inf.id = "1"
        vm = VirtualMachine(inf, "1", None, radl, radl)
        cont_out = vm.get_ctxt_output("", ssh, delete=True)
        self.assertEqual(cont_out, "Contextualization agent output processed successfully")
        self.assertEqual(vm.info.systems[0].getCredentialValues(), ('user', 'newpass', None, None))

        os.mkdir(tmp_dir)
        ssh.sftp_get.side_effect = IOError()
        with open('%s/stderr' % tmp_dir, 'w+') as f:
            f.write('stderr')
        with open('%s/stdout' % tmp_dir, 'w+') as f:
            f.write('stdout')
        cont_out = vm.get_ctxt_output("", ssh, delete=True)
        self.assertEqual(cont_out, "Error getting contextualization agent output /ctxt_agent.out:"
                         "  No such file.\nstdout\nstderr\n")

    def test_setIps(self):
        radl_data = """
            system test (
            )"""
        radl = radl_parse.parse_radl(radl_data)
        vm = VirtualMachine(None, "1", None, radl, radl)
        public_ips = ['158.42.1.1']
        private_ips = ['10.0.0.1']
        vm.setIps(public_ips, private_ips)
        self.assertEqual(vm.info.systems[0].getValue('net_interface.1.ip'), "10.0.0.1")
        self.assertEqual(vm.info.systems[0].getValue('net_interface.0.ip'), "158.42.1.1")

        radl_data = """
            network net1 (cidr = '10.0.0.1')
            system test (
            net_interface.0.connection = 'net1'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        private_ips = ['192.168.0.1', '10.0.0.1']
        vm = VirtualMachine(None, "1", None, radl, radl)
        vm.setIps(public_ips, private_ips)
        self.assertEqual(vm.info.systems[0].getValue('net_interface.0.ip'), "10.0.0.1")
        self.assertEqual(vm.info.systems[0].getValue('net_interface.2.ip'), "192.168.0.1")


if __name__ == '__main__':
    unittest.main()
