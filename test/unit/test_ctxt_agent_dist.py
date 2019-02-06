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
import sys
import logging
import json
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

sys.path.append("..")
sys.path.append(".")

from contextualization.ctxt_agent_dist import CtxtAgent
from mock import patch, MagicMock


class TestCtxtAgent(unittest.TestCase):
    """
    Class to test the CtxtAgent
    """
    def setUp(self):
        self.last_op = None, None
        self.log = StringIO()
        self.handler = logging.StreamHandler(self.log)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.handler.setFormatter(formatter)

        logging.RootLogger.propagate = 0
        logging.root.setLevel(logging.ERROR)

        self.logger = logging.getLogger('ctxt_agent')
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = 0
        for handler in self.logger.handlers:
            self.logger.removeHandler(handler)
        self.logger.addHandler(self.handler)

    def tearDown(self):
        self.handler.flush()
        self.log.close()
        self.log = StringIO()
        self.handler.close()

    def gen_general_conf(self):
        conf_data = {}

        conf_data['playbook_retries'] = 3
        conf_data['vms'] = []
        for vm in [0, 1, 2, 3]:
            vm_conf_data = {}
            vm_conf_data['id'] = vm
            if vm == 0:
                vm_conf_data['master'] = True
            else:
                vm_conf_data['master'] = False
            if vm == 2:
                vm_conf_data['os'] = "windows"
            else:
                vm_conf_data['os'] = "linux"
            vm_conf_data['ip'] = "10.0.0.1"
            vm_conf_data['private_ip'] = "10.0.0.1"
            vm_conf_data['remote_port'] = 22
            vm_conf_data['user'] = "user"
            vm_conf_data['passwd'] = "passwd"
            vm_conf_data['private_key'] = None
            vm_conf_data['new_passwd'] = "new_passwd"
            conf_data['vms'].append(vm_conf_data)
        conf_data['conf_dir'] = "/tmp"
        return conf_data

    def gen_vm_conf(self, tasks):
        conf_data = {}
        conf_data['id'] = 1
        conf_data['tasks'] = tasks
        conf_data['remote_dir'] = "/tmp"
        conf_data['changed_pass'] = True
        return conf_data

    def gen_vm_data(self, os="linux"):
        vm_conf_data = {}
        vm_conf_data['id'] = 1
        vm_conf_data['master'] = False
        vm_conf_data['os'] = os
        vm_conf_data['ip'] = "10.0.0.1"
        vm_conf_data['private_ip'] = "10.0.0.1"
        vm_conf_data['remote_port'] = 22
        vm_conf_data['user'] = "user"
        vm_conf_data['passwd'] = "passwd"
        vm_conf_data['private_key'] = None
        vm_conf_data['new_passwd'] = "new_passwd"
        return vm_conf_data

    @patch("contextualization.ctxt_agent_dist.SSH.test_connectivity")
    def test_10_wait_ssh_access(self, test_connectivity):
        CtxtAgent.logger = self.logger
        vm = self.gen_vm_data()
        ctxt_agent = CtxtAgent()
        res = ctxt_agent.wait_ssh_access(vm)
        self.assertEqual(res, "init")

    @patch("socket.socket.connect_ex")
    def test_20_wait_winrm_access(self, socket_connect_ex):
        socket_connect_ex.return_value = 0
        CtxtAgent.logger = self.logger
        vm = self.gen_vm_data("windows")
        ctxt_agent = CtxtAgent()
        res = ctxt_agent.wait_winrm_access(vm)
        self.assertTrue(res)

    @patch("contextualization.ctxt_agent_dist.SSH.execute_timeout")
    def test_30_removeRequiretty(self, execute_timeout):
        CtxtAgent.logger = self.logger
        execute_timeout.return_value = "", "", 0
        vm = self.gen_vm_data()
        res = CtxtAgent.removeRequiretty(vm, False, None)
        self.assertTrue(res)

    def test_40_run_command(self):
        CtxtAgent.logger = self.logger
        res = CtxtAgent.run_command("ls -l", 2, 0.1)
        self.assertIn("total", str(res))

    @patch('IM.ansible_utils.ansible_launcher.AnsibleThread')
    @patch("contextualization.ctxt_agent_dist.Queue")
    @patch("contextualization.ctxt_agent_dist.SSH.test_connectivity")
    def test_50_launch_ansible_thread(self, test_connectivity, queue, ansible_thread):
        ctxt_agent = CtxtAgent()
        ctxt_agent.logger = self.logger
        CtxtAgent.logger = self.logger
        vm = self.gen_vm_data()
        queue_mock = MagicMock()
        queue.return_value = queue_mock
        queue_mock.get.return_value = None, 0, None
        thread = CtxtAgent.LaunchAnsiblePlaybook(self.logger, "/tmp", "play.yml",
                                                 vm, 1, "/tmp/inv", "/tmp/pk.pem",
                                                 3, True, None)
        res = ctxt_agent.wait_thread(thread, self.gen_general_conf(), False)
        self.assertEqual(res, True)

        CtxtAgent.VM_CONF_DATA_FILENAME = "/tmp/conf.dat"
        thread[0].is_alive.return_value = False
        res = ctxt_agent.wait_thread(thread, self.gen_general_conf(), True)
        self.assertEqual(res, True)

    @patch("contextualization.ctxt_agent_dist.SSH.execute_timeout")
    @patch("contextualization.ctxt_agent_dist.SSH.execute")
    @patch("winrm.Session")
    def test_60_changeVMCredentials(self, winrm_session, execute, execute_timeout):
        CtxtAgent.logger = self.logger
        execute.return_value = "", "", 0
        execute_timeout.return_value = "", "", 0
        vm = self.gen_vm_data()
        res = CtxtAgent.changeVMCredentials(vm, None)
        self.assertTrue(res)

        vm = self.gen_vm_data()
        del vm['new_passwd']
        vm['new_public_key'] = "new_public_key"
        vm['new_private_key'] = "new_private_key"
        res = CtxtAgent.changeVMCredentials(vm, None)
        self.assertTrue(res)

        session = MagicMock()
        req = MagicMock
        req.status_code = 0
        session.run_cmd.return_value = req
        winrm_session.return_value = session
        vm = self.gen_vm_data("windows")
        res = CtxtAgent.changeVMCredentials(vm, None)
        self.assertTrue(res)

    @patch("contextualization.ctxt_agent_dist.SSH.test_connectivity")
    @patch("contextualization.ctxt_agent_dist.SSHRetry.execute")
    @patch("contextualization.ctxt_agent_dist.SSHRetry.sftp_put")
    def test_70_contextualize_vm(self, sftp_put, execute, test_connectivity):
        ctxt_agent = CtxtAgent()
        ctxt_agent.logger = self.logger
        CtxtAgent.logger = self.logger
        CtxtAgent.changeVMCredentials = MagicMock()
        CtxtAgent.changeVMCredentials.return_value = True
        CtxtAgent.LaunchAnsiblePlaybook = MagicMock()
        queue = MagicMock()
        queue.get.return_value = None, 0, None
        thread = MagicMock()
        thread.is_alive.return_value = False
        CtxtAgent.LaunchAnsiblePlaybook.return_value = (thread, queue)
        ctxt_agent.wait_winrm_access = MagicMock()
        ctxt_agent.wait_winrm_access.return_value = True
        ctxt_agent.wait_ssh_access = MagicMock()
        ctxt_agent.wait_ssh_access.return_value = True
        CtxtAgent.removeRequiretty = MagicMock()
        CtxtAgent.removeRequiretty.return_value = True
        CtxtAgent.VM_CONF_DATA_FILENAME = "/tmp/conf.dat"
        CtxtAgent.CONF_DATA_FILENAME = "/tmp/gconf.dat"
        execute.return_value = "1", 1, 1

        ctxt_vm = None
        for vm in self.gen_general_conf()['vms']:
            if vm['id'] == self.gen_vm_conf(["basic"])['id']:
                ctxt_vm = vm

        with open("/tmp/ctxt_agent.out", 'w+') as f:
            f.write('{"OK": true}')
        res = ctxt_agent.contextualize_vm(self.gen_general_conf(), self.gen_vm_conf(["basic"]), ctxt_vm, 0)
        expected_res = {'SSH_WAIT': True, 'OK': True, 'CHANGE_CREDS': True, 'basic': True}
        self.assertEqual(res, expected_res)

        res = ctxt_agent.contextualize_vm(self.gen_general_conf(), self.gen_vm_conf(["basic"]), ctxt_vm, 1)
        expected_res = {'SSH_WAIT': True, 'OK': True, 'basic': True}
        self.assertEqual(res, expected_res)

        ctxt_vm = None
        for vm in self.gen_general_conf()['vms']:
            if vm['id'] == self.gen_vm_conf(["main", "front"])['id']:
                ctxt_vm = vm

        res = ctxt_agent.contextualize_vm(self.gen_general_conf(), self.gen_vm_conf(["main", "front"]), ctxt_vm, 0)
        expected_res = {'OK': True, 'front': True, 'main': True}
        self.assertEqual(res, expected_res)

        res = ctxt_agent.contextualize_vm(self.gen_general_conf(), self.gen_vm_conf(["main", "front"]), ctxt_vm, 1)
        expected_res = {'OK': True, 'front': True, 'main': True}
        self.assertEqual(res, expected_res)

    @patch("contextualization.ctxt_agent_dist.SSH.sftp_put")
    def test_80_run(self, sftp_put):
        ctxt_agent = CtxtAgent()
        ctxt_agent.logger = self.logger
        CtxtAgent.logger = self.logger
        CtxtAgent.contextualize_vm = MagicMock()
        CtxtAgent.contextualize_vm.return_value = {'SSH_WAIT': True, 'OK': True, 'CHANGE_CREDS': True, 'basic': True}

        with open("/tmp/gen_data.json", "w+") as f:
            json.dump(self.gen_general_conf(), f)
        with open("/tmp/vm_data.json", "w+") as f:
            json.dump(self.gen_vm_conf(["basic"]), f)

        res = ctxt_agent.run("/tmp/gen_data.json", "/tmp/vm_data.json", 0)
        self.assertTrue(res)

        open("/tmp/ctxt_agent.log", 'a').close()
        res = ctxt_agent.run("/tmp/gen_data.json", "/tmp/vm_data.json", 1)
        self.assertTrue(res)

    def test_90_replace_vm_ip(self):
        CtxtAgent.logger = self.logger
        vm_data = self.gen_vm_data()
        CtxtAgent.CONF_DATA_FILENAME = "/tmp/gen_data.json"
        with open("/tmp/gen_data.json", "w+") as f:
            json.dump(self.gen_general_conf(), f)
        with open("/tmp/hosts", "w+") as f:
            f.write("%s_%s " % (vm_data['ip'], vm_data['id']))
            f.write(" ansible_host=%s " % vm_data['ip'])
            f.write(" ansible_ssh_host=%s \n" % vm_data['ip'])

        vm_data['ctxt_ip'] = "10.0.0.2"
        vm_data['ctxt_port'] = 22
        CtxtAgent.replace_vm_ip(vm_data)

        with open("/tmp/gen_data.json.rep", "r") as f:
            general_conf_data = json.load(f)
        for vm in general_conf_data['vms']:
            if vm['id'] == vm_data['id']:
                self.assertEqual(vm['ctxt_ip'], vm_data['ctxt_ip'])

        with open("/tmp/hosts", "r") as f:
            data = f.read()
        self.assertIn(" ansible_host=%s " % vm_data['ctxt_ip'], data)
        self.assertIn(" ansible_ssh_host=%s \n" % vm_data['ctxt_ip'], data)


if __name__ == '__main__':
    unittest.main()
