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
""" Base Class for the Contextualization Agent """
import time
import subprocess
import socket

from IM.SSH import SSH, AuthenticationException


class CtxtAgentBase:
    """ Base Class for the Contextualization Agent """

    SSH_WAIT_TIMEOUT = 600
    logger = None
    PK_FILE = "/tmp/ansible_key"

    def wait_winrm_access(self, vm, max_wait=None):
        """
         Test the WinRM access to the VM
        """
        if max_wait is None:
            max_wait = CtxtAgentBase.SSH_WAIT_TIMEOUT
        delay = 10
        wait = 0
        last_tested_private = False
        while wait < max_wait:
            if 'ctxt_ip' in vm:
                vm_ip = vm['ctxt_ip']
            elif 'private_ip' in vm and not last_tested_private:
                # First test the private one
                vm_ip = vm['private_ip']
                last_tested_private = True
            else:
                vm_ip = vm['ip']
                last_tested_private = False
            try:
                self.logger.debug("Testing WinRM access to VM: " + vm_ip)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((vm_ip, vm['remote_port']))
            except:
                self.logger.exception("Error connecting with WinRM with: " + vm_ip)
                result = -1

            if result == 0:
                vm['ctxt_ip'] = vm_ip
                return True
            else:
                wait += delay
                time.sleep(delay)

    def test_ssh(self, vm, vm_ip, remote_port, quiet, delay=10):
        success = False
        res = None
        if not quiet:
            self.logger.debug("Testing SSH access to VM: %s:%s" % (vm_ip, remote_port))
        try:
            ssh_client = SSH(vm_ip, vm['user'], vm['passwd'], vm['private_key'], remote_port)
            success = ssh_client.test_connectivity(delay)
            res = 'init'
        except AuthenticationException:
            try_ansible_key = True
            if 'new_passwd' in vm:
                try_ansible_key = False
                # If the process of changing credentials has finished in the
                # VM, we must use the new ones
                if not quiet:
                    self.logger.debug("Error connecting with SSH with initial credentials with: " +
                                      vm_ip + ". Try to use new ones.")
                try:
                    ssh_client = SSH(vm_ip, vm['user'], vm['new_passwd'], vm['private_key'], remote_port)
                    success = ssh_client.test_connectivity()
                    res = "new"
                except AuthenticationException:
                    try_ansible_key = True
                except:
                    if not quiet:
                        self.logger.exception("Error connecting with SSH with: " + vm_ip)
                    success = False

            if try_ansible_key:
                # In some very special cases the last two cases fail, so check
                # if the ansible key works
                if not quiet:
                    self.logger.debug("Error connecting with SSH with initial credentials with: " +
                                      vm_ip + ". Try to ansible_key.")
                try:
                    ssh_client = SSH(vm_ip, vm['user'], None, CtxtAgentBase.PK_FILE, remote_port)
                    success = ssh_client.test_connectivity()
                    res = 'pk_file'
                except:
                    if not quiet:
                        self.logger.exception("Error connecting with SSH with: " + vm_ip)
                    success = False
        except:
            if not quiet:
                self.logger.exception("Error connecting with SSH with: " + vm_ip)
            success = False

        return success, res

    def wait_ssh_access(self, vm, delay=10, max_wait=None, quiet=False):
        """
         Test the SSH access to the VM
         return: init, new or pk_file or None if it fails
        """
        if max_wait is None:
            max_wait = CtxtAgentBase.SSH_WAIT_TIMEOUT
        wait = 0
        success = False
        res = None
        while wait < max_wait:
            if 'ctxt_ip' in vm and 'ctxt_port' in vm:
                # These have been previously tested and worked use it
                vm_ip = vm['ctxt_ip']
                remote_port = vm['ctxt_port']
                success, res = self.test_ssh(vm, vm['ctxt_ip'], vm['ctxt_port'], quiet)
            else:
                # First test the private one
                if 'private_ip' in vm:
                    vm_ip = vm['private_ip']
                    remote_port = vm['remote_port']
                    success, res = self.test_ssh(vm, vm_ip, remote_port, quiet)
                    if not success and remote_port != 22:
                        remote_port = 22
                        success, res = self.test_ssh(vm, vm_ip, 22, quiet)

                # if not use the default one
                if not success:
                    vm_ip = vm['ip']
                    remote_port = vm['remote_port']
                    success, res = self.test_ssh(vm, vm_ip, remote_port, quiet)
                    if not success and remote_port != 22:
                        remote_port = 22
                        success, res = self.test_ssh(vm, vm_ip, remote_port, quiet)

                # if not use the default one
                if not success and 'reverse_port' in vm:
                    vm_ip = '127.0.0.1'
                    remote_port = vm['reverse_port']
                    success, res = self.test_ssh(vm, vm_ip, remote_port, quiet)

            wait += delay

            if success:
                vm['ctxt_ip'] = vm_ip
                vm['ctxt_port'] = remote_port
                return res
            else:
                time.sleep(delay)

        return None

    @staticmethod
    def run_command(command, timeout=None, poll_delay=5):
        """
         Function to run a command
        """
        try:
            p = subprocess.Popen(command, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, shell=True)

            if timeout is not None:
                wait = 0
                while p.poll() is None and wait < timeout:
                    time.sleep(poll_delay)
                    wait += poll_delay

                if p.poll() is None:
                    p.kill()
                    return "TIMEOUT"

            (out, err) = p.communicate()

            if p.returncode != 0:
                return "ERROR: " + err + out
            else:
                return out
        except Exception as ex:
            return "ERROR: Exception msg: " + str(ex)
