#! /usr/bin/env python
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

import argparse
import sys
import os
import getpass
import json
import time

from IM.CtxtAgentBase import CtxtAgentBase


class CtxtAgent(CtxtAgentBase):

    def wait_thread(self, thread_data, output=None):
        """
         Wait for a thread to finish
        """
        thread, result = thread_data
        thread.join()
        try:
            _, return_code, _ = result.get(timeout=60, block=False)
        except Exception:
            self.logger.exception('Error getting ansible results.')
            return_code = -1

        if output:
            if return_code == 0:
                self.logger.info(output)
            else:
                self.logger.error(output)

        return return_code == 0

    def contextualize_vm(self, general_conf_data, vm_conf_data):
        vault_pass = None
        if 'VAULT_PASS' in os.environ:
            vault_pass = os.environ['VAULT_PASS']

        res_data = {}
        self.logger.info('Generate and copy the ssh key')

        # If the file exists, do not create it again
        if not os.path.isfile(CtxtAgentBase.PK_FILE):
            out = self.run_command('ssh-keygen -t rsa -C ' + getpass.getuser() +
                                   ' -q -N "" -f ' + CtxtAgentBase.PK_FILE)
            self.logger.debug(out)

        ctxt_vm = None
        for vm in general_conf_data['vms']:
            if vm['id'] == vm_conf_data['id']:
                ctxt_vm = vm
                break

        if not ctxt_vm:
            self.logger.error("No VM to Contextualize!")
            res_data['OK'] = True
            return res_data

        for task in vm_conf_data['tasks']:
            task_ok = False
            num_retries = 0
            while not task_ok and num_retries < CtxtAgent.PLAYBOOK_RETRIES:
                self.logger.info("Sleeping %s secs." % (num_retries ** 2 * 5))
                time.sleep(num_retries ** 2 * 5)
                num_retries += 1
                self.logger.info('Launch task: ' + task)
                if ctxt_vm['os'] == "windows":
                    # playbook = general_conf_data['conf_dir'] + "/" + task + "_task_all_win.yml"
                    playbook = general_conf_data['conf_dir'] + "/" + task + "_task.yml"
                else:
                    playbook = general_conf_data['conf_dir'] + "/" + task + "_task_all.yml"
                inventory_file = general_conf_data['conf_dir'] + "/hosts"

                ansible_thread = None
                if task == "wait_all_ssh":
                    # Wait all the VMs to have remote access active
                    for vm in general_conf_data['vms']:
                        if vm['os'] == "windows":
                            self.logger.info("Waiting WinRM access to VM: " + vm['ip'])
                            cred_used = self.wait_winrm_access(vm)
                        else:
                            self.logger.info("Waiting SSH access to VM: " + vm['ip'])
                            cred_used = self.wait_ssh_access(vm)

                        if not cred_used:
                            self.logger.error("Error Waiting access to VM: " + vm['ip'])
                            res_data['SSH_WAIT'] = False
                            res_data['OK'] = False
                            return res_data
                        else:
                            res_data['SSH_WAIT'] = True
                            self.logger.info("Remote access to VM: " + vm['ip'] + " Open!")

                        # the IP has changed public for private
                        if 'ctxt_ip' in vm and vm['ctxt_ip'] != vm['ip']:
                            # update the ansible inventory
                            self.logger.info("Changing the IP %s for %s in config files." % (vm['ctxt_ip'],
                                                                                             vm['ip']))
                            self.replace_vm_ip(vm)
                elif task == "basic":
                    # This is always the fist step, so put the SSH test, the
                    # requiretty removal and change password here
                    if ctxt_vm['os'] == "windows":
                        self.logger.info("Waiting WinRM access to VM: " + ctxt_vm['ip'])
                        cred_used = self.wait_winrm_access(ctxt_vm)
                    else:
                        self.logger.info("Waiting SSH access to VM: " + ctxt_vm['ip'])
                        cred_used = self.wait_ssh_access(ctxt_vm)

                    if not cred_used:
                        self.logger.error("Error Waiting access to VM: " + ctxt_vm['ip'])
                        res_data['SSH_WAIT'] = False
                        res_data['OK'] = False
                        return res_data
                    else:
                        res_data['SSH_WAIT'] = True
                        self.logger.info("Remote access to VM: " + ctxt_vm['ip'] + " Open!")

                    # The basic task uses the credentials of VM stored in ctxt_vm
                    change_creds = False
                    pk_file = None
                    if cred_used == "pk_file":
                        pk_file = CtxtAgentBase.PK_FILE
                    elif cred_used == "new":
                        change_creds = True

                    # First remove requiretty in the node
                    if ctxt_vm['os'] != "windows" and not change_creds:
                        success = self.removeRequiretty(ctxt_vm, pk_file)
                        if success:
                            self.logger.info("Requiretty successfully removed")
                        else:
                            self.logger.error("Error removing Requiretty")

                    # Check if we must change user credentials
                    # Do not change it on the master. It must be changed only by
                    # the ConfManager
                    if not ctxt_vm['master'] and not change_creds:
                        change_creds = self.changeVMCredentials(ctxt_vm, pk_file)
                        res_data['CHANGE_CREDS'] = change_creds

                    if ctxt_vm['os'] != "windows":
                        if ctxt_vm['master']:
                            # Install ansible modules
                            playbook = self.install_ansible_modules(general_conf_data, playbook)
                        if 'nat_instance' in ctxt_vm and ctxt_vm['nat_instance']:
                            playbook = self.add_nat_gateway_tasks(playbook)
                        # this step is not needed in windows systems
                        ansible_thread = self.LaunchAnsiblePlaybook(self.logger, vm_conf_data['remote_dir'],
                                                                    playbook, ctxt_vm, 2, inventory_file,
                                                                    pk_file, CtxtAgent.INTERNAL_PLAYBOOK_RETRIES,
                                                                    change_creds, vault_pass)
                else:
                    # in the other tasks pk_file can be used
                    ansible_thread = self.LaunchAnsiblePlaybook(self.logger, vm_conf_data['remote_dir'],
                                                                playbook, ctxt_vm, 2,
                                                                inventory_file, CtxtAgentBase.PK_FILE,
                                                                CtxtAgent.INTERNAL_PLAYBOOK_RETRIES,
                                                                vm_conf_data['changed_pass'], vault_pass)

                if ansible_thread:
                    task_ok = self.wait_thread(ansible_thread)
                else:
                    task_ok = True
                if not task_ok:
                    self.logger.warning("ERROR executing task %s: (%s/%s)" %
                                        (task, num_retries, CtxtAgent.PLAYBOOK_RETRIES))
                else:
                    self.logger.info('Task %s finished successfully' % task)

            res_data[task] = task_ok
            if not task_ok:
                res_data['OK'] = False
                return res_data

        res_data['OK'] = True

        self.logger.info('Process finished')
        return res_data

    def run(self, vm_conf_file):
        with open(self.conf_data_filename) as f:
            general_conf_data = json.load(f)
        with open(vm_conf_file) as f:
            vm_conf_data = json.load(f)

        self.init_logger(vm_conf_data['remote_dir'] + "/ctxt_agent.log")

        if 'playbook_retries' in general_conf_data:
            CtxtAgent.PLAYBOOK_RETRIES = general_conf_data['playbook_retries']

        CtxtAgentBase.PK_FILE = general_conf_data['conf_dir'] + "/" + "ansible_key"

        res_data = self.contextualize_vm(general_conf_data, vm_conf_data)

        ctxt_out = open(vm_conf_data['remote_dir'] + "/ctxt_agent.out", 'w')
        json.dump(res_data, ctxt_out, indent=2)
        ctxt_out.close()

        return res_data['OK']


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Contextualization Agent.')
    parser.add_argument('general', type=str, nargs=1)
    parser.add_argument('vmconf', type=str, nargs=1)
    options = parser.parse_args()

    ctxt_agent = CtxtAgent(options.general[0])
    if ctxt_agent.run(options.vmconf[0]):
        sys.exit(0)
    else:
        sys.exit(1)
