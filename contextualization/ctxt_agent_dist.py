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
import time
import sys
import os
import getpass
import json
import threading
from multiprocessing import Queue
from multiprocessing.pool import ThreadPool

from IM.CtxtAgentBase import CtxtAgentBase
from IM.SSHRetry import SSHRetry


class CtxtAgent(CtxtAgentBase):

    MAX_SIMULTANEOUS_SSH = -1

    def __init__(self, conf_data_filename, vm_conf_data_filename):
        CtxtAgentBase.__init__(self, conf_data_filename)
        self.vm_conf_data_filename = os.path.abspath(vm_conf_data_filename)

    def wait_thread(self, thread_data, general_conf_data, copy, output=None, poll_delay=1, copy_step=10):
        """
         Wait for a thread to finish
        """
        thread, result = thread_data
        if not copy:
            thread.join()
        else:
            vm_dir = os.path.abspath(os.path.dirname(self.vm_conf_data_filename))
            ssh_master = self.get_master_ssh(general_conf_data)
            cont = 0
            while thread.is_alive():
                cont += 1
                time.sleep(poll_delay)
                if cont % copy_step == 0:
                    try:
                        ssh_master.sftp_put(vm_dir + "/ctxt_agent.log", vm_dir + "/ctxt_agent.log")
                    except Exception:
                        self.logger.exception("Error putting %s file" % (vm_dir + "/ctxt_agent.log"))

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

    def wait_remote(self, data, poll_delay=5, ssh_step=4, max_errors=10, active=False):
        ssh_client, pid = data
        if not pid:
            return False
        exit_status = 0
        vm_dir = os.path.abspath(os.path.dirname(self.vm_conf_data_filename))
        cont = 0
        err_count = 0
        while exit_status == 0 and err_count < max_errors:
            cont += 1
            try:
                if active:
                    self.logger.debug("Check status of remote process: %s" % pid)
                    (_, _, exit_status) = ssh_client.execute("ps " + str(pid))
                else:
                    # Only check the process status every ssh_step or if the out file exists
                    if cont % ssh_step == 0 or os.path.exists(vm_dir + "/ctxt_agent.out"):
                        self.logger.debug("Check status of remote process: %s" % pid)
                        (_, _, exit_status) = ssh_client.execute("ps " + str(pid))
            except Exception:
                err_count += 1
                self.logger.exception("Error (%d/%d) checking status of remote process: %s" %
                                      (err_count, max_errors, pid))
            if exit_status == 0:
                time.sleep(poll_delay)

        if active:
            try:
                ssh_client.sftp_get(vm_dir + "/ctxt_agent.out", vm_dir + "/ctxt_agent.out")
                ssh_client.sftp_get(vm_dir + "/ctxt_agent.log", vm_dir + "/ctxt_agent.log")
            except Exception:
                self.logger.exception("Error getting ctxt_agent.* files.")

        if os.path.exists(vm_dir + "/ctxt_agent.out"):
            try:
                with open(vm_dir + "/ctxt_agent.out", "r") as f:
                    results = json.load(f)
                    return results["OK"]
            except Exception:
                self.logger.exception("Error parsing %s." % (vm_dir + "/ctxt_agent.out"))
                return False
        else:
            self.logger.error("Error file %s does not exist." % (vm_dir + "/ctxt_agent.out"))
            return False

    def LaunchRemoteInstallAnsible(self, vm, pk_file, changed_pass_ok):
        self.logger.debug('Launch Ctxt agent on node: %s' % vm['ip'])

        vm_dir = os.path.abspath(os.path.dirname(self.vm_conf_data_filename))
        remote_dir = os.path.abspath(os.path.dirname(self.conf_data_filename))
        ssh_client = self.get_ssh(vm, pk_file, changed_pass_ok)

        # Create a temporary log file
        with open(vm_dir + "/ctxt_agent.log", "w+") as f:
            f.write("Installing Ansible...")

        # copy the script file
        if not vm['master']:
            ssh_client.execute("mkdir -p %s" % os.path.dirname(self.vm_conf_data_filename))
            ssh_client.sftp_put(remote_dir + "/ansible_install.sh", remote_dir + "/ansible_install.sh")

        pid = None

        try:
            sudo_pass = ""
            if ssh_client.password:
                sudo_pass = "echo '" + ssh_client.password + "' | "
            (pid, _, _) = ssh_client.execute("nohup " + sudo_pass + "sudo -S sh " + remote_dir +
                                             "/ansible_install.sh " + vm_dir + "/ctxt_agent.out  > " +
                                             vm_dir + "/ctxt_agent.log 2> " + vm_dir +
                                             "/ctxt_agent.log < /dev/null & echo -n $!")
        except Exception:
            self.logger.exception('Error launching ansible install on node: %s' % vm['ip'])
        return ssh_client, pid

    def LaunchRemoteAgent(self, vm, vault_pass, pk_file, changed_pass_ok):
        self.logger.debug('Launch Ctxt agent on node: %s' % vm['ip'])

        ssh_client = self.get_ssh(vm, pk_file, changed_pass_ok)
        # copy the config file
        if not vm['master']:
            ssh_client.execute("mkdir -p %s" % os.path.dirname(self.vm_conf_data_filename))
            ssh_client.sftp_put(self.vm_conf_data_filename, self.vm_conf_data_filename)

        vault_export = ""
        if vault_pass:
            vault_export = "export VAULT_PASS='%s' && " % vault_pass
        pid = None
        vm_dir = os.path.abspath(os.path.dirname(self.vm_conf_data_filename))
        remote_dir = os.path.abspath(os.path.dirname(self.conf_data_filename))
        try:
            (pid, _, _) = ssh_client.execute(vault_export + "nohup python3 " + remote_dir + "/ctxt_agent_dist.py " +
                                             self.conf_data_filename + " " + self.vm_conf_data_filename +
                                             " 1 > " + vm_dir + "/stdout 2> " + vm_dir +
                                             "/stderr < /dev/null & echo -n $!")
        except Exception:
            self.logger.exception('Error launch Ctxt agent on node: %s' % vm['ip'])
        return ssh_client, pid

    @staticmethod
    def set_ansible_connection_local(general_conf_data, vm):
        filename = general_conf_data['conf_dir'] + "/hosts"
        vm_id = vm['ip'] + "_" + str(vm['id'])
        with open(filename) as f:
            inventoy_data = ""
            for line in f:
                if "ansible_connection=local" in line:
                    line = line.replace("ansible_connection=local", "")
                if vm_id in line:
                    line = line[:-1] + " ansible_connection=local\n"
                inventoy_data += line
        with open(filename, 'w+') as f:
            f.write(inventoy_data)

    def get_master_ssh(self, general_conf_data):
        ctxt_vm = None
        for vm in general_conf_data['vms']:
            if vm['master']:
                ctxt_vm = vm
                break
        if not ctxt_vm:
            self.logger.error('Not VM master found to get ssh.')
            return None

        cred_used = self.wait_ssh_access(ctxt_vm, 2, 10, True)
        passwd = ctxt_vm['passwd']
        if cred_used == 'new':
            passwd = ctxt_vm['new_passwd']

        private_key = ctxt_vm['private_key']
        if cred_used == "pk_file":
            private_key = CtxtAgentBase.PK_FILE

        vm_ip = ctxt_vm['ip']
        if 'ctxt_ip' in ctxt_vm:
            vm_ip = ctxt_vm['ctxt_ip']

        return SSHRetry(vm_ip, ctxt_vm['user'], passwd, private_key, ctxt_vm['remote_port'])

    @staticmethod
    def get_ssh(vm, pk_file, changed_pass=None):
        passwd = vm['passwd']
        if 'new_passwd' in vm and vm['new_passwd'] and changed_pass:
            passwd = vm['new_passwd']

        private_key = vm['private_key']
        if pk_file:
            private_key = pk_file

        vm_ip = vm['ip']
        remote_port = vm['remote_port']
        if 'ctxt_ip' in vm:
            vm_ip = vm['ctxt_ip']
        if 'ctxt_port' in vm:
            remote_port = vm['ctxt_port']

        return SSHRetry(vm_ip, vm['user'], passwd, private_key, remote_port)

    def gen_facts_cache(self, remote_dir, inventory_file, threads):
        # Set local_tmp dir different for any VM
        os.environ['DEFAULT_LOCAL_TMP'] = remote_dir + "/.ansible_tmp"
        # it must be set before doing the import
        from IM.ansible_utils.ansible_launcher import AnsibleThread

        playbook_file = "/tmp/gen_facts_cache.yml"
        with open(playbook_file, "w+") as f:
            f.write(" - hosts: allnowindows\n")

        result = Queue()
        t = AnsibleThread(result, self.logger, playbook_file, threads, CtxtAgentBase.PK_FILE,
                          None, CtxtAgent.PLAYBOOK_RETRIES, inventory_file)
        t.start()
        return (t, result)

    def copy_playbooks(self, vm, general_conf_data, errors, lock):
        if vm['os'] != "windows" and not vm['master']:
            cred_used = self.wait_ssh_access(vm, quiet=True)

            # the IP has changed public for private
            if 'ctxt_ip' in vm and vm['ctxt_ip'] != vm['ip']:
                with lock:
                    # update the ansible inventory
                    self.logger.info("Changing the IP %s for %s in config files." % (vm['ctxt_ip'],
                                                                                     vm['ip']))
                    self.replace_vm_ip(vm)

            pk_file = None
            changed_pass = False
            if cred_used == "pk_file":
                pk_file = CtxtAgentBase.PK_FILE
            elif cred_used == "new":
                changed_pass = True

            self.logger.debug("Copying playbooks to VM: " + vm['ip'])
            try:
                ssh_client = self.get_ssh(vm, pk_file, changed_pass)
                out, _, code = ssh_client.execute("mkdir -p %s" % general_conf_data['conf_dir'])
                if code != 0:
                    raise Exception("Error creating dir %s: %s" % (general_conf_data['conf_dir'],
                                                                   out))
                ssh_client.sftp_put_dir(general_conf_data['conf_dir'],
                                        general_conf_data['conf_dir'])
                # Put the correct permissions on the key file
                ssh_client.sftp_chmod(CtxtAgentBase.PK_FILE, 0o600)
            except Exception as ex:
                self.logger.exception("Error copying playbooks to VM: " + vm['ip'])
                errors.append(ex)

    def contextualize_vm(self, general_conf_data, vm_conf_data, ctxt_vm, local):
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
                remote_process = None
                cache_dir = "/var/tmp/facts_cache"
                if task == "copy_facts_cache":
                    if ctxt_vm['os'] != "windows":
                        try:
                            self.logger.info("Copy Facts cache to: %s" % ctxt_vm['ip'])
                            ssh_client = self.get_ssh(ctxt_vm, CtxtAgentBase.PK_FILE, True)
                            ssh_client.sftp_mkdir(cache_dir)
                            ssh_client.sftp_put_dir(cache_dir, cache_dir)

                            self.logger.info("Copy ansible roles to: %s" % ctxt_vm['ip'])
                            ssh_client.sftp_mkdir(general_conf_data['conf_dir'] + "/roles")
                            ssh_client.sftp_put_dir("/etc/ansible/roles", general_conf_data['conf_dir'] + "/roles")
                        except Exception:
                            self.logger.exception("Error copying cache to VM: " + ctxt_vm['ip'])
                    else:
                        self.logger.info("Windows VM do not copy Facts cache to: %s" % ctxt_vm['ip'])
                elif task == "gen_facts_cache":
                    ansible_thread = self.gen_facts_cache(vm_conf_data['remote_dir'], inventory_file,
                                                          len(general_conf_data['vms']))
                elif task == "install_ansible":
                    if ctxt_vm['os'] == "windows":
                        self.logger.info("Waiting WinRM access to VM: " + ctxt_vm['ip'])
                        cred_used = self.wait_winrm_access(ctxt_vm)
                        if not cred_used:
                            self.logger.error("Error Waiting access to VM: " + ctxt_vm['ip'])
                            res_data['SSH_WAIT'] = False
                            res_data['OK'] = False
                            return res_data
                        res_data['CHANGE_CREDS'] = self.changeVMCredentials(ctxt_vm, None)
                        self.logger.info("Windows VM do not install Ansible.")
                    elif not ctxt_vm['master']:
                        vm_dir = os.path.abspath(os.path.dirname(self.vm_conf_data_filename))
                        # Create a temporary log file
                        with open(vm_dir + "/ctxt_agent.log", "w+") as f:
                            f.write("Waiting SSH access to VM: " + ctxt_vm['ip'])

                        # This is always the fist step, so put the SSH test, the
                        # requiretty removal and change password here
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

                        # The install_ansible task uses the credentials of VM stored in ctxt_vm
                        pk_file = None
                        changed_pass = False
                        if cred_used == "pk_file":
                            pk_file = CtxtAgentBase.PK_FILE
                        elif cred_used == "new":
                            changed_pass = True

                        success = self.removeRequiretty(ctxt_vm, pk_file, changed_pass)
                        if success:
                            self.logger.info("Requiretty successfully removed")
                        else:
                            self.logger.error("Error removing Requiretty")

                        remote_process = self.LaunchRemoteInstallAnsible(ctxt_vm, pk_file, changed_pass)
                    else:
                        # Copy dir general_conf_data['conf_dir'] to node
                        errors = []
                        lock = threading.Lock()
                        if CtxtAgent.MAX_SIMULTANEOUS_SSH <= 0:
                            threads = len(general_conf_data['vms']) - 1
                        else:
                            threads = CtxtAgent.MAX_SIMULTANEOUS_SSH
                        pool = ThreadPool(processes=threads)
                        pool.map(
                            lambda vm: self.copy_playbooks(vm, general_conf_data, errors,
                                                           lock), general_conf_data['vms'])
                        pool.close()

                        if errors:
                            self.logger.error("Error copying playbooks to VMs")
                            self.logger.error(errors)
                            res_data['COPY_PLAYBOOKS'] = False
                            res_data['OK'] = False
                            return res_data
                elif task == "basic":
                    if ctxt_vm['os'] == "windows":
                        self.logger.info("Waiting WinRM access to VM: " + ctxt_vm['ip'])
                        cred_used = self.wait_winrm_access(ctxt_vm)
                    elif local:
                        self.logger.info("Local command do not wait SSH.")
                        cred_used = "local"
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
                    pk_file = None
                    changed_pass = False
                    if cred_used == "pk_file":
                        pk_file = CtxtAgentBase.PK_FILE
                    elif cred_used == "new":
                        changed_pass = True
                    elif cred_used == "local":
                        changed_pass = True

                    # Check if we must change user credentials
                    # Do not change it on the master. It must be changed only by
                    # the ConfManager
                    if not changed_pass:
                        changed_pass = self.changeVMCredentials(ctxt_vm, pk_file)
                        res_data['CHANGE_CREDS'] = changed_pass

                    if ctxt_vm['os'] != "windows":
                        if local:
                            # this step is not needed in windows systems
                            self.set_ansible_connection_local(general_conf_data, ctxt_vm)
                            if ctxt_vm['master']:
                                # Install ansible modules
                                playbook = self.install_ansible_modules(general_conf_data, playbook)
                            if 'nat_instance' in ctxt_vm and ctxt_vm['nat_instance']:
                                playbook = self.add_nat_gateway_tasks(playbook)
                            ansible_thread = self.LaunchAnsiblePlaybook(self.logger,
                                                                        vm_conf_data['remote_dir'],
                                                                        playbook, ctxt_vm, 2,
                                                                        inventory_file, pk_file,
                                                                        CtxtAgent.INTERNAL_PLAYBOOK_RETRIES,
                                                                        changed_pass, vault_pass)
                        else:
                            remote_process = self.LaunchRemoteAgent(ctxt_vm, vault_pass, pk_file, changed_pass)
                else:
                    # in the other tasks pk_file can be used
                    if ctxt_vm['os'] != "windows" and not ctxt_vm['master'] and not local:
                        remote_process = self.LaunchRemoteAgent(ctxt_vm, vault_pass, CtxtAgentBase.PK_FILE,
                                                                vm_conf_data['changed_pass'])
                    else:
                        if ctxt_vm['os'] != "windows":
                            self.set_ansible_connection_local(general_conf_data, ctxt_vm)
                        ansible_thread = self.LaunchAnsiblePlaybook(self.logger, vm_conf_data['remote_dir'],
                                                                    playbook, ctxt_vm, 2,
                                                                    inventory_file, CtxtAgentBase.PK_FILE,
                                                                    CtxtAgent.INTERNAL_PLAYBOOK_RETRIES,
                                                                    vm_conf_data['changed_pass'], vault_pass)

                if ansible_thread:
                    copy = True
                    if ctxt_vm['master'] or ctxt_vm['os'] == "windows":
                        copy = False
                    task_ok = self.wait_thread(ansible_thread, general_conf_data, copy)
                elif remote_process:
                    task_ok = self.wait_remote(remote_process, active=task == "install_ansible")
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

    def run(self, local):
        # if we have the .rep file, read it instead
        if os.path.isfile(self.conf_data_filename + ".rep"):
            try:
                with open(self.conf_data_filename + ".rep") as f:
                    general_conf_data = json.load(f)
            except Exception:
                print("Error loading .rep file, using original one.")
                with open(self.conf_data_filename) as f:
                    general_conf_data = json.load(f)
        else:
            with open(self.conf_data_filename) as f:
                general_conf_data = json.load(f)
        with open(self.vm_conf_data_filename) as f:
            vm_conf_data = json.load(f)

        ctxt_vm = None
        for vm in general_conf_data['vms']:
            if vm['id'] == vm_conf_data['id']:
                ctxt_vm = vm
                break

        if local or "copy_facts_cache" in vm_conf_data['tasks'] or ctxt_vm['master'] or ctxt_vm['os'] == 'windows':
            log_file = vm_conf_data['remote_dir'] + "/ctxt_agent.log"
        else:
            log_file = vm_conf_data['remote_dir'] + "/ctxt_agentr.log"

        self.init_logger(log_file)

        if 'playbook_retries' in general_conf_data:
            CtxtAgent.PLAYBOOK_RETRIES = general_conf_data['playbook_retries']

        CtxtAgentBase.PK_FILE = general_conf_data['conf_dir'] + "/" + "ansible_key"

        res_data = self.contextualize_vm(general_conf_data, vm_conf_data, ctxt_vm, local)

        if (local or ctxt_vm['master'] or "install_ansible" in vm_conf_data['tasks'] or
                "copy_facts_cache" in vm_conf_data['tasks'] or ctxt_vm['os'] == 'windows'):
            ctxt_out = open(vm_conf_data['remote_dir'] + "/ctxt_agent.out", 'w+')
        else:
            ctxt_out = open(vm_conf_data['remote_dir'] + "/ctxt_agentr.out", 'w+')
        json.dump(res_data, ctxt_out, indent=2)
        ctxt_out.close()

        if local and not ctxt_vm['master'] and ctxt_vm['os'] != "windows":
            try:
                ssh_master = self.get_master_ssh(general_conf_data)
                if os.path.exists(vm_conf_data['remote_dir'] + "/ctxt_agent.log"):
                    ssh_master.sftp_put(vm_conf_data['remote_dir'] + "/ctxt_agent.log",
                                        vm_conf_data['remote_dir'] + "/ctxt_agent.log")
                    os.unlink(vm_conf_data['remote_dir'] + "/ctxt_agent.log")
                else:
                    self.logger.error("File %s does not exist" % vm_conf_data['remote_dir'] + "/ctxt_agent.log")
                    return False
                if os.path.exists(vm_conf_data['remote_dir'] + "/ctxt_agent.out"):
                    ssh_master.sftp_put(vm_conf_data['remote_dir'] + "/ctxt_agent.out",
                                        vm_conf_data['remote_dir'] + "/ctxt_agent.out")
                    os.unlink(vm_conf_data['remote_dir'] + "/ctxt_agent.out")
                else:
                    self.logger.error("File %s does not exist" % vm_conf_data['remote_dir'] + "/ctxt_agent.out")
                    return False
            except Exception:
                self.logger.exception("Error copying back the results")
                return False

        return res_data['OK']


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Contextualization Agent.')
    parser.add_argument('general', type=str, nargs=1)
    parser.add_argument('vmconf', type=str, nargs=1)
    parser.add_argument('local', type=int, nargs='?', default=False)
    options = parser.parse_args()

    ctxt_agent = CtxtAgent(options.general[0], options.vmconf[0])
    if ctxt_agent.run(bool(options.local)):
        sys.exit(0)
    else:
        sys.exit(1)
