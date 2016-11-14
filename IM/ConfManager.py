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
# GNU General Public License for more/etc/sudoers details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import yaml
import threading
import os
import time
import tempfile
import logging
import shutil
import json
import copy
from StringIO import StringIO
from multiprocessing import Queue

from IM.ansible.ansible_launcher import AnsibleThread

import InfrastructureManager
from VirtualMachine import VirtualMachine
from SSH import AuthenticationException
from SSHRetry import SSHRetry
from recipe import Recipe
from radl.radl import system, contextualize_item
import ServiceRequests

from config import Config


class ConfManager(threading.Thread):
    """
    Class to manage the contextualization steps
    """

    logger = logging.getLogger('ConfManager')
    """ Logger object """
    MASTER_YAML = "conf-ansible.yml"
    """ The file with the ansible steps to configure the master node """
    SECOND_STEP_YAML = 'conf-ansible-s2.yml'
    """ The file with the ansible steps to configure the second step of the the master node """

    def __init__(self, inf, auth, max_ctxt_time=1e9):
        threading.Thread.__init__(self)
        self.daemon = True
        self.inf = inf
        self.auth = auth
        self.init_time = time.time()
        self.max_ctxt_time = max_ctxt_time
        self._stop = False
        self.ansible_process = None

    def check_running_pids(self, vms_configuring):
        """
        Update the status of the configuration processes
        """
        res = {}
        for step, vm_list in vms_configuring.iteritems():
            for vm in vm_list:
                if isinstance(vm, VirtualMachine):
                    # Update the info of the VM to check it is in a correct
                    # state
                    vm.update_status(self.auth)
                    if vm.is_ctxt_process_running():
                        if step not in res:
                            res[step] = []
                        res[step].append(vm)
                        ConfManager.logger.debug("Inf ID: " + str(self.inf.id) +
                                                 ": Ansible process to configure " + str(
                            vm.im_id) + " with PID " + vm.ctxt_pid + " is still running.")
                    else:
                        ConfManager.logger.debug(
                            "Inf ID: " + str(self.inf.id) + ": Configuration process in VM: " +
                            str(vm.im_id) + " finished.")
                        # Force to save the data to store the log data ()
                        ServiceRequests.IMBaseRequest.create_request(
                            ServiceRequests.IMBaseRequest.SAVE_DATA, (self.inf.id))
                else:
                    # General Infrastructure tasks
                    if vm.is_ctxt_process_running():
                        if step not in res:
                            res[step] = []
                        res[step].append(vm)
                        ConfManager.logger.debug("Inf ID: " + str(self.inf.id) +
                                                 ": Configuration process of master node: " +
                                                 str(vm.get_ctxt_process_names()) + " is still running.")
                    else:
                        if vm.configured:
                            ConfManager.logger.debug("Inf ID: " + str(self.inf.id) +
                                                     ": Configuration process of master node successfully finished.")
                        else:
                            ConfManager.logger.debug(
                                "Inf ID: " + str(self.inf.id) + ": Configuration process of master node failed.")
                        # Force to save the data to store the log data
                        ServiceRequests.IMBaseRequest.create_request(
                            ServiceRequests.IMBaseRequest.SAVE_DATA, (self.inf.id))

        return res

    def stop(self):
        self._stop = True
        # put a task to assure to wake up the thread
        self.inf.ctxt_tasks.put((-10, 0, None, None))
        ConfManager.logger.debug(
            "Inf ID: " + str(self.inf.id) + ": Stop Configuration thread.")
        if self.ansible_process and self.ansible_process.is_alive():
            ConfManager.logger.debug(
                "Inf ID: " + str(self.inf.id) + ": Stopping pending Ansible process.")
            self.ansible_process.terminate()

    def check_vm_ips(self, timeout=Config.WAIT_RUNNING_VM_TIMEOUT):

        wait = 0
        # Assure that all the VMs of the Inf. have one IP
        success = False
        while not success and wait < timeout:
            success = True
            for vm in self.inf.get_vm_list():
                if vm.hasPublicNet():
                    ip = vm.getPublicIP()
                else:
                    ip = vm.getPrivateIP()
                    if not ip:
                        ip = vm.getPublicIP()

                if not ip:
                    # If the IP is not Available try to update the info
                    vm.update_status(self.auth)

                    # If the VM is not in a "running" state, ignore it
                    if vm.state in VirtualMachine.NOT_RUNNING_STATES:
                        ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": The VM ID: " + str(
                            vm.id) + " is not running, do not wait it to have an IP.")
                        continue

                    if vm.hasPublicNet():
                        ip = vm.getPublicIP()
                    else:
                        ip = vm.getPrivateIP()
                        if not ip:
                            ip = vm.getPublicIP()

                    if not ip:
                        success = False
                        break

            if not success:
                ConfManager.logger.warn(
                    "Inf ID: " + str(self.inf.id) + ": Error waiting all the VMs to have a correct IP")
                wait += Config.CONFMAMAGER_CHECK_STATE_INTERVAL
                time.sleep(Config.CONFMAMAGER_CHECK_STATE_INTERVAL)
            else:
                self.inf.set_configured(True)

        return success

    def kill_ctxt_processes(self):
        """
            Kill all the ctxt processes
        """
        for vm in self.inf.get_vm_list():
            ConfManager.logger.debug(
                "Inf ID: " + str(self.inf.id) + ": Killing ctxt processes.")
            vm.kill_check_ctxt_process()

    def run(self):
        ConfManager.logger.debug(
            "Inf ID: " + str(self.inf.id) + ": Starting the ConfManager Thread")

        last_step = None
        vms_configuring = {}

        while not self._stop:
            if self.init_time + self.max_ctxt_time < time.time():
                ConfManager.logger.debug(
                    "Inf ID: " + str(self.inf.id) + ": Max contextualization time passed. Exit thread.")
                # Kill the ansible processes
                self.kill_ctxt_processes()
                if self.ansible_process and self.ansible_process.is_alive():
                    ConfManager.logger.debug(
                        "Inf ID: " + str(self.inf.id) + ": Stopping pending Ansible process.")
                    self.ansible_process.terminate()
                return

            vms_configuring = self.check_running_pids(vms_configuring)

            # If the queue is empty but there are vms configuring wait and test
            # again
            if self.inf.ctxt_tasks.empty() and vms_configuring:
                time.sleep(Config.CONFMAMAGER_CHECK_STATE_INTERVAL)
                continue

            (step, prio, vm, tasks) = self.inf.ctxt_tasks.get()

            # stop the thread if the stop method has been called
            if self._stop:
                ConfManager.logger.debug(
                    "Inf ID: " + str(self.inf.id) + ": Exit Configuration thread.")
                return

            # if this task is from a next step
            if last_step is not None and last_step < step:
                if vm.is_configured() is False:
                    ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Configuration process of step " + str(
                        last_step) + " failed, ignoring tasks of later steps.")
                else:
                    # Add the task again to the queue only if the last step was
                    # OK
                    self.inf.add_ctxt_tasks([(step, prio, vm, tasks)])

                    # If there are any process running of last step, wait
                    if last_step in vms_configuring and len(vms_configuring[last_step]) > 0:
                        ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Waiting processes of step " +
                                                 str(last_step) + " to finish.")
                        time.sleep(Config.CONFMAMAGER_CHECK_STATE_INTERVAL)
                    else:
                        # if not, update the step, to go ahead with the new
                        # step
                        ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Step " + str(
                            last_step) + " finished. Go to step: " + str(step))
                        last_step = step
            else:
                if isinstance(vm, VirtualMachine):
                    if vm.destroy:
                        ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": VM ID " + str(
                            vm.im_id) + " has been destroyed. Not launching new tasks for it.")
                    elif vm.is_configured() is False:
                        ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Configuration process of step " +
                                                 str(last_step) + " failed, ignoring tasks of later steps.")
                        # Check that the VM has no other ansible process
                        # running
                    elif vm.ctxt_pid:
                        ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": VM ID " +
                                                 str(vm.im_id) + " has running processes, wait.")
                        # If there are, add the tasks again to the queue
                        # Set the priority to a higher number to decrease the
                        # priority enabling to select other items of the queue
                        # before
                        self.inf.add_ctxt_tasks([(step, prio + 1, vm, tasks)])
                        # Sleep to check this later
                        time.sleep(Config.CONFMAMAGER_CHECK_STATE_INTERVAL)
                    else:
                        # If not, launch it
                        # Mark this VM as configuring
                        vm.configured = None
                        # Launch the ctxt_agent using a thread
                        t = threading.Thread(name="launch_ctxt_agent_" + str(
                            vm.id), target=eval("self.launch_ctxt_agent"), args=(vm, tasks))
                        t.daemon = True
                        t.start()
                        vm.inf.conf_threads.append(t)
                        if step not in vms_configuring:
                            vms_configuring[step] = []
                        vms_configuring[step].append(vm.inf)
                        # Add the VM to the list of configuring vms
                        vms_configuring[step].append(vm)
                        # Set the "special pid" to wait untill the real pid is
                        # assigned
                        vm.ctxt_pid = VirtualMachine.WAIT_TO_PID
                        # Force to save the data to store the log data
                        ServiceRequests.IMBaseRequest.create_request(
                            ServiceRequests.IMBaseRequest.SAVE_DATA, (self.inf.id))
                else:
                    # Launch the Infrastructure tasks
                    vm.configured = None
                    for task in tasks:
                        t = threading.Thread(
                            name=task, target=eval("self." + task))
                        t.daemon = True
                        t.start()
                        vm.conf_threads.append(t)
                    if step not in vms_configuring:
                        vms_configuring[step] = []
                    vms_configuring[step].append(vm)
                    # Force to save the data to store the log data
                    ServiceRequests.IMBaseRequest.create_request(
                        ServiceRequests.IMBaseRequest.SAVE_DATA, (self.inf.id))

                last_step = step

    def launch_ctxt_agent(self, vm, tasks):
        """
        Launch the ctxt agent to configure the specified tasks in the specified VM
        """
        pid = None
        tmp_dir = None
        try:
            ip = vm.getPublicIP()
            if not ip:
                ip = vm.getPrivateIP()

            if not ip:
                ConfManager.logger.error("Inf ID: " + str(self.inf.id) +
                                         ": VM with ID %s (%s) does not have an IP!!. "
                                         "We cannot launch the ansible process!!" % (str(vm.im_id), vm.id))
            else:
                remote_dir = Config.REMOTE_CONF_DIR + "/" + \
                    str(self.inf.id) + "/" + ip + "_" + \
                    str(vm.getRemoteAccessPort())
                tmp_dir = tempfile.mkdtemp()

                ConfManager.logger.debug(
                    "Inf ID: " + str(self.inf.id) + ": Create the configuration file for the contextualization agent")
                conf_file = tmp_dir + "/config.cfg"
                self.create_vm_conf_file(conf_file, vm, tasks, remote_dir)

                ConfManager.logger.debug(
                    "Inf ID: " + str(self.inf.id) + ": Copy the contextualization agent config file")

                # Copy the contextualization agent config file
                ssh = vm.get_ssh_ansible_master()
                ssh.sftp_mkdir(remote_dir)
                ssh.sftp_put(conf_file, remote_dir + "/" +
                             os.path.basename(conf_file))

                if vm.configured is None:
                    (pid, _, _) = ssh.execute("nohup python_ansible " + Config.REMOTE_CONF_DIR + "/" +
                                              str(self.inf.id) + "/" + "/ctxt_agent.py " +
                                              Config.REMOTE_CONF_DIR + "/" + str(self.inf.id) + "/" +
                                              "/general_info.cfg " + remote_dir + "/" + os.path.basename(conf_file) +
                                              " > " + remote_dir + "/stdout" + " 2> " + remote_dir +
                                              "/stderr < /dev/null & echo -n $!")

                    ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Ansible process to configure " +
                                             str(vm.im_id) + " launched with pid: " + pid)

                    vm.ctxt_pid = pid
                    vm.launch_check_ctxt_process()
                else:
                    ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": Ansible process to configure " +
                                            str(vm.im_id) + " NOT launched")
        except:
            pid = None
            ConfManager.logger.exception("Inf ID: " + str(self.inf.id) + ": Error launching the ansible process "
                                         "to configure VM with ID %s" % str(vm.im_id))
        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)

        # If the process is not correctly launched the configuration of this VM
        # fails
        if pid is None:
            vm.ctxt_pid = None
            vm.configured = False
            vm.cont_out = "Error launching the contextualization agent to configure the VM. Check the SSH connection."

        return pid

    def generate_inventory(self, tmp_dir):
        """
        Generate the ansible inventory file
        """
        ConfManager.logger.debug(
            "Inf ID: " + str(self.inf.id) + ": create the ansible configuration file")
        res_filename = "hosts"
        ansible_file = tmp_dir + "/" + res_filename
        out = open(ansible_file, 'w')

        # get the master node name
        if self.inf.radl.ansible_hosts:
            (master_name, masterdom) = (
                self.inf.radl.ansible_hosts[0].getHost(), "")
        else:
            (master_name, masterdom) = self.inf.vm_master.getRequestedName(
                default_hostname=Config.DEFAULT_VM_NAME, default_domain=Config.DEFAULT_DOMAIN)

        no_windows = ""
        windows = ""
        all_vars = ""
        vm_group = self.inf.get_vm_list_by_system_name()
        for group in vm_group:
            vm = vm_group[group][0]
            user = vm.getCredentialValues()[0]
            out.write('[' + group + ':vars]\n')
            out.write('ansible_user=' + user + '\n')
            # For compatibility with Ansible 1.X versions
            out.write('ansible_ssh_user=' + user + '\n')

            if vm.getOS().lower() == "windows":
                out.write('ansible_connection=winrm\n')
                out.write('ansible_winrm_server_cert_validation=ignore\n')

            out.write('[' + group + ']\n')

            # Set the vars with the number of nodes of each type
            all_vars += 'IM_' + group.upper() + '_NUM_VMS=' + \
                str(len(vm_group[group])) + '\n'

            for vm in vm_group[group]:
                # first try to use the public IP
                ip = vm.getPublicIP()
                if not ip:
                    ip = vm.getPrivateIP()

                if not ip:
                    ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": The VM ID: " + str(
                        vm.id) + " does not have an IP. It will not be included in the inventory file.")
                    continue

                if vm.state in VirtualMachine.NOT_RUNNING_STATES:
                    ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": The VM ID: " + str(
                        vm.id) + " is not running. It will not be included in the inventory file.")
                    continue

                if vm.getOS().lower() == "windows":
                    windows += "%s_%d\n" % (ip, vm.getRemoteAccessPort())
                else:
                    no_windows += "%s_%d\n" % (ip, vm.getRemoteAccessPort())

                ifaces_im_vars = ''
                for i in range(vm.getNumNetworkIfaces()):
                    iface_ip = vm.getIfaceIP(i)
                    if iface_ip:
                        ifaces_im_vars += ' IM_NODE_NET_' + \
                            str(i) + '_IP=' + iface_ip
                        if vm.getRequestedNameIface(i):
                            (nodename, nodedom) = vm.getRequestedNameIface(
                                i, default_domain=Config.DEFAULT_DOMAIN)
                            ifaces_im_vars += ' IM_NODE_NET_' + \
                                str(i) + '_HOSTNAME=' + nodename
                            ifaces_im_vars += ' IM_NODE_NET_' + \
                                str(i) + '_DOMAIN=' + nodedom
                            ifaces_im_vars += ' IM_NODE_NET_' + \
                                str(i) + '_FQDN=' + nodename + "." + nodedom

                # the master node
                # TODO: Known issue: the master VM must set the public network
                # in the iface 0
                (nodename, nodedom) = system.replaceTemplateName(
                    Config.DEFAULT_VM_NAME + "." + Config.DEFAULT_DOMAIN, str(vm.im_id))
                if vm.getRequestedName():
                    (nodename, nodedom) = vm.getRequestedName(
                        default_domain=Config.DEFAULT_DOMAIN)

                node_line = "%s_%d" % (ip, vm.getRemoteAccessPort())
                node_line += ' ansible_host=%s' % ip
                # For compatibility with Ansible 1.X versions
                node_line += ' ansible_ssh_host=%s' % ip

                node_line += ' ansible_port=%d' % vm.getRemoteAccessPort()
                # For compatibility with Ansible 1.X versions
                node_line += ' ansible_ssh_port=%d' % vm.getRemoteAccessPort()

                if self.inf.vm_master and vm.id == self.inf.vm_master.id:
                    node_line += ' ansible_connection=local'

                if vm.getPublicIP():
                    node_line += ' IM_NODE_PUBLIC_IP=' + vm.getPublicIP()
                    if not vm.getPrivateIP():
                        # If the node only has a public IP set this variable to the public one
                        node_line += ' IM_NODE_PRIVATE_IP=' + vm.getPublicIP()
                if vm.getPrivateIP():
                    node_line += ' IM_NODE_PRIVATE_IP=' + vm.getPrivateIP()
                node_line += ' IM_NODE_HOSTNAME=' + nodename
                node_line += ' IM_NODE_FQDN=' + nodename + "." + nodedom
                node_line += ' IM_NODE_DOMAIN=' + nodedom
                node_line += ' IM_NODE_NUM=' + str(vm.im_id)
                node_line += ' IM_NODE_VMID=' + str(vm.id)
                node_line += ' IM_NODE_CLOUD_TYPE=' + vm.cloud.type
                node_line += ifaces_im_vars

                for app in vm.getInstalledApplications():
                    if app.getValue("path"):
                        node_line += ' IM_APP_' + \
                            app.getValue("name").upper() + \
                            '_PATH=' + app.getValue("path")
                    if app.getValue("version"):
                        node_line += ' IM_APP_' + \
                            app.getValue("name").upper() + \
                            '_VERSION=' + app.getValue("version")

                node_line += "\n"
                out.write(node_line)

            out.write("\n")

        # set the IM global variables
        out.write('[all:vars]\n')
        out.write(all_vars)
        out.write('IM_MASTER_HOSTNAME=' + master_name + '\n')
        out.write('IM_MASTER_FQDN=' + master_name + "." + masterdom + '\n')
        out.write('IM_MASTER_DOMAIN=' + masterdom + '\n')
        out.write('IM_INFRASTRUCTURE_ID=' + self.inf.id + '\n\n')

        if windows:
            out.write('[windows]\n' + windows + "\n")

        # create the allnowindows group to launch the "all" tasks
        if no_windows:
            out.write('[allnowindows]\n' + no_windows + "\n")

        out.close()

        return res_filename

    def generate_etc_hosts(self, tmp_dir):
        """
        Generate the /etc/hosts file to the infrastructure
        """
        res_filename = "etc_hosts"
        hosts_file = tmp_dir + "/" + res_filename
        hosts_out = open(hosts_file, 'w')
        hosts_out.write("127.0.0.1 localhost localhost.localdomain\r\n")

        vm_group = self.inf.get_vm_list_by_system_name()
        for group in vm_group:
            vm = vm_group[group][0]

            for vm in vm_group[group]:
                # first try to use the public IP
                ip = vm.getPublicIP()
                if not ip:
                    ip = vm.getPrivateIP()

                if not ip:
                    ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": The VM ID: " + str(
                        vm.id) + " does not have an IP. It will not be included in the /etc/hosts file.")
                    continue

                for i in range(vm.getNumNetworkIfaces()):
                    if vm.getRequestedNameIface(i):
                        (nodename, nodedom) = vm.getRequestedNameIface(i, default_domain=Config.DEFAULT_DOMAIN)
                        if vm.getIfaceIP(i):
                            hosts_out.write(vm.getIfaceIP(
                                i) + " " + nodename + "." + nodedom + " " + nodename + "\r\n")
                        else:
                            ConfManager.logger.warn("Inf ID: %s: Net interface %d request a name, "
                                                    "but it does not have an IP." % (self.inf.id, i))

                            for j in range(vm.getNumNetworkIfaces()):
                                if vm.getIfaceIP(j):
                                    ConfManager.logger.warn("Setting the IP of the iface %d." % j)
                                    hosts_out.write(vm.getIfaceIP(
                                        j) + " " + nodename + "." + nodedom + " " + nodename + "\r\n")
                                    break

                    # the master node
                    # TODO: Known issue: the master VM must set the public
                    # network in the iface 0
                    (nodename, nodedom) = system.replaceTemplateName(
                        Config.DEFAULT_VM_NAME + "." + Config.DEFAULT_DOMAIN, str(vm.im_id))
                    if not vm.getRequestedName():
                        hosts_out.write(ip + " " + nodename +
                                        "." + nodedom + " " + nodename + "\r\n")

        hosts_out.close()
        return res_filename

    def generate_basic_playbook(self, tmp_dir):
        """
        Generate the basic playbook to be launched in all the VMs
        """
        recipe_files = []
        pk_file = Config.REMOTE_CONF_DIR + "/" + \
            str(self.inf.id) + "/ansible_key"
        shutil.copy(Config.CONTEXTUALIZATION_DIR + "/basic.yml",
                    tmp_dir + "/basic_task_all.yml")
        f = open(tmp_dir + '/basic_task_all.yml', 'a')
        f.write("\n  vars:\n")
        f.write("    - pk_file: " + pk_file + ".pub\n")
        f.write("  hosts: '{{IM_HOST}}'\n")
        f.close()
        recipe_files.append("basic_task_all.yml")
        return recipe_files

    def generate_mount_disks_tasks(self, system):
        """
        Generate a set of tasks to format and mount the specified disks
        """
        res = ""
        cont = 1

        while system.getValue("disk." + str(cont) + ".size") and system.getValue("disk." + str(cont) + ".device"):
            disk_device = system.getValue("disk." + str(cont) + ".device")
            disk_mount_path = system.getValue(
                "disk." + str(cont) + ".mount_path")
            disk_fstype = system.getValue("disk." + str(cont) + ".fstype")

            # Only add the tasks if the user has specified a moun_path and a
            # filesystem
            if disk_mount_path and disk_fstype:
                # This recipe works with EC2 and OpenNebula. It must be
                # tested/completed with other providers
                condition = "    when: ansible_os_family != 'Windows' and item.key.endswith('" + disk_device[
                    -1] + "')\n"
                condition += "    with_dict: '{{ ansible_devices }}'\n"

                res += '  # Tasks to format and mount disk %d from device %s in %s\n' % (
                    cont, disk_device, disk_mount_path)
                res += '  - shell: (echo n; echo p; echo 1; echo ; echo; echo w) |'
                res += ' fdisk /dev/{{item.key}} creates=/dev/{{item.key}}1\n'
                res += condition
                res += '  - filesystem: fstype=' + \
                    disk_fstype + ' dev=/dev/{{item.key}}1\n'
                res += condition
                res += '  - file: path=' + disk_mount_path + ' state=directory recurse=yes\n'
                res += '  - mount: name=' + disk_mount_path + \
                    ' src=/dev/{{item.key}}1 state=mounted fstype=' + \
                    disk_fstype + '\n'
                res += condition
                res += '\n'

            cont += 1

        return res

    def generate_main_playbook(self, vm, group, tmp_dir):
        """
        Generate the main playbook to be launched in all the VMs.
        This playbook basically install the apps specified in the RADL
        (as apps not in the configure section)
        """
        recipe_files = []
        # Get the info about the apps from the recipes DB
        _, recipes = Recipe.getInfoApps(vm.getAppsToInstall())

        conf_out = open(tmp_dir + "/main_" + group + "_task.yml", 'w')
        conf_content = self.add_ansible_header(group, vm.getOS().lower())

        conf_content += "  pre_tasks: \n"
        # Basic tasks set copy /etc/hosts ...
        conf_content += "  - include: utils/tasks/main.yml\n"

        conf_content += "  tasks: \n"
        conf_content += "  - debug: msg='Install user requested apps'\n"

        # Generate a set of tasks to format and mount the specified disks
        conf_content += self.generate_mount_disks_tasks(vm.info.systems[0])

        for app_name, recipe in recipes:
            self.inf.add_cont_msg("App: " + app_name + " set to be installed.")

            # If there are a recipe, use it
            if recipe:
                conf_content = self.mergeYAML(conf_content, recipe)
                conf_content += "\n\n"
            else:
                # use the app name as the package to install
                parts = app_name.split(".")
                short_app_name = parts[len(parts) - 1]
                install_app = "- tasks: \n"
                # TODO set other packagers: pacman, zypper ...
                install_app += "  - name: Apt install " + short_app_name + "\n"
                install_app += "    action: apt pkg=" + short_app_name + \
                    " state=installed update_cache=yes cache_valid_time=604800\n"
                install_app += "    when: \"ansible_os_family == 'Debian'\"\n"
                install_app += "    ignore_errors: yes\n"
                install_app += "  - name: Yum install " + short_app_name + "\n"
                install_app += "    action: yum pkg=" + short_app_name + " state=installed\n"
                install_app += "    when: \"ansible_os_family == 'RedHat'\"\n"
                install_app += "    ignore_errors: yes\n"
                conf_content = self.mergeYAML(conf_content, install_app)

        conf_out.write(conf_content)
        conf_out.close()
        recipe_files.append("main_" + group + "_task.yml")

        # create the "all" to enable this playbook to see the facts of all the
        # nodes
        all_filename = self.create_all_recipe(
            tmp_dir, "main_" + group + "_task")
        recipe_files.append(all_filename)
        # all_windows_filename =  self.create_all_recipe(tmp_dir, "main_" + group + "_task", "windows", "_all_win.yml")
        # recipe_files.append(all_windows_filename)

        return recipe_files

    def generate_playbook(self, vm, ctxt_elem, tmp_dir):
        """
        Generate the playbook for the specified configure section
        """
        recipe_files = []

        conf_filename = tmp_dir + "/" + ctxt_elem.configure + \
            "_" + ctxt_elem.system + "_task.yml"
        if not os.path.isfile(conf_filename):
            configure = self.inf.radl.get_configure_by_name(
                ctxt_elem.configure)
            conf_content = self.add_ansible_header(
                ctxt_elem.system, vm.getOS().lower())
            conf_content = self.mergeYAML(conf_content, configure.recipes)

            conf_out = open(conf_filename, 'w')
            conf_out.write(conf_content + "\n\n")
            conf_out.close()
            recipe_files.append(ctxt_elem.configure + "_" +
                                ctxt_elem.system + "_task.yml")

            # create the "all" to enable this playbook to see the facts of all
            # the nodes
            all_filename = self.create_all_recipe(
                tmp_dir, ctxt_elem.configure + "_" + ctxt_elem.system + "_task")
            recipe_files.append(all_filename)
            # all_windows_filename =  self.create_all_recipe(tmp_dir, ctxt_elem.configure + "_" +
            #                                               ctxt_elem.system + "_task", "windows", "_all_win.yml")
            # recipe_files.append(all_windows_filename)

        return recipe_files

    def configure_master(self):
        """
        Perform all the tasks to configure the master VM.
          * Change the password
          * Install ansible
          * Copy the contextualization agent files
        """
        success = True
        tmp_dir = None
        if not self.inf.ansible_configured:
            success = False
            cont = 0
            while not self._stop and not success and cont < Config.PLAYBOOK_RETRIES:
                time.sleep(cont * 5)
                cont += 1
                try:
                    ConfManager.logger.info(
                        "Inf ID: " + str(self.inf.id) + ": Start the contextualization process.")

                    if self.inf.radl.ansible_hosts:
                        configured_ok = True
                    else:
                        ssh = self.inf.vm_master.get_ssh(retry=True)
                        # Activate tty mode to avoid some problems with sudo in
                        # REL
                        ssh.tty = True

                        # configuration dir os th emaster node to copy all the
                        # contextualization files
                        tmp_dir = tempfile.mkdtemp()
                        # Now call the ansible installation process on the
                        # master node
                        configured_ok = self.configure_ansible(ssh, tmp_dir)

                        if not configured_ok:
                            ConfManager.logger.error(
                                "Inf ID: " + str(self.inf.id) + ": Error in the ansible installation process")
                            if not self.inf.ansible_configured:
                                self.inf.ansible_configured = False
                        else:
                            ConfManager.logger.info(
                                "Inf ID: " + str(self.inf.id) + ": Ansible installation finished successfully")

                    remote_dir = Config.REMOTE_CONF_DIR + \
                        "/" + str(self.inf.id) + "/"
                    ConfManager.logger.debug(
                        "Inf ID: " + str(self.inf.id) + ": Copy the contextualization agent files")
                    files = []
                    files.append(
                        (Config.IM_PATH + "/SSH.py", remote_dir + "/SSH.py"))
                    files.append(
                        (Config.IM_PATH + "/ansible/ansible_callbacks.py", remote_dir + "/ansible_callbacks.py"))
                    files.append((Config.IM_PATH + "/ansible/ansible_executor_v2.py",
                                  remote_dir + "/ansible_executor_v2.py"))
                    files.append(
                        (Config.IM_PATH + "/ansible/ansible_launcher.py", remote_dir + "/ansible_launcher.py"))
                    files.append((Config.CONTEXTUALIZATION_DIR +
                                  "/ctxt_agent.py", remote_dir + "/ctxt_agent.py"))

                    if self.inf.radl.ansible_hosts:
                        for ansible_host in self.inf.radl.ansible_hosts:
                            (user, passwd, private_key) = ansible_host.getCredentialValues()
                            ssh = SSHRetry(ansible_host.getHost(),
                                           user, passwd, private_key)
                            ssh.sftp_mkdir(remote_dir)
                            ssh.sftp_chmod(remote_dir, 448)
                            ssh.sftp_put_files(files)
                            # Copy the utils helper files
                            ssh.sftp_mkdir(remote_dir + "/" + "/utils")
                            ssh.sftp_put_dir(
                                Config.RECIPES_DIR + "/utils", remote_dir + "/" + "/utils")
                    else:
                        ssh.sftp_mkdir(remote_dir)
                        ssh.sftp_chmod(remote_dir, 448)
                        ssh.sftp_put_files(files)
                        # Copy the utils helper files
                        ssh.sftp_mkdir(remote_dir + "/" + "/utils")
                        ssh.sftp_put_dir(Config.RECIPES_DIR +
                                         "/utils", remote_dir + "/" + "/utils")

                    success = configured_ok

                except Exception, ex:
                    ConfManager.logger.exception(
                        "Inf ID: " + str(self.inf.id) + ": Error in the ansible installation process")
                    self.inf.add_cont_msg(
                        "Error in the ansible installation process: " + str(ex))
                    if not self.inf.ansible_configured:
                        self.inf.ansible_configured = False
                    success = False
                finally:
                    if tmp_dir:
                        shutil.rmtree(tmp_dir, ignore_errors=True)

            if success:
                self.inf.ansible_configured = True
                self.inf.set_configured(True)
                # Force to save the data to store the log data
                ServiceRequests.IMBaseRequest.create_request(
                    ServiceRequests.IMBaseRequest.SAVE_DATA, (self.inf.id))
            else:
                self.inf.ansible_configured = False
                self.inf.set_configured(False)

        return success

    def wait_master(self):
        """
            - Select the master VM
            - Wait it to boot and has the SSH port open
        """
        if self.inf.radl.ansible_hosts:
            ConfManager.logger.debug("Inf ID: " + str(self.inf.id) +
                                     ": Usign ansible host: " + self.inf.radl.ansible_hosts[0].getHost())
            self.inf.set_configured(True)
            return True

        # First assure that ansible is installed in the master
        if not self.inf.vm_master or self.inf.vm_master.destroy:
            # If the user has deleted the master vm, it must be configured
            # again
            self.inf.ansible_configured = None

        success = True
        if not self.inf.ansible_configured:
            # Select the master VM
            try:
                self.inf.add_cont_msg("Select master VM")
                self.inf.select_vm_master()

                if not self.inf.vm_master:
                    # If there are not a valid master VM, exit
                    ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ": No correct Master VM found. Exit")
                    self.inf.add_cont_msg("Contextualization Error: No correct Master VM found. Check if there a "
                                          "linux VM with Public IP and connected with the rest of VMs.")
                    self.inf.set_configured(False)
                    return

                ConfManager.logger.info("Inf ID: " + str(self.inf.id) + ": Wait the master VM to be running")

                self.inf.add_cont_msg("Wait master VM to boot")
                all_running = self.wait_vm_running(self.inf.vm_master, Config.WAIT_RUNNING_VM_TIMEOUT, True)

                if not all_running:
                    ConfManager.logger.error("Inf ID: " + str(self.inf.id) +
                                             ":  Error Waiting the Master VM to boot, exit")
                    self.inf.add_cont_msg("Contextualization Error: Error Waiting the Master VM to boot")
                    self.inf.set_configured(False)
                    return

                # To avoid problems with the known hosts of previous calls
                if os.path.isfile(os.path.expanduser("~/.ssh/known_hosts")):
                    ConfManager.logger.debug("Remove " + os.path.expanduser("~/.ssh/known_hosts"))
                    os.remove(os.path.expanduser("~/.ssh/known_hosts"))

                self.inf.add_cont_msg("Wait master VM to have the SSH active.")
                is_connected, msg = self.wait_vm_ssh_acccess(
                    self.inf.vm_master, Config.WAIT_RUNNING_VM_TIMEOUT)
                if not is_connected:
                    ConfManager.logger.error("Inf ID: " + str(self.inf.id) +
                                             ": Error Waiting the Master VM to have the SSH active, exit: " +
                                             msg)
                    self.inf.add_cont_msg("Contextualization Error: Error Waiting the Master VM to have the SSH"
                                          " active: " + msg)
                    self.inf.set_configured(False)
                    return

                ConfManager.logger.info("Inf ID: " + str(self.inf.id) + ": VMs available.")

                # Check and change if necessary the credentials of the master
                # vm
                ssh = self.inf.vm_master.get_ssh(retry=True)
                # Activate tty mode to avoid some problems with sudo in REL
                ssh.tty = True
                self.change_master_credentials(ssh)

                # Force to save the data to store the log data
                ServiceRequests.IMBaseRequest.create_request(
                    ServiceRequests.IMBaseRequest.SAVE_DATA, (self.inf.id))

                self.inf.set_configured(True)
            except:
                ConfManager.logger.exception(
                    "Inf ID: " + str(self.inf.id) + ": Error waiting the master VM to be running")
                self.inf.set_configured(False)
        else:
            self.inf.set_configured(True)

        return success

    def generate_playbooks_and_hosts(self):
        """
        Generate all the files needed in the contextualization, playbooks, /etc/hosts, inventory
        """
        tmp_dir = None
        try:
            tmp_dir = tempfile.mkdtemp()
            remote_dir = Config.REMOTE_CONF_DIR + "/" + str(self.inf.id) + "/"
            # Get the groups for the different VM types
            vm_group = self.inf.get_vm_list_by_system_name()

            ConfManager.logger.debug(
                "Inf ID: " + str(self.inf.id) + ": Generating YAML, hosts and inventory files.")
            # Create the other configure sections (it may be included in other
            # configure)
            filenames = []
            if self.inf.radl.configures:
                for elem in self.inf.radl.configures:
                    if elem is not None and not os.path.isfile(tmp_dir + "/" + elem.name + ".yml"):
                        conf_out = open(
                            tmp_dir + "/" + elem.name + ".yml", 'w')
                        conf_out.write(elem.recipes)
                        conf_out.write("\n\n")
                        conf_out.close()
                        filenames.append(elem.name + ".yml")

            filenames.extend(self.generate_basic_playbook(tmp_dir))

            # Create the YAML file with the basic steps and the apps to install
            for group in vm_group:
                # Use the first VM as the info used is the same for all the VMs
                # in the group
                vm = vm_group[group][0]
                filenames.extend(
                    self.generate_main_playbook(vm, group, tmp_dir))

            # get the default ctxts in case of the RADL has not specified them
            ctxts = [contextualize_item(
                group, group, 1) for group in vm_group if self.inf.radl.get_configure_by_name(group)]
            # get the contextualize steps specified in the RADL, or use the
            # default value
            contextualizes = self.inf.radl.contextualize.get_contextualize_items_by_step({1: ctxts})

            # create the files for the configure sections that appears in the contextualization steps
            # and add the ansible information and modules
            for ctxt_num in contextualizes.keys():
                for ctxt_elem in contextualizes[ctxt_num]:
                    if ctxt_elem.system in vm_group and ctxt_elem.get_ctxt_tool() == "Ansible":
                        vm = vm_group[ctxt_elem.system][0]
                        filenames.extend(self.generate_playbook(
                            vm, ctxt_elem, tmp_dir))

            filenames.append(self.generate_etc_hosts(tmp_dir))
            filenames.append(self.generate_inventory(tmp_dir))

            conf_file = "general_info.cfg"
            self.create_general_conf_file(tmp_dir + "/" + conf_file, self.inf.get_vm_list())
            filenames.append(conf_file)

            recipe_files = []
            for f in filenames:
                recipe_files.append((tmp_dir + "/" + f, remote_dir + "/" + f))

            self.inf.add_cont_msg("Copying YAML, hosts and inventory files.")
            ConfManager.logger.debug(
                "Inf ID: " + str(self.inf.id) + ": Copying YAML files.")
            if self.inf.radl.ansible_hosts:
                for ansible_host in self.inf.radl.ansible_hosts:
                    (user, passwd, private_key) = ansible_host.getCredentialValues()
                    ssh = SSHRetry(ansible_host.getHost(),
                                   user, passwd, private_key)
                    ssh.sftp_mkdir(remote_dir)
                    ssh.sftp_put_files(recipe_files)
            else:
                ssh = self.inf.vm_master.get_ssh(retry=True)
                ssh.sftp_mkdir(remote_dir)
                ssh.sftp_put_files(recipe_files)

            self.inf.set_configured(True)
        except Exception, ex:
            self.inf.set_configured(False)
            ConfManager.logger.exception(
                "Inf ID: " + str(self.inf.id) + ": Error generating playbooks.")
            self.inf.add_cont_msg("Error generating playbooks: " + str(ex))
        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)

    def relaunch_vm(self, vm, failed_cloud=False):
        """
        Remove and launch again the specified VM
        """
        try:
            removed = InfrastructureManager.InfrastructureManager.RemoveResource(
                self.inf.id, vm.im_id, self.auth)
        except:
            ConfManager.logger.exception(
                "Inf ID: " + str(self.inf.id) + ": Error removing a failed VM.")
            removed = 0

        if removed != 1:
            ConfManager.logger.error(
                "Inf ID: " + str(self.inf.id) + ": Error removing a failed VM. Not launching a new one.")
            return

        new_radl = ""
        for net in vm.info.networks:
            new_radl += "network " + net.id + "\n"
        new_radl += "system " + vm.getRequestedSystem().name + "\n"
        new_radl += "deploy " + vm.getRequestedSystem().name + " 1"

        failed_clouds = []
        if failed_cloud:
            failed_clouds = [vm.cloud]
        InfrastructureManager.InfrastructureManager.AddResource(
            self.inf.id, new_radl, self.auth, False, failed_clouds)

    def wait_vm_running(self, vm, timeout, relaunch=False):
        """
        Wait for a VM to be running

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM to be running.
           - timeout(int): Max time to wait the VM to be running.
           - relaunch(bool, optional): Flag to specify if the VM must be relaunched in case of failure.
        Returns: True if all the VMs are running or false otherwise
        """
        timeout_retries = 0
        retries = 1
        delay = 10
        wait = 0
        while not self._stop and wait < timeout:
            if not vm.destroy:
                vm.update_status(self.auth)

                if vm.state == VirtualMachine.RUNNING:
                    return True
                elif vm.state == VirtualMachine.FAILED:
                    ConfManager.logger.warn(
                        "Inf ID: " + str(self.inf.id) + ": VM " + str(vm.id) + " is FAILED")

                    if relaunch and retries < Config.MAX_VM_FAILS:
                        ConfManager.logger.info(
                            "Inf ID: " + str(self.inf.id) + ": Launching new VM")
                        self.relaunch_vm(vm, True)
                        # Set the wait counter to 0
                        wait = 0
                        retries += 1
                    else:
                        ConfManager.logger.error(
                            "Inf ID: " + str(self.inf.id) + ": Relaunch is not enabled. Exit")
                        return False
            else:
                ConfManager.logger.warn(
                    "Inf ID: " + str(self.inf.id) + ": VM deleted by the user, Exit")
                return False

            ConfManager.logger.debug(
                "Inf ID: " + str(self.inf.id) + ": VM " + str(vm.id) + " is not running yet.")
            time.sleep(delay)
            wait += delay

            # if the timeout is passed
            # try to relaunch max_retries times, and restart the counter
            if wait > timeout and timeout_retries < Config.MAX_VM_FAILS:
                timeout_retries += 1
                # Set the wait counter to 0
                wait = 0
                if not vm.destroy:
                    vm.update_status(self.auth)

                    if vm.state == VirtualMachine.RUNNING:
                        return True
                    else:
                        ConfManager.logger.warn(
                            "VM " + str(vm.id) + " timeout")

                        if relaunch:
                            ConfManager.logger.info("Launch a new VM")
                            self.relaunch_vm(vm)
                        else:
                            ConfManager.logger.error(
                                "Relaunch is not available. Exit")
                            return False
                else:
                    ConfManager.logger.warn(
                        "Inf ID: " + str(self.inf.id) + ": VM deleted by the user, Exit")
                    return False

        # Timeout, return False
        return False

    def wait_vm_ssh_acccess(self, vm, timeout):
        """
        Wait for the VM to have the SSH port opened

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM to check.
           - timeout(int): Max time to wait the VM to be to have the SSH port opened.
        Returns: True if the VM have the SSH port open or false otherwise
        """
        delay = 10
        wait = 0
        auth_errors = 0
        auth_error_retries = 3
        connected = False
        while not self._stop and wait < timeout:
            if vm.destroy:
                # in this case ignore it
                return False, "VM destroyed."
            else:
                vm.update_status(self.auth)
                if vm.state == VirtualMachine.FAILED:
                    ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'VM: ' +
                                             str(vm.id) + " is in state Failed. Does not wait for SSH.")
                    return False, "VM Failure."

                ip = vm.getPublicIP()
                if ip is not None:
                    ssh = vm.get_ssh()
                    ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'SSH Connecting with: ' +
                                             ip + ' to the VM: ' + str(vm.id))

                    try:
                        connected = ssh.test_connectivity(5)
                    except AuthenticationException:
                        ConfManager.logger.warn("Error connecting with ip: " + ip + " incorrect credentials.")
                        auth_errors += 1

                        if auth_errors >= auth_error_retries:
                            ConfManager.logger.error("Too many authentication errors")
                            return False, "Error connecting with ip: " + ip + " incorrect credentials."

                    if connected:
                        ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'Works!')
                        return True, ""
                    else:
                        ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'do not connect, wait ...')
                        wait += delay
                        time.sleep(delay)
                else:
                    ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'VM ' +
                                             str(vm.id) + ' with no IP')
                    # Update the VM info and wait to have a valid public IP
                    wait += delay
                    time.sleep(delay)

        # Timeout, return False
        return False, "Timeout waiting SSH access."

    def change_master_credentials(self, ssh):
        """
        Chech the RADL of the VM master to see if we must change the user credentials

        Arguments:
           - ssh(:py:class:`IM.SSH`): Object with the authentication data to access the master VM.
        """
        change_creds = False
        try:
            creds = self.inf.vm_master.getCredentialValues()
            (user, passwd, _, _) = creds
            new_creds = self.inf.vm_master.getCredentialValues(new=True)
            if len(list(set(new_creds))) > 1 or list(set(new_creds))[0] is not None:
                change_creds = False
                if cmp(new_creds, creds) != 0:
                    (_, new_passwd, new_public_key, new_private_key) = new_creds
                    # only change to the new password if there are a previous
                    # passwd value
                    if passwd and new_passwd:
                        ConfManager.logger.info(
                            "Changing password to master VM")
                        (out, err, code) = ssh.execute('sudo bash -c \'echo "' + user + ':' + new_passwd +
                                                       '" | /usr/sbin/chpasswd && echo "OK"\' 2> /dev/null')

                        if code == 0:
                            change_creds = True
                            ssh.password = new_passwd
                        else:
                            ConfManager.logger.error(
                                "Error changing password to master VM. " + out + err)

                    if new_public_key and new_private_key:
                        ConfManager.logger.info(
                            "Changing public key to master VM")
                        (out, err, code) = ssh.execute('echo ' +
                                                       new_public_key + ' >> .ssh/authorized_keys')
                        if code != 0:
                            ConfManager.logger.error(
                                "Error changing public key to master VM. " + out + err)
                        else:
                            change_creds = True
                            ssh.private_key = new_private_key

                if change_creds:
                    self.inf.vm_master.info.systems[
                        0].updateNewCredentialValues()
        except:
            ConfManager.logger.exception(
                "Error changing credentials to master VM.")

        return change_creds

    def call_ansible(self, tmp_dir, inventory, playbook, ssh):
        """
        Call the AnsibleThread to execute an Ansible playbook

        Arguments:
           - tmp_dir(str): Temp directory where all the playbook files will be stored.
           - inventory(str): Filename with the ansible inventory file (related to the tmp_dir)
           - playbook(str): Filename with the ansible playbook file (related to the tmp_dir)
           - ssh(:py:class:`IM.SSH`): Object with the authentication data to access the node to be configured.
        Returns: a tuple (sucess, msg) with:
           - sucess: True if the process finished sucessfully, False otherwise.
           - msg: Log messages of the contextualization process.
        """

        if ssh.private_key:
            gen_pk_file = tmp_dir + "/pk_" + ssh.host + ".pem"
            # If the file exists, does not create again
            if not os.path.isfile(gen_pk_file):
                pk_out = open(gen_pk_file, 'w')
                pk_out.write(ssh.private_key)
                pk_out.close()
                os.chmod(gen_pk_file, 0400)
        else:
            gen_pk_file = None

        if not os.path.exists(tmp_dir + "/utils"):
            os.symlink(os.path.abspath(
                Config.RECIPES_DIR + "/utils"), tmp_dir + "/utils")

        ConfManager.logger.debug(
            "Inf ID: " + str(self.inf.id) + ": " + 'Lanzamos ansible.')
        result = Queue()
        # store the process to terminate it later is Ansible does not finish correctly
        self.ansible_process = AnsibleThread(result, StringIO(), tmp_dir + "/" + playbook, None, 1, gen_pk_file,
                                             ssh.password, 1, tmp_dir + "/" + inventory, ssh.username)
        self.ansible_process.start()

        wait = 0
        while self.ansible_process.is_alive():
            if wait >= Config.ANSIBLE_INSTALL_TIMEOUT:
                self.ansible_process.terminate()
                self.ansible_process = None
                return (False, "Timeout. Ansible process terminated.")
            time.sleep(Config.CHECK_CTXT_PROCESS_INTERVAL)
            wait += Config.CHECK_CTXT_PROCESS_INTERVAL
        try:
            # Try to assure that the are no ansible process running
            self.ansible_process.teminate()
        except:
            ConfManager.logger.exception("Inf ID: " + str(self.inf.id) + ": " +
                                         'Problems terminating Ansible processes.')
            pass
        self.ansible_process = None

        _, (return_code, _), output = result.get()

        if return_code == 0:
            return (True, output.getvalue())
        else:
            return (False, output.getvalue())

    def add_ansible_header(self, host, os):
        """
        Add the IM needed header in the contextualization playbooks

        Arguments:
           - host(str): Hostname of VM.
           - os(str): OS of the VM.
        Returns: True if the process finished sucessfully, False otherwise.
        """
        conf_content = "---\n"
        conf_content += "- hosts: \"{{IM_HOST}}\"\n"
        if os != 'windows':
            conf_content += "  become: yes\n"

        return conf_content

    def create_all_recipe(self, tmp_dir, filename, group="allnowindows", suffix="_all.yml"):
        """
        Create the recipe "all" enabling to access all the ansible variables from all hosts
        Arguments:
           - tmp_dir(str): Temp directory where all the playbook files will be stored.
           - filename(str): name of he yaml to include (without the extension)
        """
        all_filename = filename + suffix
        conf_all_out = open(tmp_dir + "/" + all_filename, 'w')
        conf_all_out.write("---\n")
        conf_all_out.write("- hosts: " + group + "\n")
        conf_all_out.write("- include: " + filename + ".yml\n")
        conf_all_out.write("\n\n")
        conf_all_out.close()
        return all_filename

    def configure_ansible(self, ssh, tmp_dir):
        """
        Install ansible in the master node

        Arguments:
           - ssh(:py:class:`IM.SSH`): Object to connect with the master node.
           - tmp_dir(str): Temp directory where all the playbook files will be stored.
        Returns: True if the process finished sucessfully, False otherwise.
        """
        try:
            # Get the groups for the different VM types
            vm_group = self.inf.get_vm_list_by_system_name()

            # Create the ansible inventory file
            with open(tmp_dir + "/inventory.cfg", 'w') as inv_out:
                inv_out.write("%s  ansible_port=%d  ansible_ssh_port=%d" % (
                    ssh.host, ssh.port, ssh.port))

            shutil.copy(Config.CONTEXTUALIZATION_DIR + "/" +
                        ConfManager.MASTER_YAML, tmp_dir + "/" + ConfManager.MASTER_YAML)

            # Add all the modules specified in the RADL
            modules = []
            for s in self.inf.radl.systems:
                for req_app in s.getApplications():
                    if req_app.getValue("name").startswith("ansible.modules."):
                        # Get the modules specified by the user in the RADL
                        modules.append(req_app.getValue("name")[16:])
                    else:
                        # Get the info about the apps from the recipes DB
                        vm_modules, _ = Recipe.getInfoApps([req_app])
                        modules.extend(vm_modules)

            # avoid duplicates
            modules = set(modules)

            self.inf.add_cont_msg(
                "Creating and copying Ansible playbook files")
            ConfManager.logger.debug("Inf ID: " + str(self.inf.id) +
                                     ": Preparing Ansible playbook to copy Ansible modules: " + str(modules))

            ssh.sftp_mkdir(Config.REMOTE_CONF_DIR)
            ssh.sftp_mkdir(Config.REMOTE_CONF_DIR + "/" + str(self.inf.id) + "/")
            ssh.sftp_chmod(Config.REMOTE_CONF_DIR + "/" + str(self.inf.id) + "/", 448)

            for galaxy_name in modules:
                if galaxy_name:
                    ConfManager.logger.debug(
                        "Inf ID: " + str(self.inf.id) + ": Install " + galaxy_name + " with ansible-galaxy.")
                    self.inf.add_cont_msg(
                        "Galaxy role " + galaxy_name + " detected setting to install.")

                    recipe_out = open(
                        tmp_dir + "/" + ConfManager.MASTER_YAML, 'a')

                    parts = galaxy_name.split("|")
                    if len(parts) > 1:
                        url = parts[0]
                        rolename = parts[1]

                        recipe_out.write(
                            '    - name: Create YAML file to install the %s role with ansible-galaxy\n' % rolename)
                        recipe_out.write('      copy:\n')
                        recipe_out.write(
                            '        dest: "/tmp/%s.yml"\n' % rolename)
                        recipe_out.write(
                            '        content: "- src: %s\\n  name: %s"\n' % (url, rolename))
                        url = "-r /tmp/%s.yml" % rolename
                    else:
                        url = rolename = galaxy_name

                    if galaxy_name.startswith("git"):
                        recipe_out.write("    - yum: name=git\n")
                        recipe_out.write(
                            '      when: ansible_os_family == "RedHat"\n')
                        recipe_out.write("    - apt: name=git\n")
                        recipe_out.write(
                            '      when: ansible_os_family == "Debian"\n')

                    recipe_out.write(
                        "    - name: Install the %s role with ansible-galaxy\n" % rolename)
                    recipe_out.write(
                        "      command: ansible-galaxy -f install %s\n" % url)

                    recipe_out.close()

            self.inf.add_cont_msg(
                "Performing preliminary steps to configure Ansible.")
            # TODO: check to do it with ansible
            ConfManager.logger.debug("Inf ID: " + str(self.inf.id) +
                                     ": Check if python-simplejson is installed in REL 5 systems")
            (stdout, stderr, _) = ssh.execute(
                "cat /etc/redhat-release | grep \"release 5\" &&  sudo yum -y install python-simplejson", 120)
            ConfManager.logger.debug(
                "Inf ID: " + str(self.inf.id) + ": " + stdout + stderr)

            ConfManager.logger.debug(
                "Inf ID: " + str(self.inf.id) + ": Remove requiretty in sshd config")
            (stdout, stderr, _) = ssh.execute(
                "sudo sed -i 's/.*requiretty$/#Defaults requiretty/' /etc/sudoers", 120)
            ConfManager.logger.debug(
                "Inf ID: " + str(self.inf.id) + ": " + stdout + stderr)

            self.inf.add_cont_msg("Configure Ansible in the master VM.")
            ConfManager.logger.debug(
                "Inf ID: " + str(self.inf.id) + ": Call Ansible to (re)configure in the master node")
            (success, msg) = self.call_ansible(
                tmp_dir, "inventory.cfg", ConfManager.MASTER_YAML, ssh)

            if not success:
                ConfManager.logger.error("Inf ID: " + str(self.inf.id) +
                                         ": Error configuring master node: " + msg + "\n\n")
                self.inf.add_cont_msg("Error configuring the master VM: " + msg + " " + tmp_dir)
            else:
                ConfManager.logger.debug("Inf ID: " + str(self.inf.id) +
                                         ": Ansible successfully configured in the master VM:\n" + msg + "\n\n")
                self.inf.add_cont_msg("Ansible successfully configured in the master VM.")
        except Exception, ex:
            ConfManager.logger.exception(
                "Inf ID: " + str(self.inf.id) + ": Error configuring master node.")
            self.inf.add_cont_msg("Error configuring master node: " + str(ex))
            success = False

        return success

    def create_general_conf_file(self, conf_file, vm_list):
        """
        Create the configuration file needed by the contextualization agent
        """
        conf_data = {}

        conf_data['playbook_retries'] = Config.PLAYBOOK_RETRIES
        conf_data['vms'] = []
        for vm in vm_list:
            if vm.state in VirtualMachine.NOT_RUNNING_STATES:
                ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": The VM ID: " + str(
                    vm.id) + " is not running, do not include in the general conf file.")
            else:
                vm_conf_data = {}
                vm_conf_data['id'] = vm.im_id
                if vm.getOS():
                    vm_conf_data['os'] = vm.getOS().lower()
                if self.inf.vm_master and vm.im_id == self.inf.vm_master.im_id:
                    vm_conf_data['master'] = True
                else:
                    vm_conf_data['master'] = False
                # first try to use the public IP as the default IP
                vm_conf_data['ip'] = vm.getPublicIP()
                if not vm_conf_data['ip']:
                    vm_conf_data['ip'] = vm.getPrivateIP()
                if vm.getPublicIP() and vm.getPrivateIP():
                    vm_conf_data['private_ip'] = vm.getPrivateIP()
                vm_conf_data['remote_port'] = vm.getRemoteAccessPort()
                creds = vm.getCredentialValues()
                new_creds = vm.getCredentialValues(new=True)
                (vm_conf_data['user'], vm_conf_data['passwd'],
                 _, vm_conf_data['private_key']) = creds
                # If there are new creds to set to the VM
                if len(list(set(new_creds))) > 1 or list(set(new_creds))[0] is not None:
                    if cmp(new_creds, creds) != 0:
                        (_, vm_conf_data['new_passwd'], vm_conf_data[
                         'new_public_key'], vm_conf_data['new_private_key']) = new_creds

                if not vm_conf_data['ip']:
                    # if the vm does not have an IP, do not iclude it to avoid
                    # errors configurin gother VMs
                    ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": The VM ID: " + str(
                        vm.id) + " does not have an IP, do not include in the general conf file.")
                else:
                    conf_data['vms'].append(vm_conf_data)

        conf_data['conf_dir'] = Config.REMOTE_CONF_DIR + \
            "/" + str(self.inf.id) + "/"

        conf_out = open(conf_file, 'w')
        json.dump(conf_data, conf_out, indent=2)
        conf_out.close()

    def create_vm_conf_file(self, conf_file, vm, tasks, remote_dir):
        """
        Create the configuration file needed by the contextualization agent
        """
        conf_data = {}

        conf_data['id'] = vm.im_id
        conf_data['tasks'] = tasks
        conf_data['remote_dir'] = remote_dir

        new_creds = vm.getCredentialValues(new=True)
        if len(list(set(new_creds))) > 1 or list(set(new_creds))[0] is not None:
            # If there are data in the new credentials, they has not been
            # changed
            conf_data['changed_pass'] = False
        else:
            conf_data['changed_pass'] = True

        conf_out = open(conf_file, 'w')
        ConfManager.logger.debug(
            "Ctxt agent vm configuration file: " + json.dumps(conf_data))
        json.dump(conf_data, conf_out, indent=2)
        conf_out.close()

    @staticmethod
    def mergeYAML(yaml1, yaml2):
        """
        Merge two ansible yaml docs

        Arguments:
           - yaml1(str): string with the first YAML
           - yaml1(str): string with the second YAML
        Returns: The merged YAML. In case of errors, it concatenates both strings
        """
        yamlo1o = {}
        try:
            yamlo1o = yaml.load(yaml1)[0]
            if not isinstance(yamlo1o, dict):
                yamlo1o = {}
        except Exception:
            ConfManager.logger.exception(
                "Error parsing YAML: " + yaml1 + "\n Ignore it")

        try:
            yamlo2s = yaml.load(yaml2)
            if not isinstance(yamlo2s, list) or any([not isinstance(d, dict) for d in yamlo2s]):
                yamlo2s = {}
        except Exception:
            ConfManager.logger.exception(
                "Error parsing YAML: " + yaml2 + "\n Ignore it")
            yamlo2s = {}

        if not yamlo2s and not yamlo1o:
            return ""

        result = []
        for yamlo2 in yamlo2s:
            yamlo1 = copy.deepcopy(yamlo1o)
            all_keys = []
            all_keys.extend(yamlo1.keys())
            all_keys.extend(yamlo2.keys())
            all_keys = set(all_keys)

            for key in all_keys:
                if key in yamlo1 and yamlo1[key]:
                    if key in yamlo2 and yamlo2[key]:
                        if isinstance(yamlo1[key], dict):
                            yamlo1[key].update(yamlo2[key])
                        elif isinstance(yamlo1[key], list):
                            yamlo1[key].extend(yamlo2[key])
                        else:
                            # Both use have the same key with merge in a lists
                            v1 = yamlo1[key]
                            v2 = yamlo2[key]
                            yamlo1[key] = [v1, v2]
                elif key in yamlo2 and yamlo2[key]:
                    yamlo1[key] = yamlo2[key]
            result.append(yamlo1)

        return yaml.dump(result, default_flow_style=False, explicit_start=True, width=256)
