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

from IM.ansible.ansible_launcher import AnsibleThread

import InfrastructureManager
from VirtualMachine import VirtualMachine
from SSH import AuthenticationException
from recipe import Recipe
from radl.radl import system, contextualize_item

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
	THREAD_SLEEP_DELAY = 5
	
	def __init__(self, inf, auth):
		threading.Thread.__init__(self)
		self.inf = inf
		self.auth = auth
		self._stop = False
	
	def check_running_pids(self, vms_configuring):
		"""
		Update the status of the configuration processes
		"""
		res = {}
		for step, vm_list in vms_configuring.iteritems():
			for vm in vm_list:
				if isinstance(vm,VirtualMachine):
					if vm.check_ctxt_process():
						if step not in res:
							res[step] = []
						res[step].append(vm)
						ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Ansible process to configure " + str(vm.im_id) + " with PID " + vm.ctxt_pid + " is still running.")
					else:						
						if vm.configured:
							ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Configuration process in VM: " + str(vm.im_id) + " successfully finished.")
						else:
							ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Configuration process in VM: " + str(vm.im_id) + " failed.")
						# Force to save the data to store the log data 
						InfrastructureManager.InfrastructureManager.save_data()
				else:
					# General Infrastructure tasks
					if vm.check_ctxt_process():
						if step not in res:
							res[step] = []
						res[step].append(vm)
						ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Configuration process of master node is still running.")
					else:
						if vm.configured:
							ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ":Configuration process of master node successfully finished.")
						else:
							ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Configuration process of master node failed.")
						# Force to save the data to store the log data 
						InfrastructureManager.InfrastructureManager.save_data()
				
		return res

	def stop(self):
		self._stop = True
		# put a task to assure to wake up the thread 
		self.inf.ctxt_tasks.put((-3, 0,None,None))
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Stop Configuration thread.")

	def check_vm_ips(self, timeout = Config.WAIT_RUNNING_VM_TIMEOUT):
	
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
					# If the IP is not Available try to update the info
					vm.update_status(self.auth)
	
					if vm.hasPublicNet():
						ip = vm.getPublicIP()
					else:
						ip = vm.getPrivateIP()
						
					if not ip:
						success = False
						break
			
			if not success:
				ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": Error waiting all the VMs to have a correct IP") 
				wait += self.THREAD_SLEEP_DELAY
				time.sleep(self.THREAD_SLEEP_DELAY)
			else:
				self.inf.set_configured(True)
				
		return success

	def run(self):
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Starting the ConfManager Thread")

		last_step = None
		vms_configuring = {}

		while not self._stop:
			vms_configuring = self.check_running_pids(vms_configuring)
			
			# If the queue is empty but there are vms configuring wait and test again
			if self.inf.ctxt_tasks.empty() and vms_configuring:
				time.sleep(self.THREAD_SLEEP_DELAY)
				continue

			(step, prio, vm, tasks) = self.inf.ctxt_tasks.get()
			
			if self._stop:
				return

			# if this task is from a next step
			if last_step is not None and last_step < step:
				if vm.is_configured() is False:
					ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Configuration process of step " + str(last_step) + " failed, ignoring tasks of later steps.")
				else:
					# Add the task again to the queue only if the last step was OK
					self.inf.add_ctxt_tasks([(step, prio, vm, tasks)])

					# If there are any process running of last step, wait
					if last_step in vms_configuring and len(vms_configuring[last_step]) > 0:
						ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Waiting processes of step " + str(last_step) + " to finish.")
						time.sleep(self.THREAD_SLEEP_DELAY)
					else:
						# if not, update the step, to go ahead with the new step
						ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Step " + str(last_step) + " finished. Go to step: " + str(step))
						last_step = step
			else:
				if isinstance(vm,VirtualMachine):
					if vm.is_configured() is False:
						ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Configuration process of step " + str(last_step) + " failed, ignoring tasks of later steps.")
						# Check that the VM has no other ansible process running
					elif vm.ctxt_pid:
						ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": VM ID " + str(vm.im_id) + " has running processes, wait.")
						# If there are, add the tasks again to the queue
						# Set the priority to a higher number to decrease the proprity enabling to select other items of the queue before
						self.inf.add_ctxt_tasks([(step, prio+1, vm, tasks)])
						# Sleep to check this later
						time.sleep(self.THREAD_SLEEP_DELAY)
					else:
						# If not, launch it
						try:
							# Mark this VM as configuring 
							vm.configured = None
							vm.ctxt_pid = self.launch_ctxt_agent(vm, tasks)
							if step not in vms_configuring:
								vms_configuring[step] = []
							vms_configuring[step].append(vm)
							# Force to save the data to store the log data 
							InfrastructureManager.InfrastructureManager.save_data()
						except:
							ConfManager.logger.exception("Inf ID: " + str(self.inf.id) + ": Error launching ctxt agent on VM: " + str(vm.im_id))
							# Set this VM as configuration failed
							vm.configured = False
				else:
					# Launch the Infrastructure tasks
					vm.configured = None
					for task in tasks:
						t = threading.Thread(target=eval("self." + task))
						t.daemon = True
						t.start()
						vm.conf_threads.append(t)
					if step not in vms_configuring:
						vms_configuring[step] = []
					vms_configuring[step].append(vm)
					# Force to save the data to store the log data 
					InfrastructureManager.InfrastructureManager.save_data()
					
					
				last_step = step

	def launch_ctxt_agent(self, vm, tasks):
		ip = vm.getPublicIP()
		if not ip:
			ip = vm.getPrivateIP()
		remote_dir = Config.REMOTE_CONF_DIR + "/" + ip + "_" + str(vm.getSSHPort())
		tmp_dir = tempfile.mkdtemp()

		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Create the configuration file for the contextualization agent")
		conf_file = tmp_dir + "/config.cfg"
		self.create_vm_conf_file(conf_file, vm.im_id, tasks, remote_dir)
		
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Copy the contextualization agent config file")

		# Copy the contextualization agent config file
		ssh = self.inf.vm_master.get_ssh()
		ssh.sftp_mkdir(remote_dir)
		ssh.sftp_put(conf_file, remote_dir + "/" + os.path.basename(conf_file))
		
		shutil.rmtree(tmp_dir, ignore_errors=True)

		(pid, _, _) = ssh.execute("nohup python_ansible " + Config.REMOTE_CONF_DIR + "/ctxt_agent.py " 
				+ Config.REMOTE_CONF_DIR + "/general_info.cfg "
				+ remote_dir + "/" + os.path.basename(conf_file) 
				+ " > " + remote_dir + "/stdout" + " 2> " + remote_dir + "/stderr < /dev/null & echo -n $!")
		
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Ansible process to configure " + str(vm.im_id) + " launched with pid: " + pid)

		return pid

	def generate_inventory(self, tmp_dir):
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": create the ansible configuration file")
		res_filename = "hosts"
		ansible_file = tmp_dir + "/" + res_filename 
		out = open(ansible_file, 'w')

		# get the master node name
		(master_name, masterdom) = self.inf.vm_master.getRequestedName(default_hostname = Config.DEFAULT_VM_NAME, default_domain = Config.DEFAULT_DOMAIN)

		all_nodes = "[all]\n"
		all_vars = ""
		vm_group = self.inf.get_vm_list_by_system_name()
		for group in vm_group:
			vm = vm_group[group][0]
			user = vm.getCredentialValues()[0]
			out.write('[' + group + ':vars]\n')
			out.write('IM_NODE_USER=' + user + '\n\n')
			out.write('IM_MASTER_HOSTNAME=' + master_name + '\n')
			out.write('IM_MASTER_FQDN=' + master_name + "." + masterdom + '\n')
			out.write('IM_MASTER_DOMAIN=' + masterdom + '\n\n')                     
			
			out.write('[' + group + ']\n')

			# Set the vars with the number of nodes of each type
			all_vars += 'IM_' + group.upper() + '_NUM_VMS=' + str(len(vm_group[group])) + '\n'

			for vm in vm_group[group]:
				if not vm.destroy:
					ifaces_im_vars = ''
					for i in range(vm.getNumNetworkIfaces()):
						iface_ip = vm.getIfaceIP(i)
						if iface_ip:
							ifaces_im_vars += ' IM_NODE_NET_' + str(i) + '_IP=' + iface_ip
							if vm.getRequestedNameIface(i):
								(nodename, nodedom) = vm.getRequestedNameIface(i, default_domain = Config.DEFAULT_DOMAIN)
								ifaces_im_vars += ' IM_NODE_NET_' + str(i) + '_HOSTNAME=' + nodename
								ifaces_im_vars += ' IM_NODE_NET_' + str(i) + '_DOMAIN=' + nodedom
								ifaces_im_vars += ' IM_NODE_NET_' + str(i) + '_FQDN=' + nodename + "." + nodedom

					# first try to use the public IP
					ip = vm.getPublicIP()
					if not ip:
						ip = vm.getPrivateIP()
	
					# the master node
					# TODO: Known issue: the master VM must set the public network in the iface 0 
					(nodename ,nodedom) = system.replaceTemplateName(Config.DEFAULT_VM_NAME + "." + Config.DEFAULT_DOMAIN, str(vm.im_id))
					if vm.getRequestedName():
						(nodename, nodedom) = vm.getRequestedName(default_domain = Config.DEFAULT_DOMAIN)

					node_line = ip + ":" + str(vm.getSSHPort())
					node_line += ' IM_NODE_HOSTNAME=' + nodename
					node_line += ' IM_NODE_HOSTNAME=' + nodename
					node_line += ' IM_NODE_FQDN=' + nodename + "." + nodedom
					node_line += ' IM_NODE_DOMAIN=' + nodedom
					node_line += ' IM_NODE_NUM=' + str(vm.im_id)
					node_line += ' IM_NODE_VMID=' + str(vm.id)
					node_line += ' IM_NODE_ANSIBLE_IP=' + ip
					node_line += ifaces_im_vars

					for app in vm.getInstalledApplications():
						if app.getValue("path"):
							node_line += ' IM_APP_' + app.getValue("name").upper() + '_PATH=' + app.getValue("path")
						if app.getValue("version"):
							node_line += ' IM_APP_' + app.getValue("name").upper() + '_VERSION=' + app.getValue("version")

					node_line += "\n"
					out.write(node_line)
					all_nodes += node_line
				
			out.write("\n")

		out.write(all_nodes)
		# set the IM global variables
		out.write('[all:vars]\n')
		out.write(all_vars)
		out.write('IM_MASTER_HOSTNAME=' + master_name + '\n')
		out.write('IM_MASTER_FQDN=' + master_name + "." + masterdom + '\n')
		out.write('IM_MASTER_DOMAIN=' + masterdom + '\n\n')

		out.close()
		
		return res_filename
	
	def generate_etc_hosts(self, tmp_dir):
		res_filename = "etc_hosts"
		hosts_file = tmp_dir + "/" + res_filename
		hosts_out = open(hosts_file, 'w')
		hosts_out.write("127.0.0.1 localhost localhost.localdomain\r\n")

		vm_group = self.inf.get_vm_list_by_system_name()
		for group in vm_group:
			vm = vm_group[group][0]

			for vm in vm_group[group]:
				for i in range(vm.getNumNetworkIfaces()):
					if vm.getRequestedNameIface(i):
						if vm.getIfaceIP(i):
							(nodename, nodedom) = vm.getRequestedNameIface(i, default_domain = Config.DEFAULT_DOMAIN)
							hosts_out.write(vm.getIfaceIP(i) + " " + nodename + "." + nodedom + " " + nodename + "\r\n")
						else:
							ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": Net interface " + str(i) + " request a name, but it does not have an IP.")

					# first try to use the public IP
					ip = vm.getPublicIP()
					if not ip:
						ip = vm.getPrivateIP()
	
					# the master node
					# TODO: Known issue: the master VM must set the public network in the iface 0 
					(nodename ,nodedom) = system.replaceTemplateName(Config.DEFAULT_VM_NAME + "." + Config.DEFAULT_DOMAIN, str(vm.im_id))
					if not vm.getRequestedName():
						hosts_out.write(ip + " " + nodename + "." + nodedom + " " + nodename + "\r\n")
	
		hosts_out.close()
		return res_filename
	
	def generate_basic_playbook(self, tmp_dir):
		recipe_files = []
		pk_file = "/tmp/ansible_key"
		shutil.copy(Config.CONTEXTUALIZATION_DIR + "/basic.yml", tmp_dir + "/basic_task_all.yml")
		f = open(tmp_dir + '/basic_task_all.yml', 'a')
		f.write("\n  vars:\n") 
		f.write("    - pk_file: " + pk_file + ".pub\n")
		f.write("  hosts: '{{IM_HOST}}'\n") 
		f.write("  user: \"{{ IM_NODE_USER }}\"\n") 
		f.close()
		recipe_files.append("basic_task_all.yml")
		return recipe_files
	
	def generate_main_playbook(self, vm, group, tmp_dir):
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
				install_app += "    action: apt pkg=" + short_app_name + " state=installed update_cache=yes cache_valid_time=604800\n"
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
		
		# create the "all" to enable this playbook to see the facts of all the nodes
		all_filename = self.create_all_recipe(tmp_dir, "main_" + group + "_task")
		recipe_files.append(all_filename)
		
		return recipe_files
	
	def generate_playbook(self, vm, ctxt_elem, tmp_dir):
		recipe_files = []

		conf_filename = tmp_dir + "/" + ctxt_elem.configure + "_" + ctxt_elem.system + "_task.yml"
		if not os.path.isfile(conf_filename):
			configure = self.inf.radl.get_configure_by_name(ctxt_elem.configure)
			conf_content = self.add_ansible_header(ctxt_elem.system, vm.getOS().lower()) 
			conf_content = self.mergeYAML(conf_content, configure.recipes)
			
			conf_out = open(conf_filename, 'w')
			conf_out.write(conf_content + "\n\n")
			conf_out.close()
			recipe_files.append(ctxt_elem.configure + "_" + ctxt_elem.system + "_task.yml")

			# create the "all" to enable this playbook to see the facts of all the nodes
			all_filename = self.create_all_recipe(tmp_dir, ctxt_elem.configure + "_" + ctxt_elem.system + "_task")
			recipe_files.append(all_filename)
		
		return recipe_files

	def configure_master(self):
		success = True
		if not self.inf.ansible_configured:
			try:
				ConfManager.logger.info("Inf ID: " + str(self.inf.id) + ": Start the contextualization process.")
	
				ssh = self.inf.vm_master.get_ssh()
				# Activate tty mode to avoid some problems with sudo in REL
				ssh.tty = True
				
				# Get the groups for the different VM types
				vm_group = self.inf.get_vm_list_by_system_name()
				
				# configuration dir os th emaster node to copy all the contextualization files
				tmp_dir = tempfile.mkdtemp()
				# Now call the ansible installation process on the master node
				configured_ok = self.configure_ansible(vm_group, ssh, tmp_dir)
				
				if not configured_ok:
					ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ": Error in the ansible installation process")
					if not self.inf.ansible_configured: self.inf.ansible_configured = False
				else:
					ConfManager.logger.info("Inf ID: " + str(self.inf.id) + ": Ansible installation finished successfully")
	
				remote_dir = Config.REMOTE_CONF_DIR
				ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Copy the contextualization agent files")  
				ssh.sftp_mkdir(remote_dir)
				files = []
				files.append((Config.IM_PATH + "/SSH.py",remote_dir + "/SSH.py"))
				files.append((Config.IM_PATH + "/ansible/ansible_callbacks.py", remote_dir + "/ansible_callbacks.py")) 
				files.append((Config.IM_PATH + "/ansible/ansible_launcher.py", remote_dir + "/ansible_launcher.py"))
				files.append((Config.CONTEXTUALIZATION_DIR + "/ctxt_agent.py", remote_dir + "/ctxt_agent.py")) 
				ssh.sftp_put_files(files)
	
				success = configured_ok
				
			except Exception, ex:
				ConfManager.logger.exception("Inf ID: " + str(self.inf.id) + ": Error in the ansible installation process")
				self.inf.add_cont_msg("Error in the ansible installation process: " + str(ex))
				if not self.inf.ansible_configured: self.inf.ansible_configured = False
				success = False
			finally:
				shutil.rmtree(tmp_dir, ignore_errors=True)

			if success:
				self.inf.ansible_configured = True
				self.inf.set_configured(True)
				# Force to save the data to store the log data 
				InfrastructureManager.InfrastructureManager.save_data()
			else:
				self.inf.ansible_configured = False
				self.inf.set_configured(False)

		return success

	def wait_master(self):
		"""
			- Select the master VM
			- Wait it to boot and has the SSH port open 
		"""
		# First assure that ansible is installed in the master
		if not self.inf.vm_master or self.inf.vm_master.destroy:
			# If the user has deleted the master vm, it must be configured again
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
					self.inf.add_cont_msg("Contextualization Error: No correct Master VM found. Check if there a linux VM with Public IP and connected with the rest of VMs.")
					self.inf.set_configured(False)
					return
	
				ConfManager.logger.info("Inf ID: " + str(self.inf.id) + ": Wait the master VM to be running")
	
				self.inf.add_cont_msg("Wait master VM to boot")
				all_running = self.wait_vm_running(self.inf.vm_master, Config.WAIT_RUNNING_VM_TIMEOUT, True)
	
				if not all_running:
					ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ":  Error Waiting the Master VM to boot, exit")
					self.inf.add_cont_msg("Contextualization Error: Error Waiting the Master VM to boot")
					self.inf.set_configured(False)
					return

				# To avoid problems with the known hosts of previous calls
				if os.path.isfile(os.path.expanduser("~/.ssh/known_hosts")):
					ConfManager.logger.debug("Remove " + os.path.expanduser("~/.ssh/known_hosts"))
					os.remove(os.path.expanduser("~/.ssh/known_hosts"))
	
				self.inf.add_cont_msg("Wait master VM to have the SSH active.")
				is_connected = self.wait_vm_ssh_acccess(self.inf.vm_master, Config.WAIT_RUNNING_VM_TIMEOUT)
				if not is_connected:
					ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ": Error Waiting the Master VM to have the SSH active, exit")
					self.inf.add_cont_msg("Contextualization Error: Error Waiting the Master VM to have the SSH active (Check credentials)")
					self.inf.set_configured(False)
					return
					
				ConfManager.logger.info("Inf ID: " + str(self.inf.id) + ": VMs available.")
				
				# Check and change if necessary the credentials of the master vm
				ssh = self.inf.vm_master.get_ssh()
				# Activate tty mode to avoid some problems with sudo in REL
				ssh.tty = True
				self.change_master_credentials(ssh)
				
				# Force to save the data to store the log data 
				InfrastructureManager.InfrastructureManager.save_data()
				
				self.inf.set_configured(True)
			except:
				ConfManager.logger.exception("Inf ID: " + str(self.inf.id) + ": Error waiting the master VM to be running")
				self.inf.set_configured(False)
		else:
			self.inf.set_configured(True)

		return success
	
	def generate_playbooks_and_hosts(self):
		try:
			tmp_dir = tempfile.mkdtemp()
			remote_dir = Config.REMOTE_CONF_DIR
			# Get the groups for the different VM types
			vm_group = self.inf.get_vm_list_by_system_name()
				
			ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Generating YAML, hosts and inventory files.")
			# Create the other configure sections (it may be included in other configure)
			filenames = []
			if self.inf.radl.configures:
				for elem in self.inf.radl.configures:
					if elem is not None and not os.path.isfile(tmp_dir + "/" + elem.name + ".yml"):
						conf_out = open(tmp_dir + "/" + elem.name + ".yml", 'w')
						conf_out.write(elem.recipes)
						conf_out.write("\n\n")
						conf_out.close()
						filenames.append(elem.name + ".yml")
			
			filenames.extend(self.generate_basic_playbook(tmp_dir))
			
			# Create the YAML file with the basic steps and the apps to install
			for group in vm_group:
				# Use the first VM as the info used is the same for all the VMs in the group
				vm = vm_group[group][0]
				filenames.extend(self.generate_main_playbook(vm, group, tmp_dir))
							
			# get the default ctxts in case of the RADL has not specified them 
			ctxts = [contextualize_item(group, group, 1) for group in vm_group if self.inf.radl.get_configure_by_name(group)]
			# get the contextualize steps specified in the RADL, or use the default value
			contextualizes = self.inf.radl.contextualize.get_contextualize_items_by_step({1:ctxts})
	
			# create the files for the configure sections that appears in the contextualization steps
			# and add the ansible information and modules
			for ctxt_num in contextualizes.keys():
				for ctxt_elem in contextualizes[ctxt_num]:
					vm = vm_group[ctxt_elem.system][0] 
					filenames.extend(self.generate_playbook(vm, ctxt_elem, tmp_dir))
			
			filenames.append(self.generate_etc_hosts(tmp_dir))
			filenames.append(self.generate_inventory(tmp_dir))
			
			conf_file = "general_info.cfg"
			self.create_general_conf_file(tmp_dir + "/" + conf_file, self.inf.get_vm_list())
			filenames.append(conf_file)
			
			recipe_files = []
			for f in filenames:
				recipe_files.append((tmp_dir + "/" + f, remote_dir + "/" + f ))

			# TODO: Study why it is needed
			time.sleep(2)
			
			ssh = self.inf.vm_master.get_ssh()
			self.inf.add_cont_msg("Copying YAML, hosts and inventory files.")
			ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Copying YAML files.")
			ssh.sftp_mkdir(remote_dir)
			ssh.sftp_put_files(recipe_files)
			
			# Copy the utils helper files
			ssh.sftp_mkdir(remote_dir + "/utils")
			ssh.sftp_put_dir(Config.RECIPES_DIR + "/utils", remote_dir + "/utils")
			
			self.inf.set_configured(True)
		except Exception, ex:
			self.inf.set_configured(False)
			ConfManager.logger.exception("Inf ID: " + str(self.inf.id) + ": Error generating playbooks.")
			self.inf.add_cont_msg("Error generating playbooks: " + str(ex))

	def relaunch_vm(self, vm, failed_cloud = False):
		"""
		Remove and launch again the specified VM
		"""
		InfrastructureManager.InfrastructureManager.RemoveResource(self.inf.id, vm.id, self.auth)
		
		new_radl = ""
		for net in vm.info.networks:
			new_radl = "network " + net.id + "\n"								
		new_radl += "system " + vm.getRequestedSystem().name + "\n"
		new_radl += "deploy " + vm.getRequestedSystem().name + " 1"
		
		failed_clouds = []
		if failed_cloud:
			failed_clouds = [vm.cloud]
		InfrastructureManager.InfrastructureManager.AddResource(self.inf.id, new_radl, self.auth, False, failed_clouds)

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
		retries = 0
		delay = 10
		wait = 0
		while wait < timeout:
			if not vm.destroy:
				vm.update_status(self.auth)

				if vm.state == VirtualMachine.RUNNING:
					return True
				elif vm.state == VirtualMachine.FAILED:
					ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": VM " + str(vm.id) + " is FAILED")

					if relaunch and retries < Config.MAX_VM_FAILS:
						ConfManager.logger.info("Inf ID: " + str(self.inf.id) + ": Launching new VM")
						self.relaunch_vm(vm, True)
						# Set the wait counter to 0
						wait = 0
						retries += 1
					else:
						ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ": Relaunch is not enabled. Exit")
						return False
			else:
				ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": VM deleted by the user, Exit")
				return False

			ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": VM " + str(vm.id) + " is not running yet.")
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
						ConfManager.logger.warn("VM " + str(vm.id) + " timeout")

						if relaunch:
							ConfManager.logger.info("Launch a new VM")
							self.relaunch_vm(vm)
						else:
							ConfManager.logger.error("Relaunch is not available. Exit")
							return False
				else:
					ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": VM deleted by the user, Exit")
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
		while wait < timeout:
			if vm.destroy:
				# in this case ignore it
				return False
			else:
				ip = vm.getPublicIP()
				if ip != None:
					ssh = vm.get_ssh()
					ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'SSH Connecting with: ' + ip + ' to the VM: ' + str(vm.id))

					try:
						connected = ssh.test_connectivity(5)
					except AuthenticationException:
						ConfManager.logger.warn("Error connecting with ip: " + ip + " incorrect credentials.")
						auth_errors += 1

						if auth_errors >= auth_error_retries:
							ConfManager.logger.error("Too many authentication errors")
							return False 
					
					if connected:
						ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'Works!')
						return True
					else:
						ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'do not connect, wait ...')
						wait += delay
						time.sleep(delay)
				else:
					ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'VM ' + str(vm.id) + ' with no IP')
					# Update the VM info and wait to have a valid public IP
					wait += delay
					time.sleep(delay)
					vm.update_status(self.auth)
		
		# Timeout, return False
		return False

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
			if len(list(set(new_creds))) > 1 or list(set(new_creds))[0] != None:
				change_creds = False
				if cmp(new_creds,creds) != 0:
					(_, new_passwd, new_public_key, new_private_key) = new_creds
					# only change to the new password if there are a previous passwd value 
					if passwd and new_passwd:
						ConfManager.logger.info("Changing password to master VM")
						(out, err, code) = ssh.execute('sudo bash -c \'echo "' + user + ':' + new_passwd + '" | /usr/sbin/chpasswd && echo "OK"\' 2> /dev/null')
						
						if code == 0:
							change_creds = True
							ssh.password = new_passwd
						else:
							ConfManager.logger.error("Error changing password to master VM. " + out + err)
		
					if new_public_key and new_private_key:
						ConfManager.logger.info("Changing public key to master VM")
						(out, err, code) = ssh.execute('echo ' + new_public_key + ' >> .ssh/authorized_keys')
						if code != 0:
							ConfManager.logger.error("Error changing public key to master VM. " + out + err)
						else:
							change_creds = True
							ssh.private_key = new_private_key
	
				if change_creds:
					self.inf.vm_master.info.systems[0].updateNewCredentialValues()
		except:
			ConfManager.logger.exception("Error changing credentials to master VM.")

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
			os.symlink(os.path.abspath(Config.RECIPES_DIR + "/utils"), tmp_dir + "/utils")

		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'Lanzamos ansible.')
		t = AnsibleThread(tmp_dir + "/" + playbook, None, 2, gen_pk_file, ssh.password, 1, tmp_dir + "/" + inventory, ssh.username)
		t.daemon = True
		t.start()
		t.join()
		(return_code, output, _) = t.results
		
		if return_code == 0:
			return (True, output)
		else:
			return (False, output)

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
			conf_content += "  sudo: yes\n"
		conf_content += "  user: \"{{ IM_NODE_USER }}\"\n"

		# Add the utils helper vars 
		conf_content += "  vars_files: \n"
		conf_content += '    - [ "utils/vars/{{ ansible_distribution }}.yml", "utils/vars/os_defaults.yml" ]\n\n'

		return conf_content 

	def create_all_recipe(self, tmp_dir, filename):
		"""
		Create the recipe "all" enabling to access all the ansible variables from all hosts
		Arguments:
		   - tmp_dir(str): Temp directory where all the playbook files will be stored.
		   - filename(str): name of he yaml to include (without the extension)
		"""
		all_filename = filename + "_all.yml"
		conf_all_out = open(tmp_dir + "/" + all_filename, 'w')
		conf_all_out.write("---\n")
		conf_all_out.write("- hosts: all\n")
		conf_all_out.write("  user: \"{{ IM_NODE_USER }}\"\n")
		conf_all_out.write("- include: " + filename + ".yml\n")
		conf_all_out.write("\n\n")
		conf_all_out.close()
		return all_filename

	def configure_ansible(self, vm_group, ssh, tmp_dir):
		"""
		Install ansible in the master node
	
		Arguments:
		   - ssh(:py:class:`IM.SSH`): Object to connect with the master node.
		   - tmp_dir(str): Temp directory where all the playbook files will be stored.
		Returns: True if the process finished sucessfully, False otherwise.
		"""

		# Create the ansible inventory file
		with open(tmp_dir + "/inventory.cfg", 'w') as inv_out:
			inv_out.write(ssh.host + ":" + str(ssh.port) + "\n\n")
		
		shutil.copy(Config.CONTEXTUALIZATION_DIR + "/" + ConfManager.MASTER_YAML, tmp_dir + "/" + ConfManager.MASTER_YAML)
		
		# Add all the modules needed in the RADL
		modules = []
		for group in vm_group:
			# Use the first VM as the info used is the same for all the VMs in the group
			vm = vm_group[group][0]
			
			# Get the modules specified by the user in the RADL
			modules.extend(vm.getModulesToInstall())
			# Get the info about the apps from the recipes DB
			vm_modules, _ = Recipe.getInfoApps(vm.getAppsToInstall())
			modules.extend(vm_modules)

		# avoid duplicates
		modules = set(modules)

		self.inf.add_cont_msg("Creating and copying Ansible playbook files")
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Preparing Ansible playbook to copy Ansible modules: " + str(modules))

		ssh.sftp_mkdir(Config.REMOTE_CONF_DIR)
		# Copy the utils helper files
		ssh.sftp_mkdir(Config.REMOTE_CONF_DIR + "/utils")
		ssh.sftp_put_dir(Config.RECIPES_DIR + "/utils", Config.REMOTE_CONF_DIR + "/utils")
		
		for galaxy_name in modules:
			if galaxy_name:
				recipe_out = open(tmp_dir + "/" + ConfManager.MASTER_YAML, 'a')
				self.inf.add_cont_msg("Galaxy role " + galaxy_name + " detected setting to install.")
				ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Install " + galaxy_name + " with ansible-galaxy.")
				recipe_out.write("    - name: Install the " + galaxy_name + " role with ansible-galaxy\n")
				recipe_out.write("      command: ansible-galaxy --force install " + galaxy_name + "\n")
				recipe_out.close()
				
		self.inf.add_cont_msg("Performing preliminary steps to configure Ansible.")
		# TODO: check to do it with ansible
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Check if python-simplejson is installed in REL 5 systems")
		(stdout, stderr, _) = ssh.execute("cat /etc/redhat-release | grep \"release 5\" &&  sudo yum -y install python-simplejson", 120)
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + stdout + stderr)

		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Remove requiretty in sshd config")
		(stdout, stderr, _) = ssh.execute("sudo sed -i 's/.*requiretty$/#Defaults requiretty/' /etc/sudoers", 120)
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + stdout + stderr)
		
		self.inf.add_cont_msg("Configure Ansible in the master VM.")
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Call Ansible to (re)configure in the master node")
		(success, msg) = self.call_ansible(tmp_dir, "inventory.cfg", ConfManager.MASTER_YAML, ssh)

		if not success:
			ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ": Error configuring in master node: " + msg + "\n\n")
			self.inf.add_cont_msg("Error configuring the master VM: " + msg + " " + tmp_dir)
		else:
			ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Ansible successfully configured in the master VM:\n" + msg + "\n\n")
			self.inf.add_cont_msg("Ansible successfully configured in the master VM.")
		
		return success		

	def create_general_conf_file(self, conf_file, vm_list):
		"""
		Create the configuration file needed by the contextualization agent
		"""
		conf_data = {}
		
		conf_data['playbook_retries'] = Config.PLAYBOOK_RETRIES
		conf_data['vms'] = []
		for vm in vm_list:
			vm_conf_data = {}
			vm_conf_data['id'] = vm.im_id
			if vm.im_id == self.inf.vm_master.im_id:
				vm_conf_data['master'] = True
			else:
				vm_conf_data['master'] = False
			# first try to use the public IP
			vm_conf_data['ip'] = vm.getPublicIP()
			if not vm_conf_data['ip']:
				vm_conf_data['ip'] = vm.getPrivateIP()
			vm_conf_data['ssh_port'] = vm.getSSHPort()
			creds = vm.getCredentialValues()
			new_creds = vm.getCredentialValues(new=True)
			(vm_conf_data['user'], vm_conf_data['passwd'], _, vm_conf_data['private_key']) = creds
			# If there are new creds to set to the VM
			if len(list(set(new_creds))) > 1 or list(set(new_creds))[0] != None:
				if cmp(new_creds,creds) != 0:
					(_, vm_conf_data['new_passwd'], vm_conf_data['new_public_key'], vm_conf_data['new_private_key']) = new_creds
			
			conf_data['vms'].append(vm_conf_data)

		conf_data['conf_dir'] = Config.REMOTE_CONF_DIR
		
		conf_out = open(conf_file, 'w')
		ConfManager.logger.debug("Ctxt agent configuration file: " + json.dumps(conf_data))
		json.dump(conf_data, conf_out, indent=2)
		conf_out.close()

	def create_vm_conf_file(self, conf_file, vm_id, tasks, remote_dir):
		"""
		Create the configuration file needed by the contextualization agent
		"""
		conf_data = {}
		
		conf_data['id'] = vm_id	
		conf_data['tasks'] = tasks
		conf_data['remote_dir'] = remote_dir
		
		conf_out = open(conf_file, 'w')
		ConfManager.logger.debug("Ctxt agent configuration file: " + json.dumps(conf_data))
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
			ConfManager.logger.exception("Error parsing YAML: " + yaml1 + "\n Ignore it")
		
		try:
			yamlo2s = yaml.load(yaml2)
			if not isinstance(yamlo2s, list) or any([ not isinstance(d, dict) for d in yamlo2s ]):
				yamlo2s = {}
		except Exception:
			ConfManager.logger.exception("Error parsing YAML: " + yaml2 + "\n Ignore it")
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
