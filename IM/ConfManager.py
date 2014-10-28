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
from datetime import datetime
import tempfile
import logging
import shutil
import subprocess
import json
import string
import copy

import InfrastructureManager
from VirtualMachine import VirtualMachine
from SSH import SSH, AuthenticationException
from recipe import Recipe
from radl.radl import contextualize_item, system

from config import Config

class ConfManager(threading.Thread):
	"""
	Class to manage the contextualization steps
	"""

	logger = logging.getLogger('ConfManager')
	""" Logger object """
	CONF_DIR = "/tmp/conf"
	""" Directory to copy all the ansible related files """
	MASTER_YAML = "conf-ansible.yml"
	""" The file with the ansible steps to configure the master node """
	SECOND_STEP_YAML = 'conf-ansible-s2.yml'
	""" The file with the ansible steps to configure the second step of the the master node """
	

	def Contextualize(self, inf, auth):
		"""
		Starts the contextualization thread 
	
		Arguments:
		   - inf(:py:class:`IM.InfrastructureInfo`): Infrastructure to be contextualized.
		   - auth(:py:class:`dict` of str objects): Authentication data to access cloud provider.
		"""
		self.inf = inf
		self.auth = auth
		self.contextualizing = False
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Starting the ConfManager Thread")
		self.start()

	def is_contextualizing(self):
		"""
		Check if the contextualization process is running 
	
		Returns: True if the contextualization process is running or false otherwise
		"""
		return (self.isAlive() and self.contextualizing)
	
	def waitRunningVMs(self, vm_list, timeout, relaunch=False):
		"""
		Wait for a list of VMs to be running 
	
		Arguments:
		   - vm_list(list of :py:class:`IM.VirtualMachine`): list of VMs to be running.
		   - timeout(int): Max time to wait the VMs to be running.
		   - relaunch(bool, optional): Flag to specify if the VMs must be relaunched in case of failure.
		Returns: True if all the VMs are running or false otherwise
		"""
		timeout_retries = 0
		retries = 0
		delay = 10
		wait = 0
		running = 0
		deleted = 0
		while running + deleted < len(vm_list) and wait < timeout:
			running = 0
			deleted = 0
			for vm in vm_list:
				if not vm.destroy:
					(success, new_vm_info) = vm.cloud.getCloudConnector().updateVMInfo(vm, self.auth)

					if not success:
						ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": Error getting the information about the VM " + vm.id + ": " + new_vm_info)
						ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": Using last information retrieved")
					else:
						vm = new_vm_info

					if vm.state == VirtualMachine.RUNNING:
						running += 1
					elif vm.state == VirtualMachine.FAILED:
						ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": VM " + str(vm.id) + " is FAILED")

						if relaunch and retries < Config.MAX_VM_FAILS:
							ConfManager.logger.info("Inf ID: " + str(self.inf.id) + ": Launching new VM")
							InfrastructureManager.InfrastructureManager.RemoveResource(self.inf.id, vm.id, self.auth)
							
							new_radl = ""
							for net in vm.info.networks:
								new_radl = "network " + net.id + "\n"								
							new_radl += "system " + vm.getRequestedSystem().name + "\n"
							new_radl += "deploy " + vm.getRequestedSystem().name + " 1"
							
							InfrastructureManager.InfrastructureManager.AddResource(self.inf.id, new_radl, self.auth, False, [vm.cloud])
							# Set the wait counter to 0
							wait = 0
							retries += 1
						else:
							ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ": Relaunch is not enabled. Exit")
							return False
				else:
					ConfManager.logger.warn("Inf ID: " + str(self.inf.id) + ": VM deleted by the user, ignore it")
					deleted += 1

			ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": VMs running: " + str(running) + "/" + str(len(vm_list) - deleted))
			if running + deleted < len(vm_list):
				wait += delay
				time.sleep(delay)

			# if the timeout is passed, set the VMs as failed
			# try to relaunch max_retries times, and restart the counter
			if wait > timeout and timeout_retries < Config.MAX_VM_FAILS:
				timeout_retries += 1
				wait = 0
				for vm in vm_list:
					if not vm.destroy:
						(success, vm) = vm.cloud.getCloudConnector().updateVMInfo(vm, self.auth)

						if vm.state != VirtualMachine.RUNNING:
							ConfManager.logger.warn("VM " + str(vm.id) + " timeout")

							if relaunch:
								ConfManager.logger.info("Launch a new VM")
								InfrastructureManager.InfrastructureManager.RemoveResource(self.inf.id, vm.id, self.auth)
								InfrastructureManager.InfrastructureManager.AddResource(self.inf.id, "deploy " + vm.getRequestedSystem().name + " 1", self.auth, False)
								# Set the wait counter to 0
								wait = 0
							else:
								ConfManager.logger.error("Relaunch is not available. Exit")
								return False


		if running + deleted < len(vm_list):
			return False
		else:
			return True

	def waitConnectedVMs(self, vm_list, timeout):
		"""
		Wait for all the VMs with public IP to have the SSH port opened 
	
		Arguments:
		   - vm_list(list of :py:class:`IM.VirtualMachine`): list of VMs to check.
		   - timeout(int): Max time to wait the VMs to be running.
		Returns: True if all the VMs have the SSH port open or false otherwise
		"""
		delay = 10
		total_vms = len(vm_list)
		wait = 0
		vms_connected = 0
		vms_ignored = 0
		vms_without_ip = 0
		auth_errors = {}
		auth_error_retries = 3
		while (vms_connected + vms_ignored + vms_without_ip) < total_vms and wait < timeout:
			vms_connected = 0
			vms_ignored = 0
			vms_without_ip = 0
			for vm in vm_list:
				if vm.destroy:
					# in this case ignore it
					vms_ignored += 1
				else:
					ip = vm.getPublicIP()
					if ip != None:
						(user, passwd, _, private_key) = vm.getCredentialValues()

						ssh = SSH(ip, user, passwd, private_key, vm.getSSHPort())
						ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'SSH Connecting with: ' + ip + ' to the VM: ' + str(vm.id))
						
						connected = False
						try:
							connected = ssh.test_connectivity(5)
						except AuthenticationException:
							ConfManager.logger.warn("Error connecting with ip: " + ip + " incorrect credentials.")
							if ip in auth_errors:
								auth_errors[ip] += 1
							else:
								auth_errors[ip] = 1

							if auth_errors[ip] >= auth_error_retries:
								ConfManager.logger.error("Too many authentication errors")
								return False 
						
						if connected:
							ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'Works!')
							vms_connected += 1
						else:
							ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'do not connect, wait ...')
							wait += delay
							time.sleep(delay)
					else:
						ip = vm.getPrivateIP()
						if ip != None:
							ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'VM ' + str(vm.id) + ' with private IP: ' + ip)
							vms_ignored += 1
						else:
							vms_without_ip += 1

				ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Connected VMs: " + str(vms_ignored) + "/" + str(vms_connected) + " of " + str(total_vms) + ". Without IP: " + str(vms_without_ip))
	
		if (vms_connected + vms_ignored) == total_vms:
			return True
		else:
			return False

	def change_master_credentials(self, ssh):
		"""
		Chech the RADL of the VM master to see if we must change the user credentials

		Arguments:
		   - ssh(:py:class:`IM.SSH`): Object with the authentication data to access the master VM. 
		"""
		creds = self.inf.vm_master.getCredentialValues()
		(user, _, _, _) = creds
		new_creds = self.inf.vm_master.getCredentialValues(new=True)
		if len(list(set(new_creds))) > 1 or list(set(new_creds))[0] != None:
			change_creds = False
			if cmp(new_creds,creds) != 0:
				(_, new_passwd, new_public_key, new_private_key) = new_creds
				if new_passwd:
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

	def run(self):
		"""
		Main function of the ConfManager Thread
		It performs all the needed steps to contextualize the Infrastructure
		"""
		try:
			# Select the master VM
			self.inf.add_cont_msg("Select master VM")
			self.inf.select_vm_master()

			if not self.inf.vm_master:
				# If there are not a valid master VM, exit
				ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ": No correct Master VM found. Exit")
				self.inf.add_cont_msg("Contextualization Error: No correct Master VM found. Check if there a linux VM with Public IP and connected with the rest of VMs.")
				if not self.inf.configured: self.inf.configured = False
				return

			# Now check if the master VM has specified a hostname or set the master VM hostname with the default values			
			(master_name, masterdom) = self.inf.vm_master.getRequestedName(default_hostname = Config.DEFAULT_VM_NAME, default_domain = Config.DEFAULT_DOMAIN)

			ConfManager.logger.info("Inf ID: " + str(self.inf.id) + ": Wait the master VM to be running")

			timeout = Config.WAIT_RUNNING_VM_TIMEOUT
			self.inf.add_cont_msg("Wait master VM to boot")
			all_running = self.waitRunningVMs([self.inf.vm_master], timeout, True)

			if not all_running:
				ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ":  Error Waiting the Master VM to boot, exit")
				self.inf.add_cont_msg("Contextualization Error: Error Waiting the Master VM to boot")
				if not self.inf.configured: self.inf.configured = False
				return

			# To avoid problems with the known hosts of previous calls
			if os.path.isfile(os.path.expanduser("~/.ssh/known_hosts")):
				ConfManager.logger.debug("Remove " + os.path.expanduser("~/.ssh/known_hosts"))
				os.remove(os.path.expanduser("~/.ssh/known_hosts"))

			self.inf.add_cont_msg("Wait master VM to have the SSH active.")
			all_connected = self.waitConnectedVMs([self.inf.vm_master], timeout)
			if not all_connected:
				ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ": Error Waiting the Master VM to have the SSH active, exit")
				self.inf.add_cont_msg("Contextualization Error: Error Waiting the Master VM to have the SSH active (Check credentials)")
				if not self.inf.configured: self.inf.configured = False
				return
				
			ConfManager.logger.info("Inf ID: " + str(self.inf.id) + ": VMs available.")
			ConfManager.logger.info("Inf ID: " + str(self.inf.id) + ": Start the contextualization process.")

			# set the flag the the contextualization process starts
			self.contextualizing = True

			# configure master VM with ansible
			ip = self.inf.vm_master.getPublicIP()
			master_priv_ip = self.inf.vm_master.getPrivateIP()
			# If the master VM does not have private IP use the public one
			if master_priv_ip == None:
				master_priv_ip = ip

			(user, passwd, _, private_key) = self.inf.vm_master.getCredentialValues()
			ssh = SSH(ip, user, passwd, private_key, self.inf.vm_master.getSSHPort())
			# Activate tty mode to avoid some problems with sudo in REL
			ssh.tty = True

			# Check and change if necessary the credentials of the master vm
			self.change_master_credentials(ssh)

			# Force to save the data to store the log data 
			InfrastructureManager.InfrastructureManager.save_data()
			
			# configuration dir os th emaster node to copy all the contextualization files
			tmp_dir = tempfile.mkdtemp()
			# Now call the ansible installation process on the master node
			configured_ok = self.configure_ansible(ssh, tmp_dir, master_name, masterdom)
			
			if not configured_ok:
				ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ": Error in the ansible installation process")
				if not self.inf.configured: self.inf.configured = False
				#shutil.rmtree(tmp_dir)
				return
			else:
				ConfManager.logger.info("Inf ID: " + str(self.inf.id) + ": Ansible installation finished successfully")
			
			# Now call the contextualization process
			context_ok = self.launch_ctxt_agent(ssh, tmp_dir)
			
			# set the flag the the contextualization process has finished
			self.contextualizing = False

			if not context_ok:
				ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ": Error in the contextualization process")
				if not self.inf.configured: self.inf.configured = False
				#shutil.rmtree(tmp_dir)
			else:
				ConfManager.logger.info("Inf ID: " + str(self.inf.id) + ": Contextualizacion finished successfully")
				if not self.inf.configured: self.inf.configured = True
				shutil.rmtree(tmp_dir)
		except Exception, ex:
			ConfManager.logger.exception("Inf ID: " + str(self.inf.id) + ": Contextualization Error")
			self.inf.add_cont_msg("Contextualization Error: " + str(ex))
			if not self.inf.configured: self.inf.configured = False
			#shutil.rmtree(tmp_dir)

		# Finally force to store the data to store the log info
		InfrastructureManager.InfrastructureManager.save_data()

	def call_ansible(self, tmp_dir, inventory, playbook, ssh):
		"""
		Call the ansible-playbook command to execute an Ansible playbook 
	
		Arguments:
		   - tmp_dir(str): Temp directory where all the playbook files will be stored.
		   - inventory(str): Filename with the ansible inventory file (related to the tmp_dir)
		   - playbook(str): Filename with the ansible playbook file (related to the tmp_dir)
		   - ssh(:py:class:`IM.SSH`): Object with the authentication data to access the node to be configured. 
		Returns: a tuple (sucess, msg) with:
		   - sucess: True if the process finished sucessfully, False otherwise.
		   - msg: Log messages of the contextualization process.
		"""
		if not os.path.exists(tmp_dir + "/utils"):
			os.symlink(os.path.abspath(Config.RECIPES_DIR + "/utils"), tmp_dir + "/utils")

		command = Config.CONTEXTUALIZATION_DIR + "/ansible-playbook -i " + tmp_dir + "/" + inventory + " -u " + ssh.username
		
		if ssh.private_key:
			gen_pk_file = tmp_dir + "/pk_" + ssh.host + ".pem"
			# If the file exists, does not create again
			if not os.path.isfile(gen_pk_file):
				pk_out = open(gen_pk_file, 'w')
				pk_out.write(ssh.private_key)
				pk_out.close()
				os.chmod(gen_pk_file, 0400)
			
			command += " --private-key " + gen_pk_file
		else:
			command += " -p " + ssh.password
			
		command += " " + tmp_dir + "/" + playbook
		
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + 'Lanzamos ansible: ' + command)
			
		p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		
		(out, err) = p.communicate()
		if p.returncode == 0:
			return (True, out + "\n" + err)
		else:
			return (False, out + "\n" + err)

	def add_ansible_header(self, host, os):
		"""
		Add the IM needed header in the contextualization playbooks
	
		Arguments:
		   - host(str): Hostname of VM.
		   - os(str): OS of the VM.
		Returns: True if the process finished sucessfully, False otherwise.
		"""
		conf_content = "---\n"
		conf_content += "- hosts: " + host + "\n"
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
		conf_all_out = open(tmp_dir + "/" + filename + "_all.yml", 'w')
		conf_all_out.write("---\n")
		conf_all_out.write("- hosts: all\n")
		conf_all_out.write("  user: \"{{ IM_NODE_USER }}\"\n")
		conf_all_out.write("- include: " + filename + ".yml\n")
		conf_all_out.write("\n\n")
		conf_all_out.close()

	def configure_ansible(self, ssh, tmp_dir, master_name, masterdom):
		"""
		Install and configure ansible in the master node
	
		Arguments:
		   - ssh(:py:class:`IM.SSH`): Object to connect with the master node.
		   - tmp_dir(str): Temp directory where all the playbook files will be stored.
		   - master_name(str): Hostname of the master node.
		   - masterdom(str): Domain of the master node
		Returns: True if the process finished sucessfully, False otherwise.
		"""
		
		recipe_files = []
		# Create the ansible inventory file
		with open(tmp_dir + "/inventory.cfg", 'w') as inv_out:
			inv_out.write(ssh.host + ":" + str(ssh.port) + "\n\n")
		
		shutil.copy(Config.CONTEXTUALIZATION_DIR + "/" + ConfManager.MASTER_YAML, tmp_dir + "/" + ConfManager.MASTER_YAML)
		
		# Get the groups for the different VM types
		vm_group = self.inf.get_vm_list_by_system_name()
		
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

		ssh.sftp_mkdir(ConfManager.CONF_DIR)
		# Copy the utils helper files
		ssh.sftp_mkdir(ConfManager.CONF_DIR + "/utils")
		ssh.sftp_put_dir(Config.RECIPES_DIR + "/utils", ConfManager.CONF_DIR + "/utils")
		
		for galaxy_name in modules:
			if galaxy_name:
				recipe_out = open(tmp_dir + "/" + ConfManager.MASTER_YAML, 'a')
				self.inf.add_cont_msg("Galaxy role " + galaxy_name + " detected setting to install.")
				ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Install " + galaxy_name + " with ansible-galaxy.")
				recipe_out.write("    - name: Install the " + galaxy_name + " role with ansible-galaxy\n")
				recipe_out.write("      command: ansible-galaxy --force install " + galaxy_name + "\n")
				recipe_out.close()
		
		# get the default ctxts in case of the RADL has not specified them 
		ctxts = [contextualize_item(group, group, 1) for group in vm_group if self.inf.radl.get_configure_by_name(group)]
		# get the contextualize steps specified in the RADL, or use the default value
		contextualizes = self.inf.radl.contextualize.get_contextualize_items_by_step({1:ctxts})

		# create the files for the configure sections that appears in the contextualization steps
		# and add the ansible information and modules
		for ctxt_num in contextualizes.keys():
			for ctxt_elem in contextualizes[ctxt_num]:
				configure = self.inf.radl.get_configure_by_name(ctxt_elem.configure)
				conf_filename = tmp_dir + "/" + ctxt_elem.configure + "_" + ctxt_elem.system + ".yml"
				# if the file exists, does not create it again
				# also test if there are any VM of that type
				# (may be the user has no deplyed any of that type) 
				if configure and not os.path.isfile(conf_filename) and ctxt_elem.system in vm_group:
					conf_content = self.add_ansible_header(ctxt_elem.system, vm.getOS().lower()) 
					conf_content = self.mergeYAML(conf_content, configure.recipes)
					conf_out = open(conf_filename, 'w')
					conf_out.write(conf_content + "\n\n")
					conf_out.close()
					recipe_files.append((tmp_dir + "/" + ctxt_elem.configure + "_" + ctxt_elem.system + ".yml",
										ConfManager.CONF_DIR + "/" + ctxt_elem.configure + "_" + ctxt_elem.system + ".yml"))
	
					# create the "all" to enable this playbook to see the facts of all the nodes
					all_filename = ctxt_elem.configure + "_" + ctxt_elem.system
					self.create_all_recipe(tmp_dir, all_filename)
					all_filename += "_all.yml"
					recipe_files.append((tmp_dir + "/" + all_filename, ConfManager.CONF_DIR + "/" + all_filename))

		# Create the other configure sections (it may be included in other configure)
		if self.inf.radl.configures:
			for elem in self.inf.radl.configures:
				if elem is not None and not os.path.isfile(tmp_dir + "/" + elem.name + ".yml"):
					conf_out = open(tmp_dir + "/" + elem.name + ".yml", 'w')
					conf_out.write(elem.recipes)
					conf_out.write("\n\n")
					conf_out.close()
					recipe_files.append((tmp_dir + "/" + elem.name + ".yml",
									ConfManager.CONF_DIR + "/" + elem.name + ".yml"))

		# Create the YAML file with the basic steps and the apps to install
		for group in vm_group:
			# Use the first VM as the info used is the same for all the VMs in the group
			vm = vm_group[group][0]
			user = vm.getCredentialValues()[0]
			
			# Get the info about the apps from the recipes DB
			_, recipes = Recipe.getInfoApps(vm.getAppsToInstall())

			conf_out = open(tmp_dir + "/main_" + group + ".yml", 'w')
			conf_content = self.add_ansible_header(group, vm.getOS().lower())

			conf_content += "  tasks: \n"
			# Basic tasks set copy /etc/hosts ...
			conf_content += "  - include: utils/tasks/main.yml\n"
			
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
			recipe_files.append((tmp_dir + "/main_" + group + ".yml",
							ConfManager.CONF_DIR + "/main_" + group + ".yml"))
			
			# create the "all" to enable this playbook to see the facts of all the nodes
			all_filename = "main_" + group
			self.create_all_recipe(tmp_dir, all_filename)
			all_filename += "_all.yml"
			recipe_files.append((tmp_dir + "/" + all_filename, ConfManager.CONF_DIR + "/" + all_filename ))
			

		self.inf.add_cont_msg("Copying generated playbook files.")
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Copy YAML files")
		ssh.sftp_put_files(recipe_files)
		
		self.inf.add_cont_msg("Performing preliminary steps to configure Ansible.")
		# TODO: check to do it with ansible
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Check if python-simplejson is installed in REL 5 systems")
		(stdout, stderr, _) = ssh.execute("cat /etc/redhat-release | grep \"release 5\" &&  sudo yum -y install python-simplejson", 120)
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + stdout + stderr)

		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Remove requiretty in sshd config")
		(stdout, stderr, _) = ssh.execute("sudo sed -i 's/.*requiretty$/#Defaults requiretty/' /etc/sudoers", 120)
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": " + stdout + stderr)
		
		self.inf.add_cont_msg("Configure Ansible in the master VM (step 1).")
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Call Ansible to (re)configure (step 1) in the master node " + master_name)
		(success, msg) = self.call_ansible(tmp_dir, "inventory.cfg", ConfManager.MASTER_YAML, ssh)

		if not success:
			ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ": Error configuring in master node (step 1): " + msg + "\n\n")
			self.inf.add_cont_msg("Error configuring the master VM (step 1): " + msg + " " + tmp_dir)
			return False
		else:
			ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Ansible successfully configured in the master VM (step 1):\n" + msg + "\n\n")
			self.inf.add_cont_msg("Ansible successfully configured in the master VM (step 1).")		

		# Now all the VMs must be running
		self.inf.add_cont_msg("Wating all the VMs to boot")
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Now all the VMs must be running")
		all_running = self.waitRunningVMs(self.inf.get_vm_list(), Config.WAIT_RUNNING_VM_TIMEOUT, False)
		if not all_running:
			ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ": Error waiting the VMs to boot")
			self.inf.add_cont_msg("Error wating the VMs to boot")
			return False
		
		self.inf.add_cont_msg("All the VMs to boot OK. Prepare Step 2")

		hosts_file = tmp_dir + "/etc_hosts"
		hosts_out = open(hosts_file, 'w')
		hosts_out.write("127.0.0.1 localhost localhost.localdomain\r\n")

		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": create the ansible configuration file")
		ansible_file = tmp_dir + "/hosts"
		out = open(ansible_file, 'w')

		all_nodes = "[all]\n"
		all_vars = ""
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
						ifaces_im_vars += ' IM_NODE_NET_' + str(i) + '_IP=' + iface_ip
						if vm.getRequestedNameIface(i):
							(nodename, nodedom) = vm.getRequestedNameIface(i, default_domain = Config.DEFAULT_DOMAIN)
							hosts_out.write(iface_ip + " " + nodename + "." + nodedom + " " + nodename + "\r\n")
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
					else:
						hosts_out.write(ip + " " + nodename + "." + nodedom + " " + nodename + "\r\n")

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
	
		hosts_out.close()
		out.write(all_nodes)
		# set the IM global variables
		out.write('[all:vars]\n')
		out.write(all_vars)
		out.write('IM_MASTER_HOSTNAME=' + master_name + '\n')
		out.write('IM_MASTER_FQDN=' + master_name + "." + masterdom + '\n')
		out.write('IM_MASTER_DOMAIN=' + masterdom + '\n\n')

		out.close()
		
		# Create the file to configure the step 2 of ansible
		# (those that need all the IPs of the VMs)
		recipe_out = open(tmp_dir + "/" + ConfManager.SECOND_STEP_YAML, 'w')
		recipe_out.write("---\n")
		recipe_out.write("- hosts: all\n")
		recipe_out.write("  sudo: yes\n")
		recipe_out.write("  tasks:\n")
		recipe_out.write("    - name: Create the /etc/ansible directory\n")
		recipe_out.write("      file: path=/etc/ansible state=directory\n")
		
		recipe_out.write("    - name: Copy the /etc/ansible/hosts file (needs to be sudo)\n")
		recipe_out.write("      copy: src=" + ansible_file + " dest=/etc/ansible/hosts\n")	
		
		recipe_out.write("    - name: Copy the /etc/hosts file (needs to be sudo)\n")
		recipe_out.write("      copy: src=" + hosts_file + " dest=/etc/hosts\n")
		recipe_out.write("      ignore_errors: yes\n")
		
		recipe_out.write("    - name: Set the " + ConfManager.CONF_DIR + " directory owner\n")
		recipe_out.write("      file: path=" + ConfManager.CONF_DIR + " state=directory owner=" + ssh.username + "\n")
		recipe_out.close()
		
		self.inf.add_cont_msg("Configure Ansible in the master VM (step 2).")
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Configure Ansible in the master VM (step 2) " + master_name)
		(success, msg) = self.call_ansible(tmp_dir, "inventory.cfg", ConfManager.SECOND_STEP_YAML, ssh)

		if not success:
			ConfManager.logger.error("Inf ID: " + str(self.inf.id) + ": Error configuring master node (step 2): " + msg + "\n\n")
			self.inf.add_cont_msg("Error configuring master node (step 2): " + msg + " " + tmp_dir)
			return False
		else:
			ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Ansible successfully configured in the master VM (step 2):\n" + msg + "\n\n")
			self.inf.add_cont_msg("Ansible successfully configured in the master VM (step 2).")	
			
			return True

	def create_conf_file(self, conf_file, vm_group):
		"""
		Create the configuration file needed by the contextualization agent
		"""
		conf_data = {}
		
		conf_data['playbook_retries'] = Config.PLAYBOOK_RETRIES
		conf_data['groups'] = []
		for group in vm_group:
			group_conf_data = {}
			group_conf_data['name'] = group
			group_conf_data['vms'] = [] 
			for vm in vm_group[group]:
				if not vm.destroy:
					vm_conf_data = {}
					if vm.id == self.inf.vm_master.id:
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
					
					group_conf_data['vms'].append(vm_conf_data)
			conf_data['groups'].append(group_conf_data)
		
		# get the default ctxts in case of the RADL has not specified them 
		ctxts = [contextualize_item(group, group, 1) for group in vm_group if self.inf.radl.get_configure_by_name(group)]
		# get the contextualize steps specified in the RADL, or use the default value
		contextualizes = self.inf.radl.contextualize.get_contextualize_items_by_step({1:ctxts})

		conf_data['contextualizes'] = {}
		for contxt_num in sorted(contextualizes.keys()):
			conf_data['contextualizes'][contxt_num] = []
			for contxt_elem in contextualizes[contxt_num]:
				if contxt_elem.system in vm_group:
					contxt_conf_data = {}
					contxt_conf_data['system'] = contxt_elem.system
					contxt_conf_data['configure'] = contxt_elem.configure
					conf_data['contextualizes'][contxt_num].append(contxt_conf_data)

		conf_out = open(conf_file, 'w')
		ConfManager.logger.debug("Ctxt agent configuration file: " + json.dumps(conf_data))
		json.dump(conf_data, conf_out, indent=2)
		conf_out.close()

	def process_ctxt_agent_out(self, ctxt_agent_out, vm_group):
		"""
		Get the output file of the ctxt_agent to process the results of the operations
		"""
		if 'CHANGE_CREDS' in ctxt_agent_out:
			for group in vm_group:
				for vm in vm_group[group]:
					if not vm.destroy:
						# first try to use the public IP
						vm_ip = vm.getPublicIP()
						if not vm_ip:
							vm_ip = vm.getPrivateIP()
						
						if vm_ip in ctxt_agent_out['CHANGE_CREDS'] and ctxt_agent_out['CHANGE_CREDS'][vm_ip]:
							vm.info.systems[0].updateNewCredentialValues()

	def launch_ctxt_agent(self, ssh, tmp_dir):
		"""
		Call the contextualization agent to perform all the contextualization steps
	
		Arguments:
		   - ssh(:py:class:`IM.SSH`): Object to connect with the master node.
		   - tmp_dir(str): Temp dir where the ansible files are stored.
		Returns: True if the process finished sucessfully, False otherwise.
		"""
		# Get the groups for the different VM types
		vm_group = self.inf.get_vm_list_by_system_name()

		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Create the configuration file for the contextualization agent")
		conf_file = tmp_dir + "/config.txt"
		self.create_conf_file(conf_file, vm_group)
		
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Copy the contextualization agent files")

		files = []
		files.append((Config.IM_PATH + "/SSH.py",ConfManager.CONF_DIR + "/SSH.py"))
		files.append((Config.CONTEXTUALIZATION_DIR + "/ansible_callbacks.py", ConfManager.CONF_DIR + "/ansible_callbacks.py")) 
		files.append((Config.CONTEXTUALIZATION_DIR + "/ansible-playbook", ConfManager.CONF_DIR + "/ansible-playbook"))
		files.append((Config.CONTEXTUALIZATION_DIR + "/ctxt_agent.py", ConfManager.CONF_DIR + "/ctxt_agent.py"))
		files.append((Config.CONTEXTUALIZATION_DIR + "/basic.yml", ConfManager.CONF_DIR + "/basic.yml")) 
		files.append((conf_file, ConfManager.CONF_DIR + "/" + os.path.basename(conf_file)))
		ssh.sftp_put_files(files)

		contextualize_yaml = "contextualize.yml"
		recipe_out = open(tmp_dir + "/" + contextualize_yaml, 'w')
		recipe_out.write("---\n")
		recipe_out.write("- hosts: all\n")
		recipe_out.write("  tasks:\n")
		recipe_out.write("    - name: Lanza el Contextualizador\n")
		recipe_out.write("      command: python_ansible " + ConfManager.CONF_DIR + "/ctxt_agent.py " + ConfManager.CONF_DIR + "/" + os.path.basename(conf_file) + "\n")
		recipe_out.write("      async: " + str(Config.MAX_CONTEXTUALIZATION_TIME) + "\n")
		
		recipe_out.close()

		self.inf.add_cont_msg("Launching the contextualization agent.")
		ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Launching the contextualization agent")
		(success, msg) = self.call_ansible(tmp_dir, "inventory.cfg", contextualize_yaml, ssh)

		# Donwload the contextualization agent log
		try:
			# Get the messages of the contextualization process
			ssh.sftp_get(ConfManager.CONF_DIR + '/ctxt_agent.log', tmp_dir + '/ctxt_agent.log')
			with open(tmp_dir + '/ctxt_agent.log') as f: conf_out = f.read()
			
			# Remove problematic chars
			conf_out = filter(lambda x: x in string.printable, conf_out)
			conf_out = conf_out.encode("ascii", "replace")
			
			ssh.execute("rm -rf " + ConfManager.CONF_DIR + '/ctxt_agent.log')
		except:
			ConfManager.logger.exception("Error getting contextualization process output.")
			conf_out = "Error getting contextualization process output."
			
		# Donwload the contextualization agent log
		try:
			# Get the JSON output of the ctxt_agent
			ssh.sftp_get(ConfManager.CONF_DIR + '/ctxt_agent.out', tmp_dir + '/ctxt_agent.out')
			with open(tmp_dir + '/ctxt_agent.out') as f: ctxt_agent_out = json.load(f)
			# And process it
			self.process_ctxt_agent_out(ctxt_agent_out, vm_group)
			ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Contextualization agent output:\n" + json.dumps(ctxt_agent_out, indent=2) + "\n\n")
		except:
			ConfManager.logger.exception("Error getting contextualization agent output.")
		
		if success:
			ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ": Contextualization successfully finished:\n" + msg + "\n\n")
			self.inf.add_cont_msg("Contextualization finished sucessfully:" + conf_out)
			return True
		else:
			ConfManager.logger.debug("Inf ID: " + str(self.inf.id) + ":  Contextualization finished with errors:\n" + msg + "\n\n")
			self.inf.add_cont_msg("Contextualization finished with errors: \n\n" + conf_out)
			return False


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
