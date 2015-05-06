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

import time
import threading
from IM.radl.radl import network, RADL
from IM.SSH import SSH
from config import Config
import shutil
import string
import json
import tempfile


class VirtualMachine:

	# VM states
	UNKNOWN = "unknown"
	PENDING = "pending"
	RUNNING = "running"
	STOPPED = "stopped"
	OFF = "off"
	FAILED = "failed"
	CONFIGURED = "configured"
	UNCONFIGURED = "unconfigured"
	
	WAIT_TO_PID = "WAIT"
	
	THREAD_SLEEP_DELAY = 5

	def __init__(self, inf, cloud_id, cloud, info, requested_radl, cloud_connector = None):
		self._lock = threading.Lock()
		"""Threading Lock to avoid concurrency problems."""
		self.last_update = 0
		"""Last update of the VM info"""
		self.destroy = False
		"""Flag to specify that this VM has been destroyed"""
		self.state = self.UNKNOWN
		"""VM State"""
		self.inf = inf
		"""Infrastructure which this VM is part of"""
		self.id = cloud_id 
		"""The ID of the VM assigned by the cloud provider"""
		self.im_id = inf.get_next_vm_id()
		"""The internal ID of the VM assigned by the IM"""
		self.cloud = cloud
		"""CloudInfo object with the information about the cloud provider"""
		self.info = info.clone() if info else None
		"""RADL object with the current information about the VM"""
		self.requested_radl = requested_radl
		"""Original RADL requested by the user"""
		self.cont_out = ""
		"""Contextualization output message"""
		self.configured = None
		"""Configure flag. If it is None the contextualization has not been finished yet"""
		self.ctxt_pid = None
		"""Number of the PID of the contextualization process being executed in this VM"""
		self.ssh_connect_errors = 0
		"""Number of errors in the ssh connection trying to get the state of the ctxt pid """
		self.cloud_connector = cloud_connector
		"""CloudConnector object to connect with the IaaS platform"""

	def __getstate__(self):
		"""
		Function to save the information to pickle
		"""
		with self._lock:
			odict = self.__dict__.copy()
		# Quit the lock to the data to be store by pickle
		del odict['_lock']
		del odict['cloud_connector']
		return odict
	
	def __setstate__(self, dic):
		"""
		Function to load the information to pickle
		"""
		self._lock = threading.Lock()
		with self._lock:
			self.__dict__.update(dic)
			self.cloud_connector = None
			# If we load a VM that is not configured, set it to False
			# because the configuration process will be lost
			if self.configured is None:
				self.configured = False

	def finalize(self, auth):
		"""
		Finalize the VM
		"""
		if not self.destroy:
			if not self.cloud_connector:
				self.cloud_connector = self.cloud.getCloudConnector()
			(success, msg) = self.cloud_connector.finalize(self, auth)
			if success:
				self.destroy = True
			# force the update of the information
			self.last_update = 0
			return (success, msg)
		else:
			return (True, "")

	def alter(self, radl, auth):
		"""
		Modify the features of the the VM
		"""
		if not self.cloud_connector:
			self.cloud_connector = self.cloud.getCloudConnector()
		(success, alter_res) = self.cloud_connector.alterVM(self, radl, auth)
		# force the update of the information
		self.last_update = 0
		return (success, alter_res)
	
	def stop(self, auth):
		"""
		Stop the VM
		"""
		if not self.cloud_connector:
			self.cloud_connector = self.cloud.getCloudConnector()
		(success, msg) = self.cloud_connector.stop(self, auth)
		# force the update of the information
		self.last_update = 0
		return (success, msg)
		
	def start(self, auth):
		"""
		Start the VM
		"""
		if not self.cloud_connector:
			self.cloud_connector = self.cloud.getCloudConnector()
		(success, msg) = self.cloud_connector.start(self, auth)
		# force the update of the information
		self.last_update = 0
		return (success, msg)

	def getRequestedSystem(self):
		"""
		Get the system object with the requested RADL data
		"""
		return self.requested_radl.systems[0]
	
	def hasPublicIP(self):
		"""
		Return True if this VM has a public IP
		"""
		return bool(self.info.getPublicIP())
	
	def hasPublicNet(self):
		"""
		Return True if this VM is connected to some network defined as public
		"""
		return self.info.hasPublicNet(self.info.systems[0].name)

	def hasIP(self, ip):
		"""
		Return True if this VM has an IP equals to the specified ip
		"""
		return self.info.systems[0].hasIP(ip)
		
	def getPublicIP(self):
		"""
		Get the first net interface with public IP
		"""
		return self.info.getPublicIP()
	
	def getPrivateIP(self):
		"""
		Get the first net interface with private IP
		"""
		return self.info.getPrivateIP()

	def getNumNetworkIfaces(self):
		"""
		Get the number of net interfaces of this VM 
		"""
		return self.info.systems[0].getNumNetworkIfaces()

	def getNumNetworkWithConnection(self, connection):
		"""
		Get the number of the interface connected with the net id specified 
		"""
		return self.info.systems[0].getNumNetworkWithConnection(connection)

	def getIfaceIP(self, iface_num):
		"""
		Get the IP of the interface specified 
		"""
		return self.info.systems[0].getIfaceIP(iface_num)
		
	def getOS(self):
		"""
		Get O.S. of this VM 
		"""
		return self.info.systems[0].getValue("disk.0.os.name")
		
	def getCredentialValues(self, new = False):
		"""
		Get The credentials to access of this VM by SSH
		"""
		return self.info.systems[0].getCredentialValues(new=new)

	def getInstalledApplications(self):
		"""
		Get the list of installed applications in this VM.
		(Obtained from the VMRC)
		"""
		return self.info.systems[0].getApplications()
		
	def getRequestedApplications(self):
		"""
		Get the list of requested applications to be installed in this VM.
		"""
		return self.requested_radl.systems[0].getApplications()

	def getRequestedName(self, default_hostname = None, default_domain = None):
		"""
		Get the requested name for this VM (interface 0)
		"""
		return self.getRequestedNameIface(0, default_hostname, default_domain)

	def getRequestedNameIface(self, iface_num, default_hostname = None, default_domain = None):		
		"""
		Get the requested name for the specified interface of this VM
		"""
		return self.requested_radl.systems[0].getRequestedNameIface(iface_num, self.im_id, default_hostname, default_domain)


	def isConnectedWith(self, vm):
		"""
		Check if this VM is connected with the specified VM with a network
		"""
		# If both VMs have public IPs
		if self.hasPublicIP() and vm.hasPublicIP():
			return True

		# Or if both VMs are connected to the same network
		i = 0
		while self.info.systems[0].getValue("net_interface." + str(i) + ".connection"):
			net_name = self.info.systems[0].getValue("net_interface." + str(i) + ".connection")

			common_net = False
			j = 0
			while vm.info.systems[0].getValue("net_interface." + str(j) + ".connection"):
				other_net_name = vm.info.systems[0].getValue("net_interface." + str(j) + ".connection")

				if other_net_name == net_name:
					common_net = True
					break

				j += 1
			
			if common_net:
				return True

			i += 1

		return False

	def getAppsToInstall(self):
		"""
		Get a list of applications to install in the VM 
	
		Returns: list of :py:class:`IM.radl.radl.Application` with the applications
		"""
		# check apps requested
		requested = self.getRequestedApplications()
		# check apps installed in the VM
		installed = self.getInstalledApplications()

		to_install = []
		for req_app in requested:
			# discard the ansible modules
			if not req_app.getValue("name").startswith("ansible.modules"):
				is_installed = False
				for inst_app in installed:
					if inst_app.isNewerThan(req_app):
						is_installed = True
				if not is_installed:
					to_install.append(req_app)

		return to_install
	

	def getModulesToInstall(self):
		"""
		Get a list of ansible modules to install in the VM 
	
		Arguments:
		   - vm_(:py:class:`IM.VirtualMachine`): VMs to check the modules.
		Returns: list of str with the name of the galaxy roles (i.e.: micafer.hadoop)
		"""
		requested = self.getRequestedApplications()
		to_install = []
		for req_app in requested:
			if req_app.getValue("name").startswith("ansible.modules."):
				to_install.append(req_app.getValue("name")[16:])
		return to_install
	
	def getSSHPort(self):
		"""
		Get the SSH port from the RADL 

		Returns: int with the port
		"""
		ssh_port = 22

		public_net = None
		for net in self.info.networks:
			if net.isPublic():
				public_net = net
				
		if public_net:
			outports = public_net.getOutPorts()
			if outports:
				for (remote_port,_,local_port,local_protocol) in outports:
					if local_port == 22 and local_protocol == "tcp":
						ssh_port = remote_port
		
		return ssh_port
	
	def setSSHPort(self, ssh_port):
		"""
		Set the SSH port in the RADL info of this VM 
		"""
		if ssh_port != self.getSSHPort():
			now = str(int(time.time()*100))
	
			public_net = None
			for net in self.info.networks:
				if net.isPublic():
					public_net = net
			
			# If it do
			if public_net is None:
				public_net = network.createNetwork("public." + now, True)
				self.info.networks.append(public_net)

			outports_str = str(ssh_port) + "-22"
			outports = public_net.getOutPorts()
			if outports:
				for (remote_port,_,local_port,local_protocol) in outports:
					if local_port != 22 and local_protocol != "tcp":
						if local_protocol != "tcp":
							outports_str += str(remote_port) + "-" + str(local_port)
						else:
							outports_str += str(remote_port) + "/udp" + "-" + str(local_port) + "/udp"
			public_net.setValue('outports', outports_str)
			
			# get the ID
			num_net = self.getNumNetworkWithConnection(public_net.id)
			if num_net is None:
				# There are a public net but it has not been used in this VM
				num_net = self.getNumNetworkIfaces()
	
			self.info.systems[0].setValue('net_interface.' + str(num_net) + '.connection',public_net.id)
		
	def update_status(self, auth):
		"""
		Update the status of this virtual machine.
		Only performs the update with UPDATE_FREQUENCY secs. 
		
		Args:
		- auth(Authentication): parsed authentication tokens.
		Return:
		- boolean: True if the information has been updated, false otherwise
		"""
		now = int(time.time())
		state = self.state
		updated = False
		# To avoid to refresh the information too quickly
		if now - self.last_update > Config.VM_INFO_UPDATE_FREQUENCY:
			if not self.cloud_connector:
				self.cloud_connector = self.cloud.getCloudConnector()
			(success, new_vm) = self.cloud_connector.updateVMInfo(self, auth)
			if success:
				state = new_vm.state
				updated = True

			with self._lock:
				self.last_update = now
	
		if state != VirtualMachine.RUNNING:
			new_state = state
		elif self.is_configured() is None:
			new_state = VirtualMachine.RUNNING
		elif self.is_configured():
			new_state = VirtualMachine.CONFIGURED
		else:
			new_state = VirtualMachine.UNCONFIGURED

		with self._lock:
			self.info.systems[0].setValue("state", new_state)

		return updated

	def setIps(self,public_ips,private_ips):
		"""
		Set the specified IPs in the VM RADL info 
		"""
		now = str(int(time.time()*100))
		vm_system = self.info.systems[0]

		if public_ips and not set(public_ips).issubset(set(private_ips)):
			public_net = None
			for net in self.info.networks:
				if net.isPublic():
					public_net = net
					
			if public_net is None:
				public_net = network.createNetwork("public." + now, True)
				self.info.networks.append(public_net)
				num_net = self.getNumNetworkIfaces()
			else:
				# If there are are public net, get the ID
				num_net = self.getNumNetworkWithConnection(public_net.id)
				if num_net is None:
					# There are a public net but it has not been used in this VM
					num_net = self.getNumNetworkIfaces()

			for public_ip in public_ips:
				if public_ip not in private_ips:
					vm_system.setValue('net_interface.' + str(num_net) + '.ip', str(public_ip))
					vm_system.setValue('net_interface.' + str(num_net) + '.connection',public_net.id)

		if private_ips:
			private_net_map = {}
			
			for private_ip in private_ips:
				private_net_mask = None

				# Get the private network mask
				for mask in network.private_net_masks:
					if network.addressInNetwork(private_ip,mask):
						private_net_mask = mask
						break
				
				# Search in previous user private ips
				private_net = None
				for net_mask, net in private_net_map.iteritems():
					if network.addressInNetwork(private_ip, net_mask): 	
						private_net = net								

				# Search in the RADL nets
				if private_net is None:
					for net in self.info.networks:
						if not net.isPublic() and net not in private_net_map.values():
							private_net = net
							private_net_map[private_net_mask] = net
			
				# if it is still None, then create a new one
				if private_net is None:
					private_net = network.createNetwork("private." + private_net_mask.split('/')[0])
					self.info.networks.append(private_net)
					num_net = self.getNumNetworkIfaces()
				else:
					# If there are are private net, get the ID
					num_net = self.getNumNetworkWithConnection(private_net.id)
					if num_net is None:
						# There are a private net but it has not been used in this VM
						num_net = self.getNumNetworkIfaces()
	
				vm_system.setValue('net_interface.' + str(num_net) + '.ip', str(private_ip))
				vm_system.setValue('net_interface.' + str(num_net) + '.connection',private_net.id)

	def get_ssh(self):
		"""
		Get SSH object to connect with this VM
		"""
		(user, passwd, _, private_key) = self.getCredentialValues()
		ip = self.getPublicIP()
		if ip == None:
			ip = self.getPrivateIP()
		if ip == None:
			return None
		return SSH(ip, user, passwd, private_key, self.getSSHPort())
	
	def is_ctxt_process_running(self):
		""" Return the PID of the running process or None if it is not running """
		return self.ctxt_pid
	
	def launch_check_ctxt_process(self):
		"""
		Launch the check_ctxt_process as a thread
		"""
		t = threading.Thread(target=eval("self.check_ctxt_process"))
		t.daemon = True
		t.start()
	
	def check_ctxt_process(self):
		"""
		Periodically checks if the PID of the ctxt process is running 
		"""
		while self.ctxt_pid:
			if self.ctxt_pid != self.WAIT_TO_PID:
				ssh = self.inf.vm_master.get_ssh()

				if self.state in [VirtualMachine.OFF, VirtualMachine.FAILED]:
					try:
						ssh.execute("kill -9 " + str(self.ctxt_pid))
					except:
						pass

					self.ctxt_pid = None
					self.configured = False
				else:
					try:
						(_, _, exit_status) = ssh.execute("ps " + str(self.ctxt_pid))
					except:
						exit_status = 0
						self.ssh_connect_errors += 1
						if self.ssh_connect_errors > Config.MAX_SSH_ERRORS:
							self.ssh_connect_errors = 0
							self.ctxt_pid = None
							self.configured = False
						
					if exit_status != 0:
						self.ctxt_pid = None
						# The process has finished, get the outputs
						ip = self.getPublicIP()
						if not ip:
							ip = ip = self.getPrivateIP()
						remote_dir = Config.REMOTE_CONF_DIR + "/" + ip + "_" + str(self.getSSHPort())
						self.get_ctxt_output(remote_dir)
			else:
				time.sleep(self.THREAD_SLEEP_DELAY)

		return self.ctxt_pid
	
	def is_configured(self):
		if self.inf.is_configured() is False:
			return False 
		else:
			if self.inf.vm_in_ctxt_tasks(self) or self.ctxt_pid:
				# If there are ctxt tasks pending for this VM, return None
				return None
			else:
				# Otherwise return the value of configured
				return self.configured

	def get_ctxt_output(self, remote_dir):
		ssh = self.inf.vm_master.get_ssh()
		tmp_dir = tempfile.mkdtemp()

		# Donwload the contextualization agent log
		try:
			# Get the messages of the contextualization process
			ssh.sftp_get(remote_dir + '/ctxt_agent.log', tmp_dir + '/ctxt_agent.log')
			with open(tmp_dir + '/ctxt_agent.log') as f: conf_out = f.read()
			
			# Remove problematic chars
			conf_out = filter(lambda x: x in string.printable, conf_out)
			self.cont_out += conf_out.encode("ascii", "replace")
			
			ssh.execute("rm -rf " + remote_dir + '/ctxt_agent.log')
		except Exception, ex:
			self.configured = False
			self.cont_out += "Error getting contextualization process output: " + str(ex)
			
		# Donwload the contextualization agent log
		try:
			# Get the JSON output of the ctxt_agent
			ssh.sftp_get(remote_dir + '/ctxt_agent.out', tmp_dir + '/ctxt_agent.out')
			with open(tmp_dir + '/ctxt_agent.out') as f: ctxt_agent_out = json.load(f)
			# And process it
			self.process_ctxt_agent_out(ctxt_agent_out)
		except Exception, ex:
			self.configured = False
			self.cont_out += "Error getting contextualization agent output: "  + str(ex)
		finally:
			shutil.rmtree(tmp_dir, ignore_errors=True)
		
	def process_ctxt_agent_out(self, ctxt_agent_out):
		"""
		Get the output file of the ctxt_agent to process the results of the operations
		"""
		if 'CHANGE_CREDS' in ctxt_agent_out and ctxt_agent_out['CHANGE_CREDS']:
			self.info.systems[0].updateNewCredentialValues()
		
		if 'OK' in ctxt_agent_out and ctxt_agent_out['OK']:	
			self.configured = True
		else:
			self.configured = False
	
	def get_vm_info(self):
		res = RADL()
		res.networks = self.info.networks 
		res.systems = self.info.systems
		return str(res)