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
from IM.radl.radl import network
from config import Config

class VirtualMachine:

	# VM states
	UNKNOWN = "unknown"
	PENDING = "pending"
	RUNNING = "running"
	STOPPED = "stopped"
	OFF = "off"
	FAILED = "failed"
	CONFIGURED = "configured"

	def __init__(self, inf, im_id, cloud_id, cloud, info, requested_radl):
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
		self.im_id = im_id
		"""The internal ID of the VM assigned by the IM"""
		self.cloud = cloud
		"""CloudInfo object with the information about the cloud provider"""
		self.info = info.clone() if info else None
		"""RADL object with the current information about the VM"""
		self.requested_radl = requested_radl
		"""Original RADL requested by the user"""

	def __getstate__(self):
		"""
		Function to save the information to pickle
		"""
		with self._lock:
			odict = self.__dict__.copy()
		# Quit the lock to the data to be store by pickle
		del odict['_lock']
		return odict
	
	def __setstate__(self, dic):
		"""
		Function to load the information to pickle
		"""
		self._lock = threading.Lock()
		with self._lock:
			self.__dict__.update(dic)

	def finalize(self, auth):
		"""
		Finalize the VM
		"""
		if not self.destroy:
			cl = self.cloud.getCloudConnector()
			(success, msg) = cl.finalize(self, auth)
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
		cl = self.cloud.getCloudConnector()
		(success, alter_res) = cl.alterVM(self, radl, auth)
		# force the update of the information
		self.last_update = 0
		return (success, alter_res)
	
	def stop(self, auth):
		"""
		Stop the VM
		"""
		cl = self.cloud.getCloudConnector()
		(success, msg) = cl.stop(self, auth)
		# force the update of the information
		self.last_update = 0
		return (success, msg)
		
	def start(self, auth):
		"""
		Start the VM
		"""
		cl = self.cloud.getCloudConnector()
		(success, msg) = cl.start(self, auth)
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
			outports = public_net.getValue('outports')
			if outports:
				for elem in outports.split(","):
					parts = elem.split("-")
					if len(parts) == 2 and parts[1] == "22":
						ssh_port = int(parts[0])
		
		return ssh_port
	
	def setSSHPort(self, ssh_port):
		"""
		Set the SSH port in the RADL info of this VM 
		"""
		now = str(int(time.time()*100))

		public_net = None
		for net in self.info.networks:
			if net.isPublic():
				public_net = net
		
		# If it do
		if public_net is None:
			public_net = network.createNetwork("public." + now, True)
			self.info.networks.append(public_net)

		outports = public_net.getValue('outports')
		if outports:
			outports = outports + "," + str(ssh_port) + "-22"
		else:
			outports = str(ssh_port) + "-22"
		public_net.setValue('outports', outports)
		
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
			cl = self.cloud.getCloudConnector()
			(success, new_vm) = cl.updateVMInfo(self, auth)
			if success:
				state = new_vm.state
				updated = True

			with self._lock:
				self.last_update = now
	
		if state != VirtualMachine.RUNNING:
			new_state = state
		elif self.inf.configured is None:
			new_state = VirtualMachine.RUNNING
		elif self.inf.configured:
			new_state = VirtualMachine.CONFIGURED
		else:
			new_state = VirtualMachine.FAILED

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