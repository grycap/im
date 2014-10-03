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

class VirtualMachine:

	# estados de las VMs
	UNKNOWN = "unknown"
	PENDING = "pending"
	RUNNING = "running"
	STOPPED = "stopped"
	OFF = "off"
	FAILED = "failed"
	CONFIGURED = "configured"
	
	UPDATE_FREQUENCY = 10
	""" Maximum frequency to update the VM info (in secs) """

	def __init__(self, inf, im_id, cloud_id, cloud, info, requested_radl):
		self._lock = threading.Lock()
		"""Threading Lock to avoid concurrency problems."""
		self.last_update = 0
		"""Last update of the VM info"""
		
		# Flag para indicar si esta VM ha sido eliminada por el usuario
		self.destroy = False
		# estado de la VM
		self.state = self.UNKNOWN
		# Infrastructure which this VM is part of 
		self.inf = inf
		# el ID de la VM asignado por el despliegue cloud
		self.id = cloud_id 
		# el ID de la VM asignado por el IM
		self.im_id = im_id
		# datos sobre el despliegue cloud donde ha sido lanzada
		self.cloud = cloud
		# Objeto RADL con la informacion actual sobre la VM: memoria, cpu, aplicaciones, redes, etc.
		self.info = info.clone() if info else None
		# Objeto RADL con la informacion pedida para la VM: memoria, cpu, aplicaciones, etc.
		self.requested_radl = requested_radl

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

	# Devuelve el objeto system con los datos RADL solicitados por el usuario para crear esta VM
	def getRequestedSystem(self):
		return self.requested_radl.systems[0]
	
	# Devuelve True si tiene alguna ip publica
	def hasPublicIP(self):
		return bool(self.info.getPublicIP())
	
	# Devuelve True si tiene alguna ip publica
	def hasPublicNet(self):
		return self.info.hasPublicNet(self.info.systems[0].name)
		
	# Devuelve si la VM tiene alguna IP igual a la especificada
	def hasIP(self, ip):
		return self.info.systems[0].hasIP(ip)
		
	# Devuelve la primera interfaz de red con IP publica
	# Suponemos que solo habra una publica en cada VM
	def getPublicIP(self):
		return self.info.getPublicIP()
	
	# Devuelve la primera interfaz de red con IP privada
	def getPrivateIP(self):
		return self.info.getPrivateIP()

	# Devuelve el numero de interfaces de red definidas
	def getNumNetworkIfaces(self):
		return self.info.systems[0].getNumNetworkIfaces()

	# Devuelve el numero de la interfax con el nombre de conexion indicado
	def getNumNetworkWithConnection(self, connection):
		return self.info.systems[0].getNumNetworkWithConnection(connection)

	# Devuelve la IP de la interfaz indicada
	def getIfaceIP(self, iface_num):
		return self.info.systems[0].getIfaceIP(iface_num)
		
	def getOS(self):
		return self.info.systems[0].getValue("disk.0.os.name")
	
	# Devuelve las credenciales de acceso a la VM
	def getCredentials(self):
		return self.info.systems[0].getCredentials()
		
	def getCredentialValues(self, new = False):
		return self.info.systems[0].getCredentialValues(new=new)

	def getInstalledApplications(self):
		return self.info.systems[0].getApplications()
		
	def getRequestedApplications(self):
		return self.requested_radl.systems[0].getApplications()

	def getRequestedName(self, default_hostname = None, default_domain = None):
		return self.getRequestedNameIface(0, default_hostname, default_domain)

	def getRequestedNameIface(self, iface_num, default_hostname = None, default_domain = None):		
		return self.requested_radl.systems[0].getRequestedNameIface(iface_num, self.im_id, default_hostname, default_domain)

	# Devuelve True si la VM actual y la indicada se pueden conectar
	# por alguna red
	def isConnectedWith(self, vm):
		# Si las 2 tienen IP publica
		if self.hasPublicIP() and vm.hasPublicIP():
			return True

		# O si las 2 estan conectadas una misma red
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
				parts = req_app.getValue("name")[16:].split(".")
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
		# This if avoids to refresh the information too quickly
		if now - self.last_update > VirtualMachine.UPDATE_FREQUENCY:
			cl = self.cloud.getCloudConnector()
			(success, new_vm) = cl.updateVMInfo(self, auth)
			if not success:
				state = self.state
			else:
				state = new_vm.state
	
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
				self.last_update = now
		else:
			success = False

		return success