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
	
class VirtualMachine:

	# estados de las VMs
	UNKNOWN = "unknown"
	PENDING = "pending"
	RUNNING = "running"
	STOPPED = "stopped"
	OFF = "off"
	FAILED = "failed"
	CONFIGURED = "configured"

	def __init__(self, id, cloud, info, requested_radl):
		# Flag para indicar si esta VM ha sido eliminada por el usuario
		self.destroy = False
		# estado de la VM
		self.state = self.UNKNOWN
		# el ID de la VM asignado por el despliegue cloud
		self.id = id
		# el ID de la VM asignado por el IM
		self.im_id = None
		# datos sobre el despliegue cloud donde ha sido lanzada
		self.cloud = cloud
		# Objeto RADL con la informacion actual sobre la VM: memoria, cpu, aplicaciones, redes, etc.
		self.info = info.clone() if info else None
		# Objeto RADL con la informacion pedida para la VM: memoria, cpu, aplicaciones, etc.
		self.requested_radl = requested_radl
		
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
		
	def getRequestedName(self, num = None, default_hostname = None, default_domain = None):
		return self.getRequestedNameIface(0, num, default_hostname, default_domain)

	def getRequestedNameIface(self, iface_num, num = None, default_hostname = None, default_domain = None):
		full_name = self.requested_radl.systems[0].getRequestedName(iface_num)
		replaced_full_name = VirtualMachine.replaceTemplateName(full_name, num)
	
		if replaced_full_name:
			(hostname, domain) = replaced_full_name
			if not domain:
				domain = default_domain
			return (hostname, domain)
		else:
			if default_hostname:
				return (default_hostname, default_domain)
			else:
				return None
	
	@staticmethod
	def replaceTemplateName(full_name, num = None):
		if full_name:
			if num is not None:
				full_name = full_name.replace("#N#", str(num))
			dot_pos = full_name.find('.')
			if dot_pos != -1:
				domain = full_name[dot_pos+1:]
				name = full_name[:dot_pos]
				return (name, domain)
			else:
				return (full_name, None)
		else:
			return full_name
	
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