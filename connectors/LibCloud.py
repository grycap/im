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
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from CloudConnector import CloudConnector

from libcloud.compute.base import NodeImage
from libcloud.compute.types import Provider, NodeState
from libcloud.compute.providers import get_driver

from IM.radl.radl import network

class LibCloudCloudConnector(CloudConnector):
	
	type = "LibCloud"
	
	def get_driver(self, auth_data):
		auth = auth_data.getAuthInfo(LibCloudCloudConnector.type)
		if auth and 'driver' in auth[0]:
			cls = get_driver(eval("Provider."+auth[0]['driver']))
			
			params = {}
			for key, value in auth[0].iteritems():
				if key not in ["type","driver"]:
					params[key] = value
			driver = cls(**params)
			return driver
		else:
			self.logger.error("Datos de autenticacion incorrectos")
			return None
	
	def get_instace_type(self, sizes, radl):
		cpu = radl.getValue('cpu.count')
		arch = radl.getValue('cpu.arch')
		memory = radl.getFeature('memory.size').getValue('M')

		res = None
		for type in sizes:
			# cogemos la de menor precio
			if res is None or (type.price <= res.price):
				if type.ram >= memory:
					res = type
		
		if res is None:
			self.logger.error("Ningun tipo de instancia encontrada")
		else:
			self.logger.debug("Lanzaremos una instancia de tipo: " + res.name)
		
		return res

	def get_image_id(self, path):
		driver = self.cloud.auth_data['driver']

		if driver == "EC2":
			ami = uriparse(path)[2][1:]
			return ami
		else:
			return path

	def launch(self, vmi, radl, num_vm, requested_radl, auth_data):
		driver_name = self.cloud.auth_data['driver']
		driver = self.get_driver(auth_data)

		image_id = self.get_image_id(vmi.location)
		image = NodeImage(id=image_id, name=None, driver=driver)

		sizes = driver.list_sizes()
		instance_type = self.get_instace_type(sizes, radl)
		
		res = []
		
		if driver_name == "EC2":
			keypair_name = "im-" + str(int(time.time()*100))
			# creamos el keypair
			private = requested_radl.systems[0].getValue('disk.0.os.credentials.private_key')
			public = requested_radl.systems[0].getValue('disk.0.os.credentials.public_key')
			if private and public:
				if public.find('-----BEGIN CERTIFICATE-----') != -1:
					self.logger.debug("El RADL indica la PK, la subimos a EC2")
					private_key = base64.b64encode(private)
					public_key = base64.b64encode(public)
					driver.ex_import_keypair(keypair_name, public_key)
				else:
					# el nodo public_key indica el nombre del keypair
					keypair_name = public
				# Actualizamos los datos de las credenciales
				radl.system[0].setUserKeyCredentials(radl.system[0].getCredentials().username, public, private)
			else:
				self.logger.debug("Creamos el Keypair")
				self.logger.warn("LibCloud permite crear, pero no borrar Keypairs, el keypair: " + keypair_name + " no podra ser borrado")
				keypair = driver.ex_create_keypair(keypair_name)
				radl.system[0].setUserKeyCredentials(radl.system[0].getCredentials().username, None, keypair['keyMaterial'])
		
		i = 0
		while i < num_vm:
			self.logger.debug("Lanzamos instancia")
			
			if driver_name == "EC2":
				node = driver.create_node(name=vmi.name, image=image, size=instance_type, ex_keyname=keypair_name)
			else:
				node = driver.create_node(name=vmi.name, image=image, size=instance_type)
			
			if node:
				vm = VirtualMachine(node.id, self.cloud, radl, requested_radl)
				self.logger.debug("Instancia lanzada con exito.")
				res.append((True, vm))
			else:
				res.append((False, "Error launching the image"))
				
			i += 1

		return res
		
	def get_node_with_id(self, id, auth_data):
		driver = self.get_driver(auth_data)
		nodes = driver.list_nodes()
		
		res = None
		for node in nodes:
			if node.id == id:
				res = node
		return res
		
	def finalize(self, vm, auth_data):
		node = self.get_node_with_id(vm.id, auth_data)
		
		if node:
			driver_name = self.cloud.auth_data['driver']
			driver = self.get_driver(auth_data)
			driver.destroy_node(node)
			
			self.logger.debug("Instancia " + str(vm.id) + " borrada con exito.")
		else:
			self.logger.warn("Instancia " + str(vm.id) + " no encontrada para su borrado.")
		
		return (True, "")
		
	def updateVMInfo(self, vm, auth_data):
		node = self.get_node_with_id(vm.id, auth_data)
		if node:
			if node.state == NodeState.RUNNING:
				res_state = VirtualMachine.RUNNING
			elif node.state == NodeState.REBOOTING:
				res_state = VirtualMachine.RUNNING
			elif node.state == NodeState.PENDING:
				res_state = VirtualMachine.PENDING
			elif node.state == NodeState.TERMINATED:
				res_state = VirtualMachine.OFF
			else:
				res_state = VirtualMachine.UNKNOWN
				
			vm.state = res_state
			
			self.setIPsFromInstance(vm,node)
		else:
			vm.state = VirtualMachine.OFF
		
		return (True, vm)
		
	def setIPsFromInstance(self, vm, node):
		num_nets = 0
		now = str(int(time.time()*100))
		#vm.info.network = []
		
		#node.public_ips
		#node.private_ips
				
		if node.private_ips:
			vm.info.system[0].setValue('net_interface.' + str(num_nets) + '.ip', str(node.private_ips[0]))
			
			private_net = None
			for net in vm.info.network:
				if not net.isPublic():
					private_net = net
			
			if private_net is None:
				private_net = network.createNetwork("private." + now)
				vm.info.network.append(private_net)
			
			vm.info.system[0].setValue('net_interface.' + str(num_nets) + '.connection',private_net.id)
				
			num_nets += 1
			
		if node.public_ips and node.public_ips[0] != node.private_ips[0]:
			vm.info.system[0].setValue('net_interface.' + str(num_nets) + '.ip', str(node.public_ips[0]))
				
			public_net = None
			for net in vm.info.network:
				if net.isPublic():
					public_net = net
			
			if public_net is None:
				public_net = network.createNetwork("public." + now, True)
				vm.info.network.append(public_net)
			
			vm.info.system[0].setValue('net_interface.' + str(num_nets) + '.connection',public_net.id)
				
			num_nets += 1

		
	def start(self, vm, auth_data):
		return (False, "Not supported")

	def stop(self, vm, auth_data):
		return (False, "Not supported")

	def alterVM(self, vm, radl, auth_data):
		return (False, "Not supported")
