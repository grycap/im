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

import socket,struct

import time
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from CloudConnector import CloudConnector

from libcloud.compute.base import NodeImage, NodeAuthSSHKey
from libcloud.compute.types import NodeState, Provider
from libcloud.compute.providers import get_driver

from IM.radl.radl import network, Feature

class LibCloudCloudConnector(CloudConnector):
	"""
	Cloud Launcher to the LibCloud library
	"""
	
	type = "LibCloud"
	"""str with the name of the provider."""
	
	def get_driver(self, auth_data):
		"""
		Get the driver from the auth data

		Arguments:
			- auth(Authentication): parsed authentication tokens.
		
		Returns: a :py:class:`libcloud.compute.base.NodeDriver` or None in case of error
		"""
		auth = auth_data.getAuthInfo(LibCloudCloudConnector.type)
		if auth and 'driver' in auth[0]:
			cls = get_driver(eval("Provider."+auth[0]['driver']))
			
			MAP = { "username" : "key", "password": "secret"}
		
			params = {}
			for key, value in auth[0].iteritems():
				if key not in ["type","driver","id"]:
					params[MAP[key]] = value
					
			if auth[0]['driver'] == "OPENSTACK":
				if 'host' in auth[0]:
					params["ex_force_auth_url"] = auth[0]['host']
				else:
					self.logger.error("Host data is needed in OpenStack")
					return None
			else:
				if 'host' in auth[0]:
					uri = uriparse(auth[0]['host'])
					if uri[1].find(":"):
						parts = uri[1].split(":")
						params["host"] = parts[0]
						params["port"] = int(parts[1])  
					else:
						params["host"] = uri[1] 
				
					
			driver = cls(**params)
			return driver
		else:
			self.logger.error("Incorrect auth data")
			return None
	
	def get_instance_type(self, sizes, radl):
		"""
		Get the name of the instance type to launch to EC2

		Arguments:
		   - size(list of :py:class: `libcloud.compute.base.NodeSize`): List of sizes on a provider
		   - radl(str): RADL document with the requirements of the VM to get the instance type
		Returns: a :py:class:`libcloud.compute.base.NodeSize` with the instance type to launch	
		"""
		memory = radl.getFeature('memory.size').getValue('M')

		res = None
		for size in sizes:
			# get the node size with the lowest price
			if res is None or (size.price <= res.price):
				if size.ram >= memory:
					res = size
		
		if res is None:
			self.logger.error("No compatible size found")
		
		return res
	
	def concreteSystem(self, radl_system, auth_data):
		if radl_system.getValue("disk.0.image.url"):
			url = uriparse(radl_system.getValue("disk.0.image.url"))
			protocol = url[0]
			driver = self.get_driver(auth_data)
			
			PROTOCOL_MAP = { "Amazon EC2" : "aws", "OpenNebula": "one", "OpenStack": "ost", "LibVirt": "file"}
			
			req_protocol = PROTOCOL_MAP.get(driver.name,None)
			
			if req_protocol is not None and protocol != req_protocol:
				return []
			else:
				res_system = radl_system.clone()
				instance_type = self.get_instance_type(driver.list_sizes(), res_system)
				
				res_system.addFeature(Feature("memory.size", "=", instance_type.ram, 'M'), conflict="other", missing="other")
				res_system.addFeature(Feature("disk.0.free_size", "=", instance_type.disk , 'G'), conflict="other", missing="other")
				res_system.addFeature(Feature("price", "=", instance_type.price), conflict="me", missing="other")
				
				res_system.addFeature(Feature("provider.type", "=", self.type), conflict="other", missing="other")
				if self.cloud.server:
					res_system.addFeature(Feature("provider.host", "=", self.cloud.server), conflict="other", missing="other")
				if self.cloud.port != -1:
					res_system.addFeature(Feature("provider.port", "=", self.cloud.port), conflict="other", missing="other")				
					
				return [res_system]
		else:
			return [radl_system.clone()]

	def get_image_id(self, path):
		"""
		Get the ID of the image to use from the location of the VMI

		Arguments:
		   - path(str): URL with the location of the VMI
		Returns: a str with the ID	
		"""
		return uriparse(path)[2][1:]

	def launch(self, inf, radl, requested_radl, num_vm, auth_data):
		driver = self.get_driver(auth_data)

		system = radl.systems[0]
		image_id = self.get_image_id(system.getValue("disk.0.image.url"))
		image = NodeImage(id=image_id, name=None, driver=driver)

		instance_type = self.get_instance_type(driver.list_sizes(), system)
		
		name = system.getValue("disk.0.image.name")
		if not name:
			name = "userimage"
		
		args = {'size': instance_type,
		        'image': image,
		        'name': "%s-%s" % (name, int(time.time()*100))}
		
		keypair = None
		public_key = system.getValue("disk.0.os.credentials.public_key")
		if "ssh_key" in driver.features.get("create_node", []):
			
			if public_key:
				keypair = driver.get_key_pair(public_key)
				if keypair:
					system.setUserKeyCredentials(system.getCredentials().username, None, keypair.private_key)
				else:
					args["auth"] = NodeAuthSSHKey(public_key)
			elif not system.getValue("disk.0.os.credentials.password"):
				keypair_name = "im-%s" % time.time()
				keypair = driver.create_key_pair(keypair_name)
				system.setUserKeyCredentials(system.getCredentials().username, None, keypair.private_key)
				
				if keypair.public_key:
					args["auth"] = NodeAuthSSHKey(keypair.public_key)
				else:
					args["ex_keyname"] = keypair_name

		res = []
		i = 0
		while i < num_vm:
			self.logger.debug("Creating node")

			node = driver.create_node(**args)
			
			if node:
				vm = VirtualMachine(inf, node.id, self.cloud, radl, requested_radl)
				# Add the keypair name to remove it later 
				vm.keypair = keypair
				self.logger.debug("Node successfully created.")
				res.append((True, vm))
			else:
				res.append((False, "Error creating the node"))
				
			i += 1

		return res
		
	def get_node_with_id(self, id, auth_data):
		"""
		Get the node with the specified ID

		Arguments:
		   - id(str): ID of the node to get
		   - auth(Authentication): parsed authentication tokens.
		Returns: a :py:class:`libcloud.compute.base.Node` with the node info	
		"""
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
			success = node.destroy()
			
			public_key = vm.getRequestedSystem().getValue('disk.0.os.credentials.public_key')
			if public_key is None or len(public_key) == 0 or (len(public_key) >= 1 and public_key.find('-----BEGIN CERTIFICATE-----') != -1):
				# only delete in case of the user do not specify the keypair name
				node.driver.delete_key_pair(vm.keypair)
			
			self.delete_elastic_ips(node, vm)
			
			# Delete the EBS volumes
			self.delete_volumes(vm)
			
			if not success:
				return (False, "Error destroying node: " + vm.id)

			self.logger.debug("VM " + str(vm.id) + " successfully destroyed")
		else:
			self.logger.warn("VM " + str(vm.id) + " not found.")
		
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
			elif node.state == NodeState.STOPPED:
				res_state = VirtualMachine.STOPPED
			else:
				res_state = VirtualMachine.UNKNOWN
				
			vm.state = res_state
			
			self.setIPsFromInstance(vm,node)
			self.attach_volumes(vm,node)
		else:
			vm.state = VirtualMachine.OFF
		
		return (True, vm)
		
	def setIPsFromInstance(self, vm, node):
		"""
		Adapt the RADL information of the VM to the real IPs assigned by the cloud provider

		Arguments:
		   - vm(:py:class:`IM.VirtualMachine`): VM information.	
		   - node(:py:class:`libcloud.compute.base.Node`): object to connect to EC2 instance.
		"""

		now = str(int(time.time()*100))
		vm_system = vm.info.systems[0]

		if node.public_ips and not set(node.public_ips).issubset(set(node.private_ips)):
			public_net = None
			for net in vm.info.networks:
				if net.isPublic():
					public_net = net
					
			if public_net is None:
				public_net = network.createNetwork("public." + now, True)
				vm.info.networks.append(public_net)
				num_net = vm.getNumNetworkIfaces()
			else:
				# If there are are public net, get the ID
				num_net = vm.getNumNetworkWithConnection(public_net.id)
				if num_net is None:
					# There are a public net but it has not been used in this VM
					num_net = vm.getNumNetworkIfaces()

			for public_ip in node.public_ips:
				if public_ip not in node.private_ips:
					vm_system.setValue('net_interface.' + str(num_net) + '.ip', str(public_ip))
					vm_system.setValue('net_interface.' + str(num_net) + '.connection',public_net.id)

		if node.private_ips:
			private_net_masks = ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","169.254.0.0/16"]
			private_net_map = {}
			
			for private_ip in node.private_ips:
				private_net_mask = None

				# Get the private network mask
				for mask in private_net_masks:
					if self.addressInNetwork(private_ip,mask):
						private_net_mask = mask
						break
				
				# This must not happen
				if private_net_mask is None:
					self.logger.warn("Private IP " + str(private_ip) + " is not a correct private IPV4 address.")
					break
				
				# Search in previous user private ips
				private_net = None
				for net_mask, net in private_net_map.iteritems():
					if self.addressInNetwork(private_ip, net_mask): 	
						private_net = net								

				# Search in the RADL nets
				if private_net is None:
					for net in vm.info.networks:
						if not net.isPublic() and net not in private_net_map.values():
							private_net = net
							private_net_map[private_net_mask] = net
			
				# if it is still None, then create a new one
				if private_net is None:
					private_net = network.createNetwork("private." + private_net_mask)
					vm.info.networks.append(private_net)
					num_net = vm.getNumNetworkIfaces()
				else:
					# If there are are private net, get the ID
					num_net = vm.getNumNetworkWithConnection(private_net.id)
					if num_net is None:
						# There are a private net but it has not been used in this VM
						num_net = vm.getNumNetworkIfaces()
	
				vm_system.setValue('net_interface.' + str(num_net) + '.ip', str(private_ip))
				vm_system.setValue('net_interface.' + str(num_net) + '.connection',private_net.id)

		self.manage_elastic_ips(vm, node)
		
	def manage_elastic_ips(self, vm, node):
		"""
		Manage the elastic IPs in case of EC2 and OpenStack

		Arguments:
		   - vm(:py:class:`IM.VirtualMachine`): VM information.
		   - node(:py:class:`libcloud.compute.base.Node`): node object.		
		"""
		if node.driver.name in [ "Amazon EC2", "OpenStack" ]:
			n = 0
			requested_ips = []
			while vm.getRequestedSystem().getValue("net_interface." + str(n) + ".connection"):
				net_conn = vm.getRequestedSystem().getValue('net_interface.' + str(n) + '.connection')
				if vm.info.get_network_by_id(net_conn).isPublic():
					fixed_ip = vm.getRequestedSystem().getValue("net_interface." + str(n) + ".ip")
					requested_ips.append(fixed_ip)
				n += 1
			
			for num, ip in enumerate(sorted(requested_ips, reverse=True)):
				if ip:
					# It is a fixed IP
					if ip not in node.public_ips:
						# It has not been created yet, do it
						self.add_elastic_ip(vm, node, ip)
				else:
					if num >= len(node.public_ips):
						self.add_elastic_ip(vm, node)

	def add_elastic_ip(self, vm, node, fixed_ip = None):
		"""
		Add an elastic IP to an instance

		Arguments:
		   - vm(:py:class:`IM.VirtualMachine`): VM information.
		   - node(:py:class:`libcloud.compute.base.Node`): node object to attach the volumes.
		   - fixed_ip(str, optional): specifies a fixed IP to add to the instance.
		Returns: a :py:class:`boto.ec2.address.Address` added or None if some problem occur.	
		"""
		if vm.state == VirtualMachine.RUNNING:
			try:
				self.logger.debug("Add an Elastic/Floating IP")
				if node.driver.name == "Amazon EC2":
					elastic_ip = None
					if fixed_ip:
						elastic_ips = node.driver.ex_describe_addresses_for_node(node)
						for ip in elastic_ips:
							if str(ip.ip) == ip:
								elastic_ip = ip
					if elastic_ip is None:  
						elastic_ip = node.driver.ex_allocate_address()
					node.driver.ex_associate_address_with_node(node, elastic_ip)
					return elastic_ip
				elif node.driver.name == "OpenStack":
					pool = node.driver.ex_list_floating_ip_pools()[0]
					if fixed_ip:
						floating_ip = node.driver.ex_get_floating_ip(fixed_ip)
					else:
						floating_ip = pool.create_floating_ip()
					node.driver.ex_attach_floating_ip_to_node(node, floating_ip)
					return floating_ip
				else:
					return None
			except Exception:
				self.logger.exception("Error adding an Elastic/Floating IP to VM ID: " + str(vm.id))
				return None
		else:
			self.logger.debug("The VM is not running, not adding an Elastic/Floating IP.")
			return None

	def delete_elastic_ips(self, node, vm):
		"""
		remove the elastic IPs of a VM

		Arguments:
		   - node(:py:class:`libcloud.compute.base.Node`): node object to attach the volumes.
		   - vm(:py:class:`IM.VirtualMachine`): VM information.	
		"""
		try:
			self.logger.debug("Remove Elastic/Floating IPs")
			if node.driver.name == "Amazon EC2":
				elastic_ips = node.driver.ex_describe_addresses_for_node(node)
				for elastic_ip in elastic_ips:
					node.driver.ex_disassociate_address(elastic_ip)
					
					n = 0
					found = False
					while vm.getRequestedSystem().getValue("net_interface." + str(n) + ".connection"):
						net_conn = vm.getRequestedSystem().getValue('net_interface.' + str(n) + '.connection')
						if vm.info.get_network_by_id(net_conn).isPublic():
							if vm.getRequestedSystem().getValue("net_interface." + str(n) + ".ip"):
								fixed_ip = vm.getRequestedSystem().getValue("net_interface." + str(n) + ".ip")
								# If it is a fixed IP we must not release it
								if fixed_ip == str(elastic_ip.ip):
									found = True
						n += 1

					if not found:
						self.logger.debug("Now release it")
						node.driver.ex_release_address(elastic_ip)
			elif node.driver.name == "OpenStack":
				for floating_ip in node.driver.ex_list_floating_ips(): 
					if floating_ip.node_id == node.id:
						# remove it from the node
						node.driver.ex_detach_floating_ip_from_node(node, floating_ip)
						# delete the ip
						floating_ip.delete()
		except Exception:
			self.logger.exception("Error removing Elastic/Floating IPs to VM ID: " + str(vm.id))
		
	def start(self, vm, auth_data):
		node = self.get_node_with_id(vm.id, auth_data)
		if node:
			func = getattr(node.driver, "ex_start_node",
			             getattr(node.driver, "ex_resume_node", None))
			if func:
				success = func(node)
				if success:
					return (True, "")
				else:
					return (False, "Error in start operations")
			else:
				return (False, "Not supported")
		else:
			return (False, "VM not found with id: " + vm.id)

	def stop(self, vm, auth_data):
		node = self.get_node_with_id(vm.id, auth_data)
		if node:
			func = getattr(node.driver, "ex_stop_node",
			             getattr(node.driver, "ex_suspend_node", None))
			if func:
				success = func(node)
				if success:
					return (True, "")
				else:
					return (False, "Error in stop operation")
			else:
				return (False, "Not supported")
		else:
			return (False, "VM not found with id: " + vm.id)

	def alterVM(self, vm, radl, auth_data):
		return (False, "Not supported")
	
	def wait_volume(self, volume, state = 'available', timeout=60):
		"""
		Wait a volume (with the state extra parameter) to be in certain state.

		Arguments:
		   - volume(:py:class:`libcloud.compute.base.StorageVolume`): volume object.
		   - state(str): State to wait for (default value 'available').	
		   - timeout(int): Max time to wait in seconds (default value 60).
		"""
		if 'state' in volume.extra:
			cont = 0
			while volume.extra['state'] != state and cont < timeout:
				cont += 2
				time.sleep(2)
				for vol in volume.driver.list_volumes():
					if vol.id == volume.id:
						volume = vol
						break
			return volume.extra['state'] == state

		return True
		
	def attach_volumes(self, vm, node):
		"""
		Attach a the required volumes (in the RADL) to the launched node

		Arguments:
		   - vm(:py:class:`IM.VirtualMachine`): VM information.	
		   - node(:py:class:`libcloud.compute.base.Node`): node object.
		"""
		try:
			if node.state == NodeState.RUNNING and not "volumes" in vm.__dict__.keys():
				vm.volumes = []
				cont = 1
				while vm.info.systems[0].getValue("disk." + str(cont) + ".size") and vm.info.systems[0].getValue("disk." + str(cont) + ".device"):
					disk_size = vm.info.systems[0].getFeature("disk." + str(cont) + ".size").getValue('G')
					disk_device = vm.info.systems[0].getValue("disk." + str(cont) + ".device")
					self.logger.debug("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
					volume_name = "im-%s" % time.time()
					location = self.get_node_location(node)
					volume = node.driver.create_volume(int(disk_size), volume_name, location = location)
					success = self.wait_volume(volume)
					if not success:
						self.logger.error("Error waiting the volume ID " + str(volume.id))
					vm.volumes.append(volume)					
					self.logger.debug("Attach the volume ID " + str(volume.id))
					volume.attach(node, "/dev/" + disk_device)
					cont += 1
			return True
		except Exception:
			self.logger.exception("Error creating or attaching the volume to the node")
			return False

	def get_node_location(self, node):
		"""
		Get the location of a node
		Currently only works in EC2

		Arguments:
		   - node(:py:class:`libcloud.compute.base.Node`): node object.	
		Returns: a :py:class:`libcloud.compute.base.NodeLocation`
		"""
		if 'availability' in node.extra: 
			for location in node.driver.list_locations():
				if location.name == node.extra['availability']:
					return location
		return None 
			

	def delete_volumes(self, vm, timeout = 300):
		"""
		Delete the volumes of a VM

		Arguments:
		   - vm(:py:class:`IM.VirtualMachine`): VM information.	
		   - timeout(int): Time needed to delete the volume.	
		"""
		all_ok = True
		if "volumes" in vm.__dict__.keys() and vm.volumes:
			for volume in vm.volumes:
				try:
					success = self.wait_volume(volume, timeout = timeout)
					if not success:
						self.logger.error("Error waiting the volume ID " + str(volume.id))
					success = volume.destroy()
					if not success:
						self.logger.error("Error destroying the volume: " + str(volume.id))
				except:
					self.logger.exception("Error destroying the volume: " + str(volume.id) + " from the node: " + vm.id)
					success = False

				if not success:
					all_ok = False
		return all_ok
			
	@staticmethod
	def addressInNetwork(ip,net):
			"""Is an address in a network (format: 10.0.0.0/24)"""
			ipaddr = struct.unpack('>L',socket.inet_aton(ip))[0]
			netaddr,bits = net.split('/')
			netmask = struct.unpack('>L',socket.inet_aton(netaddr))[0]
			ipaddr_masked = ipaddr & (4294967295<<(32-int(bits)))   # Logical AND of IP address and mask will equal the network address if it matches
			if netmask == netmask & (4294967295<<(32-int(bits))):   # Validate network address is valid for mask
				return ipaddr_masked == netmask
			else:
				# print "***WARNING*** Network",netaddr,"not valid with mask /"+bits
				return False