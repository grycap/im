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
from connectors.LibCloud import LibCloudCloudConnector
from libcloud.compute.types import Provider, NodeState
from libcloud.compute.providers import get_driver
from libcloud.compute.base import NodeImage, NodeAuthSSHKey
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine

from IM.radl.radl import Feature

class OpenStackCloudConnector(LibCloudCloudConnector):
	"""
	Cloud Launcher to OpenStack using LibCloud (Needs version 0.16.0 or higher version)
	"""
	
	type = "OpenStack"
	"""str with the name of the provider."""

	def get_driver(self, auth_data):
		"""
		Get the driver from the auth data

		Arguments:
			- auth(Authentication): parsed authentication tokens.
		
		Returns: a :py:class:`libcloud.compute.base.NodeDriver` or None in case of error
		"""
		if self.driver:
			return self.driver
		else:
			auths = auth_data.getAuthInfo(self.type, self.cloud.server)
			if not auths:
				raise Exception("No correct auth data has been specified to OpenStack.")
			else:
				auth = auths[0]

			if 'username' in auth and 'password' in auth and 'tenant' in auth:			
				parameters = {"auth_version":'2.0_password',
							  "auth_url":"http://" + self.cloud.server + ":" + str(self.cloud.port),
							  "auth_token":None,
							  "service_type":None,
							  "service_name":None,
							  "service_region":'RegionOne',
							  "base_url":None}
				
				for param in parameters:
					if param in auth:
						parameters[param] = auth[param]
			else:
				self.logger.error("No correct auth data has been specified to OpenStack: username, password and tenant")
				raise Exception("No correct auth data has been specified to OpenStack: username, password and tenant")
			
			cls = get_driver(Provider.OPENSTACK)
			driver = cls(auth['username'], auth['password'],
						 ex_tenant_name=auth['tenant'], 
						 ex_force_auth_url=parameters["auth_url"],
						 ex_force_auth_version=parameters["auth_version"],
						 ex_force_service_region=parameters["service_region"],
						 ex_force_base_url=parameters["base_url"],
						 ex_force_service_name=parameters["service_name"],
						 ex_force_service_type=parameters["service_type"],
						 ex_force_auth_token=parameters["auth_token"])
			
			self.driver = driver
			return driver
	
	def concreteSystem(self, radl_system, auth_data):
		image_urls = radl_system.getValue("disk.0.image.url")
		if not image_urls:
			return [radl_system.clone()]
		else:
			if not isinstance(image_urls, list):
				image_urls = [image_urls]
		
			res = []
			for str_url in image_urls:
				url = uriparse(str_url)
				protocol = url[0]

				src_host = url[1].split(':')[0]
				# TODO: check the port
				if protocol == "ost" and self.cloud.server == src_host:
					driver = self.get_driver(auth_data)
					
					res_system = radl_system.clone()
					instance_type = self.get_instance_type(driver.list_sizes(), res_system)
					self.update_system_info_from_instance(res_system, instance_type)
					
					res_system.addFeature(Feature("disk.0.image.url", "=", str_url), conflict="other", missing="other")
					
					res_system.addFeature(Feature("provider.type", "=", self.type), conflict="other", missing="other")
					res_system.addFeature(Feature("provider.host", "=", self.cloud.server), conflict="other", missing="other")
					res_system.addFeature(Feature("provider.port", "=", self.cloud.port), conflict="other", missing="other")				
						
					res.append(res_system)
				
			return res

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
			elif node.state == NodeState.ERROR:
				res_state = VirtualMachine.FAILED
			else:
				res_state = VirtualMachine.UNKNOWN
				
			vm.state = res_state
			
			flavorId = node.extra['flavorId']
			instance_type = node.driver.ex_get_size(flavorId)
			self.update_system_info_from_instance(vm.info.systems[0], instance_type)
			
			self.setIPsFromInstance(vm,node)
			self.attach_volumes(vm,node)
		else:
			vm.state = VirtualMachine.OFF
		
		return (True, vm)

	def update_system_info_from_instance(self, system, instance_type):
		"""
		Update the features of the system with the information of the instance_type
		"""
		if instance_type:
			LibCloudCloudConnector.update_system_info_from_instance(self, system, instance_type)
			if instance_type.vcpus:
				system.addFeature(Feature("cpu.count", "=", instance_type.vcpus), conflict="me", missing="other")

	def get_networks(self, driver, radl):
		"""
		Get the list of networks to connect the VM 
		"""
		nets = []
		ost_nets = driver.ex_list_networks()
		used_nets = []
		# I use this "patch" as used in the LibCloud OpenStack driver
		public_networks_labels = ['public', 'internet', 'publica']

		for radl_net in radl.networks:
			# check if this net is connected with the current VM
			if radl.systems[0].getNumNetworkWithConnection(radl_net.id) is not None:
				# First check if the user has specified a provider ID
				net_provider_id = radl_net.getValue('provider_id')
				if net_provider_id:
					for net in ost_nets:
						if net.name == net_provider_id:
							nets.append(net)
							used_nets.append(net.name)
							break
				else:
					# if not select the first not used net
					for net in ost_nets:
						# I use this "patch" as used in the LibCloud OpenStack driver
						if net.name not in public_networks_labels:
							if net.name not in used_nets:
								nets.append(net)
								used_nets.append(net.name)
								break

		return nets

	def get_cloud_init_data(self, radl):
		"""
		Get the cloud init data specified by the user in the RADL
		"""
		configure_name = None
		if radl.contextualize.items:
			system_name = radl.systems[0].name
			
			for item in radl.contextualize.items.values():
				if item.system == system_name and item.get_ctxt_tool() == "cloud_init":
					configure_name = item.configure 
		
		if configure_name:
			return radl.get_configure_by_name(configure_name).recipes
		else:
			return None

	def launch(self, inf, radl, requested_radl, num_vm, auth_data):
		driver = self.get_driver(auth_data)

		system = radl.systems[0]
		image_id = self.get_image_id(system.getValue("disk.0.image.url"))
		image = NodeImage(id=image_id, name=None, driver=driver)

		instance_type = self.get_instance_type(driver.list_sizes(), system)
		
		name = system.getValue("instance_name")
		if not name:
			name = system.getValue("disk.0.image.name")
		if not name:
			name = "userimage"
		
		nets = self.get_networks(driver, radl)
		
		sgs = self.create_security_group(driver, inf, radl)
		
		args = {'size': instance_type,
				'image': image,
				'networks': nets,
				'ex_security_groups': sgs,
				'name': "%s-%s" % (name, int(time.time()*100))}
		
		cloud_init = self.get_cloud_init_data(radl)
		if cloud_init:
			args['ex_userdata'] = cloud_init  
		
		keypair = None
		public_key = system.getValue("disk.0.os.credentials.public_key")
		if public_key:
			keypair = driver.get_key_pair(public_key)
			if keypair:
				system.setUserKeyCredentials(system.getCredentials().username, None, keypair.private_key)
			else:
				if "ssh_key" in driver.features.get("create_node", []):
					args["auth"] = NodeAuthSSHKey(public_key)
				else:
					args["ex_keyname"] = keypair.name
		elif not system.getValue("disk.0.os.credentials.password"):
			keypair_name = "im-%d" % int(time.time()*100.0)
			keypair = driver.create_key_pair(keypair_name)
			system.setUserKeyCredentials(system.getCredentials().username, None, keypair.private_key)
			
			if keypair.public_key and "ssh_key" in driver.features.get("create_node", []):
				args["auth"] = NodeAuthSSHKey(keypair.public_key)
			else:
				args["ex_keyname"] = keypair_name

		res = []
		i = 0
		all_failed = True
		while i < num_vm:
			self.logger.debug("Creating node")

			node = driver.create_node(**args)
			
			if node:
				vm = VirtualMachine(inf, node.id, self.cloud, radl, requested_radl, self.cloud.getCloudConnector())
				vm.info.systems[0].setValue('instance_id', str(node.id))
				vm.info.systems[0].setValue('instance_name', str(node.name))
				# Add the keypair name to remove it later
				vm.keypair = keypair_name
				self.logger.debug("Node successfully created.")
				all_failed = False
				res.append((True, vm))
			else:
				res.append((False, "Error creating the node"))
			i += 1

		# if all the VMs have failed, remove the sg and keypair
		if all_failed:
			if public_key is None or len(public_key) == 0 or (len(public_key) >= 1 and public_key.find('-----BEGIN CERTIFICATE-----') != -1):
				# only delete in case of the user do not specify the keypair name
				driver.delete_key_pair(keypair)
			if sgs:
				driver.ex_delete_security_group(sgs[0])

		return res
	
	def get_ip_pool(self, driver, fixed_ip):
		"""
		Return the most suitable IP pool 
		"""
		pools = driver.ex_list_floating_ip_pools()
		
		if fixed_ip:
			for pool in pools:
				ips = pool.list_floating_ips()
				
				for ip in ips:
					if ip.ip_address == fixed_ip:
						return pool
	
		#otherwise return the first pool
		return pools[0]
	
	def add_elastic_ip(self, vm, node, fixed_ip = None):
		"""
		Add an elastic IP to an instance

		Arguments:
		   - vm(:py:class:`IM.VirtualMachine`): VM information.
		   - node(:py:class:`libcloud.compute.base.Node`): node object to attach the volumes.
		   - fixed_ip(str, optional): specifies a fixed IP to add to the instance.
		Returns: a :py:class:`OpenStack_1_1_FloatingIpAddress` added or None if some problem occur.	
		"""
		if vm.state == VirtualMachine.RUNNING:
			try:
				self.logger.debug("Add an Elastic/Floating IP")

				if node.driver.ex_list_floating_ip_pools():
					pool = self.get_ip_pool(node.driver, fixed_ip)
					if fixed_ip:
						floating_ip = node.driver.ex_get_floating_ip(fixed_ip)
					else:
						floating_ip = pool.create_floating_ip()
					node.driver.ex_attach_floating_ip_to_node(node, floating_ip)
					return floating_ip
				else:
					self.logger.error("Error adding a Floating IP: No pools available.")
					return None

			except Exception:
				self.logger.exception("Error adding an Elastic/Floating IP to VM ID: " + str(vm.id))
				return None
		else:
			self.logger.debug("The VM is not running, not adding an Elastic/Floating IP.")
			return None
		
	@staticmethod
	def _get_security_group(driver, sg_name):
		try:
			sg = None
			for elem in driver.ex_list_security_groups():
				if elem.name == sg_name:
					sg = elem
					break
			return sg
		except Exception:
			return None

	def create_security_group(self, driver, inf, radl):
		res = None
		try:
			sg_name = "im-" + str(inf.id)
			sg = self._get_security_group(driver, sg_name)

			if not sg: 
				self.logger.debug("Creating security group: " + sg_name)
				try:
					sg = driver.ex_create_security_group(sg_name, "Security group created by the IM")
				except Exception, crex:
					# First check if the SG does exist
					sg = self._get_security_group(driver, sg_name)
					if not sg:
						# if not raise the exception
						raise crex
					else:
						self.logger.debug("Security group: " + sg_name + " already created.")
			
			res = [sg]
			
			public_net = None
			for net in radl.networks:
				if net.isPublic():
					public_net = net

			if public_net:
				outports = public_net.getOutPorts()
				if outports:
					for remote_port,remote_protocol,local_port,local_protocol in outports:
						if local_port != 22 and local_port != 5099:						
							protocol = remote_protocol
							if remote_protocol != local_protocol:
								self.logger.warn("Different protocols used in outports ignoring local port protocol!")								

							driver.ex_create_security_group_rule(sg,protocol,remote_port, remote_port, '0.0.0.0/0')
			
			try:
				driver.ex_create_security_group_rule(sg,'tcp',22, 22, '0.0.0.0/0')
				driver.ex_create_security_group_rule(sg,'tcp',5099, 5099, '0.0.0.0/0')
				
				# open all the ports for the VMs in the security group
				driver.ex_create_security_group_rule(sg,'tcp',1, 65535, source_security_group=sg)
				driver.ex_create_security_group_rule(sg,'udp',1, 65535, source_security_group=sg)
			except Exception, addex:
				self.logger.warn("Exception adding SG rules. Probably the rules exists:" + str(addex))
				pass
			
		except Exception:
			self.logger.exception("Error Creating the Security group")
		
		return res
	
	
	def finalize(self, vm, auth_data):
		node = self.get_node_with_id(vm.id, auth_data)
		
		if node:
			sgs = node.driver.ex_get_node_security_groups(node)

			success = node.destroy()
			
			public_key = vm.getRequestedSystem().getValue('disk.0.os.credentials.public_key')
			if vm.keypair and public_key is None or len(public_key) == 0 or (len(public_key) >= 1 and public_key.find('-----BEGIN CERTIFICATE-----') != -1):
				# only delete in case of the user do not specify the keypair name
				keypair = node.driver.get_key_pair(vm.keypair)
				if keypair:
					node.driver.delete_key_pair(keypair)
			
			self.delete_elastic_ips(node, vm)
			
			# Delete the EBS volumes
			self.delete_volumes(vm)
			
			# Delete the SG if this is the last VM
			self.delete_security_group(node, sgs, vm.inf, vm.id)
			
			if not success:
				return (False, "Error destroying node: " + vm.id)

			self.logger.debug("VM " + str(vm.id) + " successfully destroyed")
		else:
			self.logger.warn("VM " + str(vm.id) + " not found.")
		
		return (True, "")
	
	def delete_security_group(self, node, sgs, inf, vm_id, timeout = 60):
		"""
		Delete the SG of this infrastructure if this is the last VM
		"""
		if sgs:
			# There will be only one
			sg = sgs[0]

			some_vm = False
			for vm in inf.get_vm_list():
				if vm.id != vm_id:
					some_vm = True
			
			if not some_vm:
				# wait it to terminate and then remove the SG
				cont = 0				
				deleted = False
				while not deleted and cont < timeout:
					time.sleep(5)
					cont += 5
					try:
						node.driver.ex_delete_security_group(sg)
						deleted = True
					except Exception, ex:
						# Check if it has been deleted yet
						sg = self._get_security_group(node.driver, sg.name)
						if not sg:
							self.logger.debug("Error deleting the SG. But it does not exist. Ignore. " + str(ex))
							deleted = True								
						else:
								self.logger.exception("Error deleting the SG.")
			else:
				# If there are more than 1, we skip this step
				self.logger.debug("There are active instances. Not removing the SG")
		else:
			self.logger.warn("No Security Group with name: " + sg.name)