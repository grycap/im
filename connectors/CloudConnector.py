import logging
import socket,struct,time
from IM.radl.radl import network

class CloudConnector:
	"""
	Base class to all the Cloud connectors

	Arguments:
		- cloud_info(:py:class:`IM.CloudInfo`): Data about the Cloud Provider
	"""

	def __init__(self, cloud_info):
		self.cloud = cloud_info
		"""Data about the Cloud Provider."""
		self.logger = logging.getLogger('CloudConnector')
		"""Logger object."""

	def concreteSystem(self, radl_system, auth_data):
		"""
		Return a list of compatible systems with the cloud
	
		Arguments:

		   - radl_system(:py:class:`radl.system`): a system.
		   - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
				
		Returns(list of system): list of compatible systems.
		"""

		return [radl_system.clone()]

	def updateVMInfo(self, vm, auth_data):
		"""
		Updates the information of a VM
	
		Arguments:
		   - vm(:py:class:`IM.VirtualMachine`): VM information to update.
		   - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
				
		Returns: a tuple (success, vm).
		   - The first value is True if the operation finished successfully or false otherwise.
		   - The second value is a :py:class:`IM.VirtualMachine` with the updated information if the operation finished successfully or a str with an error message otherwise.
		"""

		raise NotImplementedError( "Should have implemented this" )
		
	def alterVM(self, vm, radl, auth_data):
		"""
		Modifies the features of a VM
		
		Arguments:
			- vm(:py:class:`IM.VirtualMachine`): VM to modify.
			- radl(str): RADL document with the VM features to modify.
			- auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
			
		Returns: a tuple (success, vm).
			- The first value is True if the operation finished successfully or false otherwise.
			- The second value is a :py:class:`IM.VirtualMachine` with the modified information if the operation finished successfully or a str with an error message otherwise.
		"""

		raise NotImplementedError( "Should have implemented this" )

	def launch(self, inf, vm_id, radl, requested_radl, num_vm, system_id, auth_data):
		"""
		Launch a set of VMs to the Cloud provider
		
		Args:

		- inf(InfrastructureInfo): InfrastructureInfo object the VM is part of.
		- vm_id(str): ID of the VM inside the IM.
		- radl(RADL): RADL document.
		- num_vm(int): number of instances to deploy.
		- system_id(str): system id to deploy
		- auth_data(Authentication): Authentication data to access cloud provider.
			
			Returns: a list of tuples with the format (success, vm).
		   - The first value is True if the operation finished successfully or false otherwise.
		   - The second value is a :py:class:`IM.VirtualMachine` of the launched VMs if the operation finished successfully or a str with an error message otherwise.
		"""

		raise NotImplementedError( "Should have implemented this" )

	def finalize(self, vm, auth_data):
		""" Terminates a VM
		
			Arguments:
			- vm(:py:class:`IM.VirtualMachine`): VM to terminate.
			- auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
			
			Returns: a tuple (success, vm).
		   - The first value is True if the operation finished successfully or false otherwise.
		   - The second value is a str with the ID of the removed VM if the operation finished successfully or an error message otherwise.
		"""

		raise NotImplementedError( "Should have implemented this" )
		
	def start(self, vm, auth_data):
		""" Starts a (previously stopped) VM
		
			Arguments:
			- vm(:py:class:`IM.VirtualMachine`): VM to start.
			- auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
			
			Returns: a tuple (success, vm).
		   - The first value is True if the operation finished successfully or false otherwise.
		   - The second value is a str with the ID of the started VM if the operation finished successfully or an error message otherwise.
		"""

		raise NotImplementedError( "Should have implemented this" )
		
	def stop(self, vm, auth_data):
		""" Stops (but not finalizes) a VM
		
			Arguments:
			- vm(:py:class:`IM.VirtualMachine`): VM to stop.
			- auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
			
			Returns: a tuple (success, vm).
		   - The first value is True if the operation finished successfully or false otherwise.
		   - The second value is a str with the ID of the stopped VM if the operation finished successfully or an error message otherwise.

		"""

		raise NotImplementedError( "Should have implemented this" )

	@staticmethod
	def isPrivate(ip):
		private_net_masks = ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","169.254.0.0/16"]
		for mask in private_net_masks: 
			if CloudConnector.addressInNetwork(ip,mask):
				return True
		return False

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
		
	@staticmethod
	def setIpsToVM(vm,public_ips,private_ips):
		now = str(int(time.time()*100))
		vm_system = vm.info.systems[0]

		if public_ips and not set(public_ips).issubset(set(private_ips)):
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

			for public_ip in public_ips:
				if public_ip not in private_ips:
					vm_system.setValue('net_interface.' + str(num_net) + '.ip', str(public_ip))
					vm_system.setValue('net_interface.' + str(num_net) + '.connection',public_net.id)

		if private_ips:
			private_net_masks = ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","169.254.0.0/16"]
			private_net_map = {}
			
			for private_ip in private_ips:
				private_net_mask = None

				# Get the private network mask
				for mask in private_net_masks:
					if CloudConnector.addressInNetwork(private_ip,mask):
						private_net_mask = mask
						break
				
				# Search in previous user private ips
				private_net = None
				for net_mask, net in private_net_map.iteritems():
					if CloudConnector.addressInNetwork(private_ip, net_mask): 	
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