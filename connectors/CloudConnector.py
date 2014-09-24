import logging

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
