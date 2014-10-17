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
import base64
from IM.uriparse import uriparse
import boto.ec2
import os
from IM.VirtualMachine import VirtualMachine
from CloudConnector import CloudConnector
from IM.radl.radl import network, Feature

class InstanceTypeInfo:
	"""
	Information about the instance type

	Args:
		- name(str, optional): name of the type of the instance
		- cpu_arch(list of str, optional): cpu architectures supported
		- num_cpu(int, optional): number of cpus
		- cores_per_cpu(int, optional): number of cores per cpu
		- mem(int, optional): amount of memory
		- price(int, optional): price per hour
		- cpu_perf(int, optional): performance of the type in ECUs
		- disks(int, optional): number of disks
		- disk_space(int, optional): size of the disks
	"""
	def __init__(self, name = "", cpu_arch = ["i386"], num_cpu = 1, cores_per_cpu = 1, mem = 0, price = 0, cpu_perf = 0, disks = 0, disk_space = 0):
		self.name = name
		self.num_cpu = num_cpu
		self.cores_per_cpu = cores_per_cpu
		self.mem = mem
		self.cpu_arch = cpu_arch
		self.price = price
		self.cpu_perf = cpu_perf
		self.disks = disks
		self.disk_space = disk_space

class EC2CloudConnector(CloudConnector):
	"""
	Cloud Launcher to the EC2 platform
	"""

	type = "EC2"
	"""str with the name of the provider."""
	KEYPAIR_DIR = '/tmp'
	"""str with a path to store the keypair files."""
	INSTANCE_TYPE = 't1.micro'
	"""str with the name of the default instance type to launch."""


	def concreteSystem(self, radl_system, auth_data):
		if radl_system.getValue("disk.0.image.url"):
			url = uriparse(radl_system.getValue("disk.0.image.url"))
			protocol = url[0]
			if protocol == "aws":
				# Currently EC2 plugin only uses private_key credentials
				res_system = radl_system.clone()
				if res_system.getValue('disk.0.os.credentials.private_key'):
					res_system.delValue('disk.0.os.credentials.password')
				
				instance_type = self.get_instance_type(res_system)
				if not instance_type:
					self.logger.error("Error launching the VM, no instance type available for the requirements.")
					self.logger.debug(res_system)
					return []
				else:
					res_system.addFeature(Feature("cpu.count", "=", instance_type.num_cpu * instance_type.cores_per_cpu), conflict="other", missing="other")
					res_system.addFeature(Feature("memory.size", "=", instance_type.mem, 'M'), conflict="other", missing="other")
					if instance_type.disks > 0:
						res_system.addFeature(Feature("disks.free_size", "=", instance_type.disks * instance_type.disk_space, 'G'), conflict="other", missing="other")
						for i in range(1,instance_type.disks+1):
							res_system.addFeature(Feature("disk.%d.free_size" % i, "=", instance_type.disk_space, 'G'), conflict="other", missing="other")						
					res_system.addFeature(Feature("cpu.performance", "=", instance_type.cpu_perf, 'ECU'), conflict="other", missing="other")
					res_system.addFeature(Feature("price", "=", instance_type.price), conflict="me", missing="other")
					
					res_system.addFeature(Feature("instance_type", "=", instance_type.name), conflict="other", missing="other")
					
					res_system.addFeature(Feature("provider.type", "=", self.type), conflict="other", missing="other")
						
					return [res_system]
			else:
				return []
		else:
			return [radl_system.clone()]

	# Set the EC2 credentials
	def set_ec2_credentials(self, key_id, access_key):
		"""
		Set the EC2 credentials as environment values

		Arguments:
		   - key_id(str): AWS_ACCESS_KEY_ID value.
		   - access_key(str): AWS_SECRET_ACCESS_KEY value.
		"""
		os.environ['AWS_ACCESS_KEY_ID'] = key_id
		os.environ['AWS_SECRET_ACCESS_KEY'] = access_key

	# Get the EC2 connection object
	def get_connection(self, region_name, auth_data):
		"""
		Get a :py:class:`boto.ec2.connection` to interact with.

		Arguments:
		   - region_name(str): EC2 region to connect.
		   - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
		Returns: a :py:class:`boto.ec2.connection` or None in case of error		
		"""
		conn = None
		try:
			auth = auth_data.getAuthInfo(EC2CloudConnector.type)
			if auth and 'username' in auth[0] and 'password' in auth[0]:
				self.set_ec2_credentials(auth[0]['username'], auth[0]['password'])
			else:
				self.logger.error("Incorrect auth data")
				return None

			region = None
			regions = boto.ec2.regions()

			for r in regions:
				if r.name == region_name:
					region = r
			if region != None:
				conn = region.connect()
		except Exception, e:
			self.logger.error("Error getting the region " + region_name + ": ")
			self.logger.error(e)
			return None
	
		return conn
	
	# el path sera algo asi: aws://eu-west-1/ami-00685b74
	def getAMIData(self, path):
		"""
		Get the region and the AMI ID from an URL of a VMI

		Arguments:
		   - path(str): URL of a VMI (some like this: aws://eu-west-1/ami-00685b74)
		Returns: a tuple (region, ami) with the region and the AMI ID	
		"""
		region = uriparse(path)[1]
		ami = uriparse(path)[2][1:]
		
		return (region, ami)
	
	def get_instance_type(self, radl):
		"""
		Get the name of the instance type to launch to EC2

		Arguments:
		   - radl(str): RADL document with the requirements of the VM to get the instance type
		Returns: a str with the name of the instance type to launch to EC2	
		"""
		instance_type_name = radl.getValue('instance_type')
		
		cpu = radl.getValue('cpu.count')
		cpu_op = radl.getFeature('cpu.count').getLogOperator()
		arch = radl.getValue('cpu.arch')
		memory = radl.getFeature('memory.size').getValue('M')
		memory_op = radl.getFeature('memory.size').getLogOperator()
		disk_free = 0
		disk_free_op = ">="
		if radl.getValue('disks.free_size'):
			disk_free = radl.getFeature('disks.free_size').getValue('G')
			disk_free_op = radl.getFeature('memory.size').getLogOperator()
		
		performance = 0
		performance_op = ">="
		if radl.getValue("cpu.performance"):
			cpu_perf = radl.getFeature("cpu.performance")
			# Assume that GCEU = ECU
			if cpu_perf.unit == "ECU" or cpu_perf.unidad == "GCEU":
				performance = float(cpu_perf.value)
				performance_op = cpu_perf.getLogOperator()
			else:
				self.logger.debug("Performance unit unknown: " + cpu_perf.unit + ". Ignore it")
		
		instace_types = self.get_all_instance_types()

		res = None
		for instace_type in instace_types:
			# get the instance type with the lowest price
			if res is None or (instace_type.price <= res.price):
				str_compare = "arch in instace_type.cpu_arch "
				str_compare += " and instace_type.cores_per_cpu * instace_type.num_cpu " + cpu_op + " cpu "
				str_compare += " and instace_type.mem " + memory_op + " memory "
				str_compare += " and instace_type.cpu_perf " + performance_op + " performance"
				str_compare += " and instace_type.disks * instace_type.disk_space " + disk_free_op + " disk_free"
				
				#if arch in instace_type.cpu_arch and instace_type.cores_per_cpu * instace_type.num_cpu >= cpu and instace_type.mem >= memory and instace_type.cpu_perf >= performance and instace_type.disks * instace_type.disk_space >= disk_free:
				if eval(str_compare):
					if not instance_type_name or instace_type.name == instance_type_name:
						res = instace_type
		
		if res is None:
			self.get_instance_type_by_name(self.INSTANCE_TYPE)
		else:
			return res

	def create_security_group(self, conn, inf, radl):
		res = "default"
		try:
			sg = None

			sg_name = "im-" + str(inf.uuid)
			for elem in conn.get_all_security_groups():
				if elem.name == sg_name:
					sg = elem
					break
			if not sg: 
				self.logger.debug("Creating security group: " + sg_name)
				sg = conn.create_security_group(sg_name, "Security group created by the IM")
			
			res = sg_name
			
			public_net = None
			for net in radl.networks:
				if net.isPublic():
					public_net = net

			if public_net:
				outports = public_net.getOutPorts()
				if outports:
					for remote_port,remote_protocol,local_port,local_protocol in outports:
						if local_port != "22" and local_port != "5099":						
							protocol = remote_protocol
							if remote_protocol != local_protocol:
								self.logger.warn("Diferent protocols used in outports ignoring local port protocol!")								
													
							sg.authorize(protocol, remote_port, local_port, '0.0.0.0/0')
			
			sg.authorize('tcp', 22, 22, '0.0.0.0/0')
			sg.authorize('tcp', 5099, 5099, '0.0.0.0/0')
			
		except Exception, ex:
			self.logger.exception("Error Creating the Security group")
			pass
		
		return res

	def launch(self, inf, vm_id, radl, requested_radl, num_vm, auth_data):
		
		system = radl.systems[0]
		
		# Currently EC2 plugin uses first private_key credentials
		if system.getValue('disk.0.os.credentials.private_key'):
			system.delValue('disk.0.os.credentials.password')
		
		(region_name, ami) = self.getAMIData(system.getValue("disk.0.image.url"))
		
		self.logger.debug("Connecting with the region: " + region_name)
		conn = self.get_connection(region_name, auth_data)
		
		res = []
		if not conn:
			for i in range(num_vm):
				res.append((False, "Error connecting with EC2, check the credentials"))
			return res
		
		images = conn.get_all_images([ami])

		sg_name = self.create_security_group(conn, inf, radl)
		
		if len(images) == 1:
			keypair_name = "im-" + str(int(time.time()*100))
			# create the keypair
			private = system.getValue('disk.0.os.credentials.private_key')
			public = system.getValue('disk.0.os.credentials.public_key')
			if private and public:
				if public.find('-----BEGIN CERTIFICATE-----') != -1:
					self.logger.debug("The RADL specifies the PK, upload it to EC2")
					public_key = base64.b64encode(public)
					conn.import_key_pair(keypair_name, public_key)
				else:
					# the public_key nodes specifies the keypair name
					keypair_name = public
				# Update the credential data
				system.setUserKeyCredentials(system.getCredentials().username, public, private)
			else:
				self.logger.debug("Creating the Keypair")
				keypair_file = self.KEYPAIR_DIR + '/' + keypair_name + '.pem'
				keypair = conn.create_key_pair(keypair_name)
				keypair.save(self.KEYPAIR_DIR)
				os.chmod(keypair_file, 0400)
				fkeypair = open(keypair_file, "r")
				system.setUserKeyCredentials(system.getCredentials().username, None, fkeypair.read())
				fkeypair.close()
				os.unlink(keypair_file)
			i = 0
			while i < num_vm:
				spot = False
				if system.getValue("spot") == "yes":
					spot = True

				if spot:
					self.logger.debug("Launching a spot instance")
					instance_type = self.get_instance_type(system)
					if not instance_type:
						self.logger.error("Error launching the VM, no instance type available for the requirements.")
						self.logger.debug(system)
						res.append((False, "Error launching the VM, no instance type available for the requirements."))
						
					#TODO: Amanda -> Mirar el boto EC2 y completar el tema de las spot
					price = system.getValue("price")
					#Realizamos el request de spot instances
					if system.getValue("disk.0.os.name"):
						operative_system = system.getValue("disk.0.os.name")
						if operative_system == "linux":
							operative_system = 'Linux/UNIX'
							#TODO: diferenciar entre cuando sea 'Linux/UNIX', 'SUSE Linux' o 'Windows' teniendo en cuenta tambien el atributo "flavour" del RADL
					else:
						res.append((False, "Error launching the image: spot instances need the OS defined in the RADL"))
						#operative_system = 'Linux/UNIX'
					
					availability_zone = 'us-east-1c'
					if system.getValue('availability_zone'):
						availability_zone = system.getValue('availability_zone')
					historical_price = 1000.0
					availability_zone_list = conn.get_all_zones()
					for zone in availability_zone_list:
						history = conn.get_spot_price_history(instance_type=instance_type.name, product_description=operative_system, availability_zone=zone.name, max_results=1)
						self.logger.debug("Spot price history for the region " + zone.name)
						self.logger.debug(history)
						if history:
							if (history[0].price < historical_price):
								historical_price = history[0].price
								availability_zone = zone.name
					self.logger.debug("Launching the spot request in the zone " + availability_zone)
					
					request = conn.request_spot_instances(price=price, image_id=images[0].id, count=1, type='one-time', instance_type=instance_type.name, placement=availability_zone, key_name=keypair_name, security_groups=[sg_name])
					
					if request:
						ec2_vm_id = region_name + ";" + request[0].id
						
						self.logger.debug("RADL:")
						self.logger.debug(system)
					
						vm = VirtualMachine(inf, vm_id, ec2_vm_id, self.cloud, radl, requested_radl)
						# Add the keypair name to remove it later 
						vm.keypair_name = keypair_name
						self.logger.debug("Instance successfully launched.")
						res.append((True, vm))
					else: 
						res.append((False, "Error launching the image"))
						
				else:
					self.logger.debug("Launching ondemand instance")
					instance_type = self.get_instance_type(system)
					if not instance_type:
						self.logger.error("Error launching the VM, no instance type available for the requirements.")
						self.logger.debug(system)
						res.append((False, "Error launching the VM, no instance type available for the requirements."))

					placement = system.getValue('availability_zone')
					reservation = images[0].run(min_count=1,max_count=1,key_name=keypair_name,instance_type=instance_type.name,security_groups=[sg_name],placement=placement)

					if len(reservation.instances) == 1:
						instance = reservation.instances[0]
						ec2_vm_id = region_name + ";" + instance.id
							
						self.logger.debug("RADL:")
						self.logger.debug(system)
						
						vm = VirtualMachine(inf, vm_id, ec2_vm_id, self.cloud, radl, requested_radl)
						# Add the keypair name to remove it later 
						vm.keypair_name = keypair_name
						self.logger.debug("Instance successfully launched.")
						res.append((True, vm))
					else:
						res.append((False, "Error launching the image"))
					
				i += 1
			
		return res

	def create_volume(self, conn, disk_size, placement, timeout = 60):
		"""
		Create an EBS volume

		Arguments:
		   - conn(:py:class:`boto.ec2.connection`): object to connect to EC2 API.
		   - disk_size(:py:class:`boto.ec2.connection`): The size of the new volume, in GiB
		   - placement(str): The availability zone in which the Volume will be created.
		   - timeout(int): Time needed to create the volume.
		Returns: a :py:class:`boto.ec2.volume.Volume` of the new volume	
		"""
		volume = conn.create_volume(disk_size, placement)
		cont = 0
		while str(volume.status) != 'available' and cont < timeout:
			self.logger.debug("State: " + str(volume.status))
			cont += 2
			time.sleep(2)
			volume = conn.get_all_volumes([volume.id])[0]
		return volume

	def attach_volumes(self, instance, vm):
		"""
		Attach a the required volumes (in the RADL) to the launched instance

		Arguments:
		   - instance(:py:class:`boto.ec2.instance`): object to connect to EC2 instance.
		   - vm(:py:class:`IM.VirtualMachine`): VM information.	
		"""
		try:
			if instance.state == 'running' and not "volumes" in vm.__dict__.keys():
				conn = instance.connection
				vm.volumes = []
				cont = 1
				while vm.info.systems[0].getValue("disk." + str(cont) + ".size") and vm.info.systems[0].getValue("disk." + str(cont) + ".device"):
					disk_size = vm.info.systems[0].getFeature("disk." + str(cont) + ".size").getValue('G')
					disk_device = vm.info.systems[0].getValue("disk." + str(cont) + ".device")
					self.logger.debug("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
					volume = self.create_volume(conn, int(disk_size), instance.placement)
					vm.volumes.append(volume.id)
					self.logger.debug("Attach the volume ID " + str(volume.id))
					conn.attach_volume(volume.id, instance.id, "/dev/" + disk_device)
					cont += 1
		except Exception, ex:
			self.logger.error("Error creating or attaching the volume to the instance")
			self.logger.error(ex)
			
	def delete_volumes(self, conn, vm, timeout = 240):
		"""
		Delete the volumes of a VM

		Arguments:
		   - conn(:py:class:`boto.ec2.connection`): object to connect to EC2 API.
		   - vm(:py:class:`IM.VirtualMachine`): VM information.	
		   - timeout(int): Time needed to delete the volume.	
		"""
		if "volumes" in vm.__dict__.keys() and vm.volumes:
			instance_id = vm.id.split(";")[1]
			for volume_id in vm.volumes:
				cont = 0
				deleted = False
				while not deleted and cont < timeout:
					cont += 5
					try:
						curr_vol = conn.get_all_volumes([volume_id])[0]
						if str(curr_vol.attachment_state()) == "attached":
							self.logger.debug("Detaching the volume " + volume_id + " from the instance " + instance_id)
							conn.detach_volume(volume_id, instance_id, force=True)
						elif curr_vol.attachment_state() is None:
							self.logger.debug("Removing the volume " + volume_id)
							conn.delete_volume(volume_id)
							deleted = True
						else:
							self.logger.debug("State: " + str(curr_vol.attachment_state()))
					except Exception:
						self.logger.exception("Error removing the volume.")

					time.sleep(5)
				
				if not deleted:	
					self.logger.error("Error removing the volume " + volume_id)

	# Get the EC2 instance object with the specified ID
	def get_instance_by_id(self, instance_id, region_name, auth_data):
		"""
		Get the EC2 instance object with the specified ID

		Arguments:
		   - id(str): ID of the EC2 instance.
		   - region_name(str): Region name to search the instance.
		   - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
		Returns: a :py:class:`boto.ec2.instance` of found instance or None if it was not found	
		"""
		instance = None
		
		try:
			conn = self.get_connection(region_name, auth_data)
	
			reservations = conn.get_all_instances([instance_id])
			instance = reservations[0].instances[0]
		except:
			pass
			
		return instance

	def add_elastic_ip(self, vm, instance, fixed_ip = None):
		"""
		Add an elastic IP to an instance

		Arguments:
		   - vm(:py:class:`IM.VirtualMachine`): VM information.
		   - instance(:py:class:`boto.ec2.instance`): object to connect to EC2 instance.
		   - fixed_ip(str, optional): specifies a fixed IP to add to the instance.
		Returns: a :py:class:`boto.ec2.address.Address` added or None if some problem occur.	
		"""
		if vm.state == VirtualMachine.RUNNING:
			try:
				pub_address = None
				self.logger.debug("Add an Elastic IP")
				if fixed_ip:
					for address in instance.connection.get_all_addresses():
						if str(address.public_ip) == fixed_ip:
							pub_address = address

					if pub_address:
						self.logger.debug("Setting a fixed allocated IP: " + fixed_ip)
					else:
						self.logger.warn("Setting a fixed IP NOT ALLOCATED! (" + fixed_ip + "). Ignore it.")
						return None
				else:
					pub_address = instance.connection.allocate_address()

				self.logger.debug(pub_address)
				pub_address.associate(instance.id)
				return pub_address
			except Exception:
				self.logger.exception("Error adding an Elastic IP to VM ID: " + str(vm.id))
				if pub_address:
					self.logger.exception("The Elastic IP was allocated, release it.")
					pub_address.release()
				return None
		else:
			self.logger.debug("The VM is not running, not adding an Elastic IP.")
			return None

	def delete_elastic_ips(self, conn, vm):
		"""
		remove the elastic IPs of a VM

		Arguments:
		   - conn(:py:class:`boto.ec2.connection`): object to connect to EC2 API.
		   - vm(:py:class:`IM.VirtualMachine`): VM information.	
		"""
		try:
			instance_id = vm.id.split(";")[1]
			# Get the elastic IPs
			for address in conn.get_all_addresses():
				if address.instance_id == instance_id:
					self.logger.debug("This VM has a Elastic IP, disassociate it")
					address.disassociate()

					n = 0
					found = False
					while vm.getRequestedSystem().getValue("net_interface." + str(n) + ".connection"):
						net_conn = vm.getRequestedSystem().getValue('net_interface.' + str(n) + '.connection')
						if vm.info.get_network_by_id(net_conn).isPublic():
							if vm.getRequestedSystem().getValue("net_interface." + str(n) + ".ip"):
								fixed_ip = vm.getRequestedSystem().getValue("net_interface." + str(n) + ".ip")
								# If it is a fixed IP we must not release it
								if fixed_ip == str(address.public_ip):
									found = True
						n += 1

					if not found:
						self.logger.debug("Now release it")
						address.release()
					else:
						self.logger.debug("This is a fixed IP, it is not released")
		except Exception:
			self.logger.exception("Error deleting the Elastic IPs to VM ID: " + str(vm.id))

	def setIPsFromInstance(self, vm, instance):
		"""
		Adapt the RADL information of the VM to the real IPs assigned by EC2

		Arguments:
		   - vm(:py:class:`IM.VirtualMachine`): VM information.	
		   - instance(:py:class:`boto.ec2.instance`): object to connect to EC2 instance.
		"""
		
		vm_system = vm.info.systems[0]
		num_pub_nets = num_nets = 0
		public_ips = []
		private_ips = []
		if instance.ip_address != None and len(instance.ip_address) > 0 and instance.ip_address != instance.private_ip_address:
			public_ips = [instance.ip_address]
			num_nets += 1
			num_pub_nets = 1
		if instance.private_ip_address != None and len(instance.private_ip_address) > 0:
			private_ips = [instance.private_ip_address]
			num_nets += 1
		
		vm.setIps(public_ips, private_ips)

		for net in vm.info.networks:
			if net.isPublic():
				public_net = net

		elastic_ips = []
		# Get the elastic IPs assigned (there must be only 1)
		for address in instance.connection.get_all_addresses():
			if address.instance_id == instance.id:
				elastic_ips.append(str(address.public_ip))
				# It will be used if it is different to the public IP of the instance
				if str(address.public_ip) != instance.ip_address:
					vm_system.setValue('net_interface.' + str(num_nets) + '.ip', str(instance.ip_address))
					vm_system.setValue('net_interface.' + str(num_nets) + '.connection',public_net.id)

					num_pub_nets += 1
					num_nets += 1

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
				if ip not in elastic_ips:
					# It has not been created yet, do it
					self.add_elastic_ip(vm, instance, ip)
					# EC2 only supports 1 elastic IP per instance (without VPC), so break
					break
			else:
				# Check if we have enough public IPs
				if num >= num_pub_nets:
					self.add_elastic_ip(vm, instance)
					# EC2 only supports 1 elastic IP per instance (without VPC), so break
					break


	def updateVMInfo(self, vm, auth_data):
		region = vm.id.split(";")[0]
		instance_id = vm.id.split(";")[1]
		
		try:
			conn = self.get_connection(region, auth_data)
		except:
			pass

		# Check if the instance_id starts with "sir" -> spot request
		if (instance_id[0] == "s"):
			# Check if the request has been fulfilled and the instance has been deployed
			job_instance_id = None

			self.logger.debug("Check if the request has been fulfilled and the instance has been deployed")
			job_sir_id = instance_id 
			request_list = conn.get_all_spot_instance_requests()
			for sir in request_list:
				if sir.id == job_sir_id:
					job_instance_id = sir.instance_id
					break

			if job_instance_id:
				self.logger.debug("Request fulfilled, instance_id: " + str(job_instance_id))
				instance_id = job_instance_id
				vm.id = region + ";" + instance_id
			else:
				vm.state = VirtualMachine.PENDING
				return (True, vm)
		
		instance = self.get_instance_by_id(instance_id, region, auth_data)
		if (instance != None):
			instance.update()
			
			vm.info.systems[0].setValue("virtual_system_type", "'" + instance.virtualization_type + "'")
			vm.info.systems[0].setValue("availability_zone",  "'" + instance.placement + "'")
			
			if instance.state == 'pending':
				res_state = VirtualMachine.PENDING
			elif instance.state == 'running':
				res_state = VirtualMachine.RUNNING
			elif instance.state == 'stopped':
				res_state = VirtualMachine.STOPPED
			elif instance.state == 'stopping':
				res_state = VirtualMachine.RUNNING
			elif instance.state == 'shutting-down':
				res_state = VirtualMachine.OFF
			elif instance.state == 'terminated':
				res_state = VirtualMachine.OFF
			else:
				res_state = VirtualMachine.UNKNOWN
				
			vm.state = res_state
			
			self.setIPsFromInstance(vm, instance)
			self.attach_volumes(instance, vm)
			
			try:
				vm.info.systems[0].setValue('launch_time', int(time.mktime(time.strptime(instance.launch_time[:19],'%Y-%m-%dT%H:%M:%S'))))
			except:
				self.logger.exception("Error setting the launch_time of the instance")
			
		else:
			vm.state = VirtualMachine.OFF
		
		return (True, vm)

	def cancel_spot_requests(self, conn, vm):
		"""
		Cancel the spot requests of a VM

		Arguments:
		   - conn(:py:class:`boto.ec2.connection`): object to connect to EC2 API.
		   - vm(:py:class:`IM.VirtualMachine`): VM information.	
		"""
		try:
			instance_id = vm.id.split(";")[1]
			request_list = conn.get_all_spot_instance_requests()
			for sir in request_list:
				if sir.instance_id == instance_id:
					conn.cancel_spot_instance_requests(sir.id)
					self.logger.debug("Spot instance request " + str(sir.id) + " deleted")
					break
		except Exception:
			self.logger.exception("Error deleting the spot instance request")


	def finalize(self, vm, auth_data):
		region_name = vm.id.split(";")[0]
		instance_id = vm.id.split(";")[1]
		
		conn = self.get_connection(region_name, auth_data)
		
		# Terminate the instance
		instance = self.get_instance_by_id(instance_id, region_name, auth_data)
		if (instance != None):
			instance.update()
			instance.terminate()

		public_key = vm.getRequestedSystem().getValue('disk.0.os.credentials.public_key')
		if public_key is None or len(public_key) == 0 or (len(public_key) >= 1 and public_key.find('-----BEGIN CERTIFICATE-----') != -1):
			# only delete in case of the user do not specify the keypair name
			conn.delete_key_pair(vm.keypair_name)

		# Delete the elastic IPs
		self.delete_elastic_ips(conn, vm)
		
		# Delete the  spot instance requests
		self.cancel_spot_requests(conn, vm)
		
		# Delete the EBS volumes
		self.delete_volumes(conn, vm)
		
		# Delete the SG if this is the last VM
		self.delete_security_group(conn, vm)
		
		return (True, "")
	
	def delete_security_group(self, conn, vm, timeout = 90):
		"""
		Delete the SG of this infrastructure if this is the last VM

		Arguments:
		   - conn(:py:class:`boto.ec2.connection`): object to connect to EC2 API.
		   - vm(:py:class:`IM.VirtualMachine`): VM information.	
		"""
		sg_name = "im-" + str(id(vm.inf))
		sg = None
		for elem in conn.get_all_security_groups():
			if elem.name == sg_name:
				sg = elem
				break

		if sg:
			some_vm_running = False
			for instance in sg.instances():
				if instance.state == 'running':
					some_vm_running = True
			
			# Check that all there are only one active instance (this one)
			if not some_vm_running:
				# wait it to terminate and then remove the SG
				cont = 0
				all_vms_terminated = True
				for instance in sg.instances():
					while instance.state != 'terminated' and cont < timeout:
						time.sleep(5)
						cont += 5
						instance.update()

					if instance.state != 'terminated':
						all_vms_terminated = False
	
				if all_vms_terminated:
					self.logger.debug("Remove the SG: " + sg_name)
					sg.delete()
			else:
				# If there are more than 1, we skip this step
				self.logger.debug("There are active instances. Not removing the SG")
		
		
	def stop(self, vm, auth_data):
		region_name = vm.id.split(";")[0]
		instance_id = vm.id.split(";")[1]

		instance = self.get_instance_by_id(instance_id, region_name, auth_data)
		if (instance != None):
			instance.update()
			instance.stop()
		
		return (True, "")
		
	def start(self, vm, auth_data):
		region_name = vm.id.split(";")[0]
		instance_id = vm.id.split(";")[1]

		instance = self.get_instance_by_id(instance_id, region_name, auth_data)
		if (instance != None):
			instance.update()
			instance.start()
		
		return (True, "")
		
	def alterVM(self, vm, radl, auth_data):
		return (False, "Not supported")

	def get_all_instance_types(self):
		"""
		Get all the EC2 instance types
		
		Returns: a list of :py:class:`InstanceTypeInfo`
		"""
		# TODO: use some like Cloudymetrics or CloudHarmony	
		list = []
		
		t1_micro = InstanceTypeInfo("t1.micro", ["i386", "x86_64"], 1, 1, 613, 0.0031, 0.5)
		list.append(t1_micro)
		
		t2_micro = InstanceTypeInfo("t2.micro", ["i386", "x86_64"], 1, 1, 1024, 0.013, 0.5)
		list.append(t2_micro)
		t2_small = InstanceTypeInfo("t2.small", ["i386", "x86_64"], 1, 1, 2048, 0.026, 0.5)
		list.append(t2_small)
		t2_medium = InstanceTypeInfo("t2.medium", ["i386", "x86_64"], 2, 1, 4096, 0.052, 0.5)
		list.append(t2_medium)
		
		m1_small = InstanceTypeInfo("m1.small", ["i386", "x86_64"], 1, 1, 1740, 0.0071, 1, 1, 160)
		list.append(m1_small)
		m1_medium = InstanceTypeInfo("m1.medium", ["i386", "x86_64"], 1, 1, 3840, 0.0081, 2, 1, 410)
		list.append(m1_medium)
		m1_large = InstanceTypeInfo("m1.large", ["x86_64"], 1, 2, 7680, 0.0161, 4, 2, 420)
		list.append(m1_large)
		m1_xlarge = InstanceTypeInfo("m1.xlarge", ["x86_64"], 1, 4, 15360, 0.0321, 8, 4, 420)
		list.append(m1_xlarge)
		
		m2_xlarge = InstanceTypeInfo("m2.xlarge", ["x86_64"], 1, 2, 17510, 0.0161, 6.5, 1, 420)
		list.append(m2_xlarge)
		m2_2xlarge = InstanceTypeInfo("m2.2xlarge", ["x86_64"], 1, 4, 35020, 0.0321, 13, 1, 850)
		list.append(m2_2xlarge)
		m2_4xlarge = InstanceTypeInfo("m2.4xlarge", ["x86_64"], 1, 4, 70041, 0.075, 13, 2, 840)
		list.append(m2_4xlarge)
		
		m3_medium = InstanceTypeInfo("m3.medium", ["x86_64"], 1, 1, 3840, 0.07, 3, 1, 4)
		list.append(m3_medium)
		m3_large = InstanceTypeInfo("m3.large", ["x86_64"], 2, 1, 7680, 0.14, 6.5, 1, 4)
		list.append(m3_large)
		m3_xlarge = InstanceTypeInfo("m3.xlarge", ["x86_64"], 1, 8, 15360, 0.28, 13, 2, 40)
		list.append(m3_xlarge)
		m3_2xlarge = InstanceTypeInfo("m3.2xlarge", ["x86_64"], 1, 8, 30720, 0.56, 26, 2, 80)
		list.append(m3_2xlarge)
		
		c1_medium = InstanceTypeInfo("c1.medium", ["i386", "x86_64"], 1, 2, 1740, 0.0161, 5, 1, 350)
		list.append(c1_medium)
		c1_xlarge = InstanceTypeInfo("c1.xlarge", ["x86_64"], 1, 8, 7680, 0.0641, 20, 4, 420)
		list.append(c1_xlarge)
		
		cc2_8xlarge = InstanceTypeInfo("cc2.8xlarge", ["x86_64"], 2, 8, 61952, 0.2562, 88, 4, 840)
		list.append(cc2_8xlarge)
		
		cr1_8xlarge = InstanceTypeInfo("cr1.8xlarge", ["x86_64"], 2, 8, 249856, 0.3666, 88, 2, 120)
		list.append(cr1_8xlarge)
		
		c3_large = InstanceTypeInfo("c3.large", ["x86_64"], 2, 1, 3840, 0.105, 7, 2, 16)
		list.append(c3_large)
		c3_xlarge = InstanceTypeInfo("c3.xlarge", ["x86_64"], 4, 1, 7680, 0.21, 14, 2, 40)
		list.append(c3_xlarge)
		c3_2xlarge = InstanceTypeInfo("c3.2xlarge", ["x86_64"], 8, 1, 15360, 0.42, 28, 2, 80)
		list.append(c3_2xlarge)
		c3_4xlarge = InstanceTypeInfo("c3.4xlarge", ["x86_64"], 16, 1, 30720, 0.84, 55, 2, 160)
		list.append(c3_4xlarge)
		c3_8xlarge = InstanceTypeInfo("c3.8xlarge", ["x86_64"], 32, 1, 61952, 1.68, 108, 2, 320)
		list.append(c3_8xlarge)
		
		r3_large = InstanceTypeInfo("r3.large", ["x86_64"], 2, 1, 15360, 0.175, 6.5, 1, 32)
		list.append(r3_large)
		r3_xlarge = InstanceTypeInfo("r3.xlarge", ["x86_64"], 4, 1, 31232, 0.35, 13, 1, 80)
		list.append(r3_xlarge)
		r3_2xlarge = InstanceTypeInfo("r3.2xlarge", ["x86_64"], 8, 1, 62464, 0.7, 26, 1, 160)
		list.append(r3_2xlarge)
		r3_4xlarge = InstanceTypeInfo("r3.4xlarge", ["x86_64"], 16, 1, 124928, 1.4, 52, 1, 320)
		list.append(r3_4xlarge)
		r3_8xlarge = InstanceTypeInfo("r3.8xlarge", ["x86_64"], 32, 1, 249856, 2.8, 104, 2, 320)
		list.append(r3_8xlarge)
		
		i2_xlarge = InstanceTypeInfo("i2.xlarge", ["x86_64"], 4, 1, 31232, 0.853, 14, 1, 800)
		list.append(i2_xlarge)
		i2_2xlarge = InstanceTypeInfo("i2.2xlarge", ["x86_64"], 8, 1, 62464, 1.705, 27, 2, 800)
		list.append(i2_2xlarge)
		i2_4xlarge = InstanceTypeInfo("i2.4xlarge", ["x86_64"], 16, 1, 124928, 3.41, 53, 4, 800)
		list.append(i2_4xlarge)
		i2_8xlarge = InstanceTypeInfo("i2.8xlarge", ["x86_64"], 32, 1, 249856, 6.82, 104, 8, 800)
		list.append(i2_8xlarge)
		
		return list

	def get_instance_type_by_name(self, name):
		"""
		Get the EC2 instance type with the specified name
		
		Returns: an :py:class:`InstanceTypeInfo` or None if the type is not found
		"""
		for inst_type in self.get_all_instance_types():
			if inst_type.name == name:
				return inst_type
		return None
