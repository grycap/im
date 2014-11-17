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

import json
import socket
import httplib
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from IM.config import Config
from CloudConnector import CloudConnector
from IM.radl.radl import Feature
	

class DockerCloudConnector(CloudConnector):
	"""
	Cloud Launcher to Docker servers
	"""
	
	type = "Docker"
	
	_port_base_num = 35000
	""" Base number to assign SSH port on Docker server host."""
	_port_counter = 0
	""" Counter to assign SSH port on Docker server host."""

	def get_http_connection(self, auth_data):
		"""
		Get the HTTPConnection object to contact the Docker API

		Arguments:
		   - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider.
		Returns(HTTPConnection or HTTPSConnection): HTTPConnection connection object
		"""
		auth = auth_data.getAuthInfo(DockerCloudConnector.type)
		if auth and 'cert' in auth[0] and 'key' in auth[0]:
			cert = auth[0]['cert']
			key = auth[0]['cert']
			conn = httplib.HTTPSConnection(self.cloud.server, self.cloud.port, cert_file = cert, key_file = key)
		else:
			self.logger.warn("Using a unsecure connection to docker API!")
			conn = httplib.HTTPConnection(self.cloud.server, self.cloud.port)
		return conn
		
	def concreteSystem(self, radl_system, auth_data):
		if radl_system.getValue("disk.0.image.url"):
			url = uriparse(radl_system.getValue("disk.0.image.url"))
			protocol = url[0]
			if protocol == 'docker' and url[1]:
				res_system = radl_system.clone()

				res_system.addFeature(Feature("virtual_system_type", "=", "docker"), conflict="other", missing="other")

				res_system.getFeature("cpu.count").operator = "="
				res_system.getFeature("memory.size").operator = "="
				
				res_system.addFeature(Feature("provider.type", "=", self.type), conflict="other", missing="other")
				res_system.addFeature(Feature("provider.host", "=", self.cloud.server), conflict="other", missing="other")
				res_system.addFeature(Feature("provider.port", "=", self.cloud.port), conflict="other", missing="other")
					
				return [res_system]
			else:
				return []
		else:
			return [radl_system.clone()]
		

	def setIPs(self, vm, cont_info):
		"""
		Adapt the RADL information of the VM to the real IPs assigned by the cloud provider

		Arguments:
		   - vm(:py:class:`IM.VirtualMachine`): VM information.	
		   - cont_info(dict): JSON information about the container
		"""

		public_ips = [socket.gethostbyname(vm.cloud.server)]
		private_ips = []
		if str(cont_info["NetworkSettings"]["IPAddress"]):
			private_ips.append(str(cont_info["NetworkSettings"]["IPAddress"]))

		vm.setIps(public_ips, private_ips)

	def _generate_volumes(self, system):
		volumes = ',"Volumes":{'
		
		cont = 1
		while system.getValue("disk." + str(cont) + ".size") and system.getValue("disk." + str(cont) + ".device"):
			# Use the device as the volume dir
			disk_device = system.getValue("disk." + str(cont) + ".device")
			if not disk_device.startswith('/'):
				disk_device = '/' + disk_device
			self.logger.debug("Attaching a volume in %s" % disk_device)
			if cont > 1:
				volumes += ','
			volumes += '"' + disk_device + '":{}'
			cont += 1
		
		if cont == 1:
			volumes = ""
		else:
			volumes += "}"

		return volumes
			
	def _generate_port_bindings(self, outports, ssh_port):
		port_bindings = ""
		ssh_found = False
		if outports:
			num = 0
			for remote_port,_,local_port,local_protocol in outports:
				if num > 0:
					port_bindings = port_bindings + ",\n"
				port_bindings = port_bindings + '"PortBindings":{ "' + str(local_port) + '/' + local_protocol + '": [{ "HostPort": "' + str(remote_port) + '" }] }'
				num += 1
	
		if not ssh_found:
			port_bindings = port_bindings + ',\n"PortBindings":{ "22/tcp": [{ "HostPort": "' + str(ssh_port) + '" }] }\n'

		return port_bindings

	def launch(self, inf, radl, requested_radl, num_vm, auth_data):
		system = radl.systems[0]
		
		cpu = int(system.getValue('cpu.count'))
		memory = system.getFeature('memory.size').getValue('B')
		#name = system.getValue("disk.0.image.name")
		# The URI has this format: docker://image_name
		image_name = system.getValue("disk.0.image.url")[9:]
		
		volumes = self._generate_volumes(system)
		
		public_net = None
		for net in radl.networks:
			if net.isPublic():
				public_net = net

		outports = None
		if public_net:
			outports = public_net.getOutPorts()
		
		exposed_ports = '"22/tcp": {}'
		if outports:
			for _,_,local_port,local_protocol in outports:
				if local_port != 22:
					exposed_ports = exposed_ports + ', "' + str(local_port) + '/' + local_protocol + '": {}'
		
		conn = self.get_http_connection(auth_data)
		res = []
		i = 0
		while i < num_vm:
			try:
				i += 1

				# Create the VM to get the nodename
				vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl)
				(nodename, nodedom) = vm.getRequestedName(default_hostname = Config.DEFAULT_VM_NAME, default_domain = Config.DEFAULT_DOMAIN)
		
				create_request_json = """ {
					 "Hostname":"%s",
					 "Domainname": "%s",
					 "Cpuset": "0-%d",
					 "Memory":%s,
					 "Cmd":[
							 "/bin/bash", "-c", "yum install -y openssh-server ;  apt-get update && apt-get install -y openssh-server && sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/g' /etc/ssh/sshd_config && service ssh start && service ssh stop ; echo 'root:yoyoyo' | chpasswd ; /usr/sbin/sshd -D"
					 ],
					 "Image":"%s",
					 "ExposedPorts":{
							 %s
					 }
					 %s
				}""" % (nodename, nodedom, cpu-1, memory,image_name,exposed_ports,volumes)

				# Create the container
				conn.putrequest('POST', "/containers/create")
				conn.putheader('Content-Type', 'application/json')
				
				body = create_request_json
				conn.putheader('Content-Length', len(body))
				conn.endheaders(body)

				resp = conn.getresponse()
				output = resp.read()
				if resp.status != 201:
					res.append((False, "Error creating the Container: " + output))
					continue

				output = json.loads(output)
				docker_vm_id = output["Id"]
				
				# Now start it
				conn.putrequest('POST', "/containers/" + docker_vm_id + "/start")
				conn.putheader('Content-Type', 'application/json')
				
				start_request_json = "{}"
				# If the user requested a public IP, specify the PortBindings
				ssh_port = 22
				if public_net:
					start_request_json = " { "
					
					ssh_port = DockerCloudConnector._port_base_num + DockerCloudConnector._port_counter
					DockerCloudConnector._port_counter += 1

					start_request_json += self._generate_port_bindings(outports, ssh_port)
					
					start_request_json += "}" 
				
				body = start_request_json
				conn.putheader('Content-Length', len(body))
				conn.endheaders(body)

				resp = conn.getresponse()
				output = resp.read()
				if resp.status != 204:
					res.append(False, "Error creating the Container: " + output)
					continue

				# Now set the cloud id to the VM
				vm.id = docker_vm_id
				
				# Set ssh port in the RADL info of the VM
				vm.setSSHPort(ssh_port)
				
				res.append((True, vm))

			except Exception, ex:
				self.logger.exception("Error connecting with Docker server")
				res.append((False, "ERROR: " + str(ex)))

		return res

	def updateVMInfo(self, vm, auth_data):	
		try:
			conn = self.get_http_connection(auth_data)
			conn.request('GET', "/containers/" + vm.id + "/json") 
			resp = conn.getresponse()
			output = resp.read()
			if resp.status == 404:
				# If the container does not exist, set state to OFF
				vm.state = VirtualMachine.OFF
				return (True, vm)
			elif resp.status != 200:
				return (False, "Error getting info about the Container: " + output)

			output = json.loads(output)
			if output["State"]["Running"]:
				vm.state = VirtualMachine.RUNNING
			else:
				vm.state = VirtualMachine.STOPPED

			# Actualizamos los datos de la red
			self.setIPs(vm,output)
			return (True, vm)

		except Exception, ex:
			self.logger.exception("Error connecting with Docker server")
			self.logger.error(ex)
			return (False, "Error connecting with Docker server")


	def finalize(self, vm, auth_data):
		try:
			# First Stop it
			self.stop(vm, auth_data)
		
			# Now delete it
			conn = self.get_http_connection(auth_data)
			conn.request('DELETE', "/containers/" + vm.id) 
			resp = conn.getresponse()			
			output = str(resp.read())
			if resp.status == 404:
				self.logger.warn("Trying to remove a non existing container id: " + vm.id)
				return (True, vm.id)
			elif resp.status != 204:
				return (False, "Error deleting the Container: " + output)
			else:
				return (True, vm.id)
		except Exception:
			self.logger.exception("Error connecting with Docker server")
			return (False, "Error connecting with Docker server")


	def stop(self, vm, auth_data):
		try:
			conn = self.get_http_connection(auth_data)
			conn.request('POST', "/containers/" + vm.id + "/stop") 
			resp = conn.getresponse()			
			output = str(resp.read())
			if resp.status != 204:
				return (False, "Error stopping the Container: " + output)
			else:
				return (True, vm.id)
		except Exception:
			self.logger.exception("Error connecting with Docker server")
			return (False, "Error connecting with Docker server")
			
	def start(self, vm, auth_data):
		try:
			conn = self.get_http_connection(auth_data)
			conn.request('POST', "/containers/" + vm.id + "/start") 
			resp = conn.getresponse()			
			output = str(resp.read())
			if resp.status != 204:
				return (False, "Error starting the Container: " + output)
			else:
				return (True, vm.id)
		except Exception:
			self.logger.exception("Error connecting with Docker server")
			return (False, "Error connecting with Docker server")
			
	def alterVM(self, vm, radl, auth_data):
		return (False, "Not supported")
