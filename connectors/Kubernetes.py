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
import string
import base64
import json
import httplib
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from CloudConnector import CloudConnector
from IM.radl.radl import Feature
	

class KubernetesCloudConnector(CloudConnector):
	"""
	Cloud Launcher to Kubernetes platform
	"""
	
	type = "Kubernetes"
	
	_port_base_num = 35000
	""" Base number to assign SSH port on Docker server host."""
	_port_counter = 0
	""" Counter to assign SSH port on Docker server host."""
	_namespace = "default"
	_apiVersion = "v1beta3"
	
	VM_STATE_MAP = {
		'Pending': VirtualMachine.PENDING,
		'Running': VirtualMachine.RUNNING,
		'Succeeded': VirtualMachine.OFF,
		'Failed': VirtualMachine.FAILED
	}
	"""Dictionary with a map with the Kubernetes POD states to the IM states."""

	def get_http_connection(self):
		"""
		Get the HTTPConnection object to contact the Kubernetes API

		Returns(HTTPConnection or HTTPSConnection): HTTPConnection connection object
		"""

		url = uriparse(self.cloud.server)
		
		if url[0] == 'https':
			conn = httplib.HTTPSConnection(url[1], self.cloud.port)
		elif url[0] == 'http':
			self.logger.warn("Using a unsecure connection to Kubernetes API!")
			conn = httplib.HTTPConnection(url[1], self.cloud.port)

		return conn

	def get_auth_header(self, auth_data):
		"""
		Generate the auth header needed to contact with the Kubernetes API server.
		"""
		url = uriparse(self.cloud.server)
		auths = auth_data.getAuthInfo(self.type, url[1])
		if not auths:
			self.logger.error("No correct auth data has been specified to Kubernetes.")
			return None
		else:
			auth = auths[0]
			
		auth_header = None

		if 'username' in auth and 'password' in auth:
			passwd = auth['password']
			user = auth['username'] 
			auth_header = { 'Authorization' : 'Basic ' + string.strip(base64.encodestring(user + ':' + passwd))}
		elif 'token' in auth:
			token = auth['token'] 
			auth_header = { 'Authorization' : 'Bearer ' + token }

		return auth_header


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
		
	def _generate_pod_data(self, outports, system, ssh_port):
		cpu = str(system.getValue('cpu.count'))
		memory = "%s" % system.getFeature('memory.size').getValue('B')
		# The URI has this format: docker://image_name
		image_name = system.getValue("disk.0.image.url")[9:]
		name = "im%d" % int(time.time()*100)
					
		ports = [{'containerPort': 22, 'protocol': 'TCP', 'hostPort':ssh_port}]
		if outports:
			for remote_port,_,local_port,local_protocol in outports:
				if local_port != 22:
					ports.append({'containerPort':local_port, 'protocol': local_protocol.upper(), 'hostPort': remote_port})
					
		pod_data = { 'apiVersion': self._apiVersion, 'kind': 'Pod' }
		pod_data['metadata'] = {
								'name': name,
								'namespace': self._namespace, 
								'labels': {'name': name}
								}
		containers = [{
						'name': name,
						'image': image_name,
						'imagePullPolicy': 'IfNotPresent',
						'restartPolicy': 'Always',
						'ports': ports,
						'resources': {'limits': {'cpu': cpu, 'memory': memory}}
					}]
		
		pod_data['spec'] = {'containers' : containers}
		
		return pod_data
		
	def launch(self, inf, radl, requested_radl, num_vm, auth_data):
		system = radl.systems[0]
		
		public_net = None
		for net in radl.networks:
			if net.isPublic():
				public_net = net

		outports = None
		if public_net:
			outports = public_net.getOutPorts()
		
		auth_header = self.get_auth_header(auth_data)
		conn = self.get_http_connection()
		
		res = []
		i = 0
		while i < num_vm:
			try:
				i += 1
				# Create the container
				conn.putrequest('POST', "/api/" + self._apiVersion + "/namespaces/" + self._namespace + "/pods")
				conn.putheader('Content-Type', 'application/json')
				if auth_header:
					conn.putheader(auth_header.keys()[0], auth_header.values()[0])
				
				ssh_port = KubernetesCloudConnector._port_base_num + KubernetesCloudConnector._port_counter
				KubernetesCloudConnector._port_counter += 1
				pod_data = self._generate_pod_data(outports, system, ssh_port)
				body = json.dumps(pod_data)
				conn.putheader('Content-Length', len(body))
				conn.endheaders(body)

				resp = conn.getresponse()
				output = resp.read()
				if resp.status != 201:
					res.append((False, "Error creating the Container: " + output))
				else:
					output = json.loads(output)
					vm = VirtualMachine(inf, output["metadata"]["name"], self.cloud, radl, requested_radl, self)
					# Set SSH port in the RADL info of the VM
					vm.setSSHPort(ssh_port)					
					res.append((True, vm))

			except Exception, ex:
				self.logger.exception("Error connecting with Kubernetes API server")
				res.append((False, "ERROR: " + str(ex)))

		return res

	def updateVMInfo(self, vm, auth_data):	
		try:
			auth = self.get_auth_header(auth_data)
			headers = {}
			if auth:
				headers.update(auth)
			conn = self.get_http_connection()
			
			conn.request('GET', "/api/" + self._apiVersion + "/namespaces/" + self._namespace + "/pods/" + vm.id, headers = headers)
			resp = conn.getresponse()

			output = resp.read()
			if resp.status == 404:
				# If the container does not exist, set state to OFF
				vm.state = VirtualMachine.OFF
				return (True, vm)
			elif resp.status != 200:
				return (False, "Error getting info about the POD: " + output)
			else:
				output = json.loads(output)
				vm.state = self.VM_STATE_MAP.get(output["status"]["phase"], VirtualMachine.UNKNOWN)
	
				# Update the network info
				self.setIPs(vm,output)
				return (True, vm)

		except Exception, ex:
			self.logger.exception("Error connecting with Kubernetes API server")
			self.logger.error(ex)
			return (False, "Error connecting with Kubernetes API server")


	def setIPs(self, vm, pod_info):
		"""
		Adapt the RADL information of the VM to the real IPs assigned by the cloud provider

		Arguments:
		   - vm(:py:class:`IM.VirtualMachine`): VM information.	
		   - pod_info(dict): JSON information about the POD
		"""
		
		public_ips = []
		private_ips = []
		if 'hostIP' in pod_info["status"]:
			public_ips = [pod_info["status"]["hostIP"]]
		if 'podIP' in pod_info["status"]:
			private_ips = [pod_info["status"]["podIP"]]

		vm.setIps(public_ips, private_ips)

	def finalize(self, vm, auth_data):
		try:
			auth = self.get_auth_header(auth_data)
			headers = {}
			if auth:
				headers.update(auth)
			conn = self.get_http_connection()
			
			conn.request('DELETE', "/api/" + self._apiVersion + "/namespaces/" + self._namespace + "/pods/" + vm.id, headers = headers) 
			resp = conn.getresponse()			
			output = str(resp.read())
			if resp.status == 404:
				self.logger.warn("Trying to remove a non existing POD id: " + vm.id)
				return (True, vm.id)
			elif resp.status != 200:
				return (False, "Error deleting the POD: " + output)
			else:
				return (True, vm.id)
		except Exception:
			self.logger.exception("Error connecting with Kubernetes API server")
			return (False, "Error connecting with Kubernetes API server")

	def stop(self, vm, auth_data):
		return (False, "Not supported")
			
	def start(self, vm, auth_data):
		return (False, "Not supported")
			
	def alterVM(self, vm, radl, auth_data):
		return (False, "Not supported")
