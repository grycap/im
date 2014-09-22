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

import os
import re
import base64
import string
import httplib
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from IM.config import Config
from CloudConnector import CloudConnector
from IM.radl.radl import Feature, network
	

class OCCICloudConnector(CloudConnector):
	
	type = "OCCI"
	
	VM_STATE_MAP = {
		'waiting': VirtualMachine.PENDING,
		'active': VirtualMachine.RUNNING,
		'inactive': VirtualMachine.OFF,
		'suspended': VirtualMachine.OFF
	}

	def get_http_connection(self, auth_data):
		auth = auth_data.getAuthInfo(OCCICloudConnector.type)
		if auth and 'proxy' in auth[0]:
			proxy = auth[0]['proxy']
			conn = httplib.HTTPSConnection(self.cloud.server, self.cloud.port, cert_file = proxy)
		else:
			conn = httplib.HTTPConnection(self.cloud.server, self.cloud.port)
		
		return conn

	@staticmethod
	def get_auth_header(auth_data):
		auth_header = None
		auth = auth_data.getAuthInfo(OCCICloudConnector.type) 
		if auth and 'username' in auth[0] and 'password' in auth[0]:
			passwd = auth[0]['password']
			user = auth[0]['username'] 
			auth_header = 'Basic ' + string.strip(base64.encodestring(user + ':' + passwd))

		return auth_header
		
		
	def concreteSystem(self, radl_system, auth_data):
		if radl_system.getValue("disk.0.image.url"):
			url = uriparse(radl_system.getValue("disk.0.image.url"))
			protocol = url[0]
			if protocol in ['http','https'] and url[5]:
				res_system = radl_system.clone()
				
				res_system.addFeature(Feature("cpu.count", "=", Config.DEFAULT_VM_CPUS), conflict="me", missing="other")
				res_system.addFeature(Feature("memory.size", "=", Config.DEFAULT_VM_MEMORY, Config.DEFAULT_VM_MEMORY_UNIT), conflict="me", missing="other")
				res_system.addFeature(Feature("cpu.arch", "=", Config.DEFAULT_VM_CPU_ARCH), conflict="me", missing="other")
				
				# TODO: set operator to "=" in all the features
				res_system.getFeature("cpu.count").operator = "="
				res_system.getFeature("memory.size").operator = "="
					
				return [res_system]
			else:
				return []
		else:
			return [radl_system.clone()]

	def get_net_info(self, occi_res):
		lines = occi_res.split("\n")
		res = []
		for l in lines:
			if l.find('Link:') != -1 and l.find('/network/') != -1:
				parts = l.split(';')
				for part in parts:
					kv = part.split('=')
					if kv[0] == "occi.networkinterface.address":
						ip_address = kv[1].strip('"')
						is_private = ip_address.startswith("10") or ip_address.startswith("172") or ip_address.startswith("169.254") or ip_address.startswith("192.168") 
					elif kv[0] == "occi.networkinterface.interface":
						net_interface = kv[1].strip('"')
						num_interface = re.findall('\d+', net_interface)[0]
				res.append((num_interface, ip_address, not is_private))
		return res

	def setIPs(self, vm, occi_res):
		vm_system = vm.info.systems[0]
		
		# Delete the old networks
		vm.info.networks = []
		i = 0
		while vm_system.hasFeature("net_interface.%d.connection" % i):
			vm_system.delValue("net_interface.%d.connection" % i)
			if vm_system.hasFeature("net_interface.%d.ip" % i):
				vm_system.delValue("net_interface.%d.ip" % i)
			i += 1
		
		addresses = self.get_net_info(occi_res)
		for num_interface, ip_address, is_public in addresses:
			# Set the net_interface.* with the num of the net_interface
			net = network.createNetwork("occinet_" + str(num_interface), is_public)
			vm.info.networks.append(net)
			vm_system.setValue('net_interface.' + str(num_interface) + '.ip', ip_address)
			vm_system.setValue('net_interface.' + str(num_interface) + '.connection',net.id)

	
	def get_vm_state(self, occi_res):
		lines = occi_res.split("\n")
		for l in lines:
			if l.find('X-OCCI-Attribute: occi.compute.state=') != -1:
				return l.split('=')[1].strip('"')	
	
	"""
	text/plain format:
		Category: compute;scheme="http://schemas.ogf.org/occi/infrastructure#";class="kind";location="/compute/";title="compute resource"
		Category: compute;scheme="http://opennebula.org/occi/infrastructure#";class="mixin";location="/mixin/compute/";title="OpenNebula specific Compute attributes"
		Category: small;scheme="http://fedcloud.egi.eu/occi/infrastructure/resource_tpl#";class="mixin";location="/mixin/resource_tpl/small/";title="Small Instance - 1 core and 1.7 GB of RAM"
		Category: uuid_test_0;scheme="http://occi.fc-one.i3m.upv.es/occi/infrastructure/os_tpl#";class="mixin";location="/mixin/os_tpl/uuid_test_0/";title="test"
		X-OCCI-Attribute: occi.core.id="10"
		X-OCCI-Attribute: occi.core.title="one-10"
		X-OCCI-Attribute: occi.compute.architecture="x64"
		X-OCCI-Attribute: occi.compute.cores=1
		X-OCCI-Attribute: occi.compute.memory=1.69921875
		X-OCCI-Attribute: occi.compute.speed=1.0
		X-OCCI-Attribute: occi.compute.state="active"
		X-OCCI-Attribute: org.opennebula.compute.id="10"
		X-OCCI-Attribute: org.opennebula.compute.cpu=1.0
		Link: </compute/10?action=stop>;rel="http://schemas.ogf.org/occi/infrastructure/compute/action#stop"
		Link: </compute/10?action=restart>;rel="http://schemas.ogf.org/occi/infrastructure/compute/action#restart"
		Link: </compute/10?action=suspend>;rel="http://schemas.ogf.org/occi/infrastructure/compute/action#suspend"
		Link: </storage/0>;rel="http://schemas.ogf.org/occi/infrastructure#storage";self="/link/storagelink/compute_10_disk_0";category="http://schemas.ogf.org/occi/infrastructure#storagelink http://opennebula.org/occi/infrastructure#storagelink";occi.core.id="compute_10_disk_0";occi.core.title="ttylinux - kvm_file0";occi.core.target="/storage/0";occi.core.source="/compute/10";occi.storagelink.deviceid="/dev/hda";occi.storagelink.state="active"
		Link: </network/1>;rel="http://schemas.ogf.org/occi/infrastructure#network";self="/link/networkinterface/compute_10_nic_0";category="http://schemas.ogf.org/occi/infrastructure#networkinterface http://schemas.ogf.org/occi/infrastructure/networkinterface#ipnetworkinterface http://opennebula.org/occi/infrastructure#networkinterface";occi.core.id="compute_10_nic_0";occi.core.title="private";occi.core.target="/network/1";occi.core.source="/compute/10";occi.networkinterface.interface="eth0";occi.networkinterface.mac="10:00:00:00:00:05";occi.networkinterface.state="active";occi.networkinterface.address="10.100.1.5";org.opennebula.networkinterface.bridge="br1"

	"""	
	def updateVMInfo(self, vm, auth_data):
		auth = self.get_auth_header(auth_data)
		headers = {'Accept': 'text/plain'}
		if auth:
			headers['Authorization'] = auth
		
		try:
			conn = self.get_http_connection(auth_data)
			conn.request('GET', "/compute/" + vm.id, headers = headers) 
			resp = conn.getresponse()
			
			output = resp.read()

			vm.state = self.VM_STATE_MAP.get(self.get_vm_state(output), VirtualMachine.UNKNOWN)
			
			# Actualizamos los datos de la red
			self.setIPs(vm,output)
			return (True, vm)

		except Exception, ex:
			self.logger.error("Error connecting with OCCI server")
			self.logger.error(ex)
			return (False, "Error connecting with OCCI server")


	def launch(self, inf, radl, requested_radl, num_vm, auth_data):
		system = radl.systems[0]
		auth_header = self.get_auth_header(auth_data)
		
		cpu = system.getValue('cpu.count')
		memory = system.getFeature('memory.size').getValue('G')
		name = system.getValue("disk.0.image.name")
		arch = system.getValue('cpu.arch')
		
		if arch.find('64'):
			arch = 'x64'
		else:
			arch = 'x86'
		
		res = []
		i = 0
		conn = self.get_http_connection(auth_data)
		
		# The URI has this format: http://occi.fc-one.i3m.upv.es/occi/infrastructure/os_tpl#uuid_prueba2_1
		url = uriparse(system.getValue("disk.0.image.url"))
		os_tpl = url[5]
		
		while i < num_vm:
			try:
				conn.putrequest('POST', "/compute")
				if auth_header:
					conn.putheader('Authorization', auth_header)
				conn.putheader('Accept', 'text/plain')
				conn.putheader('Content-Type', 'text/plain,text/occi')
				
				body = 'Category: compute; scheme="http://schemas.ogf.org/occi/infrastructure#"; class="kind"\n'
				#body += 'Category: ' + instance_type.name + '; scheme="http://fedcloud.egi.eu/occi/infrastructure/resource_tpl#"; class="mixin"\n'
				body += 'Category: ' + os_tpl + '; scheme="http://occi.fc-one.i3m.upv.es/occi/infrastructure/os_tpl#"; class="mixin"\n'
				body += 'X-OCCI-Attribute: occi.core.title="' + name + '"\n'
				body += 'X-OCCI-Attribute: occi.compute.hostname="' + name + '"\n'
				body += 'X-OCCI-Attribute: occi.compute.cores=' + str(cpu) +'\n'
				body += 'X-OCCI-Attribute: occi.compute.architecture=' + arch +'\n'
				body += 'X-OCCI-Attribute: occi.compute.memory=' + str(memory) + '\n'
				conn.putheader('Content-Length', len(body))
				conn.endheaders(body)

				resp = conn.getresponse()
				
				# With this format: X-OCCI-Location: http://fc-one.i3m.upv.es:11080/compute/8
				output = resp.read()
				vm_id = os.path.basename(output)
				
				vm = VirtualMachine(inf, vm_id, self.cloud, radl, requested_radl)
				res.append((True, vm))

			except Exception, ex:
				self.logger.exception("Error connecting with OCCI server")
				res.append((False, "ERROR: " + str(ex)))

			i += 1
		return res

	def finalize(self, vm, auth_data):
		auth = self.get_auth_header(auth_data)
		headers = {'Accept': 'text/plain'}
		if auth:
			headers['Authorization'] = auth
		
		try:
			conn = self.get_http_connection(auth_data)
			conn.request('DELETE', "/compute/" + vm.id, headers = headers) 
			resp = conn.getresponse()			
			output = str(resp.read())
			if resp.status != 200:
				return (False, "Error removing the VM: " + output)
			else:
				return (True, vm.id)
		except Exception:
			self.logger.exception("Error connecting with OCCI server")
			return (False, "Error connecting with OCCI server")


	def stop(self, vm, auth_data):
		auth_header = self.get_auth_header(auth_data)
		try:
			conn = self.get_http_connection(auth_data)
			conn.putrequest('POST', "/compute/" + vm.id + "?action=suspend")
			if auth_header:
				conn.putheader('Authorization', auth_header)
			conn.putheader('Accept', 'text/plain')
			conn.putheader('Content-Type', 'text/plain,text/occi')
			
			body = 'Category: suspend;scheme="http://schemas.ogf.org/occi/infrastructure/compute/action#";class="action";\n'
			conn.putheader('Content-Length', len(body))
			conn.endheaders(body)

			resp = conn.getresponse()
			output = str(resp.read())
			if resp.status != 200:
				return (False, "Error stopping the VM: " + output)
			else:
				return (True, vm.id)
		except Exception:
			self.logger.exception("Error connecting with OCCI server")
			return (False, "Error connecting with OCCI server")
			
	def start(self, vm, auth_data):
		auth_header = self.get_auth_header(auth_data)
		try:
			conn = self.get_http_connection(auth_data)
			conn.putrequest('POST', "/compute/" + vm.id + "?action=start")
			if auth_header:
				conn.putheader('Authorization', auth_header)
			conn.putheader('Accept', 'text/plain')
			conn.putheader('Content-Type', 'text/plain,text/occi')
			
			body = 'Category: start;scheme="http://schemas.ogf.org/occi/infrastructure/compute/action#";class="action";\n'
			conn.putheader('Content-Length', len(body))
			conn.endheaders(body)

			resp = conn.getresponse()
			output = str(resp.read())
			if resp.status != 200:
				return (False, "Error starting the VM: " + output)
			else:
				return (True, vm.id)
		except Exception:
			self.logger.exception("Error connecting with OCCI server")
			return (False, "Error connecting with OCCI server")
			
	def alterVM(self, vm, radl, auth_data):
		return (False, "Not supported")
