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

import subprocess
import shutil
import os
import re
import base64
import string
import httplib
import tempfile
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
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
			
			(fproxy, proxy_filename) = tempfile.mkstemp()
			os.write(fproxy, proxy)
			os.close(fproxy)

			conn = httplib.HTTPSConnection(self.cloud.server, self.cloud.port, cert_file = proxy_filename)
		else:
			conn = httplib.HTTPConnection(self.cloud.server, self.cloud.port)
		
		return conn
	
	def delete_proxy(self, conn):
		if conn.cert_file and os.path.isfile(conn.cert_file):
			os.unlink(conn.cert_file)

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
			if protocol in ['https'] and url[5] and url[1] == self.cloud.server + ":" + str(self.cloud.port):
				res_system = radl_system.clone()

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
						is_private = network.isPrivateIP(ip_address) 
					elif kv[0] == "occi.networkinterface.interface":
						net_interface = kv[1].strip('"')
						num_interface = re.findall('\d+', net_interface)[0]
				res.append((num_interface, ip_address, not is_private))
		return res

	def setIPs(self, vm, occi_res):
		
		public_ips = []
		private_ips = []
		
		addresses = self.get_net_info(occi_res)
		for _, ip_address, is_public in addresses:
			if is_public:
				public_ips.append(ip_address)
			else:
				private_ips.append(ip_address)
		
		vm.setIps(public_ips, private_ips)
	
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
			self.delete_proxy(conn)
			
			output = resp.read()
			if resp.status != 200:
				return (False, output)
			else:
				vm.state = self.VM_STATE_MAP.get(self.get_vm_state(output), VirtualMachine.UNKNOWN)
				# Update the network data
				self.setIPs(vm,output)
				return (True, vm)

		except Exception, ex:
			self.logger.exception("Error connecting with OCCI server")
			return (False, "Error connecting with OCCI server: " + str(ex))

	def keygen(self):
		tmp_dir = tempfile.mkdtemp()
		pk_file = tmp_dir + "/occi-key"
		command = 'ssh-keygen -t rsa -b 2048 -q -N "" -f ' + pk_file
		p=subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		(out, err) = p.communicate()
		if p.returncode!=0:
			shutil.rmtree(tmp_dir, ignore_errors=True)
			self.logger.error("Error executing ssh-keygen: " + out + err)
			return (None, None)
		else:
			public = None
			private = None
			try:
				with open(pk_file) as f: private = f.read()
			except:
				self.logger.exception("Error reading private_key file.")
				
			try:
				with open(pk_file + ".pub") as f: public = f.read()
			except:
				self.logger.exception("Error reading public_key file.")
			
			shutil.rmtree(tmp_dir, ignore_errors=True)
			return (public, private)
		
	def gen_cloud_config(self, public_key, user = 'cloudadm'):
		config = "#cloud-config\n"
		config += "users:\n"
		config += "  - name: " + user + "\n"
		config += "    sudo: ALL=(ALL) NOPASSWD:ALL\n"
		config += "    lock-passwd: true\n"
		config += "    ssh-import-id: " + user + "\n" 
		config += "    ssh-authorized-keys:\n"
		config += "	  - " + public_key + "\n"
		return config

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

		url = uriparse(system.getValue("disk.0.image.url"))
		os_tpl = url[5]
		os_tpl_scheme =  url[2][1:] + "#"
		
		public_key = system.getValue('disk.0.os.credentials.public_key')
		
		if not public_key:
			# We must generate them
			(public_key, private_key) = self.keygen()
			system.setValue('disk.0.os.credentials.private_key', private_key)
		
		user = system.getValue('disk.os.credentials.username')
		if not user:
			user = "cloudadm"
			system.setValue('disk.os.credentials.username', user)
		
		cloud_config = self.gen_cloud_config(public_key, user)
		user_data = base64.encodestring(cloud_config).replace("\n","")
		
		while i < num_vm:
			try:
				conn.putrequest('POST', "/compute")
				if auth_header:
					conn.putheader('Authorization', auth_header)
				conn.putheader('Accept', 'text/plain')
				conn.putheader('Content-Type', 'text/plain,text/occi')
				
				body = 'Category: compute; scheme="http://schemas.ogf.org/occi/infrastructure#"; class="kind"\n'
				body += 'Category: ' + os_tpl + '; scheme="' + os_tpl_scheme + '"; class="mixin"\n'
				body += 'Category: user_data; scheme="http://schemas.openstack.org/compute/instance#"; class="mixin"\n'
				body += 'Category: public_key; scheme="http://schemas.openstack.org/instance/credentials#"; class="mixin"\n' 				
				body += 'X-OCCI-Attribute: occi.core.title="' + name + '"\n'
				body += 'X-OCCI-Attribute: occi.compute.hostname="' + name + '"\n'
				body += 'X-OCCI-Attribute: occi.compute.cores=' + str(cpu) +'\n'
				#body += 'X-OCCI-Attribute: occi.compute.architecture=' + arch +'\n'
				body += 'X-OCCI-Attribute: occi.compute.memory=' + str(memory) + '\n'
				
				# See: https://wiki.egi.eu/wiki/HOWTO10
				#body += 'X-OCCI-Attribute: org.openstack.credentials.publickey.name="my_key"' 
				#body += 'X-OCCI-Attribute: org.openstack.credentials.publickey.data="ssh-rsa BAA...zxe ==user@host"'
				body += 'X-OCCI-Attribute: org.openstack.compute.user_data="' + user_data + '"\n'
				
				conn.putheader('Content-Length', len(body))
				conn.endheaders(body)

				resp = conn.getresponse()
				
				# With this format: X-OCCI-Location: http://fc-one.i3m.upv.es:11080/compute/8
				output = resp.read()
				
				if resp.status != 201:
					res.append((False, output))
				else:
					occi_vm_id = os.path.basename(output)				
					vm = VirtualMachine(inf, occi_vm_id, self.cloud, radl, requested_radl)
					res.append((True, vm))

			except Exception, ex:
				self.logger.exception("Error connecting with OCCI server")
				res.append((False, "ERROR: " + str(ex)))

			i += 1
			
		self.delete_proxy(conn)
		
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
			self.delete_proxy(conn)		
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
			self.delete_proxy(conn)	
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
			self.delete_proxy(conn)	
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
