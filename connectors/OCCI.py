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

from ssl import SSLError
import json
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
	"""
	Cloud Launcher to the OCCI platform (FedCloud)
	"""
	
	type = "OCCI"
	"""str with the name of the provider."""
	INSTANCE_TYPE = 'small'
	"""str with the name of the default instance type to launch."""
	
	VM_STATE_MAP = {
		'waiting': VirtualMachine.PENDING,
		'active': VirtualMachine.RUNNING,
		'inactive': VirtualMachine.OFF,
		'suspended': VirtualMachine.OFF
	}
	"""Dictionary with a map with the OCCI VM states to the IM states."""

	@staticmethod
	def get_https_connection(auth, server, port):
		"""
		Get a HTTPS connection with the specified server.
		It uses a proxy file if it has been specified in the auth credentials 
		"""
		if 'proxy' in auth[0]:
			proxy = auth[0]['proxy']
			
			(fproxy, proxy_filename) = tempfile.mkstemp()
			os.write(fproxy, proxy)
			os.close(fproxy)
	
			return httplib.HTTPSConnection(server, port, cert_file = proxy_filename)
		else:
			return httplib.HTTPSConnection(server, port)

	def get_http_connection(self, auth_data):
		"""
		Get the HTTP connection to contact the OCCI server
		"""
		auth = auth_data.getAuthInfo(OCCICloudConnector.type)
		url = uriparse(self.cloud.server)
		
		if url[0] == 'https':
			conn = self.get_https_connection(auth, url[1], self.cloud.port)
		else:
			conn = httplib.HTTPConnection(url[1], self.cloud.port)
		
		return conn
	
	@staticmethod
	def delete_proxy(conn):
		"""
		Delete the proxy file created to contact with the HTTPS server.
		(Created in the get_https_connection function)
		"""
		if isinstance(conn, httplib.HTTPSConnection) and conn.cert_file and os.path.isfile(conn.cert_file):
			os.unlink(conn.cert_file)

	def get_auth_header(self, auth_data):
		"""
		Generate the auth header needed to contact with the OCCI server.
		I supports Keystone tokens and basic auth.
		"""
		auth_header = None
		auth = auth_data.getAuthInfo(OCCICloudConnector.type) 
		keystone_uri = KeyStoneAuth.get_keystone_uri(self, auth_data)
		
		if keystone_uri:
			keystone_token = KeyStoneAuth.get_keystone_token(self, keystone_uri, auth)
			auth_header = {'X-Auth-Token' : keystone_token} 		
		else: 
			if auth and 'username' in auth[0] and 'password' in auth[0]:
				passwd = auth[0]['password']
				user = auth[0]['username'] 
				auth_header = { 'Authorization' : 'Basic ' + string.strip(base64.encodestring(user + ':' + passwd))}

		return auth_header
		
		
	def concreteSystem(self, radl_system, auth_data):
		if radl_system.getValue("disk.0.image.url"):
			url = uriparse(radl_system.getValue("disk.0.image.url"))
			protocol = url[0]
			if protocol in ['https', 'http'] and url[2] and (url[0] + "://" + url[1]) == (self.cloud.server + ":" + str(self.cloud.port)):
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
		"""
		Get the net related information about a VM from the OCCI information returned by the server 
		"""
		lines = occi_res.split("\n")
		res = []
		for l in lines:
			if l.find('Link:') != -1 and l.find('/network/') != -1:
				num_interface = None
				ip_address = None
				parts = l.split(';')
				for part in parts:
					kv = part.split('=')
					if kv[0].strip() == "occi.networkinterface.address":
						ip_address = kv[1].strip('"')
						is_private = network.isPrivateIP(ip_address) 
					elif kv[0].strip() == "occi.networkinterface.interface":
						net_interface = kv[1].strip('"')
						num_interface = re.findall('\d+', net_interface)[0]
				if num_interface and ip_address:
					res.append((num_interface, ip_address, not is_private))
		return res

	def setIPs(self, vm, occi_res):
		"""
		Set to the VM info the IPs obtained from the OCCI info  
		"""
		public_ips = []
		private_ips = []
		
		addresses = self.get_net_info(occi_res)
		for _, ip_address, is_public in addresses:
			if is_public:
				public_ips.append(ip_address)
			else:
				private_ips.append(ip_address)
		
		vm.setIps(public_ips, private_ips)
			
	def get_occi_attribute_value(self, occi_res, attr_name):
		"""
		Get the value of an OCCI attribute returned by an OCCI server
		"""
		lines = occi_res.split("\n")
		for l in lines:
			if l.find('X-OCCI-Attribute: ' + attr_name + '=') != -1:
				return l.split('=')[1].strip('"')
		return None
	
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
		headers = {'Accept': 'text/plain', 'Connection':'close'}
		if auth:
			headers.update(auth)
		
		try:
			conn = self.get_http_connection(auth_data)
			conn.request('GET', "/compute/" + vm.id, headers = headers) 
			resp = conn.getresponse()
			self.delete_proxy(conn)
			
			output = resp.read()
			if resp.status == 404:
				vm.state = VirtualMachine.OFF
				return (True, vm)
			elif resp.status != 200:
				return (False, resp.reason + "\n" + output)
			else:
				vm.state = self.VM_STATE_MAP.get(self.get_occi_attribute_value(output, 'occi.compute.state'), VirtualMachine.UNKNOWN)
				
				cores = self.get_occi_attribute_value(output, 'occi.compute.cores')
				if cores:
					vm.info.systems[0].setValue("cpu.count", int(cores))
				memory = self.get_occi_attribute_value(output, 'occi.compute.memory')
				if memory:
					vm.info.systems[0].setValue("memory.size", float(memory), 'G')
				
				# Update the network data
				self.setIPs(vm,output)
				return (True, vm)

		except Exception, ex:
			self.logger.exception("Error connecting with OCCI server")
			return (False, "Error connecting with OCCI server: " + str(ex))

	def keygen(self):
		"""
		Generates a keypair using the ssh-keygen command and returns a tuple (public, private)
		"""
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
		"""
		Generate the cloud-config file to be used in the user_data of the OCCI VM
		"""
		config = """#cloud-config
users:
  - name: %s
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock-passwd: true
    ssh-import-id: %s
    ssh-authorized-keys:
      - %s
""" % (user , user, public_key)
		return config

	def query_occi(self, auth_data):
		"""
		Get the info contacting with the OCCI server
		"""
		auth = self.get_auth_header(auth_data)
		headers = {'Accept': 'text/plain', 'Connection':'close'}
		if auth:
			headers.update(auth)
		
		try:
			conn = self.get_http_connection(auth_data)
			conn.request('GET', "/-/", headers = headers) 
			resp = conn.getresponse()
			self.delete_proxy(conn)
			
			output = resp.read()
			self.logger.debug(output)
			
			if resp.status != 200:
				self.logger.error("Error querying the OCCI server")
				return ""
			else:
				return output
		except:
			self.logger.exception("Error querying the OCCI server")
			return ""

	def get_scheme(self, occi_info, category, ctype):
		"""
		Get the scheme of an OCCI category contacting with the OCCI server
		"""
		lines = occi_info.split("\n")
		for l in lines:
			if l.find('Category: ' + category) != -1 and l.find(ctype) != -1:
				parts = l.split(';')
				for p in parts:
					kv = p.split("=")
					if kv[0].strip() == "scheme":
						return kv[1].replace('"','').replace("'",'')

		self.logger.error("Error getting scheme for category: " + category)
		return ""

	def get_instance_type_uri(self, occi_info, instance_type):
		"""
		Get the whole URI of an OCCI instance from the OCCI info
		"""
		if instance_type.startswith('http'):
			# If the user set the whole uri, do not search
			return instance_type
		else:
			return self.get_scheme(occi_info, instance_type,'resource_tpl') + instance_type
			
	def get_os_tpl_scheme(self, occi_info, os_tpl):
		"""
		Get the whole URI of an OCCI os template from the OCCI info
		"""
		return self.get_scheme(occi_info, os_tpl,'os_tpl')
			
	def launch(self, inf, radl, requested_radl, num_vm, auth_data):
		system = radl.systems[0]
		auth_header = self.get_auth_header(auth_data)
		
		cpu = system.getValue('cpu.count')
		memory = system.getFeature('memory.size').getValue('G')
		name = system.getValue("disk.0.image.name")
		if not name:
			name = "im_userimage"
		arch = system.getValue('cpu.arch')
		
		if arch.find('64'):
			arch = 'x64'
		else:
			arch = 'x86'
		
		res = []
		i = 0
		conn = self.get_http_connection(auth_data)
		
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
		user_data = base64.b64encode(cloud_config).replace("\n","")
		
		# Get the info about the OCCI server (GET /-/)
		occi_info = self.query_occi(auth_data)
		
		# Parse the info to get the os_tpl scheme
		url = uriparse(system.getValue("disk.0.image.url"))
		os_tpl =  url[2][1:]
		os_tpl_scheme = self.get_os_tpl_scheme(occi_info, os_tpl)
		if not os_tpl_scheme:
			raise Exception("Error getting os_tpl scheme. Check that the image specified is supported in the OCCI server.")
		
		# Parse the info to get the instance_type (resource_tpl) scheme
		instance_type_uri = None
		if system.getValue('instance_type'):
			instance_type = self.get_instance_type_uri(occi_info, system.getValue('instance_type'))
			instance_type_uri = uriparse(instance_type)
			if not instance_type_uri[5]:
				raise Exception("Error getting Instance type URI. Check that the instance_type specified is supported in the OCCI server.")
			else:
				instance_name = instance_type_uri[5] 
				instance_scheme =  instance_type_uri[0] + "://" + instance_type_uri[1] + instance_type_uri[2] + "#"
		
		while i < num_vm:
			try:
				conn.putrequest('POST', "/compute/")
				if auth_header:
					conn.putheader(auth_header.keys()[0], auth_header.values()[0])
				conn.putheader('Accept', 'text/plain')
				conn.putheader('Content-Type', 'text/plain')
				conn.putheader('Connection', 'close')
				
				body = 'Category: compute; scheme="http://schemas.ogf.org/occi/infrastructure#"; class="kind"\n'
				body += 'Category: ' + os_tpl + '; scheme="' + os_tpl_scheme + '"; class="mixin"\n'
				body += 'Category: user_data; scheme="http://schemas.openstack.org/compute/instance#"; class="mixin"\n'
				#body += 'Category: public_key; scheme="http://schemas.openstack.org/instance/credentials#"; class="mixin"\n' 				
				
				if instance_type_uri:
					body += 'Category: ' + instance_name + '; scheme="' + instance_scheme + '"; class="mixin"\n'
				else:
					# Try to use this OCCI attributes (not supported by openstack)
					if cpu:
						body += 'X-OCCI-Attribute: occi.compute.cores=' + str(cpu) +'\n'
					#body += 'X-OCCI-Attribute: occi.compute.architecture=' + arch +'\n'
					if memory:
						body += 'X-OCCI-Attribute: occi.compute.memory=' + str(memory) + '\n'

				body += 'X-OCCI-Attribute: occi.core.title="' + name + '"\n'
				body += 'X-OCCI-Attribute: occi.compute.hostname="' + name + '"\n'				
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
					res.append((False, resp.reason + "\n" + output))
				else:
					if 'location' in resp.msg.dict:
						occi_vm_id = os.path.basename(resp.msg.dict['location'])
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
		headers = {'Accept': 'text/plain', 'Connection':'close'}
		if auth:
			headers.update(auth)
		
		try:
			conn = self.get_http_connection(auth_data)
			conn.request('DELETE', "/compute/" + vm.id, headers = headers) 
			resp = conn.getresponse()	
			self.delete_proxy(conn)		
			output = str(resp.read())
			if resp.status == 404:
				return (True, vm.id)
			elif resp.status != 200:
				return (False, "Error removing the VM: " + resp.reason + "\n" + output)
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
				conn.putheader(auth_header.keys()[0], auth_header.values()[0])
			conn.putheader('Accept', 'text/plain')
			conn.putheader('Content-Type', 'text/plain,text/occi')
			conn.putheader('Connection', 'close')
			
			body = 'Category: suspend;scheme="http://schemas.ogf.org/occi/infrastructure/compute/action#";class="action";\n'
			conn.putheader('Content-Length', len(body))
			conn.endheaders(body)

			resp = conn.getresponse()
			self.delete_proxy(conn)	
			output = str(resp.read())
			if resp.status != 200:
				return (False, "Error stopping the VM: " + resp.reason + "\n" + output)
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
				conn.putheader(auth_header.keys()[0], auth_header.values()[0])
			conn.putheader('Accept', 'text/plain')
			conn.putheader('Content-Type', 'text/plain,text/occi')
			conn.putheader('Connection', 'close')
			
			body = 'Category: start;scheme="http://schemas.ogf.org/occi/infrastructure/compute/action#";class="action";\n'
			conn.putheader('Content-Length', len(body))
			conn.endheaders(body)

			resp = conn.getresponse()
			self.delete_proxy(conn)	
			output = str(resp.read())
			if resp.status != 200:
				return (False, "Error starting the VM: " + resp.reason + "\n" + output)
			else:
				return (True, vm.id)
		except Exception:
			self.logger.exception("Error connecting with OCCI server")
			return (False, "Error connecting with OCCI server")
			
	def alterVM(self, vm, radl, auth_data):
		return (False, "Not supported")

class KeyStoneAuth:
	"""
	Class to manage the Keystone auth tokens used in OpenStack
	"""
	
	@staticmethod
	def get_keystone_uri(occi, auth_data):
		"""
		Contact the OCCI server to check if it needs to contact a keystone server.
		It returns the keystone server URI or None.
		"""
		try:
			headers = {'Accept': 'text/plain', 'Connection':'close'}
			conn = occi.get_http_connection(auth_data)
			conn.request('HEAD', "/-/", headers = headers) 
			resp = conn.getresponse()
			www_auth_head = resp.getheader('Www-Authenticate')
			if www_auth_head and www_auth_head.startswith('Keystone uri'):
				return www_auth_head.split('=')[1].replace("'","")
			else:
				return None
		except SSLError:
			occi.logger.exception("Error with the credentials when contacting with the OCCI server.")
			raise Exception("Error with the credentials when contacting with the OCCI server. Check your proxy file.")
		except:
			occi.logger.exception("Error contacting with the OCCI server.")
			return None
	
	@staticmethod
	def get_keystone_token(occi, keystone_uri, auth):
		"""
		Contact the specified keystone server to return the token
		"""
		try:
			uri = uriparse(keystone_uri)
			server = uri[1].split(":")[0]
			port = int(uri[1].split(":")[1])
			
			conn = occi.get_https_connection(auth, server, port)
			conn.putrequest('POST', "/v2.0/tokens")
			conn.putheader('Accept', 'application/json')
			conn.putheader('Content-Type', 'application/json')
			conn.putheader('Connection', 'close')
			
			body = '{"auth":{"voms":true}}'
			
			conn.putheader('Content-Length', len(body))
			conn.endheaders(body)
	
			resp = conn.getresponse()
			
			# format: -> "{\"access\": {\"token\": {\"issued_at\": \"2014-12-29T17:10:49.609894\", \"expires\": \"2014-12-30T17:10:49Z\", \"id\": \"c861ab413e844d12a61d09b23dc4fb9c\"}, \"serviceCatalog\": [], \"user\": {\"username\": \"/DC=es/DC=irisgrid/O=upv/CN=miguel-caballer\", \"roles_links\": [], \"id\": \"475ce4978fb042e49ce0391de9bab49b\", \"roles\": [], \"name\": \"/DC=es/DC=irisgrid/O=upv/CN=miguel-caballer\"}, \"metadata\": {\"is_admin\": 0, \"roles\": []}}}"
			output = json.loads(resp.read())
			token_id = output['access']['token']['id']
			
			conn = occi.get_https_connection(auth, server, port)
			headers = {'Accept': 'application/json', 'Content-Type' : 'application/json', 'X-Auth-Token' : token_id, 'Connection':'close'}
			conn.request('GET', "/v2.0/tenants", headers = headers)
			resp = conn.getresponse()
			
			# format: -> "{\"tenants_links\": [], \"tenants\": [{\"description\": \"egi fedcloud\", \"enabled\": true, \"id\": \"fffd98393bae4bf0acf66237c8f292ad\", \"name\": \"egi\"}]}"
			output = json.loads(resp.read())
			tenant = str(output['tenants'][0]['name'])		
			
			
			conn = occi.get_https_connection(auth, server, port)
			conn.putrequest('POST', "/v2.0/tokens")
			conn.putheader('Accept', 'application/json')
			conn.putheader('Content-Type', 'application/json')
			conn.putheader('X-Auth-Token', token_id)
			conn.putheader('Connection', 'close')
			
			body = '{"auth":{"voms":true,"tenantName":"' + tenant + '"}}'
			
			conn.putheader('Content-Length', len(body))
			conn.endheaders(body)
	
			resp = conn.getresponse()
			
			# format: -> "{\"access\": {\"token\": {\"issued_at\": \"2014-12-29T17:10:49.609894\", \"expires\": \"2014-12-30T17:10:49Z\", \"id\": \"c861ab413e844d12a61d09b23dc4fb9c\"}, \"serviceCatalog\": [], \"user\": {\"username\": \"/DC=es/DC=irisgrid/O=upv/CN=miguel-caballer\", \"roles_links\": [], \"id\": \"475ce4978fb042e49ce0391de9bab49b\", \"roles\": [], \"name\": \"/DC=es/DC=irisgrid/O=upv/CN=miguel-caballer\"}, \"metadata\": {\"is_admin\": 0, \"roles\": []}}}"
			output = json.loads(resp.read())
			tenant_token_id = output['access']['token']['id']
			
			occi.delete_proxy(conn)
		
			return tenant_token_id
		except:
			occi.logger.exception("Error obtaining Keystone Token.")
			return None