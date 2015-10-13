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
import subprocess
import shutil
import os
import sys
import httplib
import tempfile
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from CloudConnector import CloudConnector
from IM.radl.radl import Feature


class FogBowCloudConnector(CloudConnector):
	"""
	Cloud Launcher to the FogBow platform
	"""
	
	type = "FogBow"
	"""str with the name of the provider."""
	INSTANCE_TYPE = 'small'
	"""str with the name of the default instance type to launch."""
	
	VM_STATE_MAP = {
		'waiting': VirtualMachine.PENDING,
		'active': VirtualMachine.RUNNING,
		'inactive': VirtualMachine.OFF,
		'suspended': VirtualMachine.OFF
	}
	"""Dictionary with a map with the FogBow VM states to the IM states."""
	
	VM_REQ_STATE_MAP = {
		'open': VirtualMachine.PENDING,
		'failed': VirtualMachine.FAILED,
		'fulfilled': VirtualMachine.PENDING,
		'deleted': VirtualMachine.OFF,
		'closed': VirtualMachine.OFF
	}
	"""Dictionary with a map with the FogBow Request states to the IM states."""

	def get_auth_headers(self, auth_data):
		"""
		Generate the auth header needed to contact with the FogBow server.
		"""
		auth = auth_data.getAuthInfo(FogBowCloudConnector.type) 
		
		if auth and 'token_type' in auth[0]:
			token_type = auth[0]['token_type']
			plugin = IdentityPlugin.getIdentityPlugin(token_type)
			token = plugin.create_token(auth[0]).replace("\n", "").replace("\r", "")
			
			auth_headers = {'X-Federation-Auth-Token' : token}
			#auth_headers = {'X-Auth-Token' : token, 'X-Local-Auth-Token' : token, 'Authorization' : token}

			return auth_headers
		else:
			raise Exception("Incorrect auth data")
			self.logger.error("Incorrect auth data")
		
		
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
				if protocol in ['fbw']:
					res_system = radl_system.clone()
	
					if not res_system.hasFeature('instance_type'):
						res_system.addFeature(Feature("instance_type", "=", self.INSTANCE_TYPE), conflict="me", missing="other")
					
					res_system.addFeature(Feature("disk.0.image.url", "=", str_url), conflict="other", missing="other")
						
					res_system.addFeature(Feature("provider.type", "=", self.type), conflict="other", missing="other")
					res_system.addFeature(Feature("provider.host", "=", self.cloud.server), conflict="other", missing="other")
					res_system.addFeature(Feature("provider.port", "=", self.cloud.port), conflict="other", missing="other")				
						
					res.append(res_system)
				
			return res

			
	def get_occi_attribute_value(self, occi_res, attr_name):
		"""
		Get the value of an OCCI attribute returned by an OCCI server
		"""
		lines = occi_res.split("\n")
		for l in lines:
			if l.find('X-OCCI-Attribute: ' + attr_name + '=') != -1:
				return str(l.split('=')[1].strip().strip('"'))
		return None
	
	"""
	text/plain format:
		Recurso:
		Category: fogbow_request; scheme="http://schemas.fogbowcloud.org/request#"; class="kind"; title="Request new Instances"; rel="http://schemas.ogf.org/occi/core#resource"; location="http://localhost:8182/fogbow_request/"; attributes="org.fogbowcloud.request.instance-count org.fogbowcloud.request.type org.fogbowcloud.request.valid-until org.fogbowcloud.request.valid-from org.fogbowcloud.request.state org.fogbowcloud.request.instance-id org.fogbowcloud.credentials.publickey.data org.fogbowcloud.request.user-data"
		Category: fogbow_small; scheme="http://schemas.fogbowcloud.org/template/resource#"; class="mixin"; title="Small Flavor"; rel="http://schemas.ogf.org/occi/infrastructure#resource_tpl"; location="http://localhost:8182/fogbow_small/"
		Category: fogbow-linux-x86; scheme="http://schemas.fogbowcloud.org/template/os#"; class="mixin"; title="fogbow-linux-x86 image"; rel="http://schemas.ogf.org/occi/infrastructure#os_tpl"; location="http://localhost:8182/fogbow-linux-x86/"
		Category: fogbow_userdata; scheme="http://schemas.fogbowcloud.org/request#"; class="mixin"; location="http://localhost:8182/fogbow_userdata/"
		X-OCCI-Attribute: org.fogbowcloud.credentials.publickey.data="Not defined" 
		X-OCCI-Attribute: org.fogbowcloud.request.state="fulfilled" 
		X-OCCI-Attribute: org.fogbowcloud.request.valid-from="Not defined" 
		X-OCCI-Attribute: occi.core.id="32b9f297-2728-4155-bcf5-409348aa474e" 
		X-OCCI-Attribute: org.fogbowcloud.request.user-data="IyEvYmluL3NoCklTX09QRU5TU0g9JChzc2ggLXZlciAyPiYxIHwgZ3JlcCBPcGVuU1NIKQpJU19EUk9QQkVBUj0kKHNzaCAtdmVyIDI+JjEgfCBncmVwIERyb3BiZWFyKQppZiBbIC1uICIkSVNfT1BFTlNTSCIgXTsgdGhlbgogIFNTSF9PUFRJT05TPSItbyBVc2VyS25vd25Ib3N0c0ZpbGU9L2Rldi9udWxsIC1vIFN0cmljdEhvc3RLZXlDaGVja2luZz1ubyAtbyBTZXJ2ZXJBbGl2ZUludGVydmFsPTMwIgplbGlmIFsgLW4gIiRJU19EUk9QQkVBUiIgXTsgdGhlbgogIFNTSF9PUFRJT05TPSIteSAtSyAzMCIKZmkKUkVNT1RFX1BPUlQ9JChjdXJsIC1YIFBPU1QgMTAuMC4wLjEwOjIyMjMvdG9rZW4vMzJiOWYyOTctMjcyOC00MTU1LWJjZjUtNDA5MzQ4YWE0NzRlKQpjYXQgPiAvYmluL2ZvZ2Jvdy1hdXRvc3NoIDw8IEVPTAojIS9iaW4vc2gKYXV0b3NzaCgpIHsKICB3aGlsZSB0cnVlOyBkbwogICAgZWNobyAiU3RhcnRpbmcgdHVubmVsIGluIHBvcnQgJFJFTU9URV9QT1JUIgogICAgc3NoICRTU0hfT1BUSU9OUyAtTiAtUiAwLjAuMC4wOiRSRU1PVEVfUE9SVDpsb2NhbGhvc3Q6MjIgMzJiOWYyOTctMjcyOC00MTU1LWJjZjUtNDA5MzQ4YWE0NzRlQDEwLjAuMC4xMCAtcCAyMjIyCiAgICBzbGVlcCA1CiAgZG9uZQp9CmF1dG9zc2ggJgpFT0wKY2htb2QgK3ggL2Jpbi9mb2dib3ctYXV0b3NzaApzZXRzaWQgL2Jpbi9mb2dib3ctYXV0b3NzaAo=" 
		X-OCCI-Attribute: org.fogbowcloud.request.type="one-time" 
		X-OCCI-Attribute: org.fogbowcloud.request.valid-until="Not defined" 
		X-OCCI-Attribute: org.fogbowcloud.request.instance-count="1" 
		X-OCCI-Attribute: org.fogbowcloud.request.instance-id="267@manager.i3m.upv.es"

		Instancia:
		Category: compute; scheme="http://schemas.ogf.org/occi/infrastructure#"; class="kind"; title="Compute Resource"; rel="http://schemas.ogf.org/occi/core#resource"; location="http://localhost:8182/compute/"; attributes="occi.compute.architecture occi.compute.state{immutable} occi.compute.speed occi.compute.memory occi.compute.cores occi.compute.hostname"; actions="http://schemas.ogf.org/occi/infrastructure/compute/action#start http://schemas.ogf.org/occi/infrastructure/compute/action#stop http://schemas.ogf.org/occi/infrastructure/compute/action#restart http://schemas.ogf.org/occi/infrastructure/compute/action#suspend"
		Category: os_tpl; scheme="http://schemas.ogf.org/occi/infrastructure#"; class="mixin"; location="http://localhost:8182/os_tpl/"
		Category: fogbow_small; scheme="http://schemas.fogbowcloud.org/template/resource#"; class="mixin"; title="Small Flavor"; rel="http://schemas.ogf.org/occi/infrastructure#resource_tpl"; location="http://localhost:8182/fogbow_small/"
		Category: fogbow-linux-x86; scheme="http://schemas.fogbowcloud.org/template/os#"; class="mixin"; title="fogbow-linux-x86 image"; rel="http://schemas.ogf.org/occi/infrastructure#os_tpl"; location="http://localhost:8182/fogbow-linux-x86/"
		X-OCCI-Attribute: occi.compute.state="active"
		X-OCCI-Attribute: occi.compute.hostname="one-267"
		X-OCCI-Attribute: occi.compute.memory="0.125"
		X-OCCI-Attribute: occi.compute.cores="1"
		X-OCCI-Attribute: org.fogbowcloud.request.ssh-public-address="158.42.104.75:20001"
		X-OCCI-Attribute: occi.core.id="267"
		X-OCCI-Attribute: occi.compute.architecture="x86"
		X-OCCI-Attribute: occi.compute.speed="Not defined"

	"""	
	def updateVMInfo(self, vm, auth_data):
		auth = self.get_auth_headers(auth_data)
		headers = {'Accept': 'text/plain'}
		if auth:
			headers.update(auth)
		
		try:			
			# First get the request info
			conn = httplib.HTTPConnection(self.cloud.server, self.cloud.port)
			conn.request('GET', "/fogbow_request/" + vm.id, headers = headers) 
			resp = conn.getresponse()
			
			output = resp.read()
			if resp.status == 404:
				vm.state = VirtualMachine.OFF
				return (True, vm)
			elif resp.status != 200:
				return (False, resp.reason + "\n" + output)
			else:
				instance_id = self.get_occi_attribute_value(output,'org.fogbowcloud.request.instance-id')
				if instance_id == "null":
					instance_id = None

				if not instance_id:
					vm.state = self.VM_REQ_STATE_MAP.get(self.get_occi_attribute_value(output, 'org.fogbowcloud.request.state'), VirtualMachine.UNKNOWN)
					return (True, vm)
				else:
					# Now get the instance info
					conn = httplib.HTTPConnection(self.cloud.server, self.cloud.port)
					conn.request('GET', "/compute/" + instance_id, headers = headers) 
					resp = conn.getresponse()
					
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
							vm.info.systems[0].addFeature(Feature("cpu.count", "=", int(cores)), conflict="other", missing="other")
						memory = self.get_occi_attribute_value(output, 'occi.compute.memory')
						if memory:
							vm.info.systems[0].addFeature(Feature("memory.size", "=", float(memory), 'G'), conflict="other", missing="other")
						
						# Update the network data
						ssh_public_address = self.get_occi_attribute_value(output, 'org.fogbowcloud.request.ssh-public-address')
						if ssh_public_address:
							parts = ssh_public_address.split(':')
							vm.setIps([parts[0]], [])
							if len(parts) > 1:
								vm.setSSHPort(int(parts[1]))
						
						return (True, vm)

		except Exception, ex:
			self.logger.exception("Error connecting with FogBow Manager")
			return (False, "Error connecting with FogBow Manager: " + str(ex))

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

	def launch(self, inf, radl, requested_radl, num_vm, auth_data):
		system = radl.systems[0]
		auth_headers = self.get_auth_headers(auth_data)

		#name = system.getValue("disk.0.image.name")
		
		res = []
		i = 0
		conn = httplib.HTTPConnection(self.cloud.server, self.cloud.port)

		url = uriparse(system.getValue("disk.0.image.url"))
		if url[1].startswith('http'):
			os_tpl = url[1] + url[2]
		else:
			os_tpl = url[1]
		
		# set the credentials the FogBow default username: fogbow
		system.delValue('disk.0.os.credentials.username')
		system.setValue('disk.0.os.credentials.username','fogbow')
		
		public_key = system.getValue('disk.0.os.credentials.public_key')
		
		if not public_key:
			# We must generate them
			(public_key, private_key) = self.keygen()
			system.setValue('disk.0.os.credentials.private_key', private_key)
		
		while i < num_vm:
			try:
				conn.putrequest('POST', "/fogbow_request/")
				conn.putheader('Content-Type', 'text/occi')
				#conn.putheader('Accept', 'text/occi')
				if auth_headers:
					for k, v in auth_headers.iteritems():
						conn.putheader(k, v)
				
				conn.putheader('Category', 'fogbow_request; scheme="http://schemas.fogbowcloud.org/request#"; class="kind"')
				
				conn.putheader('X-OCCI-Attribute', 'org.fogbowcloud.request.instance-count=1')
				conn.putheader('X-OCCI-Attribute', 'org.fogbowcloud.request.type="one-time"')
				
				conn.putheader('Category', 'fogbow_' + system.getValue('instance_type') + '; scheme="http://schemas.fogbowcloud.org/template/resource#"; class="mixin"')
				conn.putheader('Category', os_tpl + '; scheme="http://schemas.fogbowcloud.org/template/os#"; class="mixin"')
				conn.putheader('Category', 'fogbow_public_key; scheme="http://schemas.fogbowcloud/credentials#"; class="mixin"')

				conn.putheader('X-OCCI-Attribute', 'org.fogbowcloud.credentials.publickey.data="' + public_key.strip() + '"')

				conn.endheaders()

				resp = conn.getresponse()
				
				# With this format: X-OCCI-Location: http://158.42.104.75:8182/fogbow_request/436e76ef-9980-4fdb-87fe-71e82655f578
				output = resp.read()
				
				if resp.status != 201:
					res.append((False, resp.reason + "\n" + output))
				else:
					occi_vm_id = os.path.basename(resp.msg.dict['location'])
					#occi_vm_id = os.path.basename(output)				
					vm = VirtualMachine(inf, occi_vm_id, self.cloud, radl, requested_radl)
					vm.info.systems[0].setValue('instance_id', str(vm.id))
					res.append((True, vm))

			except Exception, ex:
				self.logger.exception("Error connecting with FogBow manager")
				res.append((False, "ERROR: " + str(ex)))

			i += 1
		
		return res

	def finalize(self, vm, auth_data):
		auth = self.get_auth_headers(auth_data)
		headers = {'Accept': 'text/plain'}
		if auth:
			headers.update(auth)
		
		try:
			# First get the request info
			conn = httplib.HTTPConnection(self.cloud.server, self.cloud.port)
			conn.request('GET', "/fogbow_request/" + vm.id, headers = headers) 
			resp = conn.getresponse()
			
			output = resp.read()
			if resp.status == 404:
				vm.state = VirtualMachine.OFF
				return (True, vm.id)
			elif resp.status != 200:
				return (False, "Error removing the VM: " + resp.reason + "\n" + output)
			else:
				instance_id = self.get_occi_attribute_value(output,'org.fogbowcloud.request.instance-id')
				if instance_id == "null":
					instance_id = None
				
				if instance_id:
					conn = httplib.HTTPConnection(self.cloud.server, self.cloud.port)
					conn.request('DELETE', "/compute/" + instance_id, headers = headers) 
					resp = conn.getresponse()	
				
					output = str(resp.read())
					if resp.status != 404 and resp.status != 200:
						return (False, "Error removing the VM: " + resp.reason + "\n" + output)

			conn = httplib.HTTPConnection(self.cloud.server, self.cloud.port)
			conn.request('DELETE', "/fogbow_request/" + vm.id, headers = headers) 
			resp = conn.getresponse()	
		
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
		return (False, "Not supported")
			
	def start(self, vm, auth_data):
		return (False, "Not supported")
			
	def alterVM(self, vm, radl, auth_data):
		return (False, "Not supported")

class IdentityPlugin:
	
	@staticmethod
	def create_token(params):
		"""
		Creates a token
		"""
		raise NotImplementedError( "Should have implemented this" )
	
	@staticmethod
	def getIdentityPlugin(identity_type):
		"""
		Returns the appropriate object to contact the IdentityPlugin
		"""
		if len(identity_type) > 15 or "." in identity_type:
			raise Exception("Not valid Identity Plugin.")
		try:
			return getattr(sys.modules[__name__], identity_type + "IdentityPlugin")()
		except Exception, ex:
			raise Exception("IdentityPlugin not supported: %s (error: %s)" % (identity_type, str(ex)))
	
class OpenNebulaIdentityPlugin(IdentityPlugin):
	
	@staticmethod
	def create_token(params):
		return params['username'] + ":" + params['password']

class X509IdentityPlugin(IdentityPlugin):
	
	@staticmethod
	def create_token(params):
		return params['proxy']
	
class VOMSIdentityPlugin(IdentityPlugin):
	
	@staticmethod
	def create_token(params):
		return params['proxy']

class KeyStoneIdentityPlugin(IdentityPlugin):
	"""
	Class to manage the Keystone auth tokens used in OpenStack
	"""
	
	@staticmethod
	def create_token(params):
		"""
		Contact the specified keystone server to return the token
		"""
		try:
			keystone_uri = params['auth_url']
			uri = uriparse(keystone_uri)
			server = uri[1].split(":")[0]
			port = int(uri[1].split(":")[1])

			conn = httplib.HTTPSConnection(server, port)
			conn.putrequest('POST', "/v2.0/tokens")
			conn.putheader('Accept', 'application/json')
			conn.putheader('Content-Type', 'application/json')
			conn.putheader('Connection', 'close')
			
			body = '{"auth":{"passwordCredentials":{"username": "' + params['username'] + '","password": "' + params['password'] + '"},"tenantName": "' + params['tenant'] + '"}}'
			
			conn.putheader('Content-Length', len(body))
			conn.endheaders(body)
	
			resp = conn.getresponse()
			
			# format: -> "{\"access\": {\"token\": {\"issued_at\": \"2014-12-29T17:10:49.609894\", \"expires\": \"2014-12-30T17:10:49Z\", \"id\": \"c861ab413e844d12a61d09b23dc4fb9c\"}, \"serviceCatalog\": [], \"user\": {\"username\": \"/DC=es/DC=irisgrid/O=upv/CN=miguel-caballer\", \"roles_links\": [], \"id\": \"475ce4978fb042e49ce0391de9bab49b\", \"roles\": [], \"name\": \"/DC=es/DC=irisgrid/O=upv/CN=miguel-caballer\"}, \"metadata\": {\"is_admin\": 0, \"roles\": []}}}"
			output = json.loads(resp.read())
			token_id = output['access']['token']['id']
			
			if conn.cert_file and os.path.isfile(conn.cert_file):
				os.unlink(conn.cert_file)
		
			return token_id
		except:
			return None