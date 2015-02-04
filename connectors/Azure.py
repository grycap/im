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

import base64
import httplib
import time
import os
import tempfile
from IM.xmlobject import XMLObject
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from CloudConnector import CloudConnector
from IM.radl.radl import network, UserPassCredential
from IM.config import Config

# clases para parsear el resultado de las llamadas a la API REST
class Endpoint(XMLObject):
	values = ['Name', 'Vip', 'PublicPort', 'LocalPort', 'Protocol', 'Port']

class InputEndpoints(XMLObject):
	tuples_lists = { 'InputEndpoint': Endpoint }

class ConfigurationSet(XMLObject):
	values = ['', '']
	
class ConfigurationSets(XMLObject):
	tuples_lists = { 'ConfigurationSet': ConfigurationSet }

class Role(XMLObject):
	values = ['RoleName', '<OsVersion i:nil="true"/>OsVersion']
	tuples = { 'ConfigurationSets': ConfigurationSets }
	
class RoleList(XMLObject):
	tuples_lists = { 'Role': Role }

class InstanceEndpoints(XMLObject):
	tuples_lists = { 'InstanceEndpoint': Endpoint }

class RoleInstance(XMLObject):
	values = ['InstanceSize', 'InstanceName', 'IpAddress', 'PowerState', 'HostName']
	tuples = { 'InstanceEndpoints': InstanceEndpoints }

class RoleInstanceList(XMLObject):
	tuples_lists = { 'RoleInstance': RoleInstance }

class Deployment(XMLObject):
	tuples = { 'RoleInstanceList': RoleInstanceList, 'RoleList': RoleList }
	values = ['Name', 'Status', 'Url']
	
	
# Para los discos
class AttachedTo(XMLObject):
	values = ['DeploymentName', 'HostedServiceName', 'RoleName']

class Disk(XMLObject):
	values = ['OS', 'Location', 'LogicalDiskSizeInGB', 'MediaLink', 'Name', 'SourceImageName']
	tuples = { 'AttachedTo': AttachedTo }

class Disks(XMLObject):
	tuples_lists = { 'Disk': Disk }

# Para el storage
class StorageServiceProperties(XMLObject):
	values = ['Description', 'Location', 'Label', 'Status', 'GeoReplicationEnabled', 'CreationTime']
	
class StorageService(XMLObject):
	values = ['Url', 'ServiceName']
	tuples = { 'StorageServiceProperties': StorageServiceProperties }



class AzureCloudConnector(CloudConnector):
	
	type = "Azure"
	INSTANCE_TYPE = 'Small'
	AZURE_SERVER = "management.core.windows.net"
	AZURE_PORT = 443
	STORAGE_NAME = "infmanager"
	
	VM_STATE_MAP = {
		'Starting': VirtualMachine.PENDING,
		'Running': VirtualMachine.RUNNING,
		'Stopping': VirtualMachine.OFF,
		'Stopped': VirtualMachine.OFF,
	}
	
	def get_azure_vm_create_xml(self, vm, storage_account, radl, num):
		system = radl.systems[0]
		name = system.getValue("disk.0.image.name")
		if not name:
			name = "userimage"
		url = uriparse(system.getValue("disk.0.image.url"))
		protocol = url[0]
		
		if protocol != "azr":
			self.logger.error("Protocolo incorrecto (no es azr) en la url: " + url)
			return None
		
		label = name + " IM created VM"
		(nodename, nodedom) = vm.getRequestedName(default_hostname = Config.DEFAULT_VM_NAME, default_domain = Config.DEFAULT_DOMAIN)
		hostname = nodename + "." +  nodedom
		
		if not hostname:
			hostname = "AzureNode"
		credentials = system.getCredentials()
		SourceImageName = url[1]
		MediaLink = "https://%s.blob.core.windows.net/vhds/%s.vhd" % (storage_account, SourceImageName)
		instance_type = self.get_instance_type(radl)
		
		disks = ""
		cont = 1
		while system.getValue("disk." + str(cont) + ".size") and system.getValue("disk." + str(cont) + ".device"):
			disk_size = system.getFeature("disk." + str(cont) + ".size").getValue('M')
			#disk_device = system.getValue("disk." + str(cont) + ".device")
			
			disks += '''
<DataVirtualHardDisks>
  <DataVirtualHardDisk>
    <HostCaching>ReadWrite</HostCaching> 
    <DiskName>data-disk-%d</DiskName>
    <Lun>%d</Lun>
    <LogicalDiskSizeInGB>%d</LogicalDiskSizeInGB>            
  </DataVirtualHardDisk>
</DataVirtualHardDisks>
			''' % (cont, cont, int(disk_size))

			cont +=1 
		
			
		# TODO: revisar esto
		if system.getValue("disk.0.os.name") == "windows":
			ConfigurationSet = '''
<ConfigurationSet i:type="WindowsProvisioningConfigurationSet">
  <ConfigurationSetType>WindowsProvisioningConfiguration</ConfigurationSetType>
  <ComputerName>%s</ComputerName>
  <AdminPassword>%s</AdminPassword>
  <AdminUsername>%s</AdminUsername>
  <EnableAutomaticUpdates>true</EnableAutomaticUpdates>
  <ResetPasswordOnFirstLogon>false</ResetPasswordOnFirstLogon>
</ConfigurationSet>
			''' % (hostname, credentials.password, credentials.username)
		else:
			if isinstance(credentials, UserPassCredential):
				ConfigurationSet = '''
	<ConfigurationSet i:type="LinuxProvisioningConfigurationSet">
	  <ConfigurationSetType>LinuxProvisioningConfiguration</ConfigurationSetType>
	  <HostName>%s</HostName>
	  <UserName>%s</UserName>
	  <UserPassword>%s</UserPassword>
	  <DisableSshPasswordAuthentication>false</DisableSshPasswordAuthentication>
	</ConfigurationSet>
				''' % (hostname, credentials.username, credentials.password)
			else:
				#TODO: Completar esto
				ConfigurationSet = '''
	<ConfigurationSet i:type="LinuxProvisioningConfigurationSet">
	  <ConfigurationSetType>LinuxProvisioningConfiguration</ConfigurationSetType>
	  <HostName>%s</HostName>
	  <UserName>%s</UserName>
	  <UserPassword>%s</UserPassword>
	  <DisableSshPasswordAuthentication>false</DisableSshPasswordAuthentication>
	  <SSH>
	    <PublicKeys>
              <PublicKey>
                <FingerPrint>certificate-fingerprint</FingerPrint>
                <Path>SSH-public-key-storage-location</Path>     
              </PublicKey>
            </PublicKeys>
            <KeyPairs>
              <KeyPair>
                <FingerPrint>%s</FinguerPrint>
                <Path>/home/%s/.ssh/id_rsa</Path>
              </KeyPair>
            </KeyPairs>
          </SSH>
	</ConfigurationSet>
				''' % (hostname, credentials.username, SourceImageName,  "", credentials.username)

		res = '''
<Deployment xmlns="http://schemas.microsoft.com/windowsazure" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
  <Name>%s</Name>
  <DeploymentSlot>Production</DeploymentSlot>
  <Label>%s</Label>
  <RoleList>
    <Role i:type="PersistentVMRole">
      <RoleName>IMVMRole</RoleName>
      <OsVersion i:nil="true"/>
      <RoleType>PersistentVMRole</RoleType>
      <ConfigurationSets>
      %s
        <ConfigurationSet i:type="NetworkConfigurationSet">
          <ConfigurationSetType>NetworkConfiguration</ConfigurationSetType>
          <InputEndpoints>
            <InputEndpoint>
              <LocalPort>22</LocalPort>
              <Name>SSH</Name>
              <Port>22</Port>
              <Protocol>TCP</Protocol>
            </InputEndpoint>
          </InputEndpoints>
        </ConfigurationSet>
      </ConfigurationSets>
      <Label>%s</Label>
      %s
      <OSVirtualHardDisk>
        <MediaLink>%s</MediaLink>
        <SourceImageName>%s</SourceImageName>
      </OSVirtualHardDisk>
      <RoleSize>%s</RoleSize> 
    </Role>
  </RoleList>
</Deployment>
		''' % (name, label, ConfigurationSet, label, disks, MediaLink, SourceImageName, instance_type)
		
		self.logger.debug("Azure VM Create XML: " + res)

		return res
		
	def get_user_subscription_id(self):
		if self.cloud.auth_data != None and 'subscription_id' in self.cloud.auth_data:
			return self.cloud.auth_data['subscription_id']
		else:
			return None

	def get_user_cert_data(self):
		if self.cloud.auth_data != None and 'certificate' in self.cloud.auth_data and 'private_key' in self.cloud.auth_data:
			certificate = self.cloud.auth_data['certificate']
			fd, cert_file = tempfile.mkstemp()
			os.write(fd, certificate)
			os.close(fd)
			os.chmod(cert_file,0644)
			
			private_key = self.cloud.auth_data['private_key']
			fd, key_file = tempfile.mkstemp()
			os.write(fd, private_key)
			os.close(fd)
			os.chmod(key_file,0400)

			return (cert_file, key_file)
		else:
			return None

	def create_service(self):
		subscription_id = self.get_user_subscription_id()
		auth = self.get_user_cert_data()
		
		if auth is None or subscription_id is None:
			return [(False, "Datos de autenticacion incorrectos")]
		else:
			cert_file, key_file = auth
		
		service_name = str(int(time.time()*100))
		self.logger.info("Creamos el servicio " + service_name)
		
		try:

			conn = httplib.HTTPSConnection(self.AZURE_SERVER, self.AZURE_PORT, key_file=key_file, cert_file=cert_file)
			uri = "https://%s/%s/services/hostedservices" % (self.AZURE_SERVER,subscription_id)
			service_create_xml = '''
	<CreateHostedService xmlns="http://schemas.microsoft.com/windowsazure">
	  <ServiceName>%s</ServiceName>
	  <Label>%s</Label>
	  <Description>Service %s created by the IM</Description>
	  <Location>West Europe</Location>
	</CreateHostedService> 
			''' % (service_name, base64.b64encode(service_name), service_name )
			conn.request('POST', uri, body = service_create_xml, headers = {'x-ms-version' : '2013-03-01', 'Content-Type' : 'application/xml'}) 
			resp = conn.getresponse()
			output = resp.read()
		except Exception:
			self.logger.exception("Error creando el service")
			return None
		
		if resp.status != 201:
			self.logger.error("Error creando el service: Codigo " + str(resp.status) + ". Msg: " + output)
			return None
		
		return service_name
	
	def delete_service(self, service_name):
		self.logger.info("Borramos el servicio " + service_name)
		subscription_id = self.get_user_subscription_id()
		auth = self.get_user_cert_data()
		
		if auth is None or subscription_id is None:
			return [(False, "Datos de autenticacion incorrectos")]
		else:
			cert_file, key_file = auth
		
		try:
			conn = httplib.HTTPSConnection(self.AZURE_SERVER, self.AZURE_PORT, cert_file=cert_file, key_file=key_file)
			uri = "/%s/services/hostedservices/%s" % (subscription_id, service_name)
			conn.request('DELETE', uri, headers = {'x-ms-version' : '2013-03-01'}) 
			resp = conn.getresponse()
			output = resp.read()
		except Exception:
			self.logger.exception("Error borrando el service")
			return False
		
		if resp.status != 200:
			self.logger.error("Error borrando el service: Codigo " + str(resp.status) + ". Msg: " + output)
			return False

		return True
	
	def wait_operation_status(self, request_id, req_status = 200, delay = 2, timeout = 60):
		subscription_id = self.get_user_subscription_id()
		auth = self.get_user_cert_data()
		
		if auth is None or subscription_id is None:
			return False
		else:
			cert_file, key_file = auth

		self.logger.info("Esperamos que la operacion: " + request_id + " Finalice con estado " + str(req_status))
		status = 0
		wait = 0
		while status != req_status and wait < timeout:
			time.sleep(delay)
			wait += delay
			try:
				conn = httplib.HTTPSConnection(self.AZURE_SERVER, self.AZURE_PORT, cert_file=cert_file, key_file=key_file)
				uri = "/%s/operations/%s" % (subscription_id, request_id)
				conn.request('GET', uri, headers = {'x-ms-version' : '2013-03-01'}) 
				resp = conn.getresponse()
				status = resp.status
				self.logger.debug("Estado de la operacion: " + str(status))
			except Exception:
				self.logger.exception("Error obteniendo el estado de la operacion: " + request_id)
		
		if status == req_status:
			return True
		else:
			self.logger.exception("Error esperando la operacion")
			return False
	
	def create_storage_account(self, storage_account, timeout = 120):
		subscription_id = self.get_user_subscription_id()
		auth = self.get_user_cert_data()
		
		if auth is None or subscription_id is None:
			return None
		else:
			cert_file, key_file = auth

		self.logger.info("Creamos el storage account " + storage_account)
		try:
			conn = httplib.HTTPSConnection(self.AZURE_SERVER, self.AZURE_PORT, cert_file=cert_file, key_file=key_file)
			uri = "/%s/services/storageservices" % subscription_id
			storage_create_xml = '''
<CreateStorageServiceInput xmlns="http://schemas.microsoft.com/windowsazure">
  <ServiceName>%s</ServiceName>
  <Description>Storage %s created by the IM</Description>
  <Label>%s</Label>
  <Location>West Europe</Location>
  <GeoReplicationEnabled>false</GeoReplicationEnabled>
  <ExtendedProperties>
    <ExtendedProperty>
      <Name>AccountCreatedBy</Name>
      <Value>RestAPI</Value>
    </ExtendedProperty>
  </ExtendedProperties>
</CreateStorageServiceInput> 
			''' % (storage_account, storage_account, base64.b64encode(storage_account))
			conn.request('POST', uri, body = storage_create_xml, headers = {'x-ms-version' : '2013-03-01', 'Content-Type' : 'application/xml'}) 
			resp = conn.getresponse()
			output = resp.read()
		except Exception:
			self.logger.exception("Error creando el storage account")
			return None
		
		if resp.status != 202:
			self.logger.error("Error creando el storage account: Codigo " + str(resp.status) + ". Msg: " + output)
			return None

		request_id = resp.getheader('x-ms-request-id')
		
		# Llamar a GET OPERATION STATUS hasta que sea 200 (OK)
		success = self.wait_operation_status(request_id)
		
		# Nos tenemos que asegurar de que el storage esta "Created"
		status = None
		delay = 2
		wait = 0
		while status != "Created" and wait < timeout:
			status = self.check_storage_account(storage_account)
			if status != "Created":
				time.sleep(delay)
				wait += delay

		if success:
			return storage_account
		else:
			self.logger.exception("Error creando el storage account")
			self.delete_storage_account(storage_account)
			return None
	
	def delete_storage_account(self, storage_account):
		self.logger.info("Borramos el storage account " + storage_account)
		subscription_id = self.get_user_subscription_id()
		auth = self.get_user_cert_data()
		
		if auth is None or subscription_id is None:
			return False
		else:
			cert_file, key_file = auth
		
		try:
			conn = httplib.HTTPSConnection(self.AZURE_SERVER, self.AZURE_PORT, cert_file=cert_file, key_file=key_file)
			uri = "/%s/services/storageservices/%s" % (subscription_id, storage_account)
			conn.request('DELETE', uri, headers = {'x-ms-version' : '2013-03-01'}) 
			resp = conn.getresponse()
			output = resp.read()
		except Exception:
			self.logger.exception("Error borrando el storage account")
			return False
		
		if resp.status != 200:
			self.logger.error("Error borrando el storage account: Codigo " + str(resp.status) + ". Msg: " + output)
			return False

		return True
	
	def check_storage_account(self, storage_account):
		self.logger.info("Miramos si existe el storage account " + storage_account)
		subscription_id = self.get_user_subscription_id()
		auth = self.get_user_cert_data()
		
		if auth is None or subscription_id is None:
			return False
		else:
			cert_file, key_file = auth
		
		try:
			conn = httplib.HTTPSConnection(self.AZURE_SERVER, self.AZURE_PORT, cert_file=cert_file, key_file=key_file)
			uri = "/%s/services/storageservices/%s" % (subscription_id, storage_account)
			conn.request('GET', uri, headers = {'x-ms-version' : '2013-03-01'}) 
			resp = conn.getresponse()
			output = resp.read()
			storage_info = StorageService(output)
			status = storage_info.StorageServiceProperties.Status
			self.logger.debug("Estado del storage " + storage_account + " es: " + status)
		except Exception:
			self.logger.exception("Error buscando el storage account")
			return None
		
		if resp.status != 200:
			self.logger.debug("El storage account no existe: Codigo " + str(resp.status) + ". Msg: " + output)
			return None

		return status

	def get_disk_name(self, name):
		self.logger.debug("Obtenemos el nombre del disco " + name)
		subscription_id = self.get_user_subscription_id()
		auth = self.get_user_cert_data()

		if auth is None or subscription_id is None:
			return  None
		else:
			cert_file, key_file = auth

		try:
			conn = httplib.HTTPSConnection(self.AZURE_SERVER, self.AZURE_PORT, cert_file=cert_file, key_file=key_file)
			uri = "/%s/services/disks" % (subscription_id)
			conn.request('GET', uri, headers = {'x-ms-version' : '2013-03-01'})
			resp = conn.getresponse()
			output = resp.read()
		except Exception:
			self.logger.exception("Error listando los discos")
			return  None

		if resp.status != 200:
			self.logger.error("Error listando los discos: Codigo " + str(resp.status) + ". Msg: " + output)
			return  None

		self.logger.debug(output)
		disks_info = Disks(output)
		
		for disk in disks_info.Disk:
			if disk.AttachedTo and disk.AttachedTo.HostedServiceName == name:
				return disk.Name
		
		return None

	
	def delete_disk(self, disk_name):
		self.logger.debug("Borramos el disco " + disk_name)
		subscription_id = self.get_user_subscription_id()
		auth = self.get_user_cert_data()

		if auth is None or subscription_id is None:
			return False
		else:
			cert_file, key_file = auth

		try:
			conn = httplib.HTTPSConnection(self.AZURE_SERVER, self.AZURE_PORT, cert_file=cert_file, key_file=key_file)
			uri = "/%s/services/disks/%s" % (subscription_id, disk_name)
			conn.request('DELETE', uri, headers = {'x-ms-version' : '2013-03-01'})
			resp = conn.getresponse()
			output = resp.read()
		except Exception:
			self.logger.exception("Error borrando el disco")
			return False

		if resp.status != 200:
			self.logger.error("Error borrando el disco: Codigo " + str(resp.status) + ". Msg: " + output)
			return False

		return resp.status


	def launch(self, inf, radl, requested_radl, num_vm, auth_data):
		subscription_id = self.get_user_subscription_id()
		auth = self.get_user_cert_data()
		
		if auth is None or subscription_id is None:
			return [(False, "Datos de autenticacion incorrectos")]
		else:
			cert_file, key_file = auth

		res = []
		i = 0
		while i < num_vm:
			try:
				conn = httplib.HTTPSConnection(self.AZURE_SERVER, self.AZURE_PORT, cert_file=cert_file, key_file=key_file)
				# Creamos el servicio
				service_name = self.create_service()
				if service_name is None:
					res.append((False, "Error creando el servicio"))
					break
				
				# y el storage account
				if not self.check_storage_account(self.STORAGE_NAME):
					storage_account = self.create_storage_account(self.STORAGE_NAME)
				else:
					storage_account = self.STORAGE_NAME
					
				if storage_account is None:
					self.delete_service(service_name)
					res.append((False, "Error creando el storage account"))
					break
				
				self.logger.debug("Creamos la VM con id: " + service_name)
				
				# Create the VM to get the nodename
				vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl)
				
				# generamos el XML para crear la VM
				vm_create_xml = self.get_azure_vm_create_xml(vm, storage_account, radl, i)
				
				if vm_create_xml == None:
					#self.delete_storage_account(storage_account)
					self.delete_service(service_name)
					res.append((False, "Datos de la imagen o de autenticacion incorrectos"))
					break

				uri = "/%s/services/hostedservices/%s/deployments" % (subscription_id, service_name)
				conn.request('POST', uri, body = vm_create_xml, headers = {'x-ms-version' : '2013-03-01', 'Content-Type' : 'application/xml'}) 
				resp = conn.getresponse()
				output = resp.read()
				
				if resp.status != 202:
					#self.delete_storage_account(storage_account)
					self.delete_service(service_name)
					self.logger.error("Error creando la VM: Codigo " + str(resp.status) + ". Msg: " + output)
					res.append((False, "Error creando la VM: Codigo " + str(resp.status) + ". Msg: " + output))
				else:
					#Llamar a GET OPERATION STATUS hasta que sea 200 (OK)
					request_id = resp.getheader('x-ms-request-id')
					success = self.wait_operation_status(request_id)
					if success:
						vm.id = service_name
						res.append((True, vm))
					else:
						self.logger.exception("Error esperando la creancion la VM")
						res.append((False, "Error esperando la creancion la VM"))

			except Exception, ex:
				self.logger.exception("Error creando la VM")
				res.append((False, "Error creando la VM: " + str(ex)))

			i += 1
		return res

	def get_instance_type(self, radl):
		system = radl.systems[0]
		cpu = system.getValue('cpu.count')
		arch = system.getValue('cpu.arch')	
		memory = system.getFeature('memory.size').getValue('M')
		
		instace_types = InstanceTypes.get_all_instance_types()

		res = None
		for type in instace_types:
			# cogemos la de menor precio
			if res is None or (type.price <= res.price):
				if arch in type.cpu_arch and type.cores_per_cpu * type.num_cpu >= cpu and type.mem >= memory:
					res = type
		
		if res is None:
			self.logger.debug("Lanzaremos una instancia de tipo: " + self.INSTANCE_TYPE)
			return self.INSTANCE_TYPE
		else:
			self.logger.debug("Lanzaremos una instancia de tipo: " + res.name)
			return res.name
		
	def updateVMInfo(self, vm):
		self.logger.debug("Obtenemos la info de la VM con id: " + vm.id)
		auth = self.get_user_cert_data()
		subscription_id = self.get_user_subscription_id()
		
		if auth is None or subscription_id is None:
			return [(False, "Datos de autenticacion incorrectos")]
		else:
			cert_file, key_file = auth

		service_name = vm.id
	
		try:
			conn = httplib.HTTPSConnection(self.AZURE_SERVER, self.AZURE_PORT, cert_file=cert_file, key_file=key_file)
			uri = "/%s/services/hostedservices/%s/deploymentslots/Production" % (subscription_id, service_name)
			conn.request('GET', uri, headers = {'x-ms-version' : '2013-03-01'}) 
			resp = conn.getresponse()
			output = resp.read()
		except Exception, ex:
			self.logger.exception("Error al obtener la informacion de la VM: " + vm.id)
			return (False, "Error al obtener la informacion de la VM: " + vm.id + ". " + str(ex))
		
		if resp.status != 200:
			self.logger.error("Error al obtener la informacion de la VM: " + vm.id + ". Codigo: " + str(resp.status) + ". Msg: " + output)
			self.delete_service(service_name)
			return (False, "Error al obtener la informacion de la VM: " + vm.id + ". Codigo: " + str(resp.status) + ". Msg: " + output)
		else:
			self.logger.debug("Info de la VM: " + vm.id + " obtenida.")
			# TODO: Arregla el problema de los namespaces
			# de momento hago una chapuza para evitarlo
			output = output.replace("i:type","type")
			self.logger.debug(output)
			vm_info = Deployment(output)
			
			self.logger.debug("El estado de la VM es: " + vm_info.Status)
				
			vm.state = self.VM_STATE_MAP.get(vm_info.Status, VirtualMachine.UNKNOWN)
			
			# Actualizamos los datos de la red
			self.setIPs(vm,vm_info)
			return (True, vm)

	def setIPs(self, vm, vm_info):
		num_nets = 0
		now = str(int(time.time()*100))
		#vm.info.network = []

		private_ip = None
		public_ip = None
		try:
			role_instance = vm_info.RoleInstanceList.RoleInstance[0]
			private_ip = role_instance.IpAddress
			public_ip = role_instance.InstanceEndpoints.InstanceEndpoint[0].Vip
		except:
			self.logger.debug("No IP info")
			pass

		if private_ip:
			vm.info.systems[0].setValue('net_interface.' + str(num_nets) + '.ip', str(private_ip))

			private_net = None
			for net in vm.info.network:
				if not net.isPublic():
					private_net = net
			
			if private_net is None:
				private_net = network.createNetwork("private." + now)
				vm.info.network.append(private_net)
			
			vm.info.systems[0].setValue('net_interface.' + str(num_nets) + '.connection',private_net.id)
				
			num_nets += 1
			
		if public_ip and public_ip != private_ip:
			vm.info.systems[0].setValue('net_interface.' + str(num_nets) + '.ip', str(public_ip))
				
			public_net = None
			for net in vm.info.network:
				if net.isPublic():
					public_net = net
			
			if public_net is None:
				public_net = network.createNetwork("public." + now, True)
				vm.info.network.append(public_net)
			
			vm.info.systems[0].setValue('net_interface.' + str(num_nets) + '.connection',public_net.id)
				
			num_nets += 1

	def finalize(self, vm):
		self.logger.debug("Terminamos la VM con id: " + vm.id)
		subscription_id = self.get_user_subscription_id()
		auth = self.get_user_cert_data()
		
		if auth is None or subscription_id is None:
			return (False, "Datos de autenticacion incorrectos")
		else:
			cert_file, key_file = auth

		service_name = vm.id
		
		# Antes de borrarla sacamos el nombre del disco para luego borrarlo
		disk_name = self.get_disk_name(service_name)
		
		res = (False,'')
		try:
			conn = httplib.HTTPSConnection(self.AZURE_SERVER, self.AZURE_PORT, cert_file=cert_file, key_file=key_file)
	
			uri = "/%s/services/hostedservices/%s/deploymentslots/Production" % (subscription_id, service_name)
			conn.request('DELETE', uri, headers = {'x-ms-version' : '2013-03-01'}) 
			resp = conn.getresponse()
			output = resp.read()
			
			if resp.status != 202:
				self.logger.error("Error al finalizar la VM: " + vm.id + ". Codigo: " + str(resp.status) + ". Msg: " + output)
				res = (False, "Error al finalizar la VM: " + vm.id + ". Codigo: " + str(resp.status) + ". Msg: " + output)
			else:
				self.logger.debug("VM finalizada: " + vm.id)
				res = (True, vm.id)
		except Exception, ex:
			self.logger.exception("Error al finalizar la VM: " + vm.id)
			res = (False, "Error al finalizar la VM: " + vm.id + ". " + str(ex))

		request_id = resp.getheader('x-ms-request-id')
		
		# Esperar a que acabe la operacion de eliminar la maquina virtual. Llamar a GET OPERATION STATUS hasta que sea 200 (OK)
		self.wait_operation_status(request_id)

		# en cualquier caso hay que probar a borrar esto
		self.delete_service(service_name)
		# HAY QUE BORRAR EL DISCO ALMACENADO EN ELLA

		# Esto lo intentamos varias veces para asegurarnos de que se borra
		# porque a veces la VM no ha liberado el disco a tiempo
		status = 0
		retries = 50
		delay = 10
		while disk_name and status != 200 and retries > 0:
			status = self.delete_disk(disk_name)
			if status != 200:
				retries -= 1
				time.sleep(delay)
		#self.delete_storage_account(self.STORAGE_NAME)
		
		return res
			

# Como Azure no te lo proporciona con su API, lo hacemos estatico
class InstanceTypeInfo:
	def __init__(self, name = "", cpu_arch = ["i386"], num_cpu = 1, cores_per_cpu = 1, mem = 0, price = 0):
		self.name = name
		self.num_cpu = num_cpu
		self.cores_per_cpu = cores_per_cpu
		self.mem = mem
		self.cpu_arch = cpu_arch
		self.price = price

class InstanceTypes:
	@staticmethod
	def get_all_instance_types():
		list = []
		
		small = InstanceTypeInfo("Small", ["x86_64"], 1, 1, 1740, 0.12)
		list.append(small)
		medium = InstanceTypeInfo("Medium", ["x86_64"], 1, 2, 3584, 0.24)
		list.append(medium)
		large = InstanceTypeInfo("Large", ["x86_64"], 1, 4, 7168, 0.48)
		list.append(large)
		xlarge = InstanceTypeInfo("Extra Large", ["x86_64"], 1, 8, 15360, 0.96)
		list.append(xlarge)
		
		
		return list
