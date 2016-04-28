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
from radl.radl import UserPassCredential, Feature
from IM.config import Config

# Set of classes to parse the output of the REST API


class Endpoint(XMLObject):
    values = ['Name', 'Vip', 'PublicPort', 'LocalPort', 'Protocol']


class InstanceEndpoints(XMLObject):
    tuples_lists = {'InstanceEndpoint': Endpoint}


class DataVirtualHardDisk(XMLObject):
    values = ['DiskName', 'Lun']


class DataVirtualHardDisks(XMLObject):
    tuples_lists = {'DataVirtualHardDisk': DataVirtualHardDisk}


class Role(XMLObject):
    values = ['RoleName', 'RoleType']
    tuples = {'DataVirtualHardDisks': DataVirtualHardDisks}


class RoleList(XMLObject):
    tuples_lists = {'Role': Role}


class RoleInstance(XMLObject):
    values = ['RoleName', 'InstanceStatus', 'InstanceSize',
              'InstanceName', 'IpAddress', 'PowerState']
    tuples = {'InstanceEndpoints': InstanceEndpoints}


class RoleInstanceList(XMLObject):
    tuples_lists = {'RoleInstance': RoleInstance}


class Deployment(XMLObject):
    tuples = {'RoleInstanceList': RoleInstanceList, 'RoleList': RoleList}
    values = ['Name', 'Status', 'Url']


class StorageServiceProperties(XMLObject):
    values = ['Description', 'Location', 'Label', 'Status', 'GeoReplicationEnabled',
              'CreationTime', 'GeoPrimaryRegion', 'GeoSecondaryRegion']


class StorageService(XMLObject):
    values = ['Url', 'ServiceName']
    tuples = {'StorageServiceProperties': StorageServiceProperties}


class Error(XMLObject):
    values = ['Code', 'Message']


class Operation(XMLObject):
    values = ['ID', 'Status', 'HttpStatusCode']
    tuples = {'Error': Error}


class RoleSize(XMLObject):
    values = ['Name', 'Label', 'Cores', 'MemoryInMb', 'SupportedByVirtualMachines',
              'MaxDataDiskCount', 'VirtualMachineResourceDiskSizeInMb']
    numeric = ['Cores', 'MemoryInMb', 'MaxDataDiskCount',
               'VirtualMachineResourceDiskSizeInMb']


class RoleSizes(XMLObject):
    tuples_lists = {'RoleSize': RoleSize}


class AzureCloudConnector(CloudConnector):
    """
    Cloud Launcher to the Azure platform
    Using the Service Management REST API Reference:
    https://msdn.microsoft.com/en-us/library/azure/ee460799.aspx
    """

    type = "Azure"
    """str with the name of the provider."""
    INSTANCE_TYPE = 'ExtraSmall'
    """Default instance type."""
    AZURE_SERVER = "management.core.windows.net"
    """Address of the server with the Service Management REST API."""
    AZURE_PORT = 443
    """Port of the server with the Service Management REST API."""
    DEFAULT_LOCATION = "North Europe"
    """Default location to use"""
    ROLE_NAME = "IMVMRole"
    """Name of the Role"""

    DEPLOY_STATE_MAP = {
        'Running': VirtualMachine.RUNNING,
        'Suspended': VirtualMachine.STOPPED,
        'SuspendedTransitioning': VirtualMachine.STOPPED,
        'RunningTransitioning': VirtualMachine.RUNNING,
        'Starting': VirtualMachine.PENDING,
        'Suspending': VirtualMachine.STOPPED,
        'Deploying': VirtualMachine.PENDING,
        'Deleting': VirtualMachine.OFF,
    }

    ROLE_STATE_MAP = {
        'Starting': VirtualMachine.PENDING,
        'Started': VirtualMachine.RUNNING,
        'Stopping': VirtualMachine.STOPPED,
        'Stopped': VirtualMachine.STOPPED,
        'Unknown': VirtualMachine.UNKNOWN
    }

    def __init__(self, cloud_info):
        self.cert_file = ''
        self.key_file = ''
        self.instance_type_list = None
        CloudConnector.__init__(self, cloud_info)

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

                protocol = url[0]
                if protocol == "azr":
                    res_system = radl_system.clone()
                    instance_type = self.get_instance_type(
                        res_system, auth_data)
                    if not instance_type:
                        self.logger.error(
                            "Error generating the RADL of the VM, no instance type available for the requirements.")
                        self.logger.debug(res_system)
                    else:
                        res_system.addFeature(
                            Feature("disk.0.image.url", "=", str_url), conflict="other", missing="other")
                        self.update_system_info_from_instance(
                            res_system, instance_type)
                        res_system.addFeature(
                            Feature("provider.type", "=", self.type), conflict="other", missing="other")

                        username = res_system.getValue(
                            'disk.0.os.credentials.username')
                        if not username:
                            res_system.setValue(
                                'disk.0.os.credentials.username', 'azureuser')

                        res_system.updateNewCredentialValues()

                        res.append(res_system)
            return res

    def gen_input_endpoints(self, radl):
        """
        Gen the InputEndpoints part of the XML of the VM creation
        using the outports field of the RADL network
        """
        # SSH port must be allways available
        res = """
          <InputEndpoints>
            <InputEndpoint>
              <LocalPort>5986</LocalPort>
              <Name>WinRM</Name>
              <Port>5986</Port>
              <Protocol>TCP</Protocol>
            </InputEndpoint>
            <InputEndpoint>
              <LocalPort>22</LocalPort>
              <Name>SSH</Name>
              <Port>22</Port>
              <Protocol>TCP</Protocol>
            </InputEndpoint>"""

        public_net = None
        for net in radl.networks:
            if net.isPublic():
                public_net = net

        if public_net:
            outports = public_net.getOutPorts()
            if outports:
                for remote_port, remote_protocol, local_port, local_protocol in outports:
                    if local_port != 22 and local_port != 5986:
                        protocol = remote_protocol
                        if remote_protocol != local_protocol:
                            self.logger.warn(
                                "Diferent protocols used in outports ignoring local port protocol!")

                        res += """
            <InputEndpoint>
              <LocalPort>%d</LocalPort>
              <Name>Port %d</Name>
              <Port>%d</Port>
              <Protocol>%s</Protocol>
            </InputEndpoint>""" % (local_port, local_port, remote_port, protocol.upper())

        res += "\n          </InputEndpoints>"
        return res

    def gen_configuration_set(self, hostname, system):
        """
        Gen the ConfigurationSet part of the XML of the VM creation
        """
        # Allways use the new credentials
        system.updateNewCredentialValues()
        credentials = system.getCredentials()

        if system.getValue("disk.0.os.name") == "windows":
            ConfigurationSet = '''
<ConfigurationSet i:type="WindowsProvisioningConfigurationSet">
  <ConfigurationSetType>WindowsProvisioningConfiguration</ConfigurationSetType>
  <ComputerName>%s</ComputerName>
  <AdminPassword>%s</AdminPassword>
  <AdminUsername>%s</AdminUsername>
  <EnableAutomaticUpdates>true</EnableAutomaticUpdates>
  <ResetPasswordOnFirstLogon>false</ResetPasswordOnFirstLogon>
</ConfigurationSet>''' % (hostname, credentials.password, credentials.username)
        else:
            if isinstance(credentials, UserPassCredential):
                ConfigurationSet = '''
    <ConfigurationSet i:type="LinuxProvisioningConfigurationSet">
      <ConfigurationSetType>LinuxProvisioningConfiguration</ConfigurationSetType>
      <HostName>%s</HostName>
      <UserName>%s</UserName>
      <UserPassword>%s</UserPassword>
      <DisableSshPasswordAuthentication>false</DisableSshPasswordAuthentication>
    </ConfigurationSet>''' % (hostname, credentials.username, credentials.password)
            else:
                ConfigurationSet = '''
    <ConfigurationSet i:type="LinuxProvisioningConfigurationSet">
      <ConfigurationSetType>LinuxProvisioningConfiguration</ConfigurationSetType>
      <HostName>%s</HostName>
      <UserName>%s</UserName>
      <UserPassword>%s</UserPassword>
      <DisableSshPasswordAuthentication>true</DisableSshPasswordAuthentication>
      <SSH>
        <PublicKeys>
              <PublicKey>
                <FingerPrint>%s</FingerPrint>
                <Path>/home/%s/.ssh/authorized_keys</Path>
              </PublicKey>
            </PublicKeys>
            <KeyPairs>
              <KeyPair>
                <FingerPrint>%s</FinguerPrint>
                <Path>/home/%s/.ssh/id_rsa</Path>
              </KeyPair>
            </KeyPairs>
          </SSH>
    </ConfigurationSet>''' % (hostname, credentials.username, "Pass+Not-Used1",
                              credentials.public_key, credentials.username,
                              credentials.public_key, credentials.username)

        return ConfigurationSet

    def gen_data_disks(self, system, storage_account):
        """
        Gen the DataVirtualHardDisks part of the XML of the VM creation
        """

        disks = ""
        cont = 1
        while system.getValue("disk." + str(cont) + ".size") and system.getValue("disk." + str(cont) + ".device"):
            disk_size = system.getFeature(
                "disk." + str(cont) + ".size").getValue('G')

            disk_name = "datadisk-1-" + str(int(time.time() * 100))
            disks += '''
<DataVirtualHardDisks>
  <DataVirtualHardDisk>
    <HostCaching>ReadWrite</HostCaching>
    <Lun>%d</Lun>
    <LogicalDiskSizeInGB>%d</LogicalDiskSizeInGB>
    <MediaLink>https://%s.blob.core.windows.net/vhds/%s.vhd</MediaLink>
  </DataVirtualHardDisk>
</DataVirtualHardDisks> ''' % (cont, int(disk_size), storage_account, disk_name)

            cont += 1

        return disks

    def get_azure_vm_create_xml(self, vm, storage_account, radl, num, auth_data):
        """
        Generate the XML to create the VM
        """
        system = radl.systems[0]
        name = system.getValue("instance_name")
        if not name:
            name = system.getValue("disk.0.image.name")
        if not name:
            name = "userimage" + str(num)
        url = uriparse(system.getValue("disk.0.image.url"))

        label = name + " IM created VM"
        (hostname, _) = vm.getRequestedName(
            default_hostname=Config.DEFAULT_VM_NAME, default_domain=Config.DEFAULT_DOMAIN)

        if not hostname:
            hostname = "AzureNode" + str(num)

        SourceImageName = url[1]
        MediaLink = "https://%s.blob.core.windows.net/vhds/%s.vhd" % (
            storage_account, SourceImageName)
        instance_type = self.get_instance_type(system, auth_data)

        DataVirtualHardDisks = self.gen_data_disks(system, storage_account)
        ConfigurationSet = self.gen_configuration_set(hostname, system)
        InputEndpoints = self.gen_input_endpoints(radl)

        res = '''
<Deployment xmlns="http://schemas.microsoft.com/windowsazure" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
  <Name>%s</Name>
  <DeploymentSlot>Production</DeploymentSlot>
  <Label>%s</Label>
  <RoleList>
    <Role i:type="PersistentVMRole">
      <RoleName>%s</RoleName>
      <OsVersion i:nil="true"/>
      <RoleType>PersistentVMRole</RoleType>
      <ConfigurationSets>
      %s
        <ConfigurationSet i:type="NetworkConfigurationSet">
          <ConfigurationSetType>NetworkConfiguration</ConfigurationSetType>
          %s
        </ConfigurationSet>
      </ConfigurationSets>
      %s
      <OSVirtualHardDisk>
        <MediaLink>%s</MediaLink>
        <SourceImageName>%s</SourceImageName>
      </OSVirtualHardDisk>
      <RoleSize>%s</RoleSize>
    </Role>
  </RoleList>
</Deployment>
        ''' % (vm.id, label, self.ROLE_NAME, ConfigurationSet, InputEndpoints,
               DataVirtualHardDisks, MediaLink, SourceImageName, instance_type.Name)

        self.logger.debug("Azure VM Create XML: " + res)

        return res

    def get_connection_and_subscription_id(self, auth_data):
        auths = auth_data.getAuthInfo(self.type)
        if not auths:
            raise Exception("No auth data has been specified to Azure.")
        else:
            auth = auths[0]

        if 'username' in auth:
            subscription_id = auth['username']
        else:
            raise Exception(
                "No correct auth data has been specified to Azure: username, public_key and private_key.")

        # We check if the cert and key files exist
        if os.path.isfile(self.cert_file) and os.path.isfile(self.key_file):
            cert_file = self.cert_file
            key_file = self.key_file
        else:
            cert_file, key_file = self.get_user_cert_data(auth)
            self.cert_file = cert_file
            self.key_file = key_file

        conn = httplib.HTTPSConnection(
            self.AZURE_SERVER, self.AZURE_PORT, cert_file=cert_file, key_file=key_file)

        return conn, subscription_id

    def get_user_cert_data(self, auth):
        """
        Get the Azure private_key and public_key files from the auth data
        """
        if 'public_key' in auth and 'private_key' in auth:
            certificate = auth['public_key']
            fd, cert_file = tempfile.mkstemp()
            os.write(fd, certificate)
            os.close(fd)
            os.chmod(cert_file, 0644)

            private_key = auth['private_key']
            fd, key_file = tempfile.mkstemp()
            os.write(fd, private_key)
            os.close(fd)
            os.chmod(key_file, 0600)

            return (cert_file, key_file)
        else:
            self.logger.error(
                "No correct auth data has been specified to Azure: username, public_key and private_key.")
            raise Exception(
                "No correct auth data has been specified to Azure: username, public_key and private_key.")

    def create_service(self, auth_data, region):
        """
        Create a Azure Cloud Service and return the name
        """
        service_name = "IM-" + str(int(time.time() * 100))
        self.logger.info("Create the service " +
                         service_name + " in region: " + region)

        try:
            conn, subscription_id = self.get_connection_and_subscription_id(
                auth_data)
            uri = "https://%s/%s/services/hostedservices" % (
                self.AZURE_SERVER, subscription_id)
            service_create_xml = '''
    <CreateHostedService xmlns="http://schemas.microsoft.com/windowsazure">
      <ServiceName>%s</ServiceName>
      <Label>%s</Label>
      <Description>Service %s created by the IM</Description>
      <Location>%s</Location>
    </CreateHostedService>
            ''' % (service_name, base64.b64encode(service_name), service_name, region)
            conn.request('POST', uri, body=service_create_xml, headers={
                         'x-ms-version': '2013-03-01', 'Content-Type': 'application/xml'})
            resp = conn.getresponse()
            output = resp.read()
        except Exception, ex:
            self.logger.exception("Error creating the service")
            return None, "Error creating the service" + str(ex)

        if resp.status != 201:
            self.logger.error(
                "Error creating the service: Error code: " + str(resp.status) + ". Msg: " + output)
            return None, "Error creating the service: Error code: " + str(resp.status) + ". Msg: " + output

        return service_name, None

    def delete_service(self, service_name, auth_data):
        """
        Delete the Azure Cloud Service with name "service_name"
        """
        try:
            conn, subscription_id = self.get_connection_and_subscription_id(
                auth_data)
            uri = "/%s/services/hostedservices/%s?comp=media" % (
                subscription_id, service_name)
            conn.request('DELETE', uri, headers={'x-ms-version': '2013-08-01'})
            resp = conn.getresponse()
            output = resp.read()
        except Exception, ex:
            self.logger.exception("Error deleting the service")
            return (False, "Error deleting the service: " + str(ex))

        if resp.status != 202:
            self.logger.error(
                "Error deleting the service: Error Code " + str(resp.status) + ". Msg: " + output)
            return (False, "Error deleting the service: Error Code " + str(resp.status) + ". Msg: " + output)

        request_id = resp.getheader('x-ms-request-id')

        # Call to GET OPERATION STATUS until "Succeeded"
        success = self.wait_operation_status(request_id, auth_data)

        if success:
            return (True, "")
        else:
            return (False, "Error waiting the VM termination")

    def wait_operation_status(self, request_id, auth_data, delay=2, timeout=90):
        """
        Wait for the operation "request_id" to finish in the specified state
        """
        self.logger.info("Wait the operation: " + request_id + " to finish.")
        wait = 0
        status_str = "InProgress"
        while status_str == "InProgress" and wait < timeout:
            time.sleep(delay)
            wait += delay
            try:
                conn, subscription_id = self.get_connection_and_subscription_id(
                    auth_data)
                uri = "/%s/operations/%s" % (subscription_id, request_id)
                conn.request('GET', uri, headers={
                             'x-ms-version': '2013-03-01'})
                resp = conn.getresponse()
                output = resp.read()

                if resp.status == 200:
                    output = Operation(output)
                    status_str = output.Status
                    # InProgress|Succeeded|Failed
                    self.logger.debug("Operation string state: " + status_str)
                else:
                    self.logger.error(
                        "Error waiting operation to finish: Code %d. Msg: %s." % (resp.status, output))
                    return False
            except Exception:
                self.logger.exception(
                    "Error getting the operation state: " + request_id)

        if status_str == "Succeeded":
            return True
        else:
            self.logger.exception("Error waiting the operation")
            return False

    def get_storage_name(self, subscription_id):
        res = subscription_id.replace("-", "")[:24]
        return res

    def create_storage_account(self, storage_account, auth_data, region, timeout=120):
        """
        Create an storage account with the name specified in "storage_account"
        """
        self.logger.info("Creating the storage account " + storage_account)
        try:
            conn, subscription_id = self.get_connection_and_subscription_id(
                auth_data)
            uri = "/%s/services/storageservices" % subscription_id
            storage_create_xml = '''
<CreateStorageServiceInput xmlns="http://schemas.microsoft.com/windowsazure">
  <ServiceName>%s</ServiceName>
  <Description>Storage %s created by the IM</Description>
  <Label>%s</Label>
  <Location>%s</Location>
  <GeoReplicationEnabled>false</GeoReplicationEnabled>
  <ExtendedProperties>
    <ExtendedProperty>
      <Name>AccountCreatedBy</Name>
      <Value>RestAPI</Value>
    </ExtendedProperty>
  </ExtendedProperties>
</CreateStorageServiceInput>
            ''' % (storage_account, storage_account, base64.b64encode(storage_account), region)
            conn.request('POST', uri, body=storage_create_xml, headers={
                         'x-ms-version': '2013-03-01', 'Content-Type': 'application/xml'})
            resp = conn.getresponse()
            output = resp.read()
        except Exception, ex:
            self.logger.exception("Error creating the storage account")
            return None, "Error creating the storage account" + str(ex)

        if resp.status != 202:
            self.logger.error(
                "Error creating the storage account: Error code " + str(resp.status) + ". Msg: " + output)
            return None, "Error code " + str(resp.status) + ". Msg: " + output

        request_id = resp.getheader('x-ms-request-id')

        # Call to GET OPERATION STATUS until 200 (OK)
        success = self.wait_operation_status(request_id, auth_data)

        # Wait the storage to be "Created"
        status = None
        delay = 2
        wait = 0
        while status != "Created" and wait < timeout:
            storage = self.get_storage_account(storage_account, auth_data)
            if storage:
                status = storage.Status
            if status != "Created":
                time.sleep(delay)
                wait += delay

        if success:
            return storage_account, None
        else:
            self.logger.error(
                "Error waiting the creation of the storage account")
            self.delete_storage_account(storage_account, subscription_id, conn)
            return None, "Error waiting the creation of the storage account"

    def delete_storage_account(self, storage_account, subscription_id, conn):
        """
        Delete an storage account with the name specified in "storage_account"
        """
        try:
            uri = "/%s/services/storageservices/%s" % (
                subscription_id, storage_account)
            conn.request('DELETE', uri, headers={'x-ms-version': '2013-03-01'})
            resp = conn.getresponse()
            output = resp.read()
        except Exception:
            self.logger.exception("Error deleting the storage account")
            return False

        if resp.status != 200:
            self.logger.error(
                "Error deleting the storage account: Error Code " + str(resp.status) + ". Msg: " + output)
            return False

        return True

    def get_storage_account(self, storage_account, auth_data):
        """
        Get the information about the Storage Account named "storage_account" or None if it does not exist
        """
        try:
            conn, subscription_id = self.get_connection_and_subscription_id(
                auth_data)
            uri = "/%s/services/storageservices/%s" % (
                subscription_id, storage_account)
            conn.request('GET', uri, headers={'x-ms-version': '2013-03-01'})
            resp = conn.getresponse()
            output = resp.read()
            if resp.status == 200:
                storage_info = StorageService(output)
                return storage_info.StorageServiceProperties
            elif resp.status == 404:
                self.logger.debug(
                    "Storage " + storage_account + " does not exist")
                return None
            else:
                self.logger.warn(
                    "Error checking the storage account " + storage_account + ". Msg: " + output)
                return None
        except Exception:
            self.logger.exception("Error checking the storage account")
            return None

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        region = self.DEFAULT_LOCATION
        if radl.systems[0].getValue('availability_zone'):
            region = radl.systems[0].getValue('availability_zone')
        else:
            radl.systems[0].setValue('availability_zone', region)

        res = []
        i = 0
        while i < num_vm:
            try:
                conn, subscription_id = self.get_connection_and_subscription_id(
                    auth_data)

                # Create storage account
                storage_account_name = self.get_storage_name(subscription_id)
                storage_account = self.get_storage_account(
                    storage_account_name, auth_data)
                if not storage_account:
                    storage_account_name, error_msg = self.create_storage_account(
                        self.get_storage_name(subscription_id), auth_data, region)
                    if not storage_account_name:
                        res.append((False, error_msg))
                        break
                else:
                    # if the user has specified the region
                    if radl.systems[0].getValue('availability_zone'):
                        # Check that the region of the storage account is the
                        # same of the service
                        if region != storage_account.GeoPrimaryRegion:
                            res.append((False, ("Error creating the service. The specified "
                                                "region is not the same of the service.")))
                            break
                    else:
                        # Otherwise use the storage account region
                        region = storage_account.GeoPrimaryRegion

                # and the service
                service_name, error_msg = self.create_service(
                    auth_data, region)
                if service_name is None:
                    res.append((False, error_msg))
                    break

                self.logger.debug("Creating the VM with id: " + service_name)

                # Create the VM to get the nodename
                vm = VirtualMachine(inf, service_name,
                                    self.cloud, radl, requested_radl, self)
                vm.info.systems[0].setValue('instance_id', str(vm.id))

                # Generate the XML to create the VM
                vm_create_xml = self.get_azure_vm_create_xml(
                    vm, storage_account_name, radl, i, auth_data)

                if vm_create_xml is None:
                    self.delete_service(service_name, auth_data)
                    res.append((False, "Incorrect image or auth data"))
                    break

                uri = "/%s/services/hostedservices/%s/deployments" % (
                    subscription_id, service_name)
                conn.request('POST', uri, body=vm_create_xml, headers={
                             'x-ms-version': '2013-03-01', 'Content-Type': 'application/xml'})
                resp = conn.getresponse()
                output = resp.read()

                if resp.status != 202:
                    self.delete_service(service_name, auth_data)
                    self.logger.error(
                        "Error creating the VM: Error Code " + str(resp.status) + ". Msg: " + output)
                    res.append((False, "Error creating the VM: Error Code " +
                                str(resp.status) + ". Msg: " + output))
                else:
                    # Call the GET OPERATION STATUS until sea 200 (OK)
                    request_id = resp.getheader('x-ms-request-id')
                    success = self.wait_operation_status(request_id, auth_data)
                    if success:
                        res.append((True, vm))
                    else:
                        self.logger.exception("Error waiting the VM creation")
                        res.append((False, "Error waiting the VM creation"))

            except Exception, ex:
                self.logger.exception("Error creating the VM")
                res.append((False, "Error creating the VM: " + str(ex)))

            i += 1
        return res

    def get_instance_type(self, system, auth_data):
        """
        Get the name of the instance type to launch to EC2

        Arguments:
           - radl(str): RADL document with the requirements of the VM to get the instance type
        Returns: a str with the name of the instance type to launch to EC2
        """
        instance_type_name = system.getValue('instance_type')

        cpu = 1
        cpu_op = ">="
        if system.getFeature('cpu.count'):
            cpu = system.getValue('cpu.count')
            cpu_op = system.getFeature('cpu.count').getLogOperator()

        memory = 1
        memory_op = ">="
        if system.getFeature('memory.size'):
            memory = system.getFeature('memory.size').getValue('M')
            memory_op = system.getFeature('memory.size').getLogOperator()

        disk_free = 0
        disk_free_op = ">="
        if system.getValue('disks.free_size'):
            disk_free = system.getFeature('disks.free_size').getValue('M')
            disk_free_op = system.getFeature('memory.size').getLogOperator()

        instace_types = self.get_all_instance_types(auth_data)

        res = None
        for instace_type in instace_types:
            # get the instance type with the lowest Memory
            if res is None or (instace_type.MemoryInMb <= res.MemoryInMb):
                str_compare = "instace_type.Cores " + cpu_op + " cpu "
                str_compare += " and instace_type.MemoryInMb " + memory_op + " memory "
                str_compare += " and instace_type.VirtualMachineResourceDiskSizeInMb " + \
                    disk_free_op + " disk_free"

                # if arch in instace_type.cpu_arch and
                # instace_type.cores_per_cpu * instace_type.num_cpu >= cpu and
                # instace_type.mem >= memory and instace_type.cpu_perf >=
                # performance and instace_type.disks * instace_type.disk_space
                # >= disk_free:
                if eval(str_compare):
                    if not instance_type_name or instace_type.Name == instance_type_name:
                        res = instace_type

        if res is None:
            self.get_instance_type_by_name(self.INSTANCE_TYPE, auth_data)
        else:
            return res

    def updateVMInfo(self, vm, auth_data):
        self.logger.debug("Get the VM info with the id: " + vm.id)
        service_name = vm.id

        try:
            conn, subscription_id = self.get_connection_and_subscription_id(
                auth_data)
            uri = "/%s/services/hostedservices/%s/deployments/%s" % (
                subscription_id, service_name, service_name)
            conn.request('GET', uri, headers={'x-ms-version': '2014-02-01'})
            resp = conn.getresponse()
            output = resp.read()
        except Exception, ex:
            self.logger.exception("Error getting the VM info: " + vm.id)
            return (False, "Error getting the VM info: " + vm.id + ". " + str(ex))

        if resp.status == 404:
            self.logger.warn("VM with ID: " + vm.id + ". Not found!.")
            vm.state = VirtualMachine.OFF
            return (True, vm)
        if resp.status != 200:
            self.logger.error("Error getting the VM info: " + vm.id +
                              ". Error Code: " + str(resp.status) + ". Msg: " + output)
            return (False, "Error getting the VM info: " + vm.id +
                    ". Error Code: " + str(resp.status) + ". Msg: " + output)
        else:
            self.logger.debug("VM info: " + vm.id + " obtained.")
            self.logger.debug(output)
            vm_info = Deployment(output)

            vm.state = self.get_vm_state(vm_info)

            self.logger.debug("The VM state is: " + vm.state)

            instance_type = self.get_instance_type_by_name(
                vm_info.RoleInstanceList.RoleInstance[0].InstanceSize, auth_data)
            self.update_system_info_from_instance(
                vm.info.systems[0], instance_type)

            # Update IP info
            self.setIPs(vm, vm_info)
            return (True, vm)

    def get_vm_state(self, vm_info):
        """
        Return the state of the VM using the vm info in format "Deployment"
        """
        try:
            # If the deploy is running check the state of the RoleInstance
            if vm_info.Status == "Running":
                return self.ROLE_STATE_MAP.get(vm_info.RoleInstanceList.RoleInstance[0].PowerState,
                                               VirtualMachine.UNKNOWN)
            else:
                return self.DEPLOY_STATE_MAP.get(vm_info.Status, VirtualMachine.UNKNOWN)
        except:
            return self.DEPLOY_STATE_MAP.get(vm_info.Status, VirtualMachine.UNKNOWN)

    def setIPs(self, vm, vm_info):
        """
        Set the information about the IPs of the VM
        """
        private_ips = []
        public_ips = []

        try:
            role_instance = vm_info.RoleInstanceList.RoleInstance[0]
        except:
            return
        try:
            private_ips.append(role_instance.IpAddress)
        except:
            pass
        try:
            public_ips.append(
                role_instance.InstanceEndpoints.InstanceEndpoint[0].Vip)
        except:
            pass

        vm.setIps(public_ips, private_ips)

    def finalize(self, vm, auth_data):
        self.logger.debug("Terminate VM: " + vm.id)
        service_name = vm.id

        # Delete the service
        res = self.delete_service(service_name, auth_data)

        return res

    def call_role_operation(self, op, vm, auth_data):
        """
        Call to the specified operation "op" to a Role
        """
        service_name = vm.id

        try:
            conn, subscription_id = self.get_connection_and_subscription_id(
                auth_data)
            uri = "/%s/services/hostedservices/%s/deployments/%s/roleinstances/%s/Operations" % (
                subscription_id, service_name, service_name, self.ROLE_NAME)

            conn.request('POST', uri, body=op, headers={
                         'x-ms-version': '2013-06-01', 'Content-Type': 'application/xml'})
            resp = conn.getresponse()
            output = resp.read()
        except Exception, ex:
            self.logger.exception("Error calling role operation")
            return (False, "Error calling role operation: " + str(ex))

        if resp.status != 202:
            self.logger.error(
                "Error calling role operation: Error Code " + str(resp.status) + ". Msg: " + output)
            return (False, "Error calling role operation: Error Code " + str(resp.status) + ". Msg: " + output)

        request_id = resp.getheader('x-ms-request-id')

        # Call to GET OPERATION STATUS until "Succeded"
        success = self.wait_operation_status(
            request_id, auth_data, delay=4, timeout=240)

        if success:
            return (True, "")
        else:
            return (False, "Error waiting the VM role operation")

        return (True, "")

    def stop(self, vm, auth_data):
        self.logger.debug("Stop VM: " + vm.id)

        op = """<ShutdownRoleOperation xmlns="http://schemas.microsoft.com/windowsazure"
 xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
  <OperationType>ShutdownRoleOperation</OperationType>
  <PostShutdownAction>StoppedDeallocated</PostShutdownAction>
</ShutdownRoleOperation>"""
        return self.call_role_operation(op, vm, auth_data)

    def start(self, vm, auth_data):
        self.logger.debug("Start VM: " + vm.id)

        op = """<StartRoleOperation xmlns="http://schemas.microsoft.com/windowsazure"
 xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
  <OperationType>StartRoleOperation</OperationType>
</StartRoleOperation>"""
        return self.call_role_operation(op, vm, auth_data)

    def get_all_instance_types(self, auth_data):
        if self.instance_type_list:
            return self.instance_type_list
        else:
            try:
                conn, subscription_id = self.get_connection_and_subscription_id(
                    auth_data)
                uri = "/%s/rolesizes" % subscription_id
                conn.request('GET', uri, headers={
                             'x-ms-version': '2013-08-01'})
                resp = conn.getresponse()
                output = resp.read()
            except Exception:
                self.logger.exception("Error getting Role Sizes")
                return []

            if resp.status != 200:
                self.logger.error(
                    "Error getting Role Sizes. Error Code: " + str(resp.status) + ". Msg: " + output)
                return []
            else:
                self.logger.debug("Role List obtained.")
                role_sizes = RoleSizes(output)
                res = []
                for role_size in role_sizes.RoleSize:
                    if role_size.SupportedByVirtualMachines == "true":
                        res.append(role_size)

                self.instance_type_list = res
                return res

    def get_instance_type_by_name(self, name, auth_data):
        """
        Get the Azure instance type with the specified name

        Returns: an :py:class:`InstanceTypeInfo` or None if the type is not found
        """
        for inst_type in self.get_all_instance_types(auth_data):
            if inst_type.Name == name:
                return inst_type
        return None

    def alterVM(self, vm, radl, auth_data):
        # https://msdn.microsoft.com/en-us/library/azure/jj157187.aspx
        service_name = vm.id
        system = radl.systems[0]

        instance_type = self.get_instance_type(system, auth_data)

        if not instance_type:
            return (False, "Error calling update operation: No instance type found for radl: " + str(radl))

        try:
            conn, subscription_id = self.get_connection_and_subscription_id(
                auth_data)

            uri = "/%s/services/hostedservices/%s/deployments/%s/roles/%s" % (
                subscription_id, service_name, service_name, self.ROLE_NAME)

            body = '''
            <PersistentVMRole xmlns="http://schemas.microsoft.com/windowsazure"
             xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
                <RoleSize>%s</RoleSize>
            </PersistentVMRole>
            ''' % (instance_type.Name)

            conn.request('PUT', uri, body=body, headers={
                         'x-ms-version': '2013-11-01', 'Content-Type': 'application/xml'})
            resp = conn.getresponse()
            output = resp.read()
        except Exception, ex:
            self.logger.exception("Error calling update operation")
            return (False, "Error calling update operation: " + str(ex))

        if resp.status != 202:
            self.logger.error(
                "Error update role operation: Error Code " + str(resp.status) + ". Msg: " + output)
            return (False, "Error update role operation: Error Code " + str(resp.status) + ". Msg: " + output)

        request_id = resp.getheader('x-ms-request-id')

        # Call to GET OPERATION STATUS until 200 (OK)
        success = self.wait_operation_status(request_id, auth_data)

        if success:
            self.update_system_info_from_instance(
                vm.info.systems[0], instance_type)
            return (True, "")
        else:
            return (False, "Error waiting the VM update operation")

        return (True, "")

    def update_system_info_from_instance(self, system, instance_type):
        """
        Update the features of the system with the information of the instance_type
        """
        system.addFeature(Feature("cpu.count", "=", instance_type.Cores),
                          conflict="other", missing="other")
        system.addFeature(Feature("memory.size", "=", instance_type.MemoryInMb, 'M'),
                          conflict="other", missing="other")
        system.addFeature(Feature("disks.free_size", "=", instance_type.VirtualMachineResourceDiskSizeInMb, 'M'),
                          conflict="other", missing="other")
        system.addFeature(Feature("instance_type", "=", instance_type.Name),
                          conflict="other", missing="other")
