#! /usr/bin/env python
#
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

import logging
import os

from IM.request import Request, AsyncRequest, AsyncXMLRPCServer, get_system_queue
from IM.InfrastructureManager import InfrastructureManager
from IM.config import Config
from IM.auth import Authentication
from IM import __version__ as version

logger = logging.getLogger('InfrastructureManager')

class IMBaseRequest(AsyncRequest):
	"""
	Base class for the IM requests
	"""
	def __init__(self, arguments = (), priority = Request.PRIORITY_NORMAL):
		AsyncRequest.__init__(self, arguments, priority)
		self._error_mesage = "Error."
		
	def _execute(self):
		try:
			res = self._call_function()
			self.set(res)
			return True
		except Exception, ex:
			logger.exception(self._error_mesage)
			self.set(str(ex))
			return False

class Request_AddResource(IMBaseRequest):
	"""
	Request class for the AddResource function
	"""	
	def _call_function(self):
		self._error_mesage = "Error Adding resources."
		(inf_id, radl_data, auth_data) = self.arguments
		return InfrastructureManager.AddResource(inf_id, radl_data, Authentication(auth_data))
	
class Request_RemoveResource(IMBaseRequest):
	"""
	Request class for the RemoveResource function
	"""
	def _call_function(self):
		self._error_mesage = "Error Removing resources."
		(inf_id, vm_list, auth_data) = self.arguments
		return InfrastructureManager.RemoveResource(inf_id, vm_list, Authentication(auth_data))

class Request_GetInfrastructureInfo(IMBaseRequest):
	"""
	Request class for the GetInfrastructureInfo function
	"""
	def _call_function(self):
		self._error_mesage = "Error Getting Inf. Info."
		(inf_id, auth_data) = self.arguments
		return InfrastructureManager.GetInfrastructureInfo(inf_id, Authentication(auth_data))

class Request_GetVMInfo(IMBaseRequest):
	"""
	Request class for the GetVMInfo function
	"""
	def _call_function(self):
		self._error_mesage = "Error Getting VM Info."
		(inf_id, vm_id, auth_data) = self.arguments
		return InfrastructureManager.GetVMInfo(inf_id, vm_id, Authentication(auth_data))
	
class Request_AlterVM(IMBaseRequest):
	"""
	Request class for the AlterVM function
	"""
	def _call_function(self):
		self._error_mesage = "Error Changing VM Info."
		(inf_id, vm_id, radl, auth_data) = self.arguments
		return InfrastructureManager.AlterVM(inf_id, vm_id, radl, Authentication(auth_data))

class Request_DestroyInfrastructure(IMBaseRequest):
	"""
	Request class for the DestroyInfrastructure function
	"""
	def _call_function(self):
		self._error_mesage = "Error Destroying Inf."
		(inf_id, auth_data) = self.arguments
		return InfrastructureManager.DestroyInfrastructure(inf_id, Authentication(auth_data))

class Request_StopInfrastructure(IMBaseRequest):
	"""
	Request class for the StopInfrastructure function
	"""
	def _call_function(self):
		self._error_mesage = "Error Stopping Inf."
		(inf_id, auth_data) = self.arguments
		return InfrastructureManager.StopInfrastructure(inf_id, Authentication(auth_data))
	
class Request_StartInfrastructure(IMBaseRequest):
	"""
	Request class for the StartInfrastructure function
	"""
	def _call_function(self):
		self._error_mesage = "Error Starting Inf."
		(inf_id, auth_data) = self.arguments
		return InfrastructureManager.StartInfrastructure(inf_id, Authentication(auth_data))

class Request_CreateInfrastructure(IMBaseRequest):
	"""
	Request class for the CreateInfrastructure function
	"""
	def _call_function(self):
		self._error_mesage = "Error Creating Inf."
		(radl_data, auth_data) = self.arguments
		return InfrastructureManager.CreateInfrastructure(radl_data, Authentication(auth_data))

class Request_GetInfrastructureList(IMBaseRequest):
	"""
	Request class for the GetInfrastructureList function
	"""
	def _call_function(self):
		self._error_mesage = "Error Getting Inf. List."
		(auth_data) = self.arguments
		return InfrastructureManager.GetInfrastructureList(Authentication(auth_data))


class Request_Reconfigure(IMBaseRequest):
	"""
	Request class for the Reconfigure function
	"""
	def _call_function(self):
		self._error_mesage = "Error Reconfiguring Inf."
		(inf_id, radl_data, auth_data) = self.arguments
		return InfrastructureManager.Reconfigure(inf_id, radl_data, Authentication(auth_data))

class Request_ImportInfrastructure(IMBaseRequest):
	"""
	Request class for the ImportInfrastructure function
	"""
	def _call_function(self):
		self._error_mesage = "Error Importing Inf."
		(str_inf, auth_data) = self.arguments
		return InfrastructureManager.ImportInfrastructure(str_inf, Authentication(auth_data))

class Request_ExportInfrastructure(IMBaseRequest):
	"""
	Request class for the ExportInfrastructure function
	"""
	def _call_function(self):
		self._error_mesage = "Error Exporting Inf."
		(inf_id, delete, auth_data) = self.arguments
		return InfrastructureManager.ExportInfrastructure(inf_id, delete, Authentication(auth_data))

def WaitRequest(request):
	"""
	Wait for the specified request
	"""
	request.wait()
	success = (request.status() == Request.STATUS_PROCESSED)
	return (success, request.get())

"""
API functions.
They create the specified request and wait for it.
"""
def AddResource(inf_id, radl_data, auth_data):
	request = Request_AddResource((inf_id, radl_data, auth_data))
	return WaitRequest(request)

def RemoveResource(inf_id, vm_list, auth_data):
	request = Request_RemoveResource((inf_id, vm_list, auth_data))
	return WaitRequest(request)

def GetVMInfo(inf_id, vm_id, auth_data):
	request = Request_GetVMInfo((inf_id, vm_id, auth_data))
	return WaitRequest(request)

def AlterVM(inf_id, vm_id, radl, auth_data):
	request = Request_AlterVM((inf_id, vm_id, radl, auth_data))
	return WaitRequest(request)

def GetInfrastructureInfo(inf_id, auth_data):
	request = Request_GetInfrastructureInfo((inf_id, auth_data))
	return WaitRequest(request)

def StopInfrastructure(inf_id, auth_data):
	request = Request_StopInfrastructure((inf_id, auth_data))
	return WaitRequest(request)

def StartInfrastructure(inf_id, auth_data):
	request = Request_StartInfrastructure((inf_id, auth_data))
	return WaitRequest(request)

def DestroyInfrastructure(inf_id, auth_data):
	request = Request_DestroyInfrastructure((inf_id, auth_data))
	return WaitRequest(request)

def CreateInfrastructure(radl_data, auth_data):
	request = Request_CreateInfrastructure((radl_data, auth_data))
	return WaitRequest(request)

def GetInfrastructureList(auth_data):
	request = Request_GetInfrastructureList((auth_data))
	return WaitRequest(request)

def Reconfigure(inf_id, radl_data, auth_data):
	request = Request_Reconfigure((inf_id, radl_data, auth_data))
	return WaitRequest(request)

def ImportInfrastructure(str_inf, auth_data):
	request = Request_ImportInfrastructure((str_inf, auth_data))
	return WaitRequest(request)

def ExportInfrastructure(inf_id, delete, auth_data):
	request = Request_ExportInfrastructure((inf_id, delete, auth_data))
	return WaitRequest(request)

def launch_daemon():
	"""
	Launch the IM daemon
	"""
	if os.path.isfile(Config.DATA_FILE):
		InfrastructureManager.load_data()
	
	if Config.XMLRCP_SSL:
		# if specified launch the secure version
		import ssl
		from IM.request import AsyncSSLXMLRPCServer
		server = AsyncSSLXMLRPCServer(Config.XMLRCP_ADDRESS, Config.XMLRCP_PORT, Config.XMLRCP_SSL_KEYFILE,
									  Config.XMLRCP_SSL_CERTFILE, Config.XMLRCP_SSL_CA_CERTS,
									  cert_reqs=ssl.CERT_OPTIONAL)
	else:
		# otherwise the standard XML-RPC service
		server = AsyncXMLRPCServer((Config.XMLRCP_ADDRESS, Config.XMLRCP_PORT))
	
	# Register the API functions
	server.register_function(CreateInfrastructure)
	server.register_function(DestroyInfrastructure)
	server.register_function(StartInfrastructure)
	server.register_function(StopInfrastructure)
	server.register_function(GetInfrastructureInfo)
	server.register_function(GetVMInfo)
	server.register_function(AlterVM)
	server.register_function(RemoveResource)
	server.register_function(AddResource)
	server.register_function(GetInfrastructureList)
	server.register_function(Reconfigure)
	server.register_function(ExportInfrastructure)
	server.register_function(ImportInfrastructure)
	
	InfrastructureManager.logger.info('************ Start Infrastucture Manager daemon (v.%s) ************' % version)

	# Launch the API XMLRPC thread 
	server.serve_forever_in_thread()
	
	if Config.ACTIVATE_REST:
		# If specified launch the REST server
		import IM.REST
		IM.REST.run_in_thread(host=Config.REST_ADDRESS, port=Config.REST_PORT)
	
	# Start the messages queue
	get_system_queue().timed_process_loop(None, 1)

def config_logging():
	"""
	Init the logging info
	"""
	log_dir = os.path.dirname(Config.LOG_FILE)
	if not os.path.isdir(log_dir):
		os.makedirs(log_dir)
	
	fileh = logging.handlers.RotatingFileHandler(filename=Config.LOG_FILE, maxBytes=Config.LOG_FILE_MAX_SIZE, backupCount=3)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	fileh.setFormatter(formatter)
	
	logging.RootLogger.propagate = 0
	logging.root.setLevel(logging.ERROR)
	
	log = logging.getLogger('ConfManager')
	log.setLevel(logging.DEBUG)
	log.propagate = 0
	log.addHandler(fileh)
	
	log = logging.getLogger('CloudConnector')
	log.setLevel(logging.DEBUG)
	log.propagate = 0
	log.addHandler(fileh)
	
	log = logging.getLogger('InfrastructureManager')
	log.setLevel(logging.DEBUG)
	log.propagate = 0
	log.addHandler(fileh)

if __name__ == "__main__":
	config_logging()
	launch_daemon()
