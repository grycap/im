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

# Clase request para anyadir los recursos definidos por el RADL a la infraestructura indicada
class Request_AddResource(AsyncRequest):
	def _execute(self):
		try:
			(inf_id, radl_data, auth_data) = self.arguments
			res = InfrastructureManager.AddResource(inf_id, radl_data, Authentication(auth_data))
			self.set(res)
			return True
		except Exception, ex:
			logger.exception("Error Adding resources.")
			self.set(str(ex))
			return False
	
# Clase request para borrar un recurso a una Infraestructura
class Request_RemoveResource(AsyncRequest):
	def _execute(self):
		try:
			(inf_id, vm_list, auth_data) = self.arguments
			res = InfrastructureManager.RemoveResource(inf_id, vm_list, Authentication(auth_data))
			self.set(res)
			return True
		except Exception, ex:
			logger.exception("Error Removing resources.")
			self.set(str(ex))
			return False
	
# Clase request para devolver el listado de la VMs que forman parte de la infraestructura
class Request_GetInfrastructureInfo(AsyncRequest):
	def _execute(self):
		try:
			(inf_id, auth_data) = self.arguments
			res = InfrastructureManager.GetInfrastructureInfo(inf_id, Authentication(auth_data))
			self.set(res)
			return True
		except Exception, ex:
			logger.exception("Error Getting Inf. Info.")
			self.set(str(ex))
			return False


# Clase request para devolver la informacion sobre una VM
class Request_GetVMInfo(AsyncRequest):
	def _execute(self):
		try:
			(inf_id, vm_id, auth_data) = self.arguments
			res = InfrastructureManager.GetVMInfo(inf_id, vm_id, Authentication(auth_data))
			self.set(res)
			return True
		except Exception, ex:
			logger.exception("Error Getting VM Info.")
			self.set(str(ex))
			return False
	
# Clase request para devolver la informacion sobre una VM
class Request_AlterVM(AsyncRequest):
	def _execute(self):
		try:
			(inf_id, vm_id, radl, auth_data) = self.arguments
			res = InfrastructureManager.AlterVM(inf_id, vm_id, radl, Authentication(auth_data))
			self.set(res)
			return True
		except Exception, ex:
			logger.exception("Error Changing VM Info.")
			self.set(str(ex))
			return False


# Clase request para eliminar la Infraestructura con todas sus VMs
class Request_DestroyInfrastructure(AsyncRequest):
	def _execute(self):
		try:
			(inf_id, auth_data) = self.arguments
			res = InfrastructureManager.DestroyInfrastructure(inf_id, Authentication(auth_data))
			self.set(res)
			return True
		except Exception, ex:
			logger.exception("Error Destroying Inf.")
			self.set(str(ex))
			return False
	
# Clase request para parar la Infraestructura con todas sus VMs
class Request_StopInfrastructure(AsyncRequest):
	def _execute(self):
		try:
			(inf_id, auth_data) = self.arguments
			res = InfrastructureManager.StopInfrastructure(inf_id, Authentication(auth_data))
			self.set(res)
			return True
		except Exception, ex:
			logger.exception("Error Stopping Inf.")
			self.set(str(ex))
			return False
	
# Clase request para parar la Infraestructura con todas sus VMs
class Request_StartInfrastructure(AsyncRequest):
	def _execute(self):
		try:
			(inf_id, auth_data) = self.arguments
			res = InfrastructureManager.StartInfrastructure(inf_id, Authentication(auth_data))
			self.set(res)
			return True
		except Exception, ex:
			logger.exception("Error Starting Inf.")
			self.set(str(ex))
			return False
	
# Clase request para crear la infraestructura definida por el RADL y la anyade a la lista del servicio
class Request_CreateInfrastructure(AsyncRequest):
	def _execute(self):
		try:
			(radl_data, auth_data) = self.arguments
			res = InfrastructureManager.CreateInfrastructure(radl_data, Authentication(auth_data))
			self.set(res)
			return True
		except Exception, ex:
			logger.exception("Error Creating Inf.")
			self.set(str(ex))
			return False
	
# Clase request para listar las infraestucturas del usuario
class Request_GetInfrastructureList(AsyncRequest):
	def _execute(self):
		try:
			(auth_data) = self.arguments
			res = InfrastructureManager.GetInfrastructureList(Authentication(auth_data))
			self.set(res)
			return True
		except Exception, ex:
			logger.exception("Error Getting Inf. List")
			self.set(str(ex))
			return False
	
# Clase request para reconfigurar los recursos definidos por el RADL a la infraestructura indicada
class Request_Reconfigure(AsyncRequest):
	def _execute(self):
		try:
			(inf_id, radl_data, auth_data) = self.arguments
			res = InfrastructureManager.Reconfigure(inf_id, radl_data, Authentication(auth_data))
			self.set(res)
			return True
		except Exception, ex:
			logger.exception("Error Reconfiguring Inf.")
			self.set(str(ex))
			return False

# Clase request para la funcion de importar una infraestructura
class Request_ImportInfrastructure(AsyncRequest):
	def _execute(self):
		try:
			(str_inf, auth_data) = self.arguments
			res = InfrastructureManager.ImportInfrastructure(str_inf, Authentication(auth_data))
			self.set(res)
			return True
		except Exception, ex:
			logger.exception("Error Importing Inf.")
			self.set(str(ex))
			return False

# Clase request para la funcion de exportar una infraestructura
class Request_ExportInfrastructure(AsyncRequest):
	def _execute(self):
		try:
			(inf_id, delete, auth_data) = self.arguments
			res = InfrastructureManager.ExportInfrastructure(inf_id, delete, Authentication(auth_data))
			self.set(res)
			return True
		except Exception, ex:
			logger.exception("Error Exporting Inf.")
			self.set(str(ex))
			return False

def AddResource(inf_id, radl_data, auth_data):
	request = Request_AddResource((inf_id, radl_data, auth_data))
	request.wait()
	success = (request.status() == Request.STATUS_PROCESSED)
	return (success, request.get())

def RemoveResource(inf_id, vm_list, auth_data):
	request = Request_RemoveResource((inf_id, vm_list, auth_data))
	request.wait()
	success = (request.status() == Request.STATUS_PROCESSED)
	return (success, request.get())

def GetVMInfo(inf_id, vm_id, auth_data):
	request = Request_GetVMInfo((inf_id, vm_id, auth_data))
	request.wait()
	success = (request.status() == Request.STATUS_PROCESSED)
	return (success, request.get())

def AlterVM(inf_id, vm_id, radl, auth_data):
	request = Request_AlterVM((inf_id, vm_id, radl, auth_data))
	request.wait()
	success = (request.status() == Request.STATUS_PROCESSED)
	return (success, request.get())

def GetInfrastructureInfo(inf_id, auth_data):
	request = Request_GetInfrastructureInfo((inf_id, auth_data))
	request.wait()
	success = (request.status() == Request.STATUS_PROCESSED)
	return (success, request.get())

def StopInfrastructure(inf_id, auth_data):
	request = Request_StopInfrastructure((inf_id, auth_data))
	request.wait()
	success = (request.status() == Request.STATUS_PROCESSED)
	return (success, request.get())

def StartInfrastructure(inf_id, auth_data):
	request = Request_StartInfrastructure((inf_id, auth_data))
	request.wait()
	success = (request.status() == Request.STATUS_PROCESSED)
	return (success, request.get())

def DestroyInfrastructure(inf_id, auth_data):
	request = Request_DestroyInfrastructure((inf_id, auth_data))
	request.wait()
	success = (request.status() == Request.STATUS_PROCESSED)
	return (success, request.get())

def CreateInfrastructure(radl_data, auth_data):
	request = Request_CreateInfrastructure((radl_data, auth_data))
	request.wait()
	success = (request.status() == Request.STATUS_PROCESSED)
	return (success, request.get())

def GetInfrastructureList(auth_data):
	request = Request_GetInfrastructureList((auth_data))
	request.wait()
	success = (request.status() == Request.STATUS_PROCESSED)
	return (success, request.get())

def Reconfigure(inf_id, radl_data, auth_data):
	request = Request_Reconfigure((inf_id, radl_data, auth_data))
	request.wait()
	success = (request.status() == Request.STATUS_PROCESSED)
	return (success, request.get())

def ImportInfrastructure(str_inf, auth_data):
	request = Request_ImportInfrastructure((str_inf, auth_data))
	request.wait()
	success = (request.status() == Request.STATUS_PROCESSED)
	return (success, request.get())

def ExportInfrastructure(inf_id, delete, auth_data):
	request = Request_ExportInfrastructure((inf_id, delete, auth_data))
	request.wait()
	success = (request.status() == Request.STATUS_PROCESSED)
	return (success, request.get())

def launch_daemon():
		if os.path.isfile(Config.DATA_FILE):
				InfrastructureManager.load_data()
		
		# y con esa IP creamos el servidor XMLRPC
		if Config.XMLRCP_SSL:
				import ssl
				from IM.request import AsyncSSLXMLRPCServer
				server = AsyncSSLXMLRPCServer("0.0.0.0", Config.XMLRCP_PORT, Config.XMLRCP_SSL_KEYFILE,
											  Config.XMLRCP_SSL_CERTFILE, Config.XMLRCP_SSL_CA_CERTS,
											  cert_reqs=ssl.CERT_OPTIONAL)
		else:
				server = AsyncXMLRPCServer(("0.0.0.0", Config.XMLRCP_PORT))
		
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

		# Lanzamos el thread del API XMLRPC
		server.serve_forever_in_thread()
		
		if Config.ACTIVATE_REST:
				import IM.REST
				# Lanzamos el thread del API REST
				IM.REST.run_in_thread(host="0.0.0.0", port=Config.REST_PORT)
		
		"""
		Arrancamos la cola de mensajes del sistema
		"""
		get_system_queue().timed_process_loop(None, 1)

def config_logging():
	log_dir = os.path.dirname(Config.LOG_FILE)
	if not os.path.isdir(log_dir):
		os.makedirs(log_dir)
	
	fileh = logging.handlers.RotatingFileHandler(filename=Config.LOG_FILE, maxBytes=Config.LOG_FILE_MAX_SIZE, backupCount=3)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	fileh.setFormatter(formatter)
	
	logging.RootLogger.propagate = 0
	logging.root.setLevel(logging.ERROR)
	
	logger = logging.getLogger('ConfManager')
	logger.setLevel(logging.DEBUG)
	logger.propagate = 0
	logger.addHandler(fileh)
	
	logger = logging.getLogger('CloudConnector')
	logger.setLevel(logging.DEBUG)
	logger.propagate = 0
	logger.addHandler(fileh)
	
	logger = logging.getLogger('InfrastructureManager')
	logger.setLevel(logging.DEBUG)
	logger.propagate = 0
	logger.addHandler(fileh)

if __name__ == "__main__":
	config_logging()
	launch_daemon()
