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
import threading
import bottle
import json

from bottle import HTTPError

from InfrastructureInfo import IncorrectVMException, DeletedVMException
from InfrastructureManager import InfrastructureManager, DeletedInfrastructureException, IncorrectInfrastructureException, UnauthorizedUserException
from auth import Authentication
from config import Config
from radl.radl_json import parse_radl as parse_radl_json, dump_radl as dump_radl_json

logger = logging.getLogger('InfrastructureManager')

# Combination of chars used to separate the lines in the AUTH header
AUTH_LINE_SEPARATOR = '\\n'
# Combination of chars used to separate the lines inside the auth data (i.e. in a certificate)
AUTH_NEW_LINE_SEPARATOR = '\\\\n'

app = bottle.Bottle()  
bottle_server = None

# Declaration of new class that inherits from ServerAdapter  
# It's almost equal to the supported cherrypy class CherryPyServer  
class MySSLCherryPy(bottle.ServerAdapter):  
	def run(self, handler):
		from cherrypy.wsgiserver.ssl_pyopenssl import pyOpenSSLAdapter
		from cherrypy import wsgiserver
		server = wsgiserver.CherryPyWSGIServer((self.host, self.port), handler)  
		self.srv = server

		# If cert variable is has a valid path, SSL will be used  
		# You can set it to None to disable SSL
		server.ssl_adapter = pyOpenSSLAdapter(Config.REST_SSL_CERTFILE, Config.REST_SSL_KEYFILE, Config.REST_SSL_CA_CERTS)
		try:  
			server.start()  
		finally:  
			server.stop()  
			
	def shutdown(self):
		self.srv.stop()

class StoppableWSGIRefServer(bottle.ServerAdapter):
	def run(self, app): # pragma: no cover
		from wsgiref.simple_server import WSGIRequestHandler, WSGIServer
		from wsgiref.simple_server import make_server
		import socket

		class FixedHandler(WSGIRequestHandler):
			def address_string(self): # Prevent reverse DNS lookups please.
				return self.client_address[0]
			def log_request(*args, **kw):
				if not self.quiet:
					return WSGIRequestHandler.log_request(*args, **kw)

		handler_cls = self.options.get('handler_class', FixedHandler)
		server_cls  = self.options.get('server_class', WSGIServer)

		if ':' in self.host: # Fix wsgiref for IPv6 addresses.
			if getattr(server_cls, 'address_family') == socket.AF_INET:
				class server_cls(server_cls):
					address_family = socket.AF_INET6

		srv = make_server(self.host, self.port, app, server_cls, handler_cls)
		self.srv = srv ### THIS IS THE ONLY CHANGE TO THE ORIGINAL CLASS METHOD!
		srv.serve_forever()

	def shutdown(self): ### ADD SHUTDOWN METHOD.
		self.srv.shutdown()
		# self.server.server_close()

def run_in_thread(host, port):
	bottle_thr = threading.Thread(target=run, args=(host, port))
	bottle_thr.daemon = True  
	bottle_thr.start()

def run(host, port):
	global bottle_server
	if Config.REST_SSL:
		# Add our new MySSLCherryPy class to the supported servers  
		# under the key 'mysslcherrypy'
		bottle_server = MySSLCherryPy(host=host, port=port)
		bottle.run(app, host=host, port=port, server=bottle_server, quiet=True)
	else:
		bottle_server = StoppableWSGIRefServer(host=host, port=port)
		bottle.run(app, server=bottle_server, quiet=True)

def stop():
	bottle_server.shutdown()

def get_media_type(header):
	"""
	Function to get only the header media type
	"""
	accept = bottle.request.headers.get(header)
	if accept:
		pos = accept.find(";")
		if pos != -1:
			accept = accept[:pos]
		return accept.strip()
	else:
		return accept

def get_auth_header():
	auth_data = bottle.request.headers['AUTHORIZATION'].replace(AUTH_NEW_LINE_SEPARATOR,"\n")
	auth_data = auth_data.split(AUTH_LINE_SEPARATOR)
	return Authentication(Authentication.read_auth_data(auth_data))
		
@app.route('/infrastructures/:id', method='DELETE')
def RESTDestroyInfrastructure(id=None):
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		InfrastructureManager.DestroyInfrastructure(id, auth)
		bottle.response.content_type = "text/plain"
		return ""
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error Destroying Inf: " + str(ex))
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error Destroying Inf: " + str(ex))
	except Exception, ex:
		logger.exception("Error Destroying Inf")
		bottle.abort(400, "Error Destroying Inf: " + str(ex))

@app.route('/infrastructures/:id', method='GET')
def RESTGetInfrastructureInfo(id=None):
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		vm_ids = InfrastructureManager.GetInfrastructureInfo(id, auth)
		res = ""
		
		protocol = "http://"
		if Config.REST_SSL:
			protocol = "https://"
		for vm_id in vm_ids:
			if res:
				res += "\n"
			res += protocol + bottle.request.environ['HTTP_HOST'] + '/infrastructures/' + str(id) + '/vms/' + str(vm_id)
		
		bottle.response.content_type = "text/uri-list"
		return res
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error Getting Inf. info: " + str(ex))
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error Getting Inf. info: " + str(ex))
	except Exception, ex:
		logger.exception("Error Getting Inf. info")
		bottle.abort(400, "Error Getting Inf. info: " + str(ex))

@app.route('/infrastructures/:id/:prop', method='GET')
def RESTGetInfrastructureProperty(id=None, prop=None):
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		if prop == "contmsg":
			res = InfrastructureManager.GetInfrastructureContMsg(id, auth)
			bottle.response.content_type = "text/plain"
		elif prop == "radl":
			res = InfrastructureManager.GetInfrastructureRADL(id, auth)
			bottle.response.content_type = "text/plain"
		elif prop == "state":
			bottle.response.content_type = "application/json"
			res = InfrastructureManager.GetInfrastructureState(id, auth)
			res = json.dumps(res)
		else:
			bottle.abort(403, "Incorrect infrastructure property")
		return str(res)
	except HTTPError, ex:
		raise ex
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error Getting Inf. prop: " + str(ex))
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error Getting Inf. prop: " + str(ex))
	except Exception, ex:
		logger.exception("Error Getting Inf. prop")
		bottle.abort(400, "Error Getting Inf. prop: " + str(ex))

@app.route('/infrastructures', method='GET')
def RESTGetInfrastructureList():
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		inf_ids = InfrastructureManager.GetInfrastructureList(auth)
		
		protocol = "http://"
		if Config.REST_SSL:
			protocol = "https://"
		res = ""
		for inf_id in inf_ids:
			res += protocol + bottle.request.environ['HTTP_HOST'] + "/infrastructures/" + str(inf_id) + "\n"
		
		bottle.response.content_type = "text/uri-list"
		return res
	except UnauthorizedUserException, ex:
		bottle.abort(401, "Error Getting Inf. List: " + str(ex))
	except Exception, ex:
		logger.exception("Error Getting Inf. List")
		bottle.abort(400, "Error Getting Inf. List: " + str(ex))


@app.route('/infrastructures', method='POST')
def RESTCreateInfrastructure():
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")

	try:
		content_type = get_media_type('Content-Type')
		radl_data = bottle.request.body.read()
		
		if content_type:
			if content_type == "application/json":
				radl_data = parse_radl_json(radl_data)
			elif content_type in ["text/plain","*/*","text/*"]:
				content_type = "text/plain"
			else:
				bottle.abort(415, "Unsupported Media Type %s" % content_type)
				return False

		inf_id = InfrastructureManager.CreateInfrastructure(radl_data, auth)
		
		bottle.response.content_type = "text/uri-list"
		protocol = "http://"
		if Config.REST_SSL:
			protocol = "https://"
		return protocol + bottle.request.environ['HTTP_HOST'] + "/infrastructures/" + str(inf_id)
	except HTTPError, ex:
		raise ex
	except UnauthorizedUserException, ex:
		bottle.abort(401, "Error Getting Inf. info: " + str(ex))
	except Exception, ex:
		logger.exception("Error Creating Inf.")
		bottle.abort(400, "Error Creating Inf.: " + str(ex))

@app.route('/infrastructures/:infid/vms/:vmid', method='GET')
def RESTGetVMInfo(infid=None, vmid=None):
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		accept = get_media_type('Accept')
		
		radl = InfrastructureManager.GetVMInfo(infid, vmid, auth)
		
		if accept:
			if accept == "application/json":
				bottle.response.content_type = accept
				info = dump_radl_json(radl, enter="", indent="")
			elif accept in ["text/plain","*/*","text/*"]:
				info = str(radl)
				bottle.response.content_type = "text/plain"
			else:
				bottle.abort(404, "Unsupported Accept Media Type: %s" % accept)
				return False
		else:
			info = str(radl)
			bottle.response.content_type = "text/plain"
			
		return info
	except HTTPError, ex:
		raise ex
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error Getting VM. info: " + str(ex))
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error Getting VM. info: " + str(ex))
	except DeletedVMException, ex:
		bottle.abort(404, "Error Getting VM. info: " + str(ex))
	except IncorrectVMException, ex:
		bottle.abort(404, "Error Getting VM. info: " + str(ex))
	except Exception, ex:
		logger.exception("Error Getting VM info")
		bottle.abort(400, "Error Getting VM info: " + str(ex))

@app.route('/infrastructures/:infid/vms/:vmid/:prop', method='GET')
def RESTGetVMProperty(infid=None, vmid=None, prop=None):
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		if prop == 'contmsg':
			info = InfrastructureManager.GetVMContMsg(infid, vmid, auth)
		else:
			info = InfrastructureManager.GetVMProperty(infid, vmid, prop, auth)
		
		accept = get_media_type('Accept')
		if accept:
			if accept == "application/json":
				bottle.response.content_type = accept
				if isinstance(info, str) or isinstance(info, unicode):
					info = '"' + info + '"'
			elif accept in ["text/plain","*/*","text/*"]:
				bottle.response.content_type = "text/plain"
			else:
				bottle.abort(404, "Unsupported Accept Media Type: %s" % accept)
				return False
		else:
			bottle.response.content_type = "text/plain"
		
		return str(info)
	except HTTPError, ex:
		raise ex
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error Getting VM. property: " + str(ex))
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error Getting VM. property: " + str(ex))
	except DeletedVMException, ex:
		bottle.abort(404, "Error Getting VM. property: " + str(ex))
	except IncorrectVMException, ex:
		bottle.abort(404, "Error Getting VM. property: " + str(ex))
	except Exception, ex:
		logger.exception("Error Getting VM property")
		bottle.abort(400, "Error Getting VM property: " + str(ex))

@app.route('/infrastructures/:id', method='POST')
def RESTAddResource(id=None):
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")

	try:
		context = True
		if "context" in bottle.request.params.keys():
			str_ctxt = bottle.request.params.get("context").lower()
			if str_ctxt in ['yes', 'true', '1']:
				context = True 
			elif str_ctxt in ['no', 'false', '0']:
				context = False
			else:
				bottle.abort(400, "Incorrect value in context parameter")

		content_type = get_media_type('Content-Type')
		radl_data = bottle.request.body.read()
		
		if content_type:
			if content_type == "application/json":
				radl_data = parse_radl_json(radl_data)
			elif content_type in ["text/plain","*/*","text/*"]:
				content_type = "text/plain"
			else:
				bottle.abort(415, "Unsupported Media Type %s" % content_type)
				return False

		vm_ids = InfrastructureManager.AddResource(id, radl_data, auth, context)
		
		protocol = "http://"
		if Config.REST_SSL:
			protocol = "https://"
		res = ""
		for vm_id in vm_ids:
			if res:
				res += "\n"
			res += protocol + bottle.request.environ['HTTP_HOST'] + "/infrastructures/" + str(id) + "/vms/" + str(vm_id)
		
		bottle.response.content_type = "text/uri-list"
		return res
	except HTTPError, ex:
		raise ex
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error Adding resources: " + str(ex))
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error Adding resources: " + str(ex))
	except Exception, ex:
		logger.exception("Error Adding resources")
		bottle.abort(400, "Error Adding resources: " + str(ex))
				
@app.route('/infrastructures/:infid/vms/:vmid', method='DELETE')
def RESTRemoveResource(infid=None, vmid=None):
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		context = True
		if "context" in bottle.request.params.keys():
			str_ctxt = bottle.request.params.get("context").lower()
			if str_ctxt in ['yes', 'true', '1']:
				context = True 
			elif str_ctxt in ['no', 'false', '0']:
				context = False
			else:
				bottle.abort(400, "Incorrect value in context parameter")

		InfrastructureManager.RemoveResource(infid, vmid, auth, context)
		bottle.response.content_type = "text/plain"
		return ""
	except HTTPError, ex:
		raise ex
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error Removing resources: " + str(ex))
		return False
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error Removing resources: " + str(ex))
	except DeletedVMException, ex:
		bottle.abort(404, "Error Removing resources: " + str(ex))
	except IncorrectVMException, ex:
		bottle.abort(404, "Error Removing resources: " + str(ex))
	except Exception, ex:
		logger.exception("Error Removing resources")
		bottle.abort(400, "Error Removing resources: " + str(ex))

@app.route('/infrastructures/:infid/vms/:vmid', method='PUT')
def RESTAlterVM(infid=None, vmid=None):
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		content_type = get_media_type('Content-Type')
		accept = get_media_type('Accept')
		radl_data = bottle.request.body.read()
		
		if content_type:
			if content_type == "application/json":
				radl_data = parse_radl_json(radl_data)
			elif content_type in ["text/plain","*/*","text/*"]:
				content_type = "text/plain"
			else:
				bottle.abort(415, "Unsupported Media Type %s" % content_type)
				return False
		
		vm_info = InfrastructureManager.AlterVM(infid, vmid, radl_data, auth)

		if accept:
			if accept == "application/json":
				bottle.response.content_type = accept
				res = dump_radl_json(vm_info, enter="", indent="")
			elif accept == "text/plain":
				res = str(vm_info)
				bottle.response.content_type = accept
			else:
				bottle.abort(404, "Unsupported Accept Media Type: %s" % accept)
				return False
		else:
			bottle.response.content_type = "text/plain"

		return res
	except HTTPError, ex:
		raise ex
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error modifying resources: " + str(ex))
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error modifying resources: " + str(ex))
	except DeletedVMException, ex:
		bottle.abort(404, "Error modifying resources: " + str(ex))
	except IncorrectVMException, ex:
		bottle.abort(404, "Error modifying resources: " + str(ex))
	except Exception, ex:
		logger.exception("Error modifying resources")
		bottle.abort(400, "Error modifying resources: " + str(ex))

@app.route('/infrastructures/:id/reconfigure', method='PUT')
def RESTReconfigureInfrastructure(id=None):
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")

	try:
		vm_list = None
		if "vm_list" in bottle.request.params.keys():
			str_vm_list = bottle.request.params.get("vm_list")
			try:
				vm_list = [int(vm_id) for vm_id in str_vm_list.split(",")]
			except:
				bottle.abort(400, "Incorrect vm_list format.")
		
		content_type = get_media_type('Content-Type')
		radl_data = bottle.request.body.read()
		
		if radl_data:
			if content_type:
				if content_type == "application/json":
					radl_data = parse_radl_json(radl_data)
				elif content_type in ["text/plain","*/*","text/*"]:
					content_type = "text/plain"
				else:
					bottle.abort(415, "Unsupported Media Type %s" % content_type)
					return False
		else:
			radl_data = ""
		return InfrastructureManager.Reconfigure(id, radl_data, auth, vm_list)
	except HTTPError, ex:
		raise ex
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error reconfiguring infrastructure: " + str(ex))
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error reconfiguring infrastructure: " + str(ex))
	except Exception, ex:
		logger.exception("Error reconfiguring infrastructure")
		bottle.abort(400, "Error reconfiguring infrastructure: " + str(ex))

@app.route('/infrastructures/:id/start', method='PUT')
def RESTStartInfrastructure(id=None):
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")

	try:
		return InfrastructureManager.StartInfrastructure(id, auth)	
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error starting infrastructure: " + str(ex))
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error starting infrastructure: " + str(ex))
	except Exception, ex:
		logger.exception("Error starting infrastructure")
		bottle.abort(400, "Error starting infrastructure: " + str(ex))

@app.route('/infrastructures/:id/stop', method='PUT')
def RESTStopInfrastructure(id=None):
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")

	try:
		return InfrastructureManager.StopInfrastructure(id, auth)	
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error stopping infrastructure: " + str(ex))
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error stopping infrastructure: " + str(ex))
	except Exception, ex:
		logger.exception("Error stopping infrastructure")
		bottle.abort(400, "Error stopping infrastructure: " + str(ex))
	
@app.route('/infrastructures/:infid/vms/:vmid/start', method='PUT')
def RESTStartVM(infid=None, vmid=None, prop=None):
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		info = InfrastructureManager.StartVM(infid, vmid, auth)
		bottle.response.content_type = "text/plain"
		return info
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error starting VM: " + str(ex))
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error starting VM: " + str(ex))
	except DeletedVMException, ex:
		bottle.abort(404, "Error starting VM: " + str(ex))
	except IncorrectVMException, ex:
		bottle.abort(404, "Error starting VM: " + str(ex))
	except Exception, ex:
		logger.exception("Error starting VM")
		bottle.abort(400, "Error starting VM: " + str(ex))
	
@app.route('/infrastructures/:infid/vms/:vmid/stop', method='PUT')
def RESTStopVM(infid=None, vmid=None, prop=None):
	try:
		auth = get_auth_header()
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		info = InfrastructureManager.StopVM(infid, vmid, auth)
		bottle.response.content_type = "text/plain"
		return info
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error stopping VM: " + str(ex))
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error stopping VM: " + str(ex))
	except DeletedVMException, ex:
		bottle.abort(404, "Error stopping VM: " + str(ex))
	except IncorrectVMException, ex:
		bottle.abort(404, "Error stopping VM: " + str(ex))
	except Exception, ex:
		logger.exception("Error stopping VM")
		bottle.abort(400, "Error stopping VM: " + str(ex))

@app.route('/version', method='GET')
def RESTGeVersion():
	try:
		from IM import __version__ as version
		bottle.response.content_type = "text/plain"
		return version 
	except Exception, ex:
		bottle.abort(400, "Error getting IM state: " + str(ex))
