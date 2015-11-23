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

from InfrastructureInfo import IncorrectVMException, DeletedVMException
from InfrastructureManager import InfrastructureManager, DeletedInfrastructureException, IncorrectInfrastructureException, UnauthorizedUserException
from auth import Authentication
import threading
import bottle
import json
from config import Config

AUTH_LINE_SEPARATOR = '\\n'

app = bottle.Bottle()  
bottle_server = None

# Declaration of new class that inherits from ServerAdapter  
# It's almost equal to the supported cherrypy class CherryPyServer  
class MySSLCherryPy(bottle.ServerAdapter):  
	def run(self, handler):
		from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter
		from cherrypy import wsgiserver
		server = wsgiserver.CherryPyWSGIServer((self.host, self.port), handler)  
		self.srv = server

		# If cert variable is has a valid path, SSL will be used  
		# You can set it to None to disable SSL
		server.ssl_adapter = BuiltinSSLAdapter(Config.REST_SSL_CERTFILE, Config.REST_SSL_KEYFILE, Config.REST_SSL_CA_CERTS)
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

@app.route('/infrastructures/:id', method='DELETE')
def RESTDestroyInfrastructure(id=None):
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		InfrastructureManager.DestroyInfrastructure(id, auth)
		return ""
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error Destroying Inf: " + str(ex))
		return False
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error Destroying Inf: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error Destroying Inf: " + str(ex))
		return False

@app.route('/infrastructures/:id', method='GET')
def RESTGetInfrastructureInfo(id=None):
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		vm_ids = InfrastructureManager.GetInfrastructureInfo(id, auth)
		res = ""
		
		server_ip = bottle.request.environ['SERVER_NAME']
		server_port = bottle.request.environ['SERVER_PORT']
		
		for vm_id in vm_ids:
			if res:
				res += "\n"
			res += 'http://' + server_ip + ':' + server_port + '/infrastructures/' + str(id) + '/vms/' + str(vm_id)
		
		bottle.response.content_type = "text/uri-list"
		return res
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error Getting Inf. info: " + str(ex))
		return False
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error Getting Inf. info: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error Getting Inf. info: " + str(ex))

@app.route('/infrastructures/:id/:prop', method='GET')
def RESTGetInfrastructureProperty(id=None, prop=None):
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
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
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error Getting Inf. info: " + str(ex))
		return False
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error Getting Inf. info: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error Getting Inf. info: " + str(ex))

@app.route('/infrastructures', method='GET')
def RESTGetInfrastructureList():
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		inf_ids = InfrastructureManager.GetInfrastructureList(auth)
		
		server_ip = bottle.request.environ['SERVER_NAME']
		server_port = bottle.request.environ['SERVER_PORT']
		
		res = ""
		for inf_id in inf_ids:
			res += "http://" + server_ip + ":" + server_port + "/infrastructures/" + str(inf_id) + "\n"
		
		bottle.response.content_type = "text/uri-list"
		return res
	except UnauthorizedUserException, ex:
		bottle.abort(401, "Error Getting Inf. List: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error Getting Inf. List: " + str(ex))
		return False


@app.route('/infrastructures', method='POST')
def RESTCreateInfrastructure():
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
	except:
		bottle.abort(401, "No authentication data provided")

	try:
		radl_data = bottle.request.body.read()
		inf_id = InfrastructureManager.CreateInfrastructure(radl_data, auth)

		server_ip = bottle.request.environ['SERVER_NAME']
		server_port = bottle.request.environ['SERVER_PORT']
		
		bottle.response.content_type = "text/uri-list"
		return "http://" + server_ip + ":" + server_port + "/infrastructures/" + str(inf_id)
	except UnauthorizedUserException, ex:
		bottle.abort(401, "Error Getting Inf. info: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error Creating Inf.: " + str(ex))
		return False

@app.route('/infrastructures/:infid/vms/:vmid', method='GET')
def RESTGetVMInfo(infid=None, vmid=None):
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		info = InfrastructureManager.GetVMInfo(infid, vmid, auth)
		bottle.response.content_type = "text/plain"
		return info
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error Getting VM. info: " + str(ex))
		return False
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error Getting VM. info: " + str(ex))
		return False
	except DeletedVMException, ex:
		bottle.abort(404, "Error Getting VM. info: " + str(ex))
		return False
	except IncorrectVMException, ex:
		bottle.abort(404, "Error Getting VM. info: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error Getting VM info: " + str(ex))
		return False

@app.route('/infrastructures/:infid/vms/:vmid/:prop', method='GET')
def RESTGetVMProperty(infid=None, vmid=None, prop=None):
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		if prop == 'contmsg':
			info = InfrastructureManager.GetVMContMsg(infid, vmid, auth)
		else:
			info = InfrastructureManager.GetVMProperty(infid, vmid, prop, auth)
		bottle.response.content_type = "text/plain"
		return str(info)
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error Getting VM. property: " + str(ex))
		return False
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error Getting VM. property: " + str(ex))
		return False
	except DeletedVMException, ex:
		bottle.abort(404, "Error Getting VM. property: " + str(ex))
		return False
	except IncorrectVMException, ex:
		bottle.abort(404, "Error Getting VM. property: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error Getting VM property: " + str(ex))
		return False

@app.route('/infrastructures/:id', method='POST')
def RESTAddResource(id=None):
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
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
				
		radl_data = bottle.request.body.read()
		vm_ids = InfrastructureManager.AddResource(id, radl_data, auth, context)

		server_ip = bottle.request.environ['SERVER_NAME']
		server_port = bottle.request.environ['SERVER_PORT']
		
		res = ""
		for vm_id in vm_ids:
			if res:
				res += "\n"
			res += "http://" + server_ip + ":" + server_port + "/infrastructures/" + str(id) + "/vms/" + str(vm_id)
		
		bottle.response.content_type = "text/uri-list"
		return res
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error Adding resources: " + str(ex))
		return False
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error Adding resources: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error Adding resources: " + str(ex))
		return False
				
@app.route('/infrastructures/:infid/vms/:vmid', method='DELETE')
def RESTRemoveResource(infid=None, vmid=None):
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
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
		return ""
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error Removing resources: " + str(ex))
		return False
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error Removing resources: " + str(ex))
		return False
	except DeletedVMException, ex:
		bottle.abort(404, "Error Removing resources: " + str(ex))
		return False
	except IncorrectVMException, ex:
		bottle.abort(404, "Error Removing resources: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error Removing resources: " + str(ex))
		return False

@app.route('/infrastructures/:infid/vms/:vmid', method='PUT')
def RESTAlterVM(infid=None, vmid=None):
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		radl_data = bottle.request.body.read()
		
		bottle.response.content_type = "text/plain"
		return InfrastructureManager.AlterVM(infid, vmid, radl_data, auth)
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error modifying resources: " + str(ex))
		return False
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error modifying resources: " + str(ex))
		return False
	except DeletedVMException, ex:
		bottle.abort(404, "Error modifying resources: " + str(ex))
		return False
	except IncorrectVMException, ex:
		bottle.abort(404, "Error modifying resources: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error modifying resources: " + str(ex))
		return False

@app.route('/infrastructures/:id/reconfigure', method='PUT')
def RESTReconfigureInfrastructure(id=None):
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
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
		
		if 'radl' in bottle.request.forms.keys():
			radl_data = bottle.request.forms.get('radl')
		else:
			radl_data = ""
		return InfrastructureManager.Reconfigure(id, radl_data, auth, vm_list)
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error reconfiguring infrastructure: " + str(ex))
		return False
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error reconfiguring infrastructure: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error reconfiguring infrastructure: " + str(ex))
		return False

@app.route('/infrastructures/:id/start', method='PUT')
def RESTStartInfrastructure(id=None):
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
	except:
		bottle.abort(401, "No authentication data provided")

	try:
		return InfrastructureManager.StartInfrastructure(id, auth)	
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error starting infrastructure: " + str(ex))
		return False
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error starting infrastructure: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error starting infrastructure: " + str(ex))
		return False

@app.route('/infrastructures/:id/stop', method='PUT')
def RESTStopInfrastructure(id=None):
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
	except:
		bottle.abort(401, "No authentication data provided")

	try:
		return InfrastructureManager.StopInfrastructure(id, auth)	
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error stopping infrastructure: " + str(ex))
		return False
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error stopping infrastructure: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error stopping infrastructure: " + str(ex))
		return False
	
@app.route('/infrastructures/:infid/vms/:vmid/start', method='PUT')
def RESTStartVM(infid=None, vmid=None, prop=None):
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		info = InfrastructureManager.StartVM(infid, vmid, auth)
		bottle.response.content_type = "text/plain"
		return info
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error starting VM: " + str(ex))
		return False
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error starting VM: " + str(ex))
		return False
	except DeletedVMException, ex:
		bottle.abort(404, "Error starting VM: " + str(ex))
		return False
	except IncorrectVMException, ex:
		bottle.abort(404, "Error starting VM: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error starting VM: " + str(ex))
		return False
	
@app.route('/infrastructures/:infid/vms/:vmid/stop', method='PUT')
def RESTStopVM(infid=None, vmid=None, prop=None):
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		info = InfrastructureManager.StopVM(infid, vmid, auth)
		bottle.response.content_type = "text/plain"
		return info
	except DeletedInfrastructureException, ex:
		bottle.abort(404, "Error stopping VM: " + str(ex))
		return False
	except IncorrectInfrastructureException, ex:
		bottle.abort(404, "Error stopping VM: " + str(ex))
		return False
	except DeletedVMException, ex:
		bottle.abort(404, "Error stopping VM: " + str(ex))
		return False
	except IncorrectVMException, ex:
		bottle.abort(404, "Error stopping VM: " + str(ex))
		return False
	except Exception, ex:
		bottle.abort(400, "Error stopping VM: " + str(ex))
		return False