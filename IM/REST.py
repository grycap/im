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
from config import Config

AUTH_LINE_SEPARATOR = '\\n'

# Declaration of new class that inherits from ServerAdapter  
# It's almost equal to the supported cherrypy class CherryPyServer  
class MySSLCherryPy(bottle.ServerAdapter):  
	def run(self, handler):
		from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter
		from cherrypy import wsgiserver
		server = wsgiserver.CherryPyWSGIServer((self.host, self.port), handler)  

		# If cert variable is has a valid path, SSL will be used  
		# You can set it to None to disable SSL
		server.ssl_adapter = BuiltinSSLAdapter(Config.REST_SSL_CERTFILE, Config.REST_SSL_KEYFILE, Config.REST_SSL_CA_CERTS)
		try:  
			server.start()  
		finally:  
			server.stop()  

app = bottle.Bottle()  

def run_in_thread(host, port):
	bottle_thr = threading.Thread(target=run, args=(host, port))
	bottle_thr.start()

def run(host, port):
	if Config.REST_SSL:
		# Add our new MySSLCherryPy class to the supported servers  
		# under the key 'mysslcherrypy'
		bottle.server_names['mysslcherrypy'] = MySSLCherryPy
		bottle.run(app, host=host, port=port, server='mysslcherrypy', quiet=True)
	else:
		bottle.run(app, host=host, port=port, quiet=True)

@app.route('/infrastructures/:id', method='DELETE')
def RESTDestroyInfrastructure(id=None):
	try:
		auth_data = bottle.request.headers['AUTHORIZATION'].split(AUTH_LINE_SEPARATOR)
		auth = Authentication(Authentication.read_auth_data(auth_data))
	except:
		bottle.abort(401, "No authentication data provided")
	
	try:
		InfrastructureManager.DestroyInfrastructure(int(id), auth)
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
		vm_ids = InfrastructureManager.GetInfrastructureInfo(int(id), auth)
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
			res = InfrastructureManager.GetInfrastructureContMsg(int(id), auth)
		elif prop == "radl":
			res = InfrastructureManager.GetInfrastructureRADL(int(id), auth)
		else:
			bottle.abort(403, "Incorrect infrastructure property")
		bottle.response.content_type = "text/plain"
		return res
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
		bottle.abort(403, "Error Getting Inf. info: " + str(ex))
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
		info = InfrastructureManager.GetVMInfo(int(infid), vmid, auth)
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
			info = InfrastructureManager.GetVMContMsg(int(infid), vmid, auth)
		else:
			info = InfrastructureManager.GetVMProperty(int(infid), vmid, prop, auth)
		bottle.response.content_type = "text/plain"
		return info
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
		radl_data = bottle.request.body.read()
		vm_ids = InfrastructureManager.AddResource(int(id), radl_data, auth)

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
		InfrastructureManager.RemoveResource(int(infid), vmid, auth)
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
		return InfrastructureManager.AlterVM(int(infid), vmid, radl_data, auth)
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
		radl_data = bottle.request.forms.get('radl')
		return InfrastructureManager.Reconfigure(int(id), radl_data, auth)
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
		return InfrastructureManager.StartInfrastructure(int(id), auth)	
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
		return InfrastructureManager.StopInfrastructure(int(id), auth)	
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
		info = InfrastructureManager.StartVM(int(infid), vmid, auth)
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
		info = InfrastructureManager.StopVM(int(infid), vmid, auth)
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