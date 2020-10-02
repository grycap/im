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
import json
import base64
import bottle

from IM.InfrastructureInfo import IncorrectVMException, DeletedVMException, IncorrectStateException
from IM.InfrastructureManager import (InfrastructureManager, DeletedInfrastructureException,
                                      IncorrectInfrastructureException, UnauthorizedUserException,
                                      InvaliddUserException, DisabledFunctionException)
from IM.auth import Authentication
from IM.config import Config
from IM import get_ex_error
from radl.radl_json import parse_radl as parse_radl_json, dump_radl as dump_radl_json, featuresToSimple, radlToSimple
from radl.radl import RADL, Features, Feature
from IM.tosca.Tosca import Tosca

logger = logging.getLogger('InfrastructureManager')

# Combination of chars used to separate the lines in the AUTH header
AUTH_LINE_SEPARATOR = '\\n'
# Combination of chars used to separate the lines inside the auth data
# (i.e. in a certificate)
AUTH_NEW_LINE_SEPARATOR = '\\\\n'

HTML_ERROR_TEMPLATE = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html>
    <head>
        <title>Error %d.</title>
    </head>
    <body>
        <h1>Code: %d.</h1>
        <h1>Message: %s</h1>
    </body>
</html>
"""

REST_URL = None

app = bottle.Bottle()
bottle_server = None

# Declaration of new class that inherits from ServerAdapter
# It's almost equal to the supported cherrypy class CherryPyServer


class MySSLCherryPy(bottle.ServerAdapter):

    def run(self, handler):
        try:
            # First try to use the new version
            from cheroot.ssl.pyopenssl import pyOpenSSLAdapter
            from cheroot import wsgi
            server = wsgi.Server((self.host, self.port), handler, request_queue_size=32)
        except Exception:
            from cherrypy.wsgiserver.ssl_pyopenssl import pyOpenSSLAdapter
            from cherrypy import wsgiserver
            server = wsgiserver.CherryPyWSGIServer((self.host, self.port), handler, request_queue_size=32)

        self.srv = server

        # If cert variable is has a valid path, SSL will be used
        # You can set it to None to disable SSL
        server.ssl_adapter = pyOpenSSLAdapter(Config.REST_SSL_CERTFILE,
                                              Config.REST_SSL_KEYFILE,
                                              Config.REST_SSL_CA_CERTS)
        try:
            server.start()
        finally:
            server.stop()

    def shutdown(self):
        self.srv.stop()


class MyCherryPy(bottle.ServerAdapter):

    def run(self, handler):
        try:
            # First try to use the new version
            from cheroot import wsgi
            server = wsgi.Server((self.host, self.port), handler, request_queue_size=32)
        except Exception:
            from cherrypy import wsgiserver
            server = wsgiserver.CherryPyWSGIServer((self.host, self.port), handler, request_queue_size=32)

        self.srv = server
        try:
            server.start()
        finally:
            server.stop()

    def shutdown(self):
        self.srv.stop()


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
        bottle_server = MyCherryPy(host=host, port=port)
        bottle.run(app, server=bottle_server, quiet=True)


def return_error(code, msg):
    content_type = get_media_type('Accept')

    if "application/json" in content_type:
        bottle.response.status = code
        bottle.response.content_type = "application/json"
        return json.dumps({'message': msg, 'code': code})
    elif "text/html" in content_type:
        bottle.response.status = code
        bottle.response.content_type = "text/html"
        return HTML_ERROR_TEMPLATE % (code, code, msg)
    else:
        bottle.response.status = code
        bottle.response.content_type = 'text/plain'
        return msg


def get_full_url(path):
    """
    Get the full URL to be returned by the API calls
    """
    protocol = "http://"
    if Config.REST_SSL:
        protocol = "https://"

    # if it is a forwarded call use the original protocol
    if 'HTTP_X_FORWARDED_PROTO' in bottle.request.environ and bottle.request.environ['HTTP_X_FORWARDED_PROTO']:
        protocol = bottle.request.environ['HTTP_X_FORWARDED_PROTO'] + "://"

    # if it is a forwarded call add the original prefix
    if 'HTTP_X_FORWARDED_PREFIX' in bottle.request.environ and bottle.request.environ['HTTP_X_FORWARDED_PREFIX']:
        path = bottle.request.environ['HTTP_X_FORWARDED_PREFIX'].rstrip('/') + path

    return protocol + bottle.request.environ['HTTP_HOST'] + path


def stop():
    if bottle_server:
        bottle_server.shutdown()


def get_media_type(header):
    """
    Function to get specified the header media type.
    Returns a List of strings.
    """
    res = []
    accept = bottle.request.headers.get(header)
    if accept:
        media_types = accept.split(",")
        for media_type in media_types:
            pos = media_type.find(";")
            if pos != -1:
                media_type = media_type[:pos]
            if media_type.strip() in ["text/yaml", "text/x-yaml"]:
                res.append("text/yaml")
            else:
                res.append(media_type.strip())

    return res


def get_auth_header():
    """
    Get the Authentication object from the AUTHORIZATION header
    replacing the new line chars.
    """
    # Initialize REST_URL
    global REST_URL
    if REST_URL is None:
        REST_URL = get_full_url("")

    auth_header = bottle.request.headers['AUTHORIZATION']
    if Config.SINGLE_SITE:
        if auth_header.startswith("Basic "):
            auth_data = str(base64.b64decode(auth_header[6:]))
            user_pass = auth_data.split(":")
            im_auth = {"type": "InfrastructureManager",
                       "username": user_pass[0],
                       "password": user_pass[1]}
            single_site_auth = {"type": Config.SINGLE_SITE_TYPE,
                                "host": Config.SINGLE_SITE_AUTH_HOST,
                                "username": user_pass[0],
                                "password": user_pass[1]}
            return Authentication([im_auth, single_site_auth])
        elif auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            im_auth = {"type": "InfrastructureManager",
                       "username": "user",
                       "token": token}
            if Config.SINGLE_SITE_TYPE == "OpenStack":
                single_site_auth = {"type": Config.SINGLE_SITE_TYPE,
                                    "host": Config.SINGLE_SITE_AUTH_HOST,
                                    "username": "indigo-dc",
                                    "tenant": "oidc",
                                    "password": token}
            else:
                single_site_auth = {"type": Config.SINGLE_SITE_TYPE,
                                    "host": Config.SINGLE_SITE_AUTH_HOST,
                                    "token": token}
            return Authentication([im_auth, single_site_auth])
    auth_data = auth_header.replace(AUTH_NEW_LINE_SEPARATOR, "\n")
    auth_data = auth_data.split(AUTH_LINE_SEPARATOR)
    return Authentication(Authentication.read_auth_data(auth_data))


def format_output_json(res, field_name=None, list_field_name=None):
    res_dict = res
    if field_name:
        if list_field_name and isinstance(res, list):
            res_dict = {field_name: []}
            for elem in res:
                res_dict[field_name].append({list_field_name: elem})
        else:
            res_dict = {field_name: res}

    return json.dumps(res_dict)


def format_output(res, default_type="text/plain", field_name=None, list_field_name=None):
    """
    Format the output of the API responses
    """
    accept = get_media_type('Accept')

    if accept:
        content_type = None
        for accept_item in accept:
            if accept_item in ["application/json", "application/*"]:
                if isinstance(res, RADL):
                    if field_name:
                        res_dict = {field_name: radlToSimple(res)}
                        info = json.dumps(res_dict)
                    else:
                        info = dump_radl_json(res, enter="", indent="")
                # This is the case of the "contains" properties
                elif isinstance(res, dict) and all(isinstance(x, Feature) for x in res.values()):
                    features = Features()
                    features.props = res
                    res_dict = featuresToSimple(features)
                    if field_name:
                        res_dict = {field_name: res_dict}
                    info = json.dumps(res_dict)
                else:
                    # Always return a complex object to make easier parsing
                    # steps
                    info = format_output_json(res, field_name, list_field_name)
                content_type = "application/json"
                break
            elif accept_item in [default_type, "*/*", "text/*"]:
                if default_type == "application/json":
                    info = format_output_json(res, field_name, list_field_name)
                else:
                    if isinstance(res, list):
                        info = "\n".join(res)
                    else:
                        info = "%s" % res
                content_type = default_type
                break

        if content_type:
            bottle.response.content_type = content_type
        else:
            return return_error(415, "Unsupported Accept Media Types: %s" % ",".join(accept))
    else:
        if default_type == "application/json":
            info = format_output_json(res, field_name, list_field_name)
        else:
            if isinstance(res, list):
                info = "\n".join(res)
            else:
                info = "%s" % res
        bottle.response.content_type = default_type

    return info


@app.hook('after_request')
def enable_cors():
    """
    Enable CORS to javascript SDK
    """
    if Config.ENABLE_CORS:
        bottle.response.headers['Access-Control-Allow-Origin'] = Config.CORS_ORIGIN
        bottle.response.headers['Access-Control-Allow-Methods'] = 'PUT, GET, POST, DELETE, OPTIONS'
        bottle.response.headers['Access-Control-Allow-Headers'] = 'Origin, Accept, Content-Type, Authorization'


@app.route('/infrastructures/:infid', method='DELETE')
def RESTDestroyInfrastructure(infid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        force = False
        if "force" in bottle.request.params.keys():
            str_force = bottle.request.params.get("force").lower()
            if str_force in ['yes', 'true', '1']:
                force = True
            elif str_force in ['no', 'false', '0']:
                force = False
            else:
                return return_error(400, "Incorrect value in force parameter")

        async_call = False
        if "async" in bottle.request.params.keys():
            str_ctxt = bottle.request.params.get("async").lower()
            if str_ctxt in ['yes', 'true', '1']:
                async_call = True
            elif str_ctxt in ['no', 'false', '0']:
                async_call = False
            else:
                return return_error(400, "Incorrect value in async parameter")

        InfrastructureManager.DestroyInfrastructure(infid, auth, force, async_call)
        bottle.response.content_type = "text/plain"
        return ""
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Destroying Inf: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Destroying Inf: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except IncorrectStateException as ex:
        return return_error(409, "Error Destroying Inf: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Destroying Inf")
        return return_error(400, "Error Destroying Inf: %s" % get_ex_error(ex))


@app.route('/infrastructures/:infid', method='GET')
def RESTGetInfrastructureInfo(infid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        vm_ids = InfrastructureManager.GetInfrastructureInfo(infid, auth)
        res = []

        for vm_id in vm_ids:
            res.append(get_full_url('/infrastructures/' + str(infid) + '/vms/' + str(vm_id)))

        return format_output(res, "text/uri-list", "uri-list", "uri")
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Getting Inf. info: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Getting Inf. info: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Getting Inf. info: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting Inf. info")
        return return_error(400, "Error Getting Inf. info: %s" % get_ex_error(ex))


@app.route('/infrastructures/:infid/:prop', method='GET')
def RESTGetInfrastructureProperty(infid=None, prop=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        if prop == "contmsg":
            headeronly = False
            if "headeronly" in bottle.request.params.keys():
                str_headeronly = bottle.request.params.get("headeronly").lower()
                if str_headeronly in ['yes', 'true', '1']:
                    headeronly = True
                elif str_headeronly in ['no', 'false', '0']:
                    headeronly = False
                else:
                    return return_error(400, "Incorrect value in headeronly parameter")

            res = InfrastructureManager.GetInfrastructureContMsg(infid, auth, headeronly)
        elif prop == "radl":
            res = InfrastructureManager.GetInfrastructureRADL(infid, auth)
        elif prop == "tosca":
            accept = get_media_type('Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                return return_error(415, "Unsupported Accept Media Types: %s" % accept)
            bottle.response.content_type = "application/json"
            auth = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth)
            if "TOSCA" in sel_inf.extra_info:
                res = sel_inf.extra_info["TOSCA"].serialize()
            else:
                bottle.abort(
                    403, "'tosca' infrastructure property is not valid in this infrastructure")
        elif prop == "state":
            accept = get_media_type('Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                return return_error(415, "Unsupported Accept Media Types: %s" % accept)
            bottle.response.content_type = "application/json"
            res = InfrastructureManager.GetInfrastructureState(infid, auth)
            return format_output(res, default_type="application/json", field_name="state")
        elif prop == "outputs":
            accept = get_media_type('Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                return return_error(415, "Unsupported Accept Media Types: %s" % accept)
            bottle.response.content_type = "application/json"
            auth = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth)
            if "TOSCA" in sel_inf.extra_info:
                res = sel_inf.extra_info["TOSCA"].get_outputs(sel_inf)
            else:
                bottle.abort(
                    403, "'outputs' infrastructure property is not valid in this infrastructure")
            return format_output(res, default_type="application/json", field_name="outputs")
        elif prop == "data":
            accept = get_media_type('Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                return return_error(415, "Unsupported Accept Media Types: %s" % accept)

            delete = False
            if "delete" in bottle.request.params.keys():
                str_delete = bottle.request.params.get("delete").lower()
                if str_delete in ['yes', 'true', '1']:
                    delete = True
                elif str_delete in ['no', 'false', '0']:
                    delete = False
                else:
                    return return_error(400, "Incorrect value in delete parameter")

            data = InfrastructureManager.ExportInfrastructure(infid, delete, auth)
            return format_output(data, default_type="application/json", field_name="data")
        else:
            return return_error(404, "Incorrect infrastructure property")

        return format_output(res, field_name=prop)
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Getting Inf. prop: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Getting Inf. prop: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Getting Inf. prop: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting Inf. prop")
        return return_error(400, "Error Getting Inf. prop: %s" % get_ex_error(ex))


@app.route('/infrastructures', method='GET')
def RESTGetInfrastructureList():
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        flt = None
        if "filter" in bottle.request.params.keys():
            flt = bottle.request.params.get("filter")

        inf_ids = InfrastructureManager.GetInfrastructureList(auth, flt)
        res = []

        for inf_id in inf_ids:
            res.append(get_full_url('/infrastructures/%s' % inf_id))

        return format_output(res, "text/uri-list", "uri-list", "uri")
    except InvaliddUserException as ex:
        return return_error(401, "Error Getting Inf. List: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting Inf. List")
        return return_error(400, "Error Getting Inf. List: %s" % get_ex_error(ex))


@app.route('/infrastructures', method='POST')
def RESTCreateInfrastructure():
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        content_type = get_media_type('Content-Type')
        radl_data = bottle.request.body.read().decode("utf-8")
        tosca_data = None

        async_call = False
        if "async" in bottle.request.params.keys():
            str_ctxt = bottle.request.params.get("async").lower()
            if str_ctxt in ['yes', 'true', '1']:
                async_call = True
            elif str_ctxt in ['no', 'false', '0']:
                async_call = False
            else:
                return return_error(400, "Incorrect value in async parameter")

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type:
                tosca_data = Tosca(radl_data)
                _, radl_data = tosca_data.to_radl()
            elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                content_type = "text/plain"
            else:
                return return_error(415, "Unsupported Media Type %s" % content_type)

        inf_id = InfrastructureManager.CreateInfrastructure(radl_data, auth, async_call)

        # Store the TOSCA document
        if tosca_data:
            sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
            sel_inf.extra_info['TOSCA'] = tosca_data

        bottle.response.headers['InfID'] = inf_id
        bottle.response.content_type = "text/uri-list"
        res = get_full_url('/infrastructures/%s' % inf_id)

        return format_output(res, "text/uri-list", "uri")
    except InvaliddUserException as ex:
        return return_error(401, "Error Getting Inf. info: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Creating Inf.")
        return return_error(400, "Error Creating Inf.: %s" % get_ex_error(ex))


@app.route('/infrastructures', method='PUT')
def RESTImportInfrastructure():
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        content_type = get_media_type('Content-Type')
        data = bottle.request.body.read().decode("utf-8")

        if content_type:
            if "application/json" not in content_type:
                return return_error(415, "Unsupported Media Type %s" % content_type)

        new_id = InfrastructureManager.ImportInfrastructure(data, auth)

        bottle.response.content_type = "text/uri-list"
        res = get_full_url('/infrastructures/%s' % new_id)

        return format_output(res, "text/uri-list", "uri")
    except InvaliddUserException as ex:
        return return_error(401, "Error Impporting Inf.: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Impporting Inf.")
        return return_error(400, "Error Impporting Inf.: %s" % get_ex_error(ex))


@app.route('/infrastructures/:infid/vms/:vmid', method='GET')
def RESTGetVMInfo(infid=None, vmid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        radl = InfrastructureManager.GetVMInfo(infid, vmid, auth)
        return format_output(radl, field_name="radl")
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Getting VM. info: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting VM info")
        return return_error(400, "Error Getting VM info: %s" % get_ex_error(ex))


@app.route('/infrastructures/:infid/vms/:vmid/:prop', method='GET')
def RESTGetVMProperty(infid=None, vmid=None, prop=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        if prop == 'contmsg':
            info = InfrastructureManager.GetVMContMsg(infid, vmid, auth)
        elif prop == 'command':
            auth = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth)

            step = 1
            if "step" in bottle.request.params.keys():
                step = int(bottle.request.params.get("step"))

            if step == 1:
                url = get_full_url('/infrastructures/' + str(infid) + '/vms/' + str(vmid) + '/command?step=2')
                auth = sel_inf.auth.getAuthInfo("InfrastructureManager")[0]
                if 'token' in auth:
                    imauth = "token = %s" % auth['token']
                else:
                    imauth = "username = %s; password = %s" % (auth['username'], auth['password'])
                command = ('curl --insecure -s -H "Authorization: type = InfrastructureManager; %s" '
                           '-H "Accept: text/plain" %s' % (imauth, url))

                ps_command = "ps aux | grep -v grep | grep 'ssh -N -R'"
                info = """
                res="wait"
                while [ "$res" == "wait" ]
                do
                  res=`%s`
                  if [ "$res" != "wait" ]
                  then
                    echo "$res" > /var/tmp/reverse_ssh.sh
                    chmod a+x /var/tmp/reverse_ssh.sh
                    /var/tmp/reverse_ssh.sh
                    if [ "$res" != "true" ]
                    then
                      echo "*/1 * * * * root %s || /var/tmp/reverse_ssh.sh" > /etc/cron.d/reverse_ssh
                    fi
                  else
                    sleep 20
                  fi
                done""" % (command, ps_command)
                logger.debug("Step 1 command: %s" % info)
            elif step == 2:
                sel_vm = None
                for vm in sel_inf.get_vm_list():
                    if vm.creation_im_id == int(vmid):
                        sel_vm = vm
                        break
                if not sel_vm:
                    # it sometimes happen when the VM is in creation state
                    logger.warn("Specified vmid in step2 is incorrect!!")
                    info = "wait"
                else:
                    ssh = sel_vm.get_ssh_ansible_master(retry=False)

                    ssh_ok = False
                    if ssh:
                        ssh_ok = ssh.test_connectivity(time_out=2)

                    if ssh_ok:
                        # if it is the master do not make the ssh command
                        if sel_inf.vm_master and int(vmid) == sel_inf.vm_master.creation_im_id:
                            logger.debug("Step 2: Is the master do no make ssh command.")
                            info = "true"
                        else:
                            # if this vm is connected with the master directly do not make it also
                            if sel_vm.isConnectedWith(sel_inf.vm_master):
                                logger.debug("Step 2: Is connected with the master do no make ssh command.")
                                info = "true"
                            else:
                                info = sel_vm.get_ssh_command()
                    else:
                        info = "wait"
                logger.debug("Step 2 command for vm ID: %s is %s" % (vmid, info))
            else:
                info = None
        else:
            info = InfrastructureManager.GetVMProperty(infid, vmid, prop, auth)

        if info is None:
            return return_error(404, "Incorrect property %s for VM ID %s" % (prop, vmid))
        else:
            return format_output(info, field_name=prop)
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Getting VM. property: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting VM property")
        return return_error(400, "Error Getting VM property: %s" % get_ex_error(ex))


@app.route('/infrastructures/:infid', method='POST')
def RESTAddResource(infid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        context = True
        if "context" in bottle.request.params.keys():
            str_ctxt = bottle.request.params.get("context").lower()
            if str_ctxt in ['yes', 'true', '1']:
                context = True
            elif str_ctxt in ['no', 'false', '0']:
                context = False
            else:
                return return_error(400, "Incorrect value in context parameter")

        content_type = get_media_type('Content-Type')
        radl_data = bottle.request.body.read().decode("utf-8")
        tosca_data = None
        remove_list = []

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type:
                tosca_data = Tosca(radl_data)
                auth = InfrastructureManager.check_auth_data(auth)
                sel_inf = InfrastructureManager.get_infrastructure(infid, auth)
                # merge the current TOSCA with the new one
                if isinstance(sel_inf.extra_info['TOSCA'], Tosca):
                    tosca_data = sel_inf.extra_info['TOSCA'].merge(tosca_data)
                remove_list, radl_data = tosca_data.to_radl(sel_inf)
            elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                content_type = "text/plain"
            else:
                return return_error(415, "Unsupported Media Type %s" % content_type)

        if remove_list:
            InfrastructureManager.RemoveResource(infid, remove_list, auth, context)

        vm_ids = InfrastructureManager.AddResource(infid, radl_data, auth, context)

        # Replace the TOSCA document
        if tosca_data:
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth)
            sel_inf.extra_info['TOSCA'] = tosca_data

        res = []
        for vm_id in vm_ids:
            res.append(get_full_url("/infrastructures/" + str(infid) + "/vms/" + str(vm_id)))

        return format_output(res, "text/uri-list", "uri-list", "uri")
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Adding resources: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Adding resources: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Adding resources: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Adding resources")
        return return_error(400, "Error Adding resources: %s" % get_ex_error(ex))


@app.route('/infrastructures/:infid/vms/:vmid', method='DELETE')
def RESTRemoveResource(infid=None, vmid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        context = True
        if "context" in bottle.request.params.keys():
            str_ctxt = bottle.request.params.get("context").lower()
            if str_ctxt in ['yes', 'true', '1']:
                context = True
            elif str_ctxt in ['no', 'false', '0']:
                context = False
            else:
                return return_error(400, "Incorrect value in context parameter")

        InfrastructureManager.RemoveResource(infid, vmid, auth, context)
        bottle.response.content_type = "text/plain"
        return ""
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Removing resources: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Removing resources: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Removing resources: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error Removing resources: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error Removing resources: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Removing resources")
        return return_error(400, "Error Removing resources: %s" % get_ex_error(ex))


@app.route('/infrastructures/:infid/vms/:vmid', method='PUT')
def RESTAlterVM(infid=None, vmid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        content_type = get_media_type('Content-Type')
        radl_data = bottle.request.body.read().decode("utf-8")

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type:
                tosca_data = Tosca(radl_data)
                _, radl_data = tosca_data.to_radl()
            elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                content_type = "text/plain"
            else:
                return return_error(415, "Unsupported Media Type %s" % content_type)

        vm_info = InfrastructureManager.AlterVM(infid, vmid, radl_data, auth)

        return format_output(vm_info, field_name="radl")
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error modifying resources: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error modifying resources: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error modifying resources: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error modifying resources: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error modifying resources: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error modifying resources")
        return return_error(400, "Error modifying resources: %s" % get_ex_error(ex))


@app.route('/infrastructures/:infid/reconfigure', method='PUT')
def RESTReconfigureInfrastructure(infid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        vm_list = None
        if "vm_list" in bottle.request.params.keys():
            str_vm_list = bottle.request.params.get("vm_list")
            try:
                vm_list = [int(vm_id) for vm_id in str_vm_list.split(",")]
            except Exception:
                return return_error(400, "Incorrect vm_list format.")

        content_type = get_media_type('Content-Type')
        radl_data = bottle.request.body.read().decode("utf-8")

        if radl_data:
            if content_type:
                if "application/json" in content_type:
                    radl_data = parse_radl_json(radl_data)
                elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                    content_type = "text/plain"
                else:
                    return return_error(415, "Unsupported Media Type %s" % content_type)
        else:
            radl_data = ""
        bottle.response.content_type = "text/plain"
        return InfrastructureManager.Reconfigure(infid, radl_data, auth, vm_list)
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error reconfiguring infrastructure")
        return return_error(400, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))


@app.route('/infrastructures/:infid/start', method='PUT')
def RESTStartInfrastructure(infid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        bottle.response.content_type = "text/plain"
        return InfrastructureManager.StartInfrastructure(infid, auth)
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error starting infrastructure: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error starting infrastructure: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error starting infrastructure: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error starting infrastructure")
        return return_error(400, "Error starting infrastructure: %s" % get_ex_error(ex))


@app.route('/infrastructures/:infid/stop', method='PUT')
def RESTStopInfrastructure(infid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        bottle.response.content_type = "text/plain"
        return InfrastructureManager.StopInfrastructure(infid, auth)
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error stopping infrastructure: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error stopping infrastructure: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error stopping infrastructure: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error stopping infrastructure")
        return return_error(400, "Error stopping infrastructure: %s" % get_ex_error(ex))


@app.route('/infrastructures/:infid/vms/:vmid/start', method='PUT')
def RESTStartVM(infid=None, vmid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        bottle.response.content_type = "text/plain"
        return InfrastructureManager.StartVM(infid, vmid, auth)
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error starting VM: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error starting VM: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error starting VM: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error starting VM: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error starting VM: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error starting VM")
        return return_error(400, "Error starting VM: %s" % get_ex_error(ex))


@app.route('/infrastructures/:infid/vms/:vmid/stop', method='PUT')
def RESTStopVM(infid=None, vmid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        bottle.response.content_type = "text/plain"
        return InfrastructureManager.StopVM(infid, vmid, auth)
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error stopping VM: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error stopping VM: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error stopping VM: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error stopping VM: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error stopping VM: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error stopping VM")
        return return_error(400, "Error stopping VM: %s" % get_ex_error(ex))


@app.route('/infrastructures/:infid/vms/:vmid/reboot', method='PUT')
def RESTRebootVM(infid=None, vmid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        bottle.response.content_type = "text/plain"
        return InfrastructureManager.RebootVM(infid, vmid, auth)
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error rebooting VM: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error rebooting VM: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error rebooting VM: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error rebooting VM: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error rebooting VM: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error rebooting VM")
        return return_error(400, "Error rebooting VM: %s" % get_ex_error(ex))


@app.route("/<url:re:.+>", method='OPTIONS')
def ReturnOptions(**kwargs):
    return {}


@app.route('/version', method='GET')
def RESTGeVersion():
    try:
        from IM import __version__ as version
        return format_output(version, field_name="version")
    except Exception as ex:
        return return_error(400, "Error getting IM version: %s" % get_ex_error(ex))


@app.route('/infrastructures/:infid/vms/:vmid/disks/:disknum/snapshot', method='PUT')
def RESTCreateDiskSnapshot(infid=None, vmid=None, disknum=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        bottle.response.content_type = "text/plain"

        if "image_name" in bottle.request.params.keys():
            image_name = bottle.request.params.get("image_name")
        else:
            return return_error(400, "Parameter image_name required.")
        if "auto_delete" in bottle.request.params.keys():
            str_auto_delete = bottle.request.params.get("auto_delete").lower()
            if str_auto_delete in ['yes', 'true', '1']:
                auto_delete = True
            elif str_auto_delete in ['no', 'false', '0']:
                auto_delete = False
            else:
                return return_error(400, "Incorrect value in auto_delete parameter")
        else:
            auto_delete = False

        return InfrastructureManager.CreateDiskSnapshot(infid, vmid, int(disknum), image_name, auto_delete, auth)
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error creating snapshot: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error creating snapshot: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error creating snapshot: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error creating snapshot: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error creating snapshot: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error creating snapshot")
        return return_error(400, "Error creating snapshot: %s" % get_ex_error(ex))


@app.error(403)
def error_mesage_403(error):
    return return_error(403, error.body)


@app.error(404)
def error_mesage_404(error):
    return return_error(404, error.body)


@app.error(405)
def error_mesage_405(error):
    return return_error(405, error.body)


@app.error(500)
def error_mesage_500(error):
    return return_error(500, error.body)
