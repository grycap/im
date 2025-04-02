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
import flask
import os
import yaml
import datetime

from cheroot.wsgi import Server as WSGIServer, PathInfoDispatcher
from cheroot.ssl.builtin import BuiltinSSLAdapter
from werkzeug.middleware.proxy_fix import ProxyFix
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
from IM.openid.JWT import JWT
from IM.oaipmh.oai import OAI
from IM.oaipmh.utils import Repository

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
app = flask.Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
flask_server = None


def run_in_thread(host, port):
    flask_thr = threading.Thread(target=run, args=(host, port))
    flask_thr.daemon = True
    flask_thr.start()


def run(host, port):
    global flask_server
    flask_server = WSGIServer((host, port), PathInfoDispatcher({'/': app}))
    if Config.REST_SSL:
        flask_server.ssl_adapter = BuiltinSSLAdapter(Config.REST_SSL_CERTFILE,
                                                     Config.REST_SSL_KEYFILE,
                                                     Config.REST_SSL_CA_CERTS)
    flask_server.start()


def return_error(code, msg):
    content_type = get_media_type('Accept')

    if "application/json" in content_type:
        return flask.Response(json.dumps({'message': msg, 'code': code}), status=code, mimetype='application/json')
    elif "text/html" in content_type:
        return flask.Response(HTML_ERROR_TEMPLATE % (code, code, msg), status=code, mimetype='text/html')
    else:
        return flask.Response(msg, status=code, mimetype='text/plain')


def stop():
    logger.info('Stopping REST API server...')
    flask_server.stop()


def get_media_type(header):
    """
    Function to get specified the header media type.
    Returns a List of strings.
    """
    res = []
    accept = flask.request.headers.get(header)
    if accept:
        media_types = accept.split(",")
        for media_type in media_types:
            pos = media_type.find(";")
            if pos != -1:
                media_type = media_type[:pos]
            if media_type.strip() in ["text/yaml", "text/x-yaml", "application/yaml"]:
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
        REST_URL = flask.request.url_root

    auth_header = flask.request.headers['AUTHORIZATION']

    user_pass = None
    token = None
    if auth_header.startswith("Basic "):
        auth_data = str(base64.b64decode(auth_header[6:]))
        user_pass = auth_data.split(":")
        im_auth = {"type": "InfrastructureManager",
                   "username": user_pass[0],
                   "password": user_pass[1]}
    elif auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        im_auth = {"type": "InfrastructureManager",
                   "token": token}

    if Config.SINGLE_SITE:
        if user_pass:
            single_site_auth = {"type": Config.SINGLE_SITE_TYPE,
                                "host": Config.SINGLE_SITE_AUTH_HOST,
                                "username": user_pass[0],
                                "password": user_pass[1]}
        elif token:
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
    elif Config.VAULT_URL and token:
        vault_auth = {"type": "Vault", "host": Config.VAULT_URL, "token": token}
        if Config.VAULT_PATH:
            vault_auth["path"] = Config.VAULT_PATH
        if "#USER_SUB#" in Config.VAULT_PATH:
            decoded_token = JWT().get_info(token)
            vault_auth["path"] = Config.VAULT_PATH.replace("#USER_SUB#", decoded_token.get("sub"))
        if Config.VAULT_MOUNT_POINT:
            vault_auth["mount_point"] = Config.VAULT_MOUNT_POINT
        if Config.VAULT_ROLE:
            vault_auth["role"] = Config.VAULT_ROLE
        return Authentication([im_auth, vault_auth])

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


def format_output(res, default_type="text/plain", field_name=None, list_field_name=None, extra_headers=None):
    """
    Format the output of the API responses
    """
    accept = get_media_type('Accept')

    if not accept:
        accept = [default_type]

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
        headers = {'Content-Type': content_type}
        if extra_headers:
            headers.update(extra_headers)
        return flask.make_response(info, 200, headers)
    else:
        return return_error(415, "Unsupported Accept Media Types: %s" % ",".join(accept))


@app.after_request
def enable_cors(response):
    """
    Enable CORS to javascript SDK
    """
    if Config.ENABLE_CORS:
        response.headers['Access-Control-Allow-Origin'] = Config.CORS_ORIGIN
        response.headers['Access-Control-Allow-Methods'] = 'PUT, GET, POST, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Origin, Accept, Content-Type, Authorization'
    return response


@app.route('/infrastructures/<infid>', methods=['DELETE'])
def RESTDestroyInfrastructure(infid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        force = False
        if "force" in flask.request.args.keys():
            str_force = flask.request.args.get("force").lower()
            if str_force in ['yes', 'true', '1']:
                force = True
            elif str_force in ['no', 'false', '0']:
                force = False
            else:
                return return_error(400, "Incorrect value in force parameter")

        async_call = False
        if "async" in flask.request.args.keys():
            str_ctxt = flask.request.args.get("async").lower()
            if str_ctxt in ['yes', 'true', '1']:
                async_call = True
            elif str_ctxt in ['no', 'false', '0']:
                async_call = False
            else:
                return return_error(400, "Incorrect value in async parameter")

        InfrastructureManager.DestroyInfrastructure(infid, auth, force, async_call)
        return flask.make_response("", 200, {'Content-Type': 'text/plain'})
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


@app.route('/infrastructures/<infid>', methods=['GET'])
def RESTGetInfrastructureInfo(infid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        vm_ids = InfrastructureManager.GetInfrastructureInfo(infid, auth)
        res = []

        for vm_id in vm_ids:
            res.append("%sinfrastructures/%s/vms/%s" % (flask.request.url_root, infid, vm_id))

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


@app.route('/infrastructures/<infid>/<prop>')
def RESTGetInfrastructureProperty(infid=None, prop=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        if prop == "contmsg":
            headeronly = False
            if "headeronly" in flask.request.args.keys():
                str_headeronly = flask.request.args.get("headeronly").lower()
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
            auth = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth)
            if "TOSCA" in sel_inf.extra_info:
                res = sel_inf.extra_info["TOSCA"].serialize()
            else:
                flask.abort(403, "'tosca' infrastructure property is not valid in this infrastructure")
        elif prop == "state":
            accept = get_media_type('Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                return return_error(415, "Unsupported Accept Media Types: %s" % accept)
            res = InfrastructureManager.GetInfrastructureState(infid, auth)
            return format_output(res, default_type="application/json", field_name="state")
        elif prop == "outputs":
            accept = get_media_type('Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                return return_error(415, "Unsupported Accept Media Types: %s" % accept)
            auth = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth)
            if "TOSCA" in sel_inf.extra_info:
                res = sel_inf.extra_info["TOSCA"].get_outputs(sel_inf)
            else:
                flask.abort(403, "'outputs' infrastructure property is not valid in this infrastructure")
            return format_output(res, default_type="application/json", field_name="outputs")
        elif prop == "data":
            accept = get_media_type('Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                return return_error(415, "Unsupported Accept Media Types: %s" % accept)

            delete = False
            if "delete" in flask.request.args.keys():
                str_delete = flask.request.args.get("delete").lower()
                if str_delete in ['yes', 'true', '1']:
                    delete = True
                elif str_delete in ['no', 'false', '0']:
                    delete = False
                else:
                    return return_error(400, "Incorrect value in delete parameter")

            data = InfrastructureManager.ExportInfrastructure(infid, delete, auth)
            return format_output(data, default_type="application/json", field_name="data")
        elif prop == "authorization":
            res = InfrastructureManager.GetInfrastructureOwners(infid, auth)
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


@app.route('/infrastructures', methods=['GET'])
def RESTGetInfrastructureList():
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        flt = None
        if "filter" in flask.request.args.keys():
            flt = flask.request.args.get("filter")

        inf_ids = InfrastructureManager.GetInfrastructureList(auth, flt)
        res = []

        for inf_id in inf_ids:
            res.append("%sinfrastructures/%s" % (flask.request.url_root, inf_id))

        return format_output(res, "text/uri-list", "uri-list", "uri")
    except InvaliddUserException as ex:
        return return_error(401, "Error Getting Inf. List: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting Inf. List")
        return return_error(400, "Error Getting Inf. List: %s" % get_ex_error(ex))


@app.route('/infrastructures', methods=['POST'])
def RESTCreateInfrastructure():
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        content_type = get_media_type('Content-Type')
        radl_data = flask.request.data.decode("utf-8")
        tosca_data = None

        async_call = False
        if "async" in flask.request.args.keys():
            str_async = flask.request.args.get("async").lower()
            if str_async in ['yes', 'true', '1']:
                async_call = True
            elif str_async in ['no', 'false', '0']:
                async_call = False
            else:
                return return_error(400, "Incorrect value in async parameter")

        dry_run = False
        if "dry_run" in flask.request.args.keys():
            str_dry_run = flask.request.args.get("dry_run").lower()
            if str_dry_run in ['yes', 'true', '1']:
                dry_run = True
            elif str_dry_run in ['no', 'false', '0']:
                dry_run = False
            else:
                return return_error(400, "Incorrect value in dry_run parameter")

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
                tosca_data = Tosca(radl_data, tosca_repo=Config.OAIPMH_REPO_BASE_IDENTIFIER_URL)
                _, radl_data = tosca_data.to_radl()
            elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                content_type = "text/plain"
            else:
                return return_error(415, "Unsupported Media Type %s" % content_type)

        if dry_run:
            res = InfrastructureManager.EstimateResouces(radl_data, auth)
            return format_output(res, "application/json")
        else:
            inf_id = InfrastructureManager.CreateInfrastructure(radl_data, auth, async_call)

            # Store the TOSCA document
            if tosca_data:
                sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
                sel_inf.extra_info['TOSCA'] = tosca_data

            res = "%sinfrastructures/%s" % (flask.request.url_root, inf_id)
            return format_output(res, "text/uri-list", "uri", extra_headers={'InfID': inf_id})
    except InvaliddUserException as ex:
        return return_error(401, "Error Creating Inf. info: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Creating Inf, info: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Creating Inf.")
        return return_error(400, "Error Creating Inf.: %s" % get_ex_error(ex))


@app.route('/infrastructures', methods=['PUT'])
def RESTImportInfrastructure():
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        content_type = get_media_type('Content-Type')
        data = flask.request.data.decode("utf-8")

        if content_type:
            if "application/json" not in content_type:
                return return_error(415, "Unsupported Media Type %s" % content_type)

        new_id = InfrastructureManager.ImportInfrastructure(data, auth)

        res = "%sinfrastructures/%s" % (flask.request.url_root, new_id)

        return format_output(res, "text/uri-list", "uri")
    except InvaliddUserException as ex:
        return return_error(401, "Error Impporting Inf.: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Impporting Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Impporting Inf.")
        return return_error(400, "Error Impporting Inf.: %s" % get_ex_error(ex))


@app.route('/infrastructures/<infid>/vms/<vmid>', methods=['GET'])
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


@app.route('/infrastructures/<infid>/vms/<vmid>/<prop>', methods=['GET'])
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
            if "step" in flask.request.args.keys():
                step = int(flask.request.args.get("step"))

            if step == 1:
                url = "%sinfrastructures/%s/vms/%s/command?step=2" % (flask.request.url_root, infid, vmid)
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
                    logger.warning("Specified vmid in step2 is incorrect!!")
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


@app.route('/infrastructures/<infid>', methods=['POST'])
def RESTAddResource(infid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        context = True
        if "context" in flask.request.args.keys():
            str_ctxt = flask.request.args.get("context").lower()
            if str_ctxt in ['yes', 'true', '1']:
                context = True
            elif str_ctxt in ['no', 'false', '0']:
                context = False
            else:
                return return_error(400, "Incorrect value in context parameter")

        content_type = get_media_type('Content-Type')
        radl_data = flask.request.data.decode("utf-8")
        tosca_data = None
        remove_list = []

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
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
            removed_vms = InfrastructureManager.RemoveResource(infid, remove_list, auth, context)
            if len(remove_list) != removed_vms:
                logger.error("Error deleting resources %s (removed %s)" % (remove_list, removed_vms))

        vm_ids = InfrastructureManager.AddResource(infid, radl_data, auth, context)

        # If there are no changes in the infra, launch a reconfigure
        if not remove_list and not vm_ids and context:
            InfrastructureManager.Reconfigure(infid, "", auth)

        # Replace the TOSCA document
        if tosca_data:
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth)
            sel_inf.extra_info['TOSCA'] = tosca_data

        res = []
        for vm_id in vm_ids:
            res.append("%sinfrastructures/%s/vms/%s" % (flask.request.url_root, infid, vm_id))

        if not vm_ids and remove_list and len(remove_list) != removed_vms:
            return return_error(404, "Error deleting resources %s (removed %s)" % (remove_list, removed_vms))
        else:
            extra_headers = {}
            # If we have to reconfigure the infra, return the ID for the HAProxy stickiness
            if context:
                extra_headers = {'InfID': infid}
            return format_output(res, "text/uri-list", "uri-list", "uri", extra_headers)
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error Adding resources: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error Adding resources: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error Adding resources: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error Adding resources: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Adding resources")
        return return_error(400, "Error Adding resources: %s" % get_ex_error(ex))


@app.route('/infrastructures/<infid>/vms/<vmid>', methods=['DELETE'])
def RESTRemoveResource(infid=None, vmid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        context = True
        if "context" in flask.request.args.keys():
            str_ctxt = flask.request.args.get("context").lower()
            if str_ctxt in ['yes', 'true', '1']:
                context = True
            elif str_ctxt in ['no', 'false', '0']:
                context = False
            else:
                return return_error(400, "Incorrect value in context parameter")

        InfrastructureManager.RemoveResource(infid, vmid, auth, context)
        return flask.make_response("", 200, {'Content-Type': 'text/plain'})
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
        return return_error(403, "Error Removing resources: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Removing resources")
        return return_error(400, "Error Removing resources: %s" % get_ex_error(ex))


@app.route('/infrastructures/<infid>/vms/<vmid>', methods=['PUT'])
def RESTAlterVM(infid=None, vmid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        content_type = get_media_type('Content-Type')
        radl_data = flask.request.data.decode("utf-8")

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
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
        return return_error(403, "Error modifying resources: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error modifying resources")
        return return_error(400, "Error modifying resources: %s" % get_ex_error(ex))


@app.route('/infrastructures/<infid>/reconfigure', methods=['PUT'])
def RESTReconfigureInfrastructure(infid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        vm_list = None
        if "vm_list" in flask.request.args.keys():
            str_vm_list = flask.request.args.get("vm_list")
            try:
                vm_list = [int(vm_id) for vm_id in str_vm_list.split(",")]
            except Exception:
                return return_error(400, "Incorrect vm_list format.")

        content_type = get_media_type('Content-Type')
        radl_data = flask.request.data.decode("utf-8")

        if radl_data:
            if content_type:
                if "application/json" in content_type:
                    radl_data = parse_radl_json(radl_data)
                elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
                    tosca_data = Tosca(radl_data)
                    _, radl_data = tosca_data.to_radl()
                elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                    content_type = "text/plain"
                else:
                    return return_error(415, "Unsupported Media Type %s" % content_type)
        else:
            radl_data = ""

        res = InfrastructureManager.Reconfigure(infid, radl_data, auth, vm_list)
        # As we have to reconfigure the infra, return the ID for the HAProxy stickiness
        return flask.make_response(res, 200, {'Content-Type': 'text/plain', 'InfID': infid})
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error reconfiguring infrastructure")
        return return_error(400, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))


@app.route('/infrastructures/<infid>/<op>', methods=['PUT'])
def RESTOperateInfrastructure(infid=None, op=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        if op == "start":
            res = InfrastructureManager.StartInfrastructure(infid, auth)
        elif op == "stop":
            res = InfrastructureManager.StopInfrastructure(infid, auth)
        else:
            flask.abort(404)
        return flask.make_response(res, 200, {'Content-Type': 'text/plain'})
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except DisabledFunctionException as ex:
        return return_error(403, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except Exception as ex:
        logger.exception("Error in %s operation" % op)
        return return_error(400, "Error in %s operation: %s" % (op, get_ex_error(ex)))


@app.route('/infrastructures/<infid>/vms/<vmid>/<op>', methods=['PUT'])
def RESTOperateVM(infid=None, vmid=None, op=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        if op == "start":
            res = InfrastructureManager.StartVM(infid, vmid, auth)
        elif op == "stop":
            res = InfrastructureManager.StopVM(infid, vmid, auth)
        elif op == "reboot":
            res = InfrastructureManager.RebootVM(infid, vmid, auth)
        else:
            flask.abort(404)
        return flask.make_response(res, 200, {'Content-Type': 'text/plain'})
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except DeletedVMException as ex:
        return return_error(404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except IncorrectVMException as ex:
        return return_error(404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except DisabledFunctionException as ex:
        return return_error(403, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except Exception as ex:
        logger.exception("Error in %s op in VM" % op)
        return return_error(400, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))


@app.route('/<path:url>', methods=['OPTIONS'])
def ReturnOptions(**kwargs):
    return {}


@app.route('/version')
def RESTGetVersion():
    try:
        from IM import __version__ as version
        return format_output(version, field_name="version")
    except Exception as ex:
        return return_error(400, "Error getting IM version: %s" % get_ex_error(ex))


@app.route('/')
def RESTIndex():
    rest_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(rest_path, 'swagger_api.yaml')
    api_docs = yaml.safe_load(open(abs_file_path, 'r'))
    api_docs['servers'][0]['url'] = flask.request.url_root
    return flask.make_response(json.dumps(api_docs), 200, {'Content-Type': 'application/json'})


@app.route('/infrastructures/<infid>/vms/<vmid>/disks/<disknum>/snapshot', methods=['PUT'])
def RESTCreateDiskSnapshot(infid=None, vmid=None, disknum=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        if "image_name" in flask.request.args.keys():
            image_name = flask.request.args.get("image_name")
        else:
            return return_error(400, "Parameter image_name required.")
        if "auto_delete" in flask.request.args.keys():
            str_auto_delete = flask.request.args.get("auto_delete").lower()
            if str_auto_delete in ['yes', 'true', '1']:
                auto_delete = True
            elif str_auto_delete in ['no', 'false', '0']:
                auto_delete = False
            else:
                return return_error(400, "Incorrect value in auto_delete parameter")
        else:
            auto_delete = False

        res = InfrastructureManager.CreateDiskSnapshot(infid, vmid, int(disknum), image_name, auto_delete, auth)
        return flask.make_response(res, 200, {'Content-Type': 'text/plain'})
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
        return return_error(403, "Error creating snapshot: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error creating snapshot")
        return return_error(400, "Error creating snapshot: %s" % get_ex_error(ex))


def _filters_str_to_dict(filters_str):
    filters = {}
    for elem in filters_str.split(","):
        kv = elem.split("=")
        if len(kv) != 2:
            raise Exception("Incorrect format")
        else:
            filters[kv[0]] = kv[1]
    return filters


@app.route('/clouds/<cloudid>/<param>', methods=['GET'])
def RESTGetCloudInfo(cloudid=None, param=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        if param == 'images':
            filters = None
            if "filters" in flask.request.args.keys():
                try:
                    filters = _filters_str_to_dict(flask.request.args.get("filters"))
                except Exception:
                    return return_error(400, "Invalid format in filters parameter.")
            images = InfrastructureManager.GetCloudImageList(cloudid, auth, filters)
            return format_output(images, default_type="application/json", field_name="images")
        elif param == 'quotas':
            quotas = InfrastructureManager.GetCloudQuotas(cloudid, auth)
            return format_output(quotas, default_type="application/json", field_name="quotas")
    except InvaliddUserException as ex:
        return return_error(401, "Error getting cloud info: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error getting cloud info")
        return return_error(400, "Error getting cloud info: %s" % get_ex_error(ex))


@app.route('/infrastructures/<infid>/authorization', methods=['POST'])
def RESTChangeInfrastructureAuth(infid=None):
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        overwrite = False
        if "overwrite" in flask.request.args.keys():
            str_overwrite = flask.request.args.get("overwrite").lower()
            if str_overwrite in ['yes', 'true', '1']:
                overwrite = True
            elif str_overwrite in ['no', 'false', '0']:
                overwrite = False
            else:
                return return_error(400, "Incorrect value in overwrite parameter")

        content_type = get_media_type('Content-Type') or ["application/json"]

        if "application/json" in content_type:
            auth_dict = json.loads(flask.request.data.decode("utf-8"))
            if "type" not in auth_dict:
                auth_dict["type"] = "InfrastructureManager"
            new_auth = Authentication([auth_dict])
        else:
            return return_error(415, "Unsupported Media Type %s" % content_type)

        InfrastructureManager.ChangeInfrastructureAuth(infid, new_auth, overwrite, auth)
        return flask.make_response("", 200, {'Content-Type': 'text/plain'})
    except DeletedInfrastructureException as ex:
        return return_error(404, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(404, "Error modifying infrastructure owners: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(403, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(404, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(404, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(403, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error modifying infrastructure owner.")
        return return_error(400, "Error modifying infrastructure owner: %s" % get_ex_error(ex))


@app.route('/stats', methods=['GET'])
def RESTGetStats():
    try:
        auth = get_auth_header()
    except Exception:
        return return_error(401, "No authentication data provided")

    try:
        init_date = None
        if "init_date" in flask.request.args.keys():
            init_date = flask.request.args.get("init_date").lower()
            init_date = init_date.replace("/", "-")
            parts = init_date.split("-")
            try:
                year = int(parts[0])
                month = int(parts[1])
                day = int(parts[2])
                datetime.date(year, month, day)
            except Exception:
                return return_error(400, "Incorrect format in init_date parameter: YYYY/MM/dd")
        else:
            init_date = "1970-01-01"

        end_date = None
        if "end_date" in flask.request.args.keys():
            end_date = flask.request.args.get("end_date").lower()
            end_date = end_date.replace("/", "-")
            parts = end_date.split("-")
            try:
                year = int(parts[0])
                month = int(parts[1])
                day = int(parts[2])
                datetime.date(year, month, day)
            except Exception:
                return return_error(400, "Incorrect format in end_date parameter: YYYY/MM/dd")

        stats = InfrastructureManager.GetStats(init_date, end_date, auth)
        return format_output(stats, default_type="application/json", field_name="stats")
    except Exception as ex:
        logger.exception("Error getting stats")
        return return_error(400, "Error getting stats: %s" % get_ex_error(ex))


@app.route('/oai', methods=['GET', 'POST'])
def oaipmh():
    if not (Config.OAIPMH_REPO_BASE_IDENTIFIER_URL and
            Config.OAIPMH_REPO_NAME and Config.OAIPMH_REPO_DESCRIPTION):
        return return_error(400, "OAI-PMH not enabled.")

    oai = OAI(Config.OAIPMH_REPO_NAME, flask.request.base_url, Config.OAIPMH_REPO_DESCRIPTION,
              Config.OAIPMH_REPO_BASE_IDENTIFIER_URL, repo_admin_email=Config.OAIPMH_REPO_ADMIN_EMAIL)

    # Get list of TOSCA templates from Config.OAIPMH_REPO_BASE_IDENTIFIER_URL
    metadata_dict = {}
    try:
        repo = Repository.create(Config.OAIPMH_REPO_BASE_IDENTIFIER_URL)
        for name, elem in repo.list().items():
            tosca = yaml.safe_load(repo.get(elem))
            metadata = tosca["metadata"]
            metadata["identifier"] = Config.OAIPMH_REPO_BASE_IDENTIFIER_URL + name
            metadata["resource_type"] = "software"
            metadata["rights"] = "openaccess"
            metadata_dict[name] = metadata
    except Exception as ex:
        logger.exception("Error getting metadata from TOSCA templates")
        return return_error(400, "Error getting metadata from TOSCA templates: %s" % get_ex_error(ex))

    response_xml = oai.processRequest(flask.request, metadata_dict)
    return flask.make_response(response_xml, 200, {'Content-Type': 'text/xml'})


@app.route('/static/<filename>', methods=['GET'])
def static_files(filename):
    if Config.STATIC_FILES_DIR:
        return flask.send_from_directory(Config.STATIC_FILES_DIR, filename)
    else:
        return return_error(404, "Static files not enabled.")


@app.errorhandler(403)
def error_mesage_403(error):
    return return_error(403, error.description)


@app.errorhandler(404)
def error_mesage_404(error):
    return return_error(404, error.description)


@app.errorhandler(405)
def error_mesage_405(error):
    return return_error(405, error.description)


@app.errorhandler(500)
def error_mesage_500(error):
    return return_error(500, error.description)
