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
import os
import yaml
import datetime
import io
import csv
from typing import Optional, List

from fastapi import FastAPI, Request, Response, Header, HTTPException, Query, Depends
from fastapi.responses import PlainTextResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

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
app = FastAPI(title="Infrastructure Manager API", version="2.0")
uvicorn_server = None


def run_in_thread(host, port):
    """Run the FastAPI server in a thread"""
    thread = threading.Thread(target=run, args=(host, port))
    thread.daemon = True
    thread.start()


def run(host, port):
    """Run the FastAPI server"""
    global uvicorn_server
    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        ssl_keyfile=Config.REST_SSL_KEYFILE if Config.REST_SSL else None,
        ssl_certfile=Config.REST_SSL_CERTFILE if Config.REST_SSL else None,
        ssl_ca_certs=Config.REST_SSL_CA_CERTS if Config.REST_SSL else None,
        log_config=None  # Use existing logging configuration
    )
    uvicorn_server = uvicorn.Server(config)
    uvicorn_server.run()


def stop():
    """Stop the FastAPI server"""
    logger.info('Stopping REST API server...')
    if uvicorn_server:
        uvicorn_server.should_exit = True


# Configure CORS
if Config.ENABLE_CORS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[Config.CORS_ORIGIN] if Config.CORS_ORIGIN != "*" else ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["Origin", "Accept", "Content-Type", "Authorization"],
    )


def get_media_type(request: Request, header: str) -> List[str]:
    """
    Function to get specified the header media type.
    Returns a List of strings.
    """
    res = []
    accept = request.headers.get(header)
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


def get_auth_header(authorization: Optional[str] = Header(None)):
    """
    Get the Authentication object from the AUTHORIZATION header
    replacing the new line chars.
    """
    global REST_URL
    
    if not authorization:
        raise HTTPException(status_code=401, detail="No authentication data provided")
    
    user_pass = None
    token = None
    if authorization.startswith("Basic "):
        auth_data = base64.b64decode(authorization[6:]).decode('utf-8')
        user_pass = auth_data.split(":")
        im_auth = {"type": "InfrastructureManager",
                   "username": user_pass[0],
                   "password": user_pass[1]}
    elif authorization.startswith("Bearer "):
        token = authorization[7:].strip()
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

    auth_data = authorization.replace(AUTH_NEW_LINE_SEPARATOR, "\n")
    auth_data = auth_data.split(AUTH_LINE_SEPARATOR)
    return Authentication(Authentication.read_auth_data(auth_data))


def format_output_json(res, field_name=None, list_field_name=None):
    """Format output as JSON"""
    res_dict = res
    if field_name:
        if list_field_name and isinstance(res, list):
            res_dict = {field_name: []}
            for elem in res:
                res_dict[field_name].append({list_field_name: elem})
        else:
            res_dict = {field_name: res}
    return res_dict


def format_output(request: Request, res, default_type="text/plain", field_name=None, 
                  list_field_name=None, extra_headers=None):
    """
    Format the output of the API responses
    """
    accept = get_media_type(request, 'Accept')

    if not accept:
        accept = [default_type]

    content_type = None
    info = None
    
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
                info = json.dumps(format_output_json(res, field_name, list_field_name))
            content_type = "application/json"
            break
        elif accept_item in [default_type, "*/*", "text/*"]:
            if default_type == "application/json":
                info = json.dumps(format_output_json(res, field_name, list_field_name))
            else:
                if isinstance(res, list):
                    info = "\n".join(res)
                else:
                    info = "%s" % res
            content_type = default_type
            break

    if content_type:
        headers = extra_headers or {}
        if content_type == "application/json":
            return JSONResponse(content=json.loads(info) if isinstance(info, str) and info else info, 
                              headers=headers)
        else:
            return Response(content=info, media_type=content_type, headers=headers)
    else:
        raise HTTPException(status_code=415, 
                          detail="Unsupported Accept Media Types: %s" % ",".join(accept))


def return_error(request: Request, code: int, msg: str):
    """Return error response in appropriate format"""
    content_type = get_media_type(request, 'Accept')

    if "application/json" in content_type:
        return JSONResponse(
            status_code=code,
            content={'message': msg, 'code': code}
        )
    elif "text/html" in content_type:
        return Response(
            content=HTML_ERROR_TEMPLATE % (code, code, msg),
            status_code=code,
            media_type='text/html'
        )
    else:
        return PlainTextResponse(content=msg, status_code=code)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/")
async def get_api_info(request: Request):
    """Get OpenAPI specification"""
    try:
        rest_path = os.path.dirname(os.path.abspath(__file__))
        abs_file_path = os.path.join(rest_path, 'swagger_api.yaml')
        api_docs = yaml.safe_load(open(abs_file_path, 'r'))
        api_docs['servers'][0]['url'] = str(request.url_for("get_api_info")).rstrip("/")
        return JSONResponse(content=api_docs)
    except Exception as ex:
        logger.exception("Error getting API info")
        return return_error(request, 400, "Error getting API info: %s" % get_ex_error(ex))


@app.get("/version")
async def get_version(request: Request):
    """Get IM version"""
    try:
        from IM import __version__ as version
        return format_output(request, version, field_name="version")
    except Exception as ex:
        return return_error(request, 400, "Error getting IM version: %s" % get_ex_error(ex))


@app.get("/infrastructures")
async def get_infrastructure_list(
    request: Request,
    filter: Optional[str] = Query(None),
    auth: Authentication = Depends(get_auth_header)
):
    """Get list of infrastructures"""
    try:
        inf_ids = InfrastructureManager.GetInfrastructureList(auth, filter)
        res = []
        for inf_id in inf_ids:
            res.append(f"{str(request.base_url).rstrip('/')}/infrastructures/{inf_id}")
        return format_output(request, res, "text/uri-list", "uri-list", "uri")
    except InvaliddUserException as ex:
        return return_error(request, 401, "Error Getting Inf. List: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting Inf. List")
        return return_error(request, 400, "Error Getting Inf. List: %s" % get_ex_error(ex))


@app.post("/infrastructures")
async def create_infrastructure(
    request: Request,
    async_call: bool = Query(False, alias="async"),
    dry_run: bool = Query(False),
    auth: Authentication = Depends(get_auth_header)
):
    """Create new infrastructure"""
    # Check content type first, outside of try/except to preserve 415 status code
    content_type = get_media_type(request, 'Content-Type')
    if content_type:
        valid_types = ["application/json", "text/yaml", "text/x-yaml", 
                       "application/yaml", "text/plain", "*/*", "text/*"]
        if not any(ct in content_type for ct in valid_types):
            raise HTTPException(status_code=415, detail="Unsupported Media Type %s" % content_type)
    
    try:
        body = await request.body()
        radl_data = body.decode("utf-8")
        tosca_data = None

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
                tosca_data = Tosca(radl_data, tosca_repo=Config.OAIPMH_REPO_BASE_IDENTIFIER_URL, auth=auth)
                _, radl_data = tosca_data.to_radl()
            elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                pass

        if dry_run:
            res = InfrastructureManager.EstimateResouces(radl_data, auth)
            return format_output(request, res, "application/json")
        else:
            inf_id = InfrastructureManager.CreateInfrastructure(radl_data, auth, async_call)

            # Store the TOSCA document
            if tosca_data:
                sel_inf = InfrastructureManager.get_infrastructure(inf_id, auth)
                sel_inf.extra_info['TOSCA'] = tosca_data

            res = f"{str(request.base_url).rstrip('/')}/infrastructures/{inf_id}"
            return format_output(request, res, "text/uri-list", "uri", extra_headers={'InfID': inf_id})
    except InvaliddUserException as ex:
        return return_error(request, 401, "Error Creating Inf.: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error Creating Inf.: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Creating Inf.")
        return return_error(request, 400, "Error Creating Inf.: %s" % get_ex_error(ex))


@app.put("/infrastructures")
async def import_infrastructure(
    request: Request,
    auth: Authentication = Depends(get_auth_header)
):
    """Import infrastructure"""
    try:
        content_type = get_media_type(request, 'Content-Type')
        body = await request.body()
        data = body.decode("utf-8")

        if content_type:
            if "application/json" not in content_type:
                raise HTTPException(status_code=415, detail="Unsupported Media Type %s" % content_type)

        new_id = InfrastructureManager.ImportInfrastructure(data, auth)
        res = f"{str(request.base_url).rstrip('/')}/infrastructures/{new_id}"
        return format_output(request, res, "text/uri-list", "uri")
    except InvaliddUserException as ex:
        return return_error(request, 401, "Error Importing Inf.: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error Importing Inf.: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Importing Inf.")
        return return_error(request, 400, "Error Importing Inf.: %s" % get_ex_error(ex))


@app.get("/infrastructures/{infid}")
async def get_infrastructure_info(
    request: Request,
    infid: str,
    auth: Authentication = Depends(get_auth_header)
):
    """Get infrastructure information"""
    try:
        vm_ids = InfrastructureManager.GetInfrastructureInfo(infid, auth)
        res = []
        for vm_id in vm_ids:
            res.append(f"{str(request.base_url).rstrip('/')}/infrastructures/{infid}/vms/{vm_id}")
        return format_output(request, res, "text/uri-list", "uri-list", "uri")
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error Getting Inf. info: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error Getting Inf. info: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error Getting Inf. info: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting Inf. info")
        return return_error(request, 400, "Error Getting Inf. info: %s" % get_ex_error(ex))


@app.delete("/infrastructures/{infid}")
async def destroy_infrastructure(
    request: Request,
    infid: str,
    force: bool = Query(False),
    async_call: bool = Query(False, alias="async"),
    auth: Authentication = Depends(get_auth_header)
):
    """Destroy infrastructure"""
    try:
        InfrastructureManager.DestroyInfrastructure(infid, auth, force, async_call)
        return Response(status_code=200, media_type='text/plain')
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error Destroying Inf: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error Destroying Inf: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except IncorrectStateException as ex:
        return return_error(request, 409, "Error Destroying Inf: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error Destroying Inf: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Destroying Inf")
        return return_error(request, 400, "Error Destroying Inf: %s" % get_ex_error(ex))


@app.get("/infrastructures/{infid}/{prop}")
async def get_infrastructure_property(
    request: Request,
    infid: str,
    prop: str,
    headeronly: bool = Query(False),
    delete: bool = Query(False),
    auth: Authentication = Depends(get_auth_header)
):
    """Get infrastructure property"""
    try:
        if prop == "contmsg":
            res = InfrastructureManager.GetInfrastructureContMsg(infid, auth, headeronly)
        elif prop == "radl":
            res = InfrastructureManager.GetInfrastructureRADL(infid, auth)
        elif prop == "tosca":
            accept = get_media_type(request, 'Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                raise HTTPException(status_code=415, detail="Unsupported Accept Media Types: %s" % accept)
            auth_checked = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth_checked)
            if "TOSCA" in sel_inf.extra_info:
                res = sel_inf.extra_info["TOSCA"].serialize()
            else:
                raise HTTPException(status_code=403, 
                                  detail="'tosca' infrastructure property is not valid in this infrastructure")
        elif prop == "state":
            accept = get_media_type(request, 'Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                raise HTTPException(status_code=415, detail="Unsupported Accept Media Types: %s" % accept)
            res = InfrastructureManager.GetInfrastructureState(infid, auth)
            return format_output(request, res, default_type="application/json", field_name="state")
        elif prop == "outputs":
            accept = get_media_type(request, 'Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                raise HTTPException(status_code=415, detail="Unsupported Accept Media Types: %s" % accept)
            auth_checked = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth_checked)
            if "TOSCA" in sel_inf.extra_info:
                res = sel_inf.extra_info["TOSCA"].get_outputs(sel_inf)
            else:
                raise HTTPException(status_code=403,
                                  detail="'outputs' infrastructure property is not valid in this infrastructure")
            return format_output(request, res, default_type="application/json", field_name="outputs")
        elif prop == "data":
            accept = get_media_type(request, 'Accept')
            if accept and "application/json" not in accept and "*/*" not in accept and "application/*" not in accept:
                raise HTTPException(status_code=415, detail="Unsupported Accept Media Types: %s" % accept)
            data = InfrastructureManager.ExportInfrastructure(infid, delete, auth)
            return format_output(request, data, default_type="application/json", field_name="data")
        elif prop == "authorization":
            res = InfrastructureManager.GetInfrastructureOwners(infid, auth)
        else:
            raise HTTPException(status_code=404, detail="Incorrect infrastructure property")

        return format_output(request, res, field_name=prop)
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error Getting Inf. prop: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error Getting Inf. prop: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error Getting Inf. prop: %s" % get_ex_error(ex))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error Getting Inf. prop")
        return return_error(request, 400, "Error Getting Inf. prop: %s" % get_ex_error(ex))


@app.post("/infrastructures/{infid}")
async def add_resource(
    request: Request,
    infid: str,
    context: bool = Query(True),
    auth: Authentication = Depends(get_auth_header)
):
    """Add resources to infrastructure"""
    try:
        content_type = get_media_type(request, 'Content-Type')
        body = await request.body()
        radl_data = body.decode("utf-8")
        tosca_data = None
        remove_list = []

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
                tosca_data = Tosca(radl_data)
                auth_checked = InfrastructureManager.check_auth_data(auth)
                sel_inf = InfrastructureManager.get_infrastructure(infid, auth_checked)
                # merge the current TOSCA with the new one
                if isinstance(sel_inf.extra_info.get('TOSCA'), Tosca):
                    tosca_data = sel_inf.extra_info['TOSCA'].merge(tosca_data)
                remove_list, radl_data = tosca_data.to_radl(sel_inf)
            elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                pass
            else:
                raise HTTPException(status_code=415, detail="Unsupported Media Type %s" % content_type)

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
            auth_checked = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth_checked)
            sel_inf.extra_info['TOSCA'] = tosca_data

        res = []
        for vm_id in vm_ids:
            res.append(f"{str(request.base_url).rstrip('/')}/infrastructures/{infid}/vms/{vm_id}")

        if not vm_ids and remove_list and len(remove_list) != removed_vms:
            return return_error(request, 404, 
                              "Error deleting resources %s (removed %s)" % (remove_list, removed_vms))
        else:
            extra_headers = {}
            # If we have to reconfigure the infra, return the ID for the HAProxy stickiness
            if context:
                extra_headers = {'InfID': infid}
            return format_output(request, res, "text/uri-list", "uri-list", "uri", extra_headers)
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error Adding resources: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error Adding resources: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error Adding resources: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error Adding resources: %s" % get_ex_error(ex))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error Adding resources")
        return return_error(request, 400, "Error Adding resources: %s" % get_ex_error(ex))


@app.put("/infrastructures/{infid}/reconfigure")
async def reconfigure_infrastructure(
    request: Request,
    infid: str,
    vm_list: Optional[str] = Query(None),
    auth: Authentication = Depends(get_auth_header)
):
    """Reconfigure infrastructure"""
    try:
        vm_list_parsed = None
        if vm_list:
            try:
                vm_list_parsed = [int(vm_id) for vm_id in vm_list.split(",")]
            except Exception:
                raise HTTPException(status_code=400, detail="Incorrect vm_list format.")

        content_type = get_media_type(request, 'Content-Type')
        body = await request.body()
        radl_data = body.decode("utf-8") if body else ""

        if radl_data:
            if content_type:
                if "application/json" in content_type:
                    radl_data = parse_radl_json(radl_data)
                elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
                    tosca_data = Tosca(radl_data)
                    _, radl_data = tosca_data.to_radl()
                elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                    pass
                else:
                    raise HTTPException(status_code=415, detail="Unsupported Media Type %s" % content_type)
        else:
            radl_data = ""

        res = InfrastructureManager.Reconfigure(infid, radl_data, auth, vm_list_parsed)
        # As we have to reconfigure the infra, return the ID for the HAProxy stickiness
        return Response(content=res, media_type='text/plain', headers={'InfID': infid})
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error reconfiguring infrastructure")
        return return_error(request, 400, "Error reconfiguring infrastructure: %s" % get_ex_error(ex))


@app.put("/infrastructures/{infid}/{op}")
async def operate_infrastructure(
    request: Request,
    infid: str,
    op: str,
    auth: Authentication = Depends(get_auth_header)
):
    """Start or stop infrastructure"""
    try:
        if op == "start":
            res = InfrastructureManager.StartInfrastructure(infid, auth)
        elif op == "stop":
            res = InfrastructureManager.StopInfrastructure(infid, auth)
        else:
            raise HTTPException(status_code=404, detail="Operation not found")
        return Response(content=res, media_type='text/plain')
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error in %s operation: %s" % (op, get_ex_error(ex)))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error in %s operation" % op)
        return return_error(request, 400, "Error in %s operation: %s" % (op, get_ex_error(ex)))


@app.post("/infrastructures/{infid}/authorization")
async def change_infrastructure_auth(
    request: Request,
    infid: str,
    overwrite: bool = Query(False),
    auth: Authentication = Depends(get_auth_header)
):
    """Change infrastructure authorization"""
    try:
        content_type = get_media_type(request, 'Content-Type') or ["application/json"]

        body = await request.body()
        if "application/json" in content_type:
            auth_dict = json.loads(body.decode("utf-8"))
            if "type" not in auth_dict:
                auth_dict["type"] = "InfrastructureManager"
            new_auth = Authentication([auth_dict])
        else:
            raise HTTPException(status_code=415, detail="Unsupported Media Type %s" % content_type)

        InfrastructureManager.ChangeInfrastructureAuth(infid, new_auth, overwrite, auth)
        return Response(status_code=200, media_type='text/plain')
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error modifying infrastructure owners: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error modifying infrastructure owner: %s" % get_ex_error(ex))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error modifying infrastructure owner.")
        return return_error(request, 400, "Error modifying infrastructure owner: %s" % get_ex_error(ex))


@app.get("/infrastructures/{infid}/vms/{vmid}")
async def get_vm_info(
    request: Request,
    infid: str,
    vmid: str,
    auth: Authentication = Depends(get_auth_header)
):
    """Get VM information"""
    try:
        radl = InfrastructureManager.GetVMInfo(infid, vmid, auth)
        return format_output(request, radl, field_name="radl")
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error Getting VM. info: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(request, 404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(request, 404, "Error Getting VM. info: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Getting VM info")
        return return_error(request, 400, "Error Getting VM info: %s" % get_ex_error(ex))


@app.delete("/infrastructures/{infid}/vms/{vmid}")
async def remove_resource(
    request: Request,
    infid: str,
    vmid: str,
    context: bool = Query(True),
    auth: Authentication = Depends(get_auth_header)
):
    """Remove VM from infrastructure"""
    try:
        InfrastructureManager.RemoveResource(infid, vmid, auth, context)
        return Response(status_code=200, media_type='text/plain')
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error Removing resources: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error Removing resources: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error Removing resources: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(request, 404, "Error Removing resources: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(request, 404, "Error Removing resources: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error Removing resources: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error Removing resources")
        return return_error(request, 400, "Error Removing resources: %s" % get_ex_error(ex))


@app.put("/infrastructures/{infid}/vms/{vmid}")
async def alter_vm(
    request: Request,
    infid: str,
    vmid: str,
    auth: Authentication = Depends(get_auth_header)
):
    """Alter VM"""
    try:
        content_type = get_media_type(request, 'Content-Type')
        body = await request.body()
        radl_data = body.decode("utf-8")

        if content_type:
            if "application/json" in content_type:
                radl_data = parse_radl_json(radl_data)
            elif "text/yaml" in content_type or "text/x-yaml" in content_type or "application/yaml" in content_type:
                tosca_data = Tosca(radl_data)
                _, radl_data = tosca_data.to_radl()
            elif "text/plain" in content_type or "*/*" in content_type or "text/*" in content_type:
                pass
            else:
                raise HTTPException(status_code=415, detail="Unsupported Media Type %s" % content_type)

        vm_info = InfrastructureManager.AlterVM(infid, vmid, radl_data, auth)
        return format_output(request, vm_info, field_name="radl")
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error modifying resources: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error modifying resources: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error modifying resources: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(request, 404, "Error modifying resources: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(request, 404, "Error modifying resources: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error modifying resources: %s" % get_ex_error(ex))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error modifying resources")
        return return_error(request, 400, "Error modifying resources: %s" % get_ex_error(ex))


@app.get("/infrastructures/{infid}/vms/{vmid}/{prop}")
async def get_vm_property(
    request: Request,
    infid: str,
    vmid: str,
    prop: str,
    step: int = Query(1),
    auth: Authentication = Depends(get_auth_header)
):
    """Get VM property"""
    try:
        if prop == 'contmsg':
            info = InfrastructureManager.GetVMContMsg(infid, vmid, auth)
        elif prop == 'command':
            auth_checked = InfrastructureManager.check_auth_data(auth)
            sel_inf = InfrastructureManager.get_infrastructure(infid, auth_checked)

            if step == 1:
                base_url = str(request.base_url).rstrip('/')
                url = f"{base_url}/infrastructures/{infid}/vms/{vmid}/command?step=2"
                auth_info = sel_inf.auth.getAuthInfo("InfrastructureManager")[0]
                if 'token' in auth_info:
                    imauth = "token = %s" % auth_info['token']
                else:
                    imauth = "username = %s; password = %s" % (auth_info['username'], auth_info['password'])
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
                    logger.warning("Specified vmid in step2 is incorrect!!")
                    info = "wait"
                else:
                    ssh = sel_vm.get_ssh_ansible_master(retry=False)
                    ssh_ok = False
                    if ssh:
                        ssh_ok = ssh.test_connectivity(time_out=2)

                    if ssh_ok:
                        if sel_inf.vm_master and int(vmid) == sel_inf.vm_master.creation_im_id:
                            logger.debug("Step 2: Is the master do no make ssh command.")
                            info = "true"
                        else:
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
            raise HTTPException(status_code=404, detail="Incorrect property %s for VM ID %s" % (prop, vmid))
        else:
            return format_output(request, info, field_name=prop)
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error Getting VM. property: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(request, 404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(request, 404, "Error Getting VM. property: %s" % get_ex_error(ex))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error Getting VM property")
        return return_error(request, 400, "Error Getting VM property: %s" % get_ex_error(ex))


@app.put("/infrastructures/{infid}/vms/{vmid}/{op}")
async def operate_vm(
    request: Request,
    infid: str,
    vmid: str,
    op: str,
    auth: Authentication = Depends(get_auth_header)
):
    """Start, stop or reboot VM"""
    try:
        if op == "start":
            res = InfrastructureManager.StartVM(infid, vmid, auth)
        elif op == "stop":
            res = InfrastructureManager.StopVM(infid, vmid, auth)
        elif op == "reboot":
            res = InfrastructureManager.RebootVM(infid, vmid, auth)
        else:
            raise HTTPException(status_code=404, detail="Operation not found")
        return Response(content=res, media_type='text/plain')
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except DeletedVMException as ex:
        return return_error(request, 404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except IncorrectVMException as ex:
        return return_error(request, 404, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error in %s op in VM" % op)
        return return_error(request, 400, "Error in %s op in VM: %s" % (op, get_ex_error(ex)))


@app.put("/infrastructures/{infid}/vms/{vmid}/disks/{disknum}/snapshot")
async def create_disk_snapshot(
    request: Request,
    infid: str,
    vmid: str,
    disknum: int,
    image_name: str = Query(...),
    auto_delete: bool = Query(False),
    auth: Authentication = Depends(get_auth_header)
):
    """Create disk snapshot"""
    try:
        res = InfrastructureManager.CreateDiskSnapshot(infid, vmid, disknum, image_name, auto_delete, auth)
        return Response(content=res, media_type='text/plain')
    except DeletedInfrastructureException as ex:
        return return_error(request, 404, "Error creating snapshot: %s" % get_ex_error(ex))
    except IncorrectInfrastructureException as ex:
        return return_error(request, 404, "Error creating snapshot: %s" % get_ex_error(ex))
    except UnauthorizedUserException as ex:
        return return_error(request, 403, "Error creating snapshot: %s" % get_ex_error(ex))
    except DeletedVMException as ex:
        return return_error(request, 404, "Error creating snapshot: %s" % get_ex_error(ex))
    except IncorrectVMException as ex:
        return return_error(request, 404, "Error creating snapshot: %s" % get_ex_error(ex))
    except DisabledFunctionException as ex:
        return return_error(request, 403, "Error creating snapshot: %s" % get_ex_error(ex))
    except Exception as ex:
        logger.exception("Error creating snapshot")
        return return_error(request, 400, "Error creating snapshot: %s" % get_ex_error(ex))


@app.get("/clouds/{cloudid}/{param}")
async def get_cloud_info(
    request: Request,
    cloudid: str,
    param: str,
    filters: Optional[str] = Query(None),
    auth: Authentication = Depends(get_auth_header)
):
    """Get cloud information (images or quotas)"""
    try:
        if param == 'images':
            filters_dict = None
            if filters:
                try:
                    filters_dict = _filters_str_to_dict(filters)
                except Exception:
                    raise HTTPException(status_code=400, detail="Invalid format in filters parameter.")
            images = InfrastructureManager.GetCloudImageList(cloudid, auth, filters_dict)
            return format_output(request, images, default_type="application/json", field_name="images")
        elif param == 'quotas':
            quotas = InfrastructureManager.GetCloudQuotas(cloudid, auth)
            return format_output(request, quotas, default_type="application/json", field_name="quotas")
        else:
            raise HTTPException(status_code=404, detail="Incorrect cloud property")
    except InvaliddUserException as ex:
        return return_error(request, 401, "Error getting cloud info: %s" % get_ex_error(ex))
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error getting cloud info")
        return return_error(request, 400, "Error getting cloud info: %s" % get_ex_error(ex))


def _filters_str_to_dict(filters_str: str) -> dict:
    """Convert filter string to dictionary"""
    filters = {}
    for elem in filters_str.split(","):
        kv = elem.split("=")
        if len(kv) != 2:
            raise Exception("Incorrect format")
        else:
            filters[kv[0]] = kv[1]
    return filters


@app.get("/stats")
async def get_stats(
    request: Request,
    init_date: Optional[str] = Query("1970-01-01"),
    end_date: Optional[str] = Query(None),
    auth: Authentication = Depends(get_auth_header)
):
    """Get statistics"""
    try:
        # Validate init_date
        if init_date:
            init_date = init_date.replace("/", "-")
            parts = init_date.split("-")
            try:
                year = int(parts[0])
                month = int(parts[1])
                day = int(parts[2])
                datetime.date(year, month, day)
            except Exception:
                raise HTTPException(status_code=400, detail="Incorrect format in init_date parameter: YYYY/MM/dd")

        # Validate end_date
        if end_date:
            end_date = end_date.replace("/", "-")
            parts = end_date.split("-")
            try:
                year = int(parts[0])
                month = int(parts[1])
                day = int(parts[2])
                datetime.date(year, month, day)
            except Exception:
                raise HTTPException(status_code=400, detail="Incorrect format in end_date parameter: YYYY/MM/dd")

        stats = InfrastructureManager.GetStats(init_date, end_date, auth)

        accept_type = get_media_type(request, 'Accept')
        if not accept_type or "application/json" in accept_type or "*/*" in accept_type or "application/*" in accept_type:
            return format_output(request, stats, default_type="application/json", field_name="stats")
        elif "text/csv" in accept_type or "text/*" in accept_type:
            output = io.StringIO()
            csv_writer = csv.writer(output)

            # Write header
            header = stats[0].keys() if stats else []
            csv_writer.writerow(header)

            # Write data rows
            for stat in stats:
                csv_writer.writerow(stat.values())

            return Response(content=output.getvalue(), media_type="text/csv")
    except HTTPException:
        raise
    except Exception as ex:
        logger.exception("Error getting stats")
        return return_error(request, 400, "Error getting stats: %s" % get_ex_error(ex))


@app.get("/oai")
@app.post("/oai")
async def oaipmh(request: Request):
    """OAI-PMH endpoint"""
    if not (Config.OAIPMH_REPO_BASE_IDENTIFIER_URL and
            Config.OAIPMH_REPO_NAME and Config.OAIPMH_REPO_DESCRIPTION):
        return return_error(request, 400, "OAI-PMH not enabled.")

    oai = OAI(Config.OAIPMH_REPO_NAME, str(request.base_url).rstrip('/') + '/oai', Config.OAIPMH_REPO_DESCRIPTION,
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
        return return_error(request, 400, "Error getting metadata from TOSCA templates: %s" % get_ex_error(ex))

    # Convert FastAPI request to a format compatible with OAI-PMH module
    values_dict = dict(request.query_params)
    if request.method == "POST":
        try:
            form_data = await request.form()
            values_dict.update(form_data)
        except Exception as ex:
            logger.warning("Error parsing POST form data: %s" % get_ex_error(ex))

    response_xml = oai.processRequest(values_dict, metadata_dict)
    return Response(content=response_xml, media_type='text/xml')


@app.get("/static/{filename}")
async def static_files(filename: str):
    """Serve static files"""
    if Config.STATIC_FILES_DIR:
        file_path = os.path.join(Config.STATIC_FILES_DIR, filename)
        if os.path.exists(file_path):
            return FileResponse(file_path)
        else:
            raise HTTPException(status_code=404, detail="File not found")
    else:
        raise HTTPException(status_code=404, detail="Static files not enabled.")


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return return_error(request, exc.status_code, exc.detail)


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.exception("Unhandled exception")
    return return_error(request, 500, str(exc))
