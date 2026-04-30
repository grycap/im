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

import json
import base64

from typing import List, Optional

from fastapi import Request, Response, HTTPException, Security
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.security import APIKeyHeader

from IM.rest.REST import RESTServer
from IM.auth import Authentication
from IM.config import Config
from IM.tosca.Tosca import Tosca
from radl.radl_json import dump_radl as dump_radl_json, parse_radl as parse_radl_json, featuresToSimple, radlToSimple
from radl.radl_parse import parse_radl
from radl.radl import RADL, Features, Feature
from IM.openid.JWT import JWT
from IM.rest.models import Deployment


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


security = APIKeyHeader(
    name="Authorization",
    auto_error=False,
    description="IM Authentication header"
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


def get_auth_header(request: Request, credentials: Optional[str] = Security(security)) -> Authentication:
    """
    Get the Authentication object from the AUTHORIZATION header
    replacing the new line chars.
    """

    # Initialize REST_URL
    if not RESTServer.REST_URL:
        RESTServer.REST_URL = str(request.base_url)

    if not credentials:
        raise HTTPException(status_code=401, detail="No authentication data provided")

    user_pass = None
    token = None
    im_auth = {}
    if credentials.startswith("Basic "):
        auth_data = base64.b64decode(credentials[6:]).decode('utf-8')
        user_pass = auth_data.split(":")
        im_auth = {"type": "InfrastructureManager",
                   "username": user_pass[0],
                   "password": user_pass[1]}
    elif credentials.startswith("Bearer "):
        token = credentials[7:].strip()
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
        else:
            raise HTTPException(status_code=401, detail="No authentication data provided")
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

    auth_data = credentials.replace(AUTH_NEW_LINE_SEPARATOR, "\n")
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
    """Format the output of the API responses"""
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


async def parse_deployment(request: Request) -> Deployment:
    """Parse the body of the request to get the RADL and TOSCA data"""
    content_type = get_media_type(request, "Content-Type") or ["text/plain"]
    raw = (await request.body()).decode("utf-8")
    tosca_data = None

    if "application/json" in content_type:
        radl_data = parse_radl_json(raw)
    elif any(mt in content_type for mt in ("text/yaml", "text/x-yaml", "application/yaml")):
        tosca_data = Tosca(raw)
        _, radl_data = tosca_data.to_radl()
    elif any(mt in content_type for mt in ("text/plain", "*/*", "text/*")):
        radl_data = parse_radl(raw)
    else:
        raise HTTPException(status_code=415, detail=f"Unsupported Media Type {content_type}")

    return Deployment(radl_data=radl_data, tosca_data=tosca_data)


async def parse_auth(request: Request) -> Authentication:
    content_type = get_media_type(request, 'Content-Type') or ["application/json"]

    if "application/json" in content_type:
        raw = (await request.body()).decode("utf-8")
        auth_dict = json.loads(raw)
        if "type" not in auth_dict:
            auth_dict["type"] = "InfrastructureManager"
        return Authentication([auth_dict])
    else:
        raise HTTPException(status_code=415, detail="Unsupported Media Type %s" % content_type)
