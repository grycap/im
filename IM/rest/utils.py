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
import flask
from functools import wraps
from radl.radl import RADL, Features, Feature
from radl.radl_json import dump_radl as dump_radl_json, featuresToSimple, radlToSimple
from IM.config import Config
from IM.auth import Authentication
from IM.openid.JWT import JWT

REST_URL = None

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


def return_error(code, msg):
    content_type = get_media_type('Accept')

    if "application/json" in content_type:
        return flask.Response(json.dumps({'message': msg, 'code': code}), status=code, mimetype='application/json')
    elif "text/html" in content_type:
        return flask.Response(HTML_ERROR_TEMPLATE % (code, code, msg), status=code, mimetype='text/html')
    else:
        return flask.Response(msg, status=code, mimetype='text/plain')


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


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            auth = get_auth_header()
        except Exception:
            return return_error(401, "No authentication data provided")
        return f(auth=auth, *args, **kwargs)
    return wrapper
