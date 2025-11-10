#! /usr/bin/env python
#
# IM - Infrastructure Manager
# Copyright (C) 2025 - GRyCAP - Universitat Politecnica de Valencia
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
from flask import Request
from IM.rest.awm.oidc.client import OpenIDClient

logger = logging.getLogger(__name__)


def authenticate(flask_request: Request):
    """
    Extrae el token Bearer desde flask.request y valida contra OIDC.
    Lanza Exception en caso de fallo para que el decorador de Flask lo capture.
    """
    auth_header = flask_request.headers.get("Authorization", "")
    if not auth_header:
        raise Exception("Invalid or missing token")

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise Exception("Invalid Authorization header")

    token = parts[1].strip()
    user_info = check_OIDC(token)
    if user_info is None:
        raise Exception("Invalid or missing token")
    return user_info


def check_OIDC(token):
    try:
        expired, _ = OpenIDClient.is_access_token_expired(token)
        if expired:
            logger.warning("Token expired")
            return None
        success, user_info = OpenIDClient.get_user_info_request(token)
        if not success:
            return None
    except Exception:
        logger.exception("Error checking OIDC token")
        return None

    user_info["token"] = token
    return user_info
