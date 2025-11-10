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

from typing import Tuple
from functools import wraps
from IM.rest.awm.authorization import authenticate
from flask import Response, request, Request
from IM.rest.awm.models.error import Error


def return_error(message: str, status_code: int = 500) -> Response:
    err = Error(id=f"{status_code}", description=message)
    return Response(err.model_dump_json(exclude_unset=True),
                    status=status_code,
                    mimetype="application/json")


def validate_from_limit(request: Request) -> Tuple[int, int]:
    try:
        from_ = int(request.args.get("from", 0))
    except (TypeError, ValueError):
        from_ = 0
    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    return from_, limit


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            # try to call authenticate similarly to FastAPI dependency
            user_info = authenticate(request)
        except Exception as e:
            # convert auth failure to JSON error response
            err = Error(id="401", description=str(e) if str(e) else "Permission denied")
            return Response(err.model_dump_json(exclude_unset=True), status=401,
                            mimetype="application/json")
        kwargs["user_info"] = user_info
        return f(*args, **kwargs)
    return wrapper
