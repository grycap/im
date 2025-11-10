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
import flask
from IM.rest.utils import return_error, format_output, require_auth
from IM.InfrastructureManager import InfrastructureManager


clouds_bp = flask.Blueprint("clouds", __name__, url_prefix="/clouds")
logger = logging.getLogger(__name__)


def _filters_str_to_dict(filters_str):
    filters = {}
    for elem in filters_str.split(","):
        kv = elem.split("=")
        if len(kv) != 2:
            raise Exception("Incorrect format")
        else:
            filters[kv[0]] = kv[1]
    return filters


@clouds_bp.route('/<cloudid>/<param>', methods=['GET'])
@require_auth
def RESTGetCloudInfo(cloudid=None, param=None, auth=None):
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
    else:
        return return_error(404, "Incorrect cloud property")
