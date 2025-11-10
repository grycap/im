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

import datetime
import flask
import logging
from IM.config import Config
from IM.InfrastructureManager import InfrastructureManager
from IM.rest.utils import return_error, format_output, require_auth


sys_bp = flask.Blueprint("service", __name__, url_prefix='/')
logger = logging.getLogger('InfrastructureManager')


@sys_bp.route('/stats', methods=['GET'])
@require_auth
def RESTGetStats(auth=None):
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


@sys_bp.route('/static/<filename>', methods=['GET'])
def static_files(filename):
    if Config.STATIC_FILES_DIR:
        return flask.send_from_directory(Config.STATIC_FILES_DIR, filename)
    else:
        return return_error(404, "Static files not enabled.")


@sys_bp.route('/version')
def RESTGetVersion():
    from IM import __version__ as version
    return format_output(version, field_name="version")
