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

import os
import logging


from fastapi import HTTPException, APIRouter, Request
from fastapi.responses import FileResponse
from IM.config import Config
from IM import get_ex_error
from IM import __version__ as version
from IM.rest.routers import format_output, return_error

logger = logging.getLogger('InfrastructureManager')


router = APIRouter()


@router.get("/version",
            summary="Get IM version",)
async def get_version(request: Request):
    """Get IM version"""
    try:
        return format_output(request, version, field_name="version")
    except Exception as ex:
        return return_error(request, 400, "Error getting IM version: %s" % get_ex_error(ex))


@router.get("/static/{filename}",
            summary="Serve static files",
            response_class=FileResponse)
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
