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

from typing import Literal, Optional

from fastapi import Request, HTTPException, Query, Depends, APIRouter

from IM.InfrastructureManager import InfrastructureManager, InvaliddUserException
from IM.auth import Authentication
from IM import get_ex_error
from IM.rest import STANDARD_RESPONSES
from IM.rest.routers import get_auth_header, format_output, return_error

logger = logging.getLogger('InfrastructureManager')


router = APIRouter()


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


@router.get("/clouds/{cloudid}/{param}",
            summary="Get cloud information (images or quotas)",
            responses=STANDARD_RESPONSES)
async def get_cloud_info(
    request: Request,
    cloudid: str,
    param: Literal["images", "quotas"],
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
