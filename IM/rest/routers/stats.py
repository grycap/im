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


import csv
import io
import datetime
import logging
from typing import Optional

from fastapi import Request, Response, HTTPException, Query, Depends, APIRouter
from IM.auth import Authentication
from IM import get_ex_error
from IM.InfrastructureManager import InfrastructureManager
from IM.rest.routers import format_output, return_error, get_auth_header, get_media_type

logger = logging.getLogger('InfrastructureManager')


router = APIRouter()


@router.get("/stats", summary="Get statistics")
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
