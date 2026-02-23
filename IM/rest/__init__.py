# IM - Infrastructure Manager
# Copyright (C) 2026 - GRyCAP - Universitat Politecnica de Valencia
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

from typing import Dict, Any
from IM.rest.models import ErrorMsg


STANDARD_RESPONSES: Dict[int | str, Dict[str, Any]] = {
    400: {"model": ErrorMsg, "description": "Invalid status value"},
    401: {"model": ErrorMsg, "description": "Unauthorized"},
    403: {"model": ErrorMsg, "description": "Forbidden"},
    404: {"model": ErrorMsg, "description": "Not Found"}
}

DELETE_RESPONSES: Dict[int | str, Dict[str, Any]] = STANDARD_RESPONSES.copy()
DELETE_RESPONSES[409] = {"model": ErrorMsg, "description": "Conflict"}
