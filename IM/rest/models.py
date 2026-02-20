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

from typing import Literal
from pydantic import BaseModel, Field, HttpUrl


State = Literal["pending", "running", "configured", "unconfigured", "stopped",
                "off", "failed", "unknown", "deleting"]


class ErrorMsg(BaseModel):
    """Class to represent an error message"""
    message: str
    code: int


class InfrastructureState(BaseModel):
    """Class to represent the state of an infrastructure"""
    state: State
    vm_states: dict[str, State]


class Uri(BaseModel):
    """Class to represent a URI"""
    uri: HttpUrl


class UriList(BaseModel):
    """Class to represent a list of URLs"""
    uri_list: list[Uri] = Field(..., alias="uri-list")

    model_config = {"populate_by_name": True}
