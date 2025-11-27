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

from typing import Literal
from pydantic import BaseModel, Field, HttpUrl
from .allocation import AllocationId
from .tool import ToolId


class DeploymentId(BaseModel):
    id: str
    kind: Literal["DeploymentId"] = "DeploymentId"
    infoLink: HttpUrl = None


class Deployment(BaseModel):
    allocation: AllocationId
    tool: ToolId


class DeploymentInfo(BaseModel):
    deployment: Deployment
    id: str
    status: Literal["unknown",
                    "pending",
                    "running",
                    "stopped",
                    "off",
                    "failed",
                    "configured",
                    "unconfigured",
                    "deleting"]
    self_: HttpUrl | None = Field(None, alias="self")

    model_config = {"populate_by_name": True}
