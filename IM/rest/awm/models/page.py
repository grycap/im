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

from typing import List, Union
from pydantic import BaseModel, Field, HttpUrl
from .allocation import AllocationInfo
from .tool import ToolInfo
from .deployment import DeploymentInfo


class Page(BaseModel):
    """Page Base class for pagination"""
    from_: int = Field(..., alias="from")
    limit: int
    count: int
    self_: HttpUrl | None = Field(None, alias="self")
    prevPage: HttpUrl = None
    nextPage: HttpUrl = None

    class Config:
        populate_by_name = True


class PageOfAllocations(Page):
    """Page of Allocations"""
    elements: List[AllocationInfo]


class PageOfDeployments(Page):
    """Page of Deployments"""
    elements: List[DeploymentInfo]


class PageOfTools(Page):
    """Page of Tools"""
    elements: List[ToolInfo]


class PageOfItems(Page):
    """Generic Page of any item"""
    elements: List[Union[AllocationInfo, DeploymentInfo, ToolInfo]]
