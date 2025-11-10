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

from typing import List, Literal
from pydantic import BaseModel, Field, EmailStr, HttpUrl
from datetime import datetime


class ToolId(BaseModel):
    kind: Literal['ToolId'] = 'ToolId'
    id: str
    version: str = None
    infoLink: HttpUrl = None


class ToolInfo(BaseModel):
    kind: Literal['ToolInfo'] = 'ToolInfo'
    id: str
    nodeId: str = None
    type: Literal["vm", "container"]
    blueprint: str
    blueprintType: Literal["tosca", "ansible", "helm"]
    name: str = None
    description: str = None
    published: bool = None
    favorite: bool = None
    authorName: str = None
    authorEmail: EmailStr = None
    organisation: str = None
    keywords: List[str] = []
    license: str = None
    version: str = None
    versionFrom: datetime = None
    versionLatest: datetime = None
    repository: HttpUrl = None
    helpdesk: HttpUrl = None
    validated: bool = False
    validatedOn: datetime = None
    self_: HttpUrl | None = Field(None, alias="self")

    class Config:
        populate_by_name = True
