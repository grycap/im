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
from pydantic import BaseModel


class UserInfo(BaseModel):
    kind: Literal['UserInfo'] = 'UserInfo'
    base_id: str = None
    user_dn: str = None
    delegation_id: str = None
    dn: List[str] = None
    vos: List[str] | None
    vos_id: List[str] | None
    voms_cred: List[str] = None
