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

import requests
import logging
from pydantic import BaseModel, HttpUrl
from typing import List, Tuple
from IM.rest.awm.models.tool import ToolInfo
from IM.rest.awm.models.page import PageOfTools


logger = logging.getLogger(__name__)


class EOSCNode(BaseModel):
    """Class that represents an EOSC Node"""
    nodeId: str
    nodeName: str = None
    awmAPI: HttpUrl

    def list_tools(self, from_: int, limit: int, count: int, token: str) -> Tuple[int, List[ToolInfo]]:
        """Return the list of tools of this node"""
        init = max(0, from_ - count)
        elems = limit - (count - from_)
        url = f"{self.awmAPI}tools?from0&limit={elems}"
        try:
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            if response.status_code == 200:
                page = PageOfTools.model_validate(response.json())
                tools = page.elements[init:] if len(page.elements) > init else []
                return page.count, tools
        except Exception:
            logger.exception("Error getting tools from node: %s", self.nodeId)
        return 0, []


class EOSCNodeRegistry():
    """Class to interact with the central EOSC Node Registry"""

    @staticmethod
    def list_nodes() -> List[EOSCNode]:
        """Return the list of available nodes"""
        # @TODO(list): Complete
        return []

    @staticmethod
    def get_node_by_id(node_id: str) -> EOSCNode:
        """Retun the node with ID `node_id`"""
        # @TODO(get): Complete
        return None
