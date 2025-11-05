import requests
import logging
from pydantic import BaseModel, HttpUrl
from typing import List, Tuple
from IM.awm.models.tool import ToolInfo
from IM.awm.models.page import PageOfTools


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
