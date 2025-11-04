from pydantic import BaseModel, HttpUrl
from typing import List, Tuple
from IM.awm.models.tool import ToolInfo
from IM.awm.models.page import PageOfTools
import requests


class EOSCNode(BaseModel):
    """Class that represents an EOSC Node"""
    nodeId: str
    nodeName: str = None
    awmAPI: HttpUrl

    def list_tools(self, from_: int, limit: int, count: int, token: str) -> Tuple[int, List[ToolInfo]]:
        init = 0 if count > from_ else from_ - count
        elems = limit - (count - from_)
        if elems > 0:
            url = f"{self.awmAPI}tools?from{init}&limit={elems}"
            try:
                headers = {"Authorization": f"Bearer {token}"}
                response = requests.get(url, headers=headers, timeout=30)
                if response.status_code == 200:
                    page = PageOfTools.model_validate(response.json())
                    return page.count, page.elements
            except Exception:
                return 0, []
        else:
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
