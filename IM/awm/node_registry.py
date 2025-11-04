from pydantic import BaseModel, HttpUrl
from typing import List


class EOSCNode(BaseModel):
    """Class that represents an EOSC Node"""
    nodeId: str
    nodeName: str
    awmAPI: HttpUrl = None


class EOSCNodeRegistry():
    """Class to interact with the central EOSC Node Registry"""

    def list_nodes(self) -> List[EOSCNode]:
        """Return the list of available nodes"""
        # @TODO(list): Complete
        return []

    def get_node_by_id(self, node_id: str) -> EOSCNode:
        """Retun the node with ID `node_id`"""
        # @TODO(get): Complete
        return None
