from pydantic import BaseModel, HttpUrl


class EOSCNode(BaseModel):
    """Class that represents an EOSC Node"""
    nodeId: str
    nodeName: str
    awmAPI: HttpUrl = None


class EOSCNodeRegistry():
    """Class to interact with the central EOSC Node Registry"""

    def list_nodes(self): 
        """Return the list of available nodes"""
        # @TODO(list): Complete
        return []

    def get_node_by_id(self, node_id):
        """Retun the node with ID `node_id`"""
        # @TODO(get): Complete
        return None
