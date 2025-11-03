from typing import Literal
from pydantic import BaseModel, Field, HttpUrl
from IM.awm.models.allocation import AllocationId
from IM.awm.models.tool import ToolId


class DeploymentId(BaseModel):
    id: str = Field(..., description="Unique identifier for this deployment")
    kind: Literal["DeploymentId"] = "DeploymentId"
    infoLink: HttpUrl | None = Field(None, description="Endpoint that returns more details about this entity")

    class Config:
        populate_by_name = True


class Deployment(BaseModel):
    allocation: AllocationId
    tool: ToolId


class DeploymentInfo(BaseModel):
    deployment: Deployment
    id: str = Field(..., description="Unique identifier for this tool blueprint")
    status: Literal["unknown",
                    "pending",
                    "running",
                    "stopped",
                    "off",
                    "failed",
                    "configured",
                    "unconfigured",
                    "deleting"]
    self_: HttpUrl | None = Field(None, alias="self",
                                  description="Endpoint that returns the details of this tool blueprint")

    class Config:
        populate_by_name = True
