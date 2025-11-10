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

    class Config:
        populate_by_name = True
