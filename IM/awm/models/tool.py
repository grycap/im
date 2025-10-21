from typing import List, Union, Literal
from pydantic import BaseModel, Field, EmailStr, HttpUrl
from datetime import datetime


class ToolId(BaseModel):
    kind: Literal['ToolId'] = 'ToolId'
    id: str = Field(..., description="Unique identifier for this tool blueprint")
    infoLink: str | None = Field(None, description="URL that returns the full details of this tool blueprint")


class ToolInfo(BaseModel):
    kind: Literal['ToolInfo'] = 'ToolInfo'
    id: str = Field(..., description="Unique identifier for this tool blueprint")
    type: Literal["vm", "container"]
    blueprint: str = Field(..., description="Blueprint of the tool's workload")
    blueprint_type: Literal["tosca", "ansible", "helm"]
    name: str = None
    description: str = None
    author_name: str = None
    author_email: EmailStr = None
    organisation: str = None
    keywords: List[str] = []
    license: str = None
    version: str = None
    version_from: datetime = None
    repository: HttpUrl = None
    helpdesk: HttpUrl = None
    validated: bool = False
    validated_on: datetime = None
    self_: HttpUrl | None = Field(None, alias="self", description="Endpoint that returns the details of this tool blueprint")

    class Config:
        populate_by_name = True


Tool = Union[ToolId, ToolInfo]
