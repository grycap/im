from typing import List, Union, Literal
from pydantic import BaseModel, Field, EmailStr, HttpUrl
from datetime import datetime


class ToolId(BaseModel):
    kind: Literal['ToolId'] = 'ToolId'
    id: str = Field(..., description="Unique identifier for this tool blueprint")
    version: str | None = Field(None, description="The specific version of this blueprint version")
    infoLink: HttpUrl | None = Field(None, description="URL that returns the full details of this tool blueprint")


class ToolInfo(BaseModel):
    kind: Literal['ToolInfo'] = 'ToolInfo'
    id: str = Field(..., description="Unique identifier for this tool blueprint")
    nodeId: str | None = Field(None, description="Unique identifier of the EOSC node where this tool blueprint is hosted")
    type: Literal["vm", "container"]
    blueprint: str = Field(..., description="Prescriptive IaC script of the tool's workload")
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
    self_: HttpUrl | None = Field(None, alias="self", description="Endpoint that returns the details of this tool blueprint")

    class Config:
        populate_by_name = True
