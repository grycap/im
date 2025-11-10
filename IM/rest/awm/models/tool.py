from typing import List, Literal
from pydantic import BaseModel, Field, EmailStr, HttpUrl
from datetime import datetime


class ToolId(BaseModel):
    kind: Literal['ToolId'] = 'ToolId'
    id: str
    version: str = None
    infoLink: HttpUrl = None


class ToolInfo(BaseModel):
    kind: Literal['ToolInfo'] = 'ToolInfo'
    id: str
    nodeId: str = None
    type: Literal["vm", "container"]
    blueprint: str
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
    self_: HttpUrl | None = Field(None, alias="self")

    class Config:
        populate_by_name = True
