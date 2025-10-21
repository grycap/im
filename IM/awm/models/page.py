from typing import List, Union, Literal
from pydantic import BaseModel, Field, EmailStr, HttpUrl
from datetime import datetime
from IM.awm.models.allocation import AllocationInfo
from IM.awm.models.tool import ToolInfo
from IM.awm.models.deployment import DeploymentInfo


class Page(BaseModel):
    """Page Base class for pagination"""
    from_: int = Field(..., alias="from", description="Index of the first element to return")
    limit: int = Field(..., description="Maximum number of elements to return")
    count: int = Field(..., description="Total number of elements")
    self_: HttpUrl | None = Field(None, alias="self", description="Endpoint that returned this page")
    prevPage: HttpUrl | None = Field(None, description="Endpoint that returns the previous page")
    nextPage: HttpUrl | None = Field(None, description="Endpoint that returns the next page")

    class Config:
        populate_by_name = True


class PageOfAllocations(Page):
    """Page of Allocations"""
    elements: List[AllocationInfo]


class PageOfDeployments(Page):
    """Page of Deployments"""
    elements: List[DeploymentInfo]


class PageOfTools(Page):
    """Page of Tools"""
    elements: List[ToolInfo]
