from typing import List
from pydantic import BaseModel, Field, HttpUrl
from IM.awm.models.allocation import AllocationInfo
from IM.awm.models.tool import ToolInfo
from IM.awm.models.deployment import DeploymentInfo


class Page(BaseModel):
    """Page Base class for pagination"""
    from_: int = Field(..., alias="from")
    limit: int
    count: int
    self_: HttpUrl | None = Field(None, alias="self")
    prevPage: HttpUrl = None
    nextPage: HttpUrl = None

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
