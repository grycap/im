#! /usr/bin/env python
#
# IM - Infrastructure Manager
# Copyright (C) 2025 - GRyCAP - Universitat Politecnica de Valencia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from typing import Union, Literal, Annotated
from pydantic import BaseModel, Field, HttpUrl, RootModel
from datetime import datetime


class EoscNodeEnvironment_offer(BaseModel):
    offerId: str
    offerName: str = None
    offerType: Literal["openstack", "kubernetes"]
    cpus: int | None = Field(None, ge=1)
    gpus: int = None
    memory: int | None = Field(None, ge=1)
    fastStorage: int = None
    bulkStorage: int = None
    s3Storage: int = None
    registryStorage: int = None
    creditsPerDay: int = Field(..., ge=1)


class EoscNodeEnvironment(BaseModel):
    """Environment variables for EOSC node"""
    kind: Literal['EoscNodeAllocation'] = 'EoscNodeAllocation'
    offer: EoscNodeEnvironment_offer
    projectId: str
    hostname: HttpUrl = None
    provisionedOn: datetime = None
    expiresOn: datetime = None
    nodeId: str
    nodeName: str
    nodeUI: str = None
    awmAPI: HttpUrl


class OpenStackEnvironment(BaseModel):
    """Credentials for OpenStack"""
    kind: Literal['OpenStackEnvironment'] = 'OpenStackEnvironment'
    userName: str
    domain: str = None
    domainId: str = None
    tenant: str
    tenantId: str = None
    region: str = None
    host: HttpUrl
    authVersion: Literal['3.x-oidc'] = '3.x-oidc'
    apiVersion: str = None


class KubernetesEnvironment(BaseModel):
    """Credentials for Kubernetes"""
    kind: Literal['KubernetesEnvironment'] = 'KubernetesEnvironment'
    host: HttpUrl


AllocationUnion = Annotated[
    Union[EoscNodeEnvironment, OpenStackEnvironment, KubernetesEnvironment],
    Field(discriminator='kind')
]


class Allocation(RootModel[AllocationUnion]):
    pass


class AllocationId(BaseModel):
    kind: Literal['AllocationId'] = 'AllocationId'
    id: str
    infoLink: HttpUrl = None


class AllocationInfo(BaseModel):
    id: str
    self_: HttpUrl = Field(..., alias="self")
    allocation: Allocation

    model_config = {"populate_by_name": True}
