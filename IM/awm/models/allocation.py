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


Credentials = Annotated[
    Union[OpenStackEnvironment, KubernetesEnvironment],
    Field(discriminator='kind')
]


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

    class Config:
        populate_by_name = True
