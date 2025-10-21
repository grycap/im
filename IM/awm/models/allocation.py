from typing import Union, Literal, Annotated
from pydantic import BaseModel, Field, HttpUrl
from datetime import datetime


class EoscNodeEnvironment_offer(BaseModel):
    offerId: str
    offerName: str = None
    offerType: Literal["openstack", "kubernetes"]
    cpus: int | None = Field(None, ge=1)
    gpus: int = None
    memory: int | None = Field(None, ge=1, description=("RAM quota in GB"))
    fastStorage: int | None = Field(None, description=("SSD or NVMe based (fast) storage quota in GB"))
    bulkStorage: int | None = Field(None, description=("HDD based (slow) storage quota in GB"))
    s3Storage: int | None = Field(None, description=("S3 storage quota in GB"))
    registryStorage: int | None = Field(None, description=("Container Registry storage quota in GB"))
    creditsPerDay: int = Field(..., ge=1, description=("Credits per day"))


class EoscNodeEnvironment(BaseModel):
    """Environment variables for EOSC node"""
    kind: Literal['EoscNodeEnvironment'] = 'EoscNodeEnvironment'
    offer: EoscNodeEnvironment_offer
    projectId: str = None
    hostname: HttpUrl = None
    provisionedOn: datetime = None
    expiresOn: datetime = None
    nodeName: str = Field(..., description="Name of the EOSC node where this environment was allocated")
    nodeUID: str | None = Field(None, description="URL to the interactive UI of the EOSC node where this environment was allocated")
    awmAPI: HttpUrl = Field(..., description="Base URL for the AWM API of the EOSC node where this environment was allocated, or null for environments private to the calling user that accessed via explicit credentials")


class CredentialsOpenStack(BaseModel):
    """Credentials for OpenStack"""
    kind: Literal['CredentialsOpenStack'] = 'CredentialsOpenStack'
    userName: str = None
    domain: str = None
    domainId: str = None
    tenant: str = None
    tenantId: str = None
    region: str = None
    host: HttpUrl
    authVersion: Literal['3.x-oidc'] = '3.x-oidc'
    apiVersion: str = None


class CredentialsKubernetes(BaseModel):
    """Credentials for Kubernetes"""
    kind: Literal['CredentialsKubernetes'] = 'CredentialsKubernetes'
    host: HttpUrl


Credentials = Annotated[
    Union[CredentialsOpenStack, CredentialsKubernetes],
    Field(discriminator='kind')
]


Allocation = Annotated[
    Union[EoscNodeEnvironment, CredentialsOpenStack, CredentialsKubernetes],
    Field(discriminator='kind')
]


class AllocationlId(BaseModel):
    kind: Literal['AllocationId'] = 'AllocationId'
    id: str = Field(..., description="Unique identifier for this allocation")
    infoLink: str | None = Field(None, description="Endpoint that returns more details about this entity")


class AllocationInfo(BaseModel):
    id: str = Field(..., description="Unique identifier for this allocation")
    self_: HttpUrl | None = Field(None, alias="self", description="Endpoint that returns the details of this allocation")
    allocation: Allocation

    class Config:
        populate_by_name = True
