from typing import List, Literal
from pydantic import BaseModel, Field


class UserInfo(BaseModel):
    kind: Literal['UserInfo'] = 'UserInfo'
    base_id: str = None
    user_dn: str = None
    delegation_id: str = None
    dn: List[str] = None
    vos: List[str] | None = Field(None, description="Virtual organisation name(s)")
    vos_id: List[str] | None = Field(None, description="Virtual organisation identifier(s)")
    voms_cred: List[str] = None
