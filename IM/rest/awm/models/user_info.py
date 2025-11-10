from typing import List, Literal
from pydantic import BaseModel


class UserInfo(BaseModel):
    kind: Literal['UserInfo'] = 'UserInfo'
    base_id: str = None
    user_dn: str = None
    delegation_id: str = None
    dn: List[str] = None
    vos: List[str] | None
    vos_id: List[str] | None
    voms_cred: List[str] = None
