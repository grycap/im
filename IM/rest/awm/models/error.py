from pydantic import BaseModel
from typing import Dict


class Error(BaseModel):
    id: str
    description: str = None
    details: Dict[str, str] = None
