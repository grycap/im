from pydantic import BaseModel, Field
from typing import Dict, Optional


class Error(BaseModel):
    id: str = Field(..., description="Error type")
    description: Optional[str] = Field(None, description="Error message")
    details: Optional[Dict[str, str]] = Field(None, description="Additional details about the error")
