from pydantic import BaseModel, Field
from typing import Dict, Any


class Error(BaseModel):
    id: str | None = Field(None, description="Error type")
    description: str | None = Field("Error", description="Error message")
    details: Dict[str, Any] | None = Field(None, description="Additional details about the error")
