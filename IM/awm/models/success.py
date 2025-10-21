from pydantic import BaseModel, Field


class Success(BaseModel):
    message: str = Field("Success", description="Confirmation message")
