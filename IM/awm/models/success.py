from pydantic import BaseModel, Field


class Success(BaseModel):
    message: str | None = Field("Success", description="Confirmation message")
