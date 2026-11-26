"""HTTP selects a server-published execution, never supplies trusted facts or paths."""

from pydantic import Field

from app.models import StrictModel


class NativeServiceAnalysisRequest(StrictModel):
    execution_ref: str = Field(pattern=r"^[a-f0-9]{64}$")
