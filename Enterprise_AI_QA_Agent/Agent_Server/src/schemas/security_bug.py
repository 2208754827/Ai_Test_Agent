from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


SecurityBugManualStatus = Literal["confirmed", "fixed", "false_positive"]


class SecurityBugTransitionRequest(BaseModel):
    status: SecurityBugManualStatus
    fixed_version: str = ""
    note: str = ""


__all__ = ["SecurityBugManualStatus", "SecurityBugTransitionRequest"]
