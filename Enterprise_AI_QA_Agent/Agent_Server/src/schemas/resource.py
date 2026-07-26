from __future__ import annotations

from pydantic import BaseModel


class ResourceScope(BaseModel):
    tenant_id: str | None = None
    workspace_id: str | None = None
    project_id: str | None = None
    project_name: str | None = None
    project_url: str | None = None
    environment_id: str | None = None

    @property
    def is_scoped(self) -> bool:
        return any((self.tenant_id, self.workspace_id, self.project_id, self.project_name, self.project_url))
