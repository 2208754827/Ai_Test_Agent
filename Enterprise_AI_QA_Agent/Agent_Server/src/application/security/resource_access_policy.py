from __future__ import annotations

from typing import Any

from src.schemas.resource import ResourceScope


class ResourceAccessPolicy:
    """Prevent tool arguments from widening a server-provided resource scope."""

    def scope_from_context(self, context: dict[str, Any] | None) -> ResourceScope:
        context = context or {}
        raw_scope = context.get("trusted_resource_scope") or context.get("resource_scope")
        return ResourceScope.model_validate(raw_scope) if isinstance(raw_scope, dict) else ResourceScope()

    def resolve_api_doc_filters(
        self,
        *,
        arguments: dict[str, Any],
        context: dict[str, Any] | None,
    ) -> tuple[str | None, str | None]:
        scope = self.scope_from_context(context)
        requested_name = self._text(arguments.get("project_name"))
        requested_url = self._text(arguments.get("project_url"))
        scoped_name = self._text(scope.project_name)
        scoped_url = self._text(scope.project_url)
        if scoped_name and requested_name and scoped_name.casefold() != requested_name.casefold():
            raise PermissionError("API document project_name is outside the active resource scope.")
        if scoped_url and requested_url and self._normalize_url(scoped_url) != self._normalize_url(requested_url):
            raise PermissionError("API document project_url is outside the active resource scope.")
        return scoped_name or requested_name, scoped_url or requested_url

    def _text(self, value: object) -> str | None:
        text = str(value or "").strip()
        return text or None

    def _normalize_url(self, value: str) -> str:
        return value.strip().rstrip("/").casefold()
