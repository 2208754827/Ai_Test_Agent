from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


class ApprovalScopeService:
    """Bind approval to the exact mode, target, resource scope, and arguments."""

    def build_hash(
        self,
        *,
        mode_key: str,
        tool_key: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> str:
        context = context or {}
        payload = {
            "mode_key": mode_key,
            "tool_key": tool_key,
            "arguments": arguments,
            "environment": context.get("environment") or context.get("safety_assessment", {}).get("environment"),
            "tenant_id": context.get("tenant_id"),
            "workspace_id": context.get("workspace_id"),
            "project_id": context.get("project_id"),
        }
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def matches(
        self,
        stored_hash: str,
        *,
        mode_key: str,
        tool_key: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> bool:
        if not stored_hash:
            return False
        current_hash = self.build_hash(
            mode_key=mode_key,
            tool_key=tool_key,
            arguments=arguments,
            context=context,
        )
        return hmac.compare_digest(stored_hash, current_hash)
