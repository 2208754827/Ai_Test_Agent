from __future__ import annotations

from collections.abc import Iterable

from src.schemas.agent import ToolDescriptor


class CapabilityResolver:
    """Filter tools by mode ownership and the capabilities requested this turn."""

    def eligible_tools(
        self,
        *,
        tools: Iterable[ToolDescriptor],
        active_mode_key: str,
        required_capabilities: list[str] | None = None,
        allowed_capabilities: list[str] | None = None,
    ) -> list[ToolDescriptor]:
        capabilities = set(required_capabilities or [])
        mode_capabilities = None if allowed_capabilities is None else set(allowed_capabilities)
        return [
            tool
            for tool in tools
            if self.is_eligible(
                tool=tool,
                active_mode_key=active_mode_key,
                required_capabilities=capabilities,
                allowed_capabilities=mode_capabilities,
            )
        ]

    def is_eligible(
        self,
        *,
        tool: ToolDescriptor,
        active_mode_key: str,
        required_capabilities: set[str] | None = None,
        allowed_capabilities: set[str] | None = None,
    ) -> bool:
        capabilities = required_capabilities or set()
        if tool.allowed_mode_keys and active_mode_key not in tool.allowed_mode_keys:
            return False
        if active_mode_key in tool.denied_mode_keys:
            return False
        if tool.exposure == "internal":
            return bool(tool.owner_mode_key and tool.owner_mode_key == active_mode_key)
        if tool.exposure == "workflow_entry" and tool.owner_mode_key != active_mode_key:
            requested = capabilities.intersection(tool.capability_keys)
            if not requested:
                return False
            return allowed_capabilities is None or bool(allowed_capabilities.intersection(requested))
        return True
