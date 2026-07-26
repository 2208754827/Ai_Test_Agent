from __future__ import annotations

from src.application.mcp.host.connection_state import McpToolInfo
from src.application.mcp.host.namespace import encode
from src.registry.tools import ToolRegistry
from src.schemas.agent import ToolDescriptor


class McpToolBridge:
    def __init__(self, *, tool_registry: ToolRegistry) -> None:
        self._tool_registry = tool_registry
        self._registered_by_server: dict[str, set[str]] = {}

    def sync_server_tools(self, server_key: str, tools: list[McpToolInfo]) -> None:
        self.remove_server_tools(server_key)
        registered: set[str] = set()
        for tool in tools:
            descriptor = self.to_tool_descriptor(server_key, tool)
            self._tool_registry.register_dynamic(descriptor, handler_key="mcp-bridge")
            registered.add(descriptor.key)
        self._registered_by_server[server_key] = registered

    def remove_server_tools(self, server_key: str) -> None:
        for tool_key in self._registered_by_server.pop(server_key, set()):
            self._tool_registry.unregister_dynamic(tool_key)

    def to_tool_descriptor(self, server_key: str, tool: McpToolInfo) -> ToolDescriptor:
        tool_key = encode(server_key, tool.name)
        return ToolDescriptor(
            key=tool_key,
            name=f"{server_key}:{tool.name}",
            description=tool.description or f"External MCP tool '{tool.name}' from server '{server_key}'.",
            category="mcp",
            permission_level="ask",
            input_schema=tool.input_schema or {"type": "object", "additionalProperties": True},
            output_schema={"type": "object", "additionalProperties": True},
            capability_keys=["mcp.external"],
            tags=["mcp", server_key],
        )
