from __future__ import annotations

from src.schemas.agent import AgentDescriptor, ToolDescriptor


class ToolExposurePolicy:
    """Require the selected agent to explicitly support a tool or capability."""

    def is_supported(self, *, tool: ToolDescriptor, agent: AgentDescriptor) -> bool:
        if tool.key == "skill":
            return True
        if tool.key in agent.supported_tools:
            return True
        return bool(set(agent.supported_capabilities).intersection(tool.capability_keys))

    def filter_supported(
        self,
        *,
        tools: list[ToolDescriptor],
        agent: AgentDescriptor,
    ) -> list[ToolDescriptor]:
        return [tool for tool in tools if self.is_supported(tool=tool, agent=agent)]
