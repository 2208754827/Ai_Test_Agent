from __future__ import annotations

import json
import re
from typing import Any

from src.application.model_adapters.base import (
    AdapterDescriptor,
    ProviderAdapter,
    StreamChunkParseResult,
    StreamParseState,
)
from src.schemas.model_config import ContentPart, ModelConfigRecord, ModelInvocationRequest, UnifiedMessage
from src.schemas.tool_runtime import ModelToolCall


class GoogleGeminiGenerateContentAdapter(ProviderAdapter):
    adapter_key = "google_gemini_generate_content"
    _SCHEMA_ALLOWED_KEYS = {
        "type",
        "description",
        "properties",
        "items",
        "required",
        "enum",
        "format",
        "nullable",
        "minimum",
        "maximum",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
    }

    def matches(self, config: ModelConfigRecord) -> bool:
        return config.transport == "google_gemini_generate_content"

    def build_tool_name_map(self, tools: list[dict[str, Any]]) -> dict[str, str]:
        name_map: dict[str, str] = {}
        used: set[str] = set()
        for item in tools:
            original = str(item.get("name") or "").strip()
            if not original:
                continue
            candidate = self._sanitize_google_tool_name(original)
            suffix = 2
            while candidate in used and name_map.get(original) != candidate:
                candidate = self._sanitize_google_tool_name(f"{original}_{suffix}")
                suffix += 1
            used.add(candidate)
            name_map[original] = candidate
        return name_map

    def describe(self, config: ModelConfigRecord) -> AdapterDescriptor:
        return AdapterDescriptor(
            name="google",
            protocol="google_gemini_generate_content",
            chat_path=f"/v1beta/models/{config.model_id}:generateContent",
            auth_header="x-goog-api-key",
            auth_prefix="",
        )

    def build_url(self, config: ModelConfigRecord) -> str:
        base_url = config.api_base_url.rstrip("/")
        descriptor = self.describe(config)
        if base_url.endswith(descriptor.chat_path):
            return base_url
        return f"{base_url}{descriptor.chat_path}"

    def build_request(
        self,
        config: ModelConfigRecord,
        request: ModelInvocationRequest,
        tool_name_map: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "contents": self._build_contents(request, tool_name_map),
            "generationConfig": {
                "maxOutputTokens": config.max_output_tokens,
            },
        }
        if request.system_prompt:
            payload["systemInstruction"] = {
                "parts": [{"text": request.system_prompt}],
            }
        if config.temperature is not None:
            payload["generationConfig"]["temperature"] = config.temperature
        if config.supports_tools and request.tools:
            payload["tools"] = [
                {
                    "functionDeclarations": [
                        {
                            "name": (tool_name_map or {}).get(item["name"], item["name"]),
                            "description": item["description"],
                            "parameters": self._sanitize_function_parameters(item["input_schema"]),
                        }
                        for item in request.tools
                    ]
                }
            ]
        return payload

    def build_headers(self, config: ModelConfigRecord, api_key: str) -> dict[str, str]:
        if config.auth_type == "oauth2":
            return {
                "Authorization": f"Bearer {api_key}",
                "content-type": "application/json",
                **config.extra_headers,
            }
        return super().build_headers(config, api_key)

    def parse_response(self, config: ModelConfigRecord, data: dict[str, Any]) -> dict[str, Any]:
        candidates = data.get("candidates", []) or []
        first = candidates[0] if candidates and isinstance(candidates[0], dict) else {}
        content = first.get("content") or {}
        parts = content.get("parts") or []

        text_blocks: list[str] = []
        tool_calls: list[ModelToolCall] = []
        for index, part in enumerate(parts):
            if not isinstance(part, dict):
                continue
            if part.get("text"):
                text_blocks.append(str(part.get("text") or ""))
            function_call = part.get("functionCall") or {}
            if isinstance(function_call, dict) and function_call.get("name"):
                tool_calls.append(
                    ModelToolCall(
                        id=f"gemini_call_{index}",
                        name=str(function_call.get("name") or ""),
                        arguments=function_call.get("args", {})
                        if isinstance(function_call.get("args"), dict)
                        else {},
                    )
                )

        usage = data.get("usageMetadata", {}) if isinstance(data.get("usageMetadata"), dict) else {}
        finish_reason = first.get("finishReason")
        return {
            "text": "\n".join(block.strip() for block in text_blocks if block.strip()).strip(),
            "tool_calls": tool_calls,
            "finish_reason": finish_reason,
            "stop_reason": finish_reason,
            "usage": usage,
            "response_id": data.get("responseId"),
            "raw_response": data,
        }

    def parse_stream_chunk(
        self,
        config: ModelConfigRecord,
        state: StreamParseState,
        chunk: str,
    ) -> StreamChunkParseResult:
        parsed = self.parse_json_chunk(chunk)
        if parsed is None:
            return StreamChunkParseResult()

        candidates = parsed.get("candidates", []) or []
        if candidates and isinstance(candidates[0], dict):
            first = candidates[0]
            content = first.get("content") or {}
            parts = content.get("parts") or []
            text_delta = ""
            for index, part in enumerate(parts):
                if not isinstance(part, dict):
                    continue
                if part.get("text"):
                    block = str(part.get("text") or "")
                    state.text_parts.append(block)
                    text_delta += block
                function_call = part.get("functionCall") or {}
                if isinstance(function_call, dict) and function_call.get("name"):
                    state.tool_call_buffers[index] = {
                        "id": f"gemini_call_{index}",
                        "name": str(function_call.get("name") or ""),
                        "arguments": json.dumps(function_call.get("args", {}), ensure_ascii=False),
                    }
            state.finish_reason = first.get("finishReason") or state.finish_reason
            state.stop_reason = first.get("finishReason") or state.stop_reason
            return StreamChunkParseResult(text_delta=text_delta)

        usage = parsed.get("usageMetadata")
        if isinstance(usage, dict):
            state.usage = usage
        if parsed.get("responseId"):
            state.response_id = str(parsed.get("responseId"))
        return StreamChunkParseResult()

    def finalize_stream(
        self,
        config: ModelConfigRecord,
        state: StreamParseState,
    ) -> dict[str, Any]:
        tool_calls = [
            ModelToolCall(
                id=str(item.get("id") or f"gemini_call_{index}"),
                name=str(item.get("name") or ""),
                arguments=self.parse_tool_arguments(item.get("arguments", "")),
            )
            for index, item in sorted(state.tool_call_buffers.items(), key=lambda pair: pair[0])
        ]
        return {
            "text": "".join(state.text_parts).strip(),
            "tool_calls": tool_calls,
            "finish_reason": state.finish_reason,
            "stop_reason": state.stop_reason,
            "usage": state.usage,
            "response_id": state.response_id,
            "raw_response": {
                "mode": "stream",
                "provider": config.provider,
                "finish_reason": state.finish_reason,
                "usage": state.usage,
            },
        }

    def _build_contents(
        self,
        request: ModelInvocationRequest,
        tool_name_map: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        contents: list[dict[str, Any]] = []
        for message in request.structured_messages:
            if message.role == "system":
                continue
            if message.role == "tool":
                role = "user"
            elif message.role == "assistant":
                role = "model"
            else:
                role = "user"
            parts = self._serialize_parts(message)
            if message.role == "assistant" and message.tool_calls:
                for tool_call in message.tool_calls:
                    parts.append(
                        {
                            "functionCall": {
                                "name": (tool_name_map or {}).get(tool_call.name, tool_call.name),
                                "args": tool_call.arguments or {},
                            }
                        }
                    )
            contents.append(
                {
                    "role": role,
                    "parts": parts,
                }
            )
        return contents

    def _serialize_parts(self, message: UnifiedMessage) -> list[dict[str, Any]]:
        parts: list[dict[str, Any]] = []
        for part in message.parts:
            serialized = self._serialize_part(part)
            if serialized is not None:
                parts.append(serialized)
        return parts or [{"text": ""}]

    def _serialize_part(self, part: ContentPart) -> dict[str, Any] | None:
        if part.type == "text":
            return {"text": part.text or ""}
        if part.type == "image_base64" and part.data_base64:
            return {
                "inlineData": {
                    "mimeType": part.mime_type or "image/jpeg",
                    "data": part.data_base64,
                }
            }
        if part.type == "image_url" and part.url:
            if part.url.startswith("data:") and ";base64," in part.url:
                prefix, data_base64 = part.url.split(";base64,", 1)
                mime_type = prefix.split("data:", 1)[-1] or "image/jpeg"
                return {
                    "inlineData": {
                        "mimeType": mime_type,
                        "data": data_base64,
                    }
                }
            return {"text": f"Image URL: {part.url}"}
        if part.type == "tool_result":
            payload = part.payload if isinstance(part.payload, dict) else {}
            return {
                "functionResponse": {
                    "name": part.tool_name or "tool_result",
                    "response": payload or {"content": part.text or ""},
                }
            }
        if part.type == "file":
            label = part.file_name or "file"
            return {"text": f"[file:{label}]"}
        return None

    def _sanitize_function_parameters(self, schema: Any) -> dict[str, Any]:
        if not isinstance(schema, dict):
            return {"type": "object", "properties": {}}

        working = dict(schema)
        for union_key in ("anyOf", "oneOf", "allOf"):
            if union_key in working and "type" not in working:
                candidate = self._first_supported_union_member(working.get(union_key))
                if candidate:
                    working = {**candidate, **{key: value for key, value in working.items() if key != union_key}}
                else:
                    working.pop(union_key, None)

        sanitized: dict[str, Any] = {}
        for key, value in working.items():
            if key not in self._SCHEMA_ALLOWED_KEYS:
                continue
            if key == "properties" and isinstance(value, dict):
                sanitized["properties"] = {
                    str(name): self._sanitize_function_parameters(child_schema)
                    for name, child_schema in value.items()
                    if isinstance(name, str)
                }
                continue
            if key == "items":
                sanitized["items"] = self._sanitize_function_parameters(value)
                continue
            if key == "required" and isinstance(value, list):
                known = set((sanitized.get("properties") or {}).keys()) if isinstance(sanitized.get("properties"), dict) else None
                required = [str(item) for item in value if isinstance(item, str)]
                sanitized["required"] = [item for item in required if known is None or item in known]
                continue
            if key == "type":
                if isinstance(value, list):
                    preferred = next((item for item in value if isinstance(item, str) and item != "null"), None)
                    if preferred:
                        sanitized["type"] = preferred
                elif isinstance(value, str):
                    sanitized["type"] = value
                continue
            sanitized[key] = value

        if sanitized.get("type") == "object":
            sanitized.setdefault("properties", {})
        return sanitized or {"type": "object", "properties": {}}

    def _first_supported_union_member(self, value: Any) -> dict[str, Any] | None:
        if not isinstance(value, list):
            return None
        for item in value:
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            if item_type == "null":
                continue
            if isinstance(item_type, list) and all(part == "null" for part in item_type):
                continue
            return item
        return None

    def _sanitize_google_tool_name(self, value: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9_]+", "_", value).strip("_")
        if not cleaned:
            cleaned = "tool"
        if cleaned[0].isdigit():
            cleaned = f"tool_{cleaned}"
        return cleaned[:64]
