from __future__ import annotations

import openai
from openai import AsyncOpenAI

from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types

from src.application.model_clients.base import ProviderClientError
from src.application.model_clients.google_client import GoogleGenAIClient
from src.application.model_clients.provider_profiles import normalize_transport
from src.schemas.model_config import ModelConfigRecord

_ANTHROPIC_NO_EMBEDDINGS_MESSAGE = (
    "Anthropic does not expose an embeddings API. Configure a dedicated "
    "embedding model from OpenAI, Qwen/DashScope, Google, or another "
    "OpenAI-compatible provider."
)


class OpenAICompatibleEmbeddingClient:
    key = "openai_compatible_embeddings"

    def __init__(self, *, timeout_seconds: float = 300.0, max_retries: int = 2) -> None:
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries

    async def embed(
        self,
        config: ModelConfigRecord,
        api_key: str,
        texts: list[str],
    ) -> list[list[float]]:
        try:
            async with AsyncOpenAI(
                api_key=api_key,
                base_url=self._normalize_base_url(config.api_base_url),
                default_headers=dict(config.extra_headers) or None,
                timeout=self._timeout_seconds,
                max_retries=self._max_retries,
            ) as client:
                response = await client.embeddings.create(
                    model=config.model_id,
                    input=texts,
                    encoding_format="float",
                )
        except openai.APIStatusError as exc:
            body = ""
            try:
                body = exc.response.text or ""
            except Exception:
                body = ""
            raise ProviderClientError(
                str(exc),
                status_code=exc.status_code,
                response_body=body,
            ) from exc
        except openai.APIError as exc:
            raise ProviderClientError(str(exc)) from exc
        items = sorted(response.data or [], key=lambda item: int(item.index or 0))
        vectors = [[float(value) for value in item.embedding] for item in items]
        if not vectors:
            raise ValueError("Embedding response does not contain valid vectors.")
        return vectors

    @staticmethod
    def _normalize_base_url(base_url: str) -> str:
        # Stored base URLs may already include the /embeddings resource path.
        cleaned = str(base_url or "").rstrip("/")
        if cleaned.endswith("/embeddings"):
            cleaned = cleaned[: -len("/embeddings")]
        return cleaned


class GoogleEmbeddingClient:
    key = "google_embeddings"

    def __init__(self, *, timeout_seconds: float = 300.0) -> None:
        self._timeout_seconds = timeout_seconds

    async def embed(
        self,
        config: ModelConfigRecord,
        api_key: str,
        texts: list[str],
    ) -> list[list[float]]:
        model_name = config.model_id
        if not model_name.startswith("models/"):
            model_name = f"models/{model_name}"
        headers: dict[str, str] = {**config.extra_headers}
        if config.auth_type == "oauth2":
            headers["Authorization"] = f"Bearer {api_key}"
        client = genai.Client(
            api_key=api_key,
            http_options=genai_types.HttpOptions(
                base_url=GoogleGenAIClient._normalize_base_url(config.api_base_url),
                headers=headers or None,
                timeout=int(self._timeout_seconds * 1000),
            ),
        )
        try:
            response = await client.aio.models.embed_content(
                model=model_name,
                contents=texts,
            )
        except genai_errors.APIError as exc:
            raise ProviderClientError(
                str(exc),
                status_code=getattr(exc, "code", None),
            ) from exc
        embeddings = getattr(response, "embeddings", None) or []
        vectors = [
            [float(value) for value in (getattr(item, "values", None) or [])]
            for item in embeddings
        ]
        if not vectors or not all(vectors):
            raise ValueError("Google embedding response does not contain valid vectors.")
        return vectors


def resolve_embedding_client(
    config: ModelConfigRecord,
    *,
    timeout_seconds: float = 300.0,
):
    """Dispatch by transport: the protocol describes the endpoint URL format.

    google_gemini_generate_content -> native :embedContent URL format;
    openai_chat_completions -> OpenAI-compatible /embeddings (also valid for
    vendors like Google that expose an OpenAI-compatible base URL);
    anthropic_messages -> no embeddings endpoint exists for this protocol.
    """
    transport = normalize_transport(config.transport, provider=config.provider)
    if transport == "google_gemini_generate_content":
        return GoogleEmbeddingClient(timeout_seconds=timeout_seconds)
    if transport == "anthropic_messages":
        raise ValueError(_ANTHROPIC_NO_EMBEDDINGS_MESSAGE)
    return OpenAICompatibleEmbeddingClient(timeout_seconds=timeout_seconds)
