from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse

from src.runtime.streaming import format_sse
from src.schemas.session import (
    ApprovalDecisionRequest,
    CreateSessionRequest,
    HeadlessExecutionRequest,
    InterruptSessionRequest,
    ResumeSessionRequest,
    SendMessageRequest,
    UpdateSessionRequest,
)
from src.schemas.tool_job import ToolArtifactRecord, ToolJobDetail, ToolJobRecord


# ─── Artifact download helpers ───────────────────────────────────────

_EXTENSION_MIME_MAP: dict[str, str] = {
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".xls": "application/vnd.ms-excel",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".doc": "application/msword",
    ".pdf": "application/pdf",
    ".json": "application/json",
    ".csv": "text/csv",
    ".html": "text/html",
    ".xml": "application/xml",
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".zip": "application/zip",
    ".log": "text/plain",
    ".yml": "text/yaml",
    ".yaml": "text/yaml",
}


def _guess_media_type(filename: str, fallback: str = "application/octet-stream") -> str:
    """Return a MIME type based on filename extension."""
    suffix = Path(filename).suffix.lower() if filename else ""
    return _EXTENSION_MIME_MAP.get(suffix, fallback)


def _content_disposition_attachment(filename: str) -> str:
    """Build a Content-Disposition header value for file download.

    Follows RFC 6266 / RFC 5987: includes both ``filename=`` (ASCII-safe
    fallback) and ``filename*=`` (UTF-8 encoded) so browsers can correctly
    handle non-ASCII characters (e.g. Chinese filenames).
    """
    # ASCII-safe fallback: replace non-ASCII and disallowed chars with _
    safe_filename = "".join(
        ch if 32 <= ord(ch) < 127 and ch not in {'"', "\\", ";"} else "_"
        for ch in str(filename or "artifact")
    ).strip(" ._")
    safe_filename = safe_filename or "artifact"
    # UTF-8 encoded value per RFC 5987
    encoded = quote(str(filename or safe_filename), safe="")
    return f'attachment; filename="{safe_filename}"; filename*=UTF-8\'\'{encoded}'


router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.get("")
async def list_sessions(
    request: Request,
    limit: int | None = None,
    offset: int = 0,
    mode_key: str | None = None,
):
    if limit is None:
        return await request.app.state.session_service.list_sessions()
    return await request.app.state.session_service.list_sessions_page(
        limit=limit,
        offset=offset,
        mode_key=mode_key,
    )


@router.post("")
async def create_session(payload: CreateSessionRequest, request: Request):
    return await request.app.state.session_service.create_session(payload)


@router.post("/headless/execute")
async def execute_headless(payload: HeadlessExecutionRequest, request: Request):
    return await request.app.state.session_service.execute_headless(payload)


@router.get("/{session_id}")
async def get_session(session_id: str, request: Request):
    try:
        return await request.app.state.session_service.get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc


@router.patch("/{session_id}")
async def update_session(session_id: str, payload: UpdateSessionRequest, request: Request):
    try:
        return await request.app.state.session_service.update_session(session_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{session_id}/events/history")
async def list_events(
    session_id: str,
    request: Request,
    limit: int = Query(500, ge=0, le=5000),
    after_event_id: str | None = None,
):
    try:
        return await request.app.state.session_service.list_events(
            session_id,
            limit=None if limit == 0 else limit,
            after_event_id=after_event_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc


@router.post("/{session_id}/messages")
async def send_message(session_id: str, payload: SendMessageRequest, request: Request):
    try:
        return await request.app.state.session_service.send_message(session_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{session_id}/snapshots")
async def list_snapshots(
    session_id: str,
    request: Request,
    limit: int = Query(10, ge=0, le=200),
    include_graph_state: bool = False,
):
    try:
        return await request.app.state.session_service.list_snapshots(
            session_id,
            limit=None if limit == 0 else limit,
            include_graph_state=include_graph_state,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc


@router.post("/{session_id}/interrupt")
async def interrupt_session(
    session_id: str,
    payload: InterruptSessionRequest,
    request: Request,
):
    try:
        return await request.app.state.session_service.interrupt_session(session_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{session_id}/resume")
async def resume_session(
    session_id: str,
    payload: ResumeSessionRequest,
    request: Request,
):
    try:
        return await request.app.state.session_service.resume_session(session_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{session_id}/replay")
async def replay_session(
    session_id: str,
    request: Request,
    limit: int = Query(500, ge=0, le=5000),
):
    try:
        return await request.app.state.session_service.replay_session(
            session_id,
            limit=None if limit == 0 else limit,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc


@router.get("/{session_id}/tool-jobs", response_model=list[ToolJobRecord])
async def list_tool_jobs(session_id: str, request: Request):
    try:
        await request.app.state.session_service.get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc
    return await request.app.state.tool_job_service.list_jobs(session_id=session_id)


@router.get("/{session_id}/tool-jobs/{job_id}", response_model=ToolJobDetail)
async def get_tool_job_detail(session_id: str, job_id: str, request: Request):
    try:
        await request.app.state.session_service.get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc
    job = await request.app.state.tool_job_service.get_job_detail(job_id)
    if job is None or job.session_id != session_id:
        raise HTTPException(status_code=404, detail="Tool job not found")
    return job


@router.get("/{session_id}/artifacts", response_model=list[ToolArtifactRecord])
async def list_session_artifacts(session_id: str, request: Request):
    try:
        await request.app.state.session_service.get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc
    return await request.app.state.tool_job_service.list_artifacts(session_id=session_id)


@router.get("/{session_id}/artifacts/{artifact_id}/content")
async def get_artifact_content(session_id: str, artifact_id: str, request: Request):
    """Download artifact file content for a session.

    Supports local file paths, MinIO URIs, and inline text content.
    Sets Content-Disposition: attachment to trigger browser download.
    """
    try:
        await request.app.state.session_service.get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc

    artifact = await request.app.state.tool_job_service.get_artifact(artifact_id)
    if artifact is None or artifact.session_id != session_id:
        raise HTTPException(status_code=404, detail="Artifact not found")

    raw_path = str(artifact.path or "").strip()
    inline_content = str(artifact.metadata.get("__content_text") or "").strip() if artifact.metadata else ""
    storage_mode = str(artifact.metadata.get("__storage_mode") or "") if artifact.metadata else ""

    # Case 1: MinIO URI
    if raw_path.startswith("minio://") and hasattr(request.app.state, "artifact_storage_service"):
        try:
            stored = await request.app.state.artifact_storage_service.read_object_uri(raw_path)
            content_bytes = stored.get("content", b"")
            content_type = str(stored.get("content_type") or "application/octet-stream")
            filename = str(artifact.label or stored.get("object_name", "").split("/")[-1] or artifact_id)
            # Guess a better MIME type from the filename when the stored one is generic
            if content_type == "application/octet-stream" and filename:
                content_type = _guess_media_type(filename, fallback=content_type)
            return Response(
                content=content_bytes,
                media_type=content_type,
                headers={"Content-Disposition": _content_disposition_attachment(filename)},
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to read artifact from storage: {exc}") from exc

    # Case 2: Local file path
    if raw_path and not raw_path.startswith("inline://"):
        try:
            local_path = Path(raw_path)
            if local_path.exists() and local_path.is_file():
                filename = str(artifact.label or local_path.name)
                media_type = _guess_media_type(filename)
                # Read file bytes and return as Response with RFC 5987
                # Content-Disposition so browsers handle non-ASCII filenames.
                file_bytes = local_path.read_bytes()
                return Response(
                    content=file_bytes,
                    media_type=media_type,
                    headers={"Content-Disposition": _content_disposition_attachment(filename)},
                )
        except (OSError, ValueError):
            pass

    # Case 3: Inline text content
    if inline_content:
        filename = str(artifact.label or f"{artifact_id}.txt")
        return Response(
            content=inline_content.encode("utf-8"),
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": _content_disposition_attachment(filename)},
        )

    raise HTTPException(status_code=404, detail="Artifact content not available")


@router.get("/{session_id}/approvals")
async def list_approvals(session_id: str, request: Request):
    try:
        return await request.app.state.session_service.list_approvals(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc


@router.get("/{session_id}/verifications")
async def list_verifications(session_id: str, request: Request):
    try:
        return await request.app.state.session_service.list_verifications(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc


@router.get("/{session_id}/observations")
async def list_observations(session_id: str, request: Request):
    try:
        return await request.app.state.session_service.list_observations(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc


@router.post("/{session_id}/approvals/{approval_id}")
async def resolve_approval(
    session_id: str,
    approval_id: str,
    payload: ApprovalDecisionRequest,
    request: Request,
):
    try:
        return await request.app.state.session_service.resolve_approval(session_id, approval_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Approval or session not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{session_id}/events")
async def stream_events(session_id: str, request: Request):
    try:
        await request.app.state.session_service.get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc

    queue = request.app.state.session_service.get_event_queue(session_id)
    last_event_id = (
        request.headers.get("last-event-id")
        or request.query_params.get("last_event_id")
        or request.query_params.get("Last-Event-ID")
        or ""
    ).strip()

    async def event_generator():
        if last_event_id:
            events = await request.app.state.session_service.list_events(
                session_id,
                limit=1000,
                after_event_id=last_event_id,
            )
            for event in events:
                yield format_sse(event)

        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(queue.get(), timeout=15)
                yield format_sse(event)
            except TimeoutError:
                yield ": keep-alive\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")
