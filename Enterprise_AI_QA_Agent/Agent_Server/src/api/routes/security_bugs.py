from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response

from src.modes.security_testing_mode.campaign_state import SecurityBugRecord
from src.modes.security_testing_mode.security_bug_reproduction_package import (
    SecurityBugReproductionPackageService,
)
from src.schemas.security_bug import SecurityBugTransitionRequest


router = APIRouter(prefix="/security-bugs", tags=["security-bugs"])


def _attachment_header(filename: str) -> str:
    resolved = filename or "security_bug_reproduction_package"
    ascii_name = "".join(
        character if 32 <= ord(character) < 127 and character not in {'"', "\\", ";"} else "_"
        for character in resolved
    ).strip(" ._") or "security_bug_reproduction_package"
    return f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(resolved, safe="")}'


@router.get("", response_model=list[SecurityBugRecord])
async def list_security_bugs(
    request: Request,
    target_fingerprint: str = Query("", max_length=160),
    status: str = Query("", max_length=32),
):
    return await request.app.state.security_bug_service.list(
        target_fingerprint=target_fingerprint.strip(),
        status=status.strip().lower(),
    )


@router.get("/{bug_id}", response_model=SecurityBugRecord)
async def get_security_bug(bug_id: str, request: Request):
    bug = await request.app.state.security_bug_service.get(bug_id)
    if bug is None:
        raise HTTPException(status_code=404, detail="Security Bug not found")
    return bug


@router.get("/{bug_id}/reproduction-package")
async def download_security_bug_reproduction_package(
    bug_id: str,
    request: Request,
    format: str = Query("json", pattern="^(json|markdown|md)$"),
):
    bug = await request.app.state.security_bug_service.get(bug_id)
    if bug is None:
        raise HTTPException(status_code=404, detail="Security Bug not found")
    builder = SecurityBugReproductionPackageService()
    package = builder.build_package(bug)
    normalized_format = "markdown" if format == "md" else format
    suffix = "md" if normalized_format == "markdown" else "json"
    filename = f"security_bug_reproduction_{_safe_filename_segment(bug.bug_id)}.{suffix}"
    if normalized_format == "markdown":
        return Response(
            content=builder.build_markdown_bytes(package),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": _attachment_header(filename)},
        )
    return Response(
        content=builder.build_json_bytes(package),
        media_type="application/json",
        headers={"Content-Disposition": _attachment_header(filename)},
    )


@router.patch("/{bug_id}", response_model=SecurityBugRecord)
async def transition_security_bug(
    bug_id: str,
    payload: SecurityBugTransitionRequest,
    request: Request,
):
    try:
        return await request.app.state.security_bug_service.transition(
            bug_id,
            status=payload.status,
            fixed_version=payload.fixed_version,
            note=payload.note,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Security Bug not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


__all__ = ["router"]


def _safe_filename_segment(value: str) -> str:
    resolved = "".join(
        character if character.isalnum() or character in {"-", "_", "."} else "_"
        for character in str(value or "")
    ).strip("._")
    return Path(resolved).name or "bug"
