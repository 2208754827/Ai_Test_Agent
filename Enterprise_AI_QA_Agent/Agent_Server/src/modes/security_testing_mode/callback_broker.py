"""Loopback-only callback leases for authorized P3 verification.

This broker is deliberately not a C2 channel: it records a bounded HTTP
callback observation and releases its listener at campaign cleanup.
"""
from __future__ import annotations

import asyncio
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from src.modes.security_testing_mode.campaign_state import CallbackLeaseState


class SecurityCallbackBroker:
    """Allocate local callback ports and retain only minimal callback metadata."""

    def __init__(
        self,
        *,
        port_range: str = "28000-28100",
        lease_timeout_seconds: float = 300.0,
    ) -> None:
        self._port_start, self._port_end = self._parse_port_range(port_range)
        self._lease_timeout_seconds = max(5.0, min(float(lease_timeout_seconds or 300), 3600.0))
        self._servers: dict[str, asyncio.AbstractServer] = {}
        self._leases: dict[str, CallbackLeaseState] = {}
        self._lock = asyncio.Lock()

    async def lease(
        self,
        *,
        campaign_id: str,
        target: str,
        approval_scope_hash: str,
        protocol: str = "http",
    ) -> CallbackLeaseState:
        if not str(campaign_id or "").strip() or not str(target or "").strip():
            raise ValueError("Callback lease requires campaign_id and authorized target.")
        if not str(approval_scope_hash or "").strip():
            raise ValueError("Callback lease requires an authorization scope hash.")
        if str(protocol or "").lower() != "http":
            raise ValueError("Only bounded loopback HTTP callbacks are supported.")

        async with self._lock:
            now = _utc_now()
            lease_id = f"callback_{uuid4().hex[:20]}"
            for port in range(self._port_start, self._port_end + 1):
                lease = CallbackLeaseState(
                    lease_id=lease_id,
                    campaign_id=str(campaign_id).strip(),
                    target=str(target).strip(),
                    protocol="http",
                    port=port,
                    callback_url=f"http://127.0.0.1:{port}/callback/{lease_id}",
                    approval_scope_hash=str(approval_scope_hash).strip(),
                    status="active",
                    created_at=now.isoformat(),
                    expires_at=(now + timedelta(seconds=self._lease_timeout_seconds)).isoformat(),
                )
                try:
                    server = await asyncio.start_server(
                        lambda reader, writer, active_lease_id=lease_id: self._handle_callback(
                            active_lease_id, reader, writer
                        ),
                        host="127.0.0.1",
                        port=port,
                    )
                except OSError:
                    continue
                self._servers[lease_id] = server
                self._leases[lease_id] = lease
                return lease.model_copy(deep=True)
        raise RuntimeError(
            f"No callback port available in configured range {self._port_start}-{self._port_end}."
        )

    async def release(self, lease_id: str, *, reason: str = "completed") -> CallbackLeaseState:
        normalized = str(lease_id or "").strip()
        async with self._lock:
            lease = self._leases.get(normalized)
            if lease is None:
                raise KeyError(f"Unknown callback lease: {normalized}")
            server = self._servers.pop(normalized, None)
            if server is not None:
                server.close()
                await server.wait_closed()
            lease.status = "released"
            lease.release_reason = str(reason or "completed")[:160]
            lease.released_at = _utc_now().isoformat()
            lease.cleanup_complete = True
            return lease.model_copy(deep=True)

    async def release_campaign(self, campaign_id: str, *, reason: str = "campaign_cleanup") -> list[CallbackLeaseState]:
        lease_ids = [
            lease_id
            for lease_id, lease in self._leases.items()
            if lease.campaign_id == str(campaign_id or "").strip() and lease.status == "active"
        ]
        return [await self.release(lease_id, reason=reason) for lease_id in lease_ids]

    def get(self, lease_id: str) -> CallbackLeaseState | None:
        lease = self._leases.get(str(lease_id or "").strip())
        return lease.model_copy(deep=True) if lease else None

    async def close(self) -> None:
        for lease_id in list(self._servers):
            await self.release(lease_id, reason="broker_closed")

    async def _handle_callback(
        self,
        lease_id: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        source = str(peer[0]) if isinstance(peer, tuple) and peer else ""
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3.0)
            request_line = raw.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            path = request_line.split(" ", 2)[1] if " " in request_line else ""
            lease = self._leases.get(lease_id)
            expected_path = f"/callback/{lease_id}"
            if lease is None or lease.status != "active" or path != expected_path:
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            if source and _is_loopback(source) and source not in lease.callback_sources:
                lease.callback_sources.append(source)
            lease.callback_count += 1
            writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            return
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    @staticmethod
    def _parse_port_range(value: str) -> tuple[int, int]:
        text = str(value or "").strip()
        try:
            start_text, end_text = text.split("-", 1)
            start, end = int(start_text), int(end_text)
        except (TypeError, ValueError):
            raise ValueError("Callback port range must use start-end format.") from None
        if not (1024 <= start <= end <= 65535) or end - start > 500:
            raise ValueError("Callback port range must be between 1024-65535 and at most 501 ports.")
        return start, end


def _is_loopback(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


__all__ = ["SecurityCallbackBroker"]
