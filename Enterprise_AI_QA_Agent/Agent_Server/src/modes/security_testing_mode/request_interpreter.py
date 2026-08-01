"""Request interpretation for Security Testing Mode."""
from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from src.modes.security_testing_mode.campaign_state import (
    SecurityTestingRequestState,
    TargetCandidate,
)
from src.modes.security_testing_mode.contracts import REQUEST_CONTEXT_KEY


class SecurityRequestInterpreter:
    """Build structured request and target objects from user/context input."""

    _EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", flags=re.IGNORECASE)
    _PROTECTED_PLATFORM_HINTS: tuple[tuple[str, str, str], ...] = (
        (
            "tryhackme.com",
            "TryHackMe",
            "This target is hosted on TryHackMe and often requires an authenticated account or room access. "
            "Limit the run to the public unauthenticated surface and report coverage as restricted when access is missing.",
        ),
        (
            "hackthebox.com",
            "Hack The Box",
            "This target is hosted on Hack The Box and often requires an authenticated account, enrollment, or lab launch. "
            "Limit the run to the public unauthenticated surface and report coverage as restricted when access is missing.",
        ),
    )

    def interpret(self, arguments: dict[str, Any], context: Any) -> SecurityTestingRequestState:
        bundle = getattr(context, "context_bundle", None) or {}
        mode_request = bundle.get(REQUEST_CONTEXT_KEY) or {}
        if not isinstance(mode_request, dict):
            mode_request = {}

        user_message = str(getattr(context, "user_message", "") or "")
        target = self._clean_target_value(arguments.get("target") or mode_request.get("target"))
        target_url = self._clean_target_value(arguments.get("target_url") or mode_request.get("target_url"))
        target_host = self._clean_target_value(arguments.get("target_host") or mode_request.get("target_host"))
        target_network = self._clean_target_value(arguments.get("target_network") or mode_request.get("target_network"))
        if target and not any([target_url, target_host, target_network]):
            inferred = self.build_target(target)
            if inferred.target_type == "url":
                target_url = target
            elif inferred.target_type == "network":
                target_network = target
            else:
                target_host = target

        recipients = self.to_string_list(arguments.get("report_recipients") or mode_request.get("report_recipients"))
        if not recipients:
            recipients = self.extract_emails_from_text(user_message)

        explicit_risk = str(arguments.get("risk_tolerance") or mode_request.get("risk_tolerance") or "").strip()
        risk_tolerance = explicit_risk or self.infer_risk_tolerance(user_message)
        primary_target = target_url or target_host or target_network or target or self.extract_target_from_text(user_message)
        platform_label, access_constraints = self.infer_access_constraints(primary_target)
        target_fingerprint = self.build_target_fingerprint(primary_target)

        return SecurityTestingRequestState(
            objective=str(arguments.get("objective") or mode_request.get("objective") or user_message).strip(),
            target_url=target_url,
            target_host=target_host,
            target_network=target_network,
            target_type=str(arguments.get("target_type") or mode_request.get("target_type") or "").strip(),
            scope_preference=str(arguments.get("scope_preference") or mode_request.get("scope_preference") or "limited").strip(),
            auth_hint=str(arguments.get("auth_hint") or mode_request.get("auth_hint") or "").strip(),
            credentials=dict(arguments.get("credentials") or mode_request.get("credentials") or {}),
            focus_areas=self.to_string_list(arguments.get("focus_areas") or mode_request.get("focus_areas")),
            excluded_areas=self.to_string_list(arguments.get("excluded_areas") or mode_request.get("excluded_areas")),
            risk_tolerance=risk_tolerance,
            target_fingerprint=target_fingerprint,
            platform_label=platform_label,
            access_constraints=access_constraints,
            report_recipients=recipients,
            raw_message=user_message,
        )

    def resolve_primary_target(self, request: SecurityTestingRequestState) -> TargetCandidate | None:
        target_value = (
            request.target_url
            or request.target_host
            or request.target_network
            or self.extract_target_from_text(request.raw_message)
        ).strip()
        if not target_value:
            return None
        target = self.build_target(target_value)
        if request.platform_label and request.access_constraints and not target.notes:
            target.notes = " ".join(request.access_constraints)
        if request.target_fingerprint and not target.fingerprint:
            target.fingerprint = request.target_fingerprint
        return target

    def build_target(self, value: str) -> TargetCandidate:
        value = self._clean_target_value(value)
        if re.match(r"^https?://", value, flags=re.IGNORECASE):
            parsed = urlparse(value)
            return TargetCandidate(
                target_id=f"target_{uuid4().hex[:8]}",
                target_type="url",
                value=value.rstrip("/"),
                label=parsed.hostname or value,
                fingerprint=self.build_target_fingerprint(value),
                resolved_domain=parsed.hostname or "",
                port=parsed.port,
                protocol=parsed.scheme,
            )
        if "/" in value and re.match(r"^[0-9a-fA-F:.]+/\d{1,3}$", value):
            return TargetCandidate(
                target_id=f"target_{uuid4().hex[:8]}",
                target_type="network",
                value=value,
                label=value,
                fingerprint=self.build_target_fingerprint(value),
            )
        return TargetCandidate(
            target_id=f"target_{uuid4().hex[:8]}",
            target_type="host",
            value=value,
            label=value,
            fingerprint=self.build_target_fingerprint(value),
            resolved_domain=value if not re.match(r"^\d+\.\d+\.\d+\.\d+$", value) else "",
        )

    def extract_target_from_text(self, text: str) -> str:
        for pattern in (
            r"https?://[^\s,;]+",
            r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b",
            r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        ):
            match = re.search(pattern, text or "")
            if match:
                return match.group(0).rstrip(".,;)")
        return ""

    def _clean_target_value(self, value: Any) -> str:
        return str(value or "").strip().rstrip(".,;:!?，。；：！？)]}")

    def to_string_list(self, value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str) and value.strip():
            return [item.strip() for item in value.split(",") if item.strip()]
        return []

    def extract_emails_from_text(self, text: str) -> list[str]:
        matches = self._EMAIL_PATTERN.findall(text or "")
        seen: set[str] = set()
        recipients: list[str] = []
        for match in matches:
            value = match.strip()
            if not value or value in seen:
                continue
            seen.add(value)
            recipients.append(value)
        return recipients

    def infer_risk_tolerance(self, text: str) -> str:
        normalized = (text or "").lower()
        if any(token in normalized for token in ("low-risk", "low risk", "smoke test", "smoke", "低风险")):
            return "low"
        if any(token in normalized for token in ("high-risk", "high risk", "aggressive", "高风险")):
            return "high"
        return "medium"

    def infer_access_constraints(self, target_value: str) -> tuple[str, list[str]]:
        value = str(target_value or "").strip().lower()
        if not value:
            return "", []
        for host_hint, platform_label, constraint in self._PROTECTED_PLATFORM_HINTS:
            if host_hint in value:
                return platform_label, [constraint]
        return "", []

    def build_target_fingerprint(self, target_value: str) -> str:
        normalized = self._normalize_target_value(target_value)
        if not normalized:
            return ""
        digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()
        return f"target-{digest[:16]}"

    def _normalize_target_value(self, value: str) -> str:
        target = str(value or "").strip()
        if not target:
            return ""
        if re.match(r"^https?://", target, flags=re.IGNORECASE):
            parsed = urlparse(target)
            scheme = (parsed.scheme or "http").lower()
            hostname = (parsed.hostname or "").lower()
            port = parsed.port
            path = (parsed.path or "").rstrip("/")
            if path == "/":
                path = ""
            port_suffix = ""
            if port is not None and not (
                (scheme == "http" and port == 80)
                or (scheme == "https" and port == 443)
            ):
                port_suffix = f":{port}"
            return f"{scheme}://{hostname}{port_suffix}{path}"
        return target.rstrip("/").lower()


__all__ = ["SecurityRequestInterpreter"]
