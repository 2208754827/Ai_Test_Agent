"""Threat-intelligence provenance and applicability checks."""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from src.modes.security_testing_mode.campaign_state import ThreatIntelligenceRecord


logger = logging.getLogger("uvicorn.error.security_testing_mode.threat_intelligence")


class SecurityThreatIntelligenceService:
    """Normalize research into non-executable, provenance-preserving records."""

    _SOURCE_CONFIDENCE = {
        "vendor": "high",
        "cve": "high",
        "cisa": "high",
        "owasp": "high",
        "cwe": "high",
        "capec": "high",
        "mitre": "high",
        "research": "medium",
        "community": "unverified",
        "post": "unverified",
        "poc": "unverified",
    }

    def normalize(self, item: dict[str, Any]) -> ThreatIntelligenceRecord:
        source_url = str(item.get("source_url") or "").strip()
        source_type = str(item.get("source_type") or "community").strip().lower()
        canonical = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
        record = ThreatIntelligenceRecord(
            intelligence_id=str(item.get("intelligence_id") or f"intel_{uuid4().hex[:12]}"),
            source_url=source_url,
            source_type=source_type,
            title=str(item.get("title") or source_url or "Untitled security intelligence"),
            published_at=str(item.get("published_at") or ""),
            retrieved_at=str(item.get("retrieved_at") or datetime.now(timezone.utc).isoformat()),
            content_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            applicable_products=self._string_list(item.get("applicable_products")),
            applicable_versions=self._string_list(item.get("applicable_versions")),
            prerequisites=self._string_list(item.get("prerequisites")),
            cve_ids=self._string_list(item.get("cve_ids")),
            cwe_ids=self._string_list(item.get("cwe_ids")),
            confidence=self._SOURCE_CONFIDENCE.get(source_type, "unverified"),
            validation_status="pending",
            evidence_ids=self._string_list(item.get("evidence_ids")),
        )
        logger.info(
            "security.threat_intelligence.normalized %s",
            json.dumps(
                {
                    "intelligence_id": record.intelligence_id,
                    "source_host": urlparse(source_url).hostname or "",
                    "source_type": record.source_type,
                    "confidence": record.confidence,
                },
                separators=(",", ":"),
            ),
        )
        return record

    def match(
        self,
        record: ThreatIntelligenceRecord,
        *,
        product: str,
        version: str = "",
    ) -> ThreatIntelligenceRecord:
        product_match = not record.applicable_products or any(
            candidate.lower() in product.lower() or product.lower() in candidate.lower()
            for candidate in record.applicable_products
            if candidate
        )
        version_match = not record.applicable_versions or (
            bool(version) and version in record.applicable_versions
        )
        record.validation_status = "matched" if product_match and version_match else "rejected"
        logger.info(
            "security.threat_intelligence.matched %s",
            json.dumps(
                {
                    "intelligence_id": record.intelligence_id,
                    "product_match": product_match,
                    "version_match": version_match,
                    "validation_status": record.validation_status,
                },
                separators=(",", ":"),
            ),
        )
        return record

    def may_generate_executable_attempt(self, record: ThreatIntelligenceRecord) -> bool:
        return record.validation_status == "lab_verified" and bool(record.evidence_ids)

    def _string_list(self, value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return list(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))


__all__ = ["SecurityThreatIntelligenceService"]
