"""Evidence-backed scenario analysis for Security Testing Mode."""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from src.modes.security_testing_mode.campaign_state import (
    AssetNode,
    ScenarioFact,
    SecurityScenarioProfile,
    SecurityTestingRequestState,
    TargetCandidate,
    ThreatHypothesis,
)


logger = logging.getLogger("uvicorn.error.security_testing_mode.scenario_analysis")


class SecurityScenarioAnalysisService:
    """Build a conservative scenario model before executable task planning."""

    _PRODUCT_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("admin", ("admin", "management", "dashboard", "后台", "管理端")),
        ("ecommerce", ("shop", "store", "cart", "checkout", "order", "商城", "电商", "订单")),
        ("payment", ("payment", "pay", "billing", "支付", "账单")),
        ("ai", ("ai agent", "chatbot", "llm", "large language model", "prompt injection", "智能体", "大模型")),
        ("api", ("/api", "swagger", "openapi", "graphql", "接口")),
        ("content", ("blog", "cms", "article", "content", "内容")),
    )
    _OBSERVED_PRODUCT_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("admin", ("xxl-job", "admin", "management", "dashboard", "任务调度平台", "管理端")),
        ("ecommerce", ("shop", "storefront", "cart", "checkout", "商城", "电商")),
        ("payment", ("payment", "billing", "支付", "账单")),
        ("ai", ("chatbot", "llm", "large language model", "openai", "智能体", "大模型")),
        ("api", ("swagger", "openapi", "graphql", "api documentation", "接口文档")),
        ("content", ("wordpress", "blog", "cms", "article", "内容管理")),
    )

    def analyze(
        self,
        *,
        request: SecurityTestingRequestState,
        targets: list[TargetCandidate],
        assets: list[AssetNode],
        analyst_payload: dict[str, Any] | None = None,
        planner_payload: dict[str, Any] | None = None,
    ) -> tuple[SecurityScenarioProfile, list[ThreatHypothesis]]:
        target = targets[0].value if targets else ""
        scenario_id = f"scenario_{uuid4().hex[:12]}"
        product_type = self._infer_product_type(request, target, assets)
        facts = self._base_facts(request, targets, assets)
        profile = SecurityScenarioProfile(
            scenario_id=scenario_id,
            target=target,
            product_type=product_type,
            business_capabilities=self._business_capabilities(product_type),
            technologies=self._asset_technologies(assets),
            entry_points=self._entry_points(target, product_type),
            auth_flows=self._auth_flows(request, product_type),
            roles=self._roles(product_type),
            sensitive_data_types=self._sensitive_data(product_type),
            trust_boundaries=self._trust_boundaries(product_type),
            facts=facts,
            assumptions=self._assumptions(product_type),
            unknowns=self._unknowns(request, assets),
            confidence=self._profile_confidence(facts),
            analyzed_at=datetime.now(timezone.utc).isoformat(),
        )
        self._merge_analyst_payload(profile, analyst_payload or {})
        threats = self._build_threats(profile)
        self._merge_planner_payload(profile, threats, planner_payload or {})
        logger.info(
            "security.scenario.analyzed %s",
            json.dumps(
                {
                    "scenario_id": profile.scenario_id,
                    "target": profile.target,
                    "product_type": profile.product_type,
                    "fact_count": len(profile.facts),
                    "assumption_count": len(profile.assumptions),
                    "unknown_count": len(profile.unknowns),
                    "confidence": profile.confidence,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        )
        for threat in threats:
            logger.info(
                "security.threat_hypothesis.created %s",
                json.dumps(
                    {
                        "scenario_id": profile.scenario_id,
                        "threat_id": threat.threat_id,
                        "technique": threat.technique,
                        "priority": threat.priority,
                        "confidence": threat.confidence,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            )
        return profile, threats

    def _infer_product_type(
        self,
        request: SecurityTestingRequestState,
        target: str,
        assets: list[AssetNode],
    ) -> str:
        observed_values: list[str] = []
        for asset in assets:
            observed_values.extend(
                [
                    str(asset.service_name or ""),
                    str(asset.service_version or ""),
                    str(asset.notes or ""),
                    *(str(item) for item in asset.technologies),
                ]
            )
        observed = " ".join(observed_values).lower()
        for product_type, hints in self._OBSERVED_PRODUCT_HINTS:
            if any(self._contains_hint(observed, hint) for hint in hints):
                return product_type

        target_haystack = target.lower()
        for product_type, hints in self._PRODUCT_HINTS:
            if any(self._contains_hint(target_haystack, hint) for hint in hints):
                return product_type

        request_haystack = " ".join([request.objective, request.raw_message, *request.focus_areas]).lower()
        for product_type, hints in self._PRODUCT_HINTS:
            if any(self._contains_unnegated_hint(request_haystack, hint) for hint in hints):
                return product_type
        return "web" if target.lower().startswith(("http://", "https://")) else "network_service"

    def _contains_hint(self, haystack: str, hint: str) -> bool:
        if not haystack or not hint:
            return False
        normalized_hint = hint.lower()
        if any(ord(character) > 127 for character in normalized_hint) or "/" in normalized_hint:
            return normalized_hint in haystack
        return re.search(rf"(?<![a-z0-9]){re.escape(normalized_hint)}(?![a-z0-9])", haystack) is not None

    def _contains_unnegated_hint(self, haystack: str, hint: str) -> bool:
        if not haystack or not hint:
            return False
        for start, end in self._hint_spans(haystack, hint):
            if not self._hint_is_negated(haystack, start, end):
                return True
        return False

    def _hint_spans(self, haystack: str, hint: str) -> list[tuple[int, int]]:
        normalized_hint = hint.lower()
        if any(ord(character) > 127 for character in normalized_hint) or "/" in normalized_hint:
            return [
                (match.start(), match.end())
                for match in re.finditer(re.escape(normalized_hint), haystack)
            ]
        return [
            (match.start(), match.end())
            for match in re.finditer(rf"(?<![a-z0-9]){re.escape(normalized_hint)}(?![a-z0-9])", haystack)
        ]

    def _hint_is_negated(self, haystack: str, start: int, end: int) -> bool:
        prefix = haystack[max(0, start - 48) : start]
        suffix = haystack[end : min(len(haystack), end + 24)]
        negation_markers = (
            "do not assume",
            "don't assume",
            "not assume",
            "not to assume",
            "avoid assuming",
            "without assuming",
            "do not use",
            "don't use",
            "not use",
            "do not apply",
            "don't apply",
            "not apply",
            "do not reuse",
            "don't reuse",
            "not reuse",
            "not ",
            "no ",
            "不要假设",
            "不能假设",
            "不应假设",
            "无需假设",
            "别假设",
            "不要套用",
            "不能套用",
            "不应套用",
            "不得套用",
            "不套用",
            "不要沿用",
            "不能沿用",
            "不应沿用",
            "不得沿用",
            "不沿用",
            "不要复用",
            "不能复用",
            "不应复用",
            "不得复用",
            "不复用",
            "不等同",
            "不代表",
            "不是",
            "并非",
            "非",
            "勿",
        )
        negative_before = any(marker in prefix for marker in negation_markers)
        negative_after = any(marker in suffix for marker in ("is not", "不是", "并非", "不等同", "不代表"))
        return negative_before or negative_after

    def _base_facts(
        self,
        request: SecurityTestingRequestState,
        targets: list[TargetCandidate],
        assets: list[AssetNode],
    ) -> list[ScenarioFact]:
        facts: list[ScenarioFact] = []
        for target in targets:
            facts.append(
                ScenarioFact(
                    fact_id=f"fact_target_{len(facts) + 1}",
                    statement=f"Authorized target supplied as {target.target_type}: {target.value}",
                    source_type="user_declared",
                    confidence=1.0,
                )
            )
        if request.auth_hint:
            facts.append(
                ScenarioFact(
                    fact_id=f"fact_auth_{len(facts) + 1}",
                    statement=f"Authentication context supplied by the user: {request.auth_hint}",
                    source_type="user_declared",
                    confidence=1.0,
                )
            )
        for asset in assets:
            exposure = f"{asset.asset_type} at {asset.address or 'an unspecified address'}"
            if asset.port is not None:
                exposure += f":{asset.port}"
            if asset.service_name:
                exposure += f" ({asset.service_name})"
            facts.append(
                ScenarioFact(
                    fact_id=f"fact_asset_{len(facts) + 1}",
                    statement=(
                        f"Observed service exposure: {exposure} over "
                        f"{asset.protocol or 'an unknown protocol'}."
                    ),
                    source_type="observed",
                    evidence_ids=[asset.discovered_by] if asset.discovered_by else [],
                    confidence=asset.confidence,
                )
            )
            technologies = self._unique([str(item).strip() for item in asset.technologies])
            if technologies:
                facts.append(
                    ScenarioFact(
                        fact_id=f"fact_technology_{len(facts) + 1}",
                        statement=f"Observed web fingerprint: {', '.join(technologies[:12])}",
                        source_type="observed",
                        evidence_ids=[asset.discovered_by] if asset.discovered_by else [],
                        confidence=max(0.6, asset.confidence),
                    )
                )
        return facts

    def _merge_analyst_payload(self, profile: SecurityScenarioProfile, payload: dict[str, Any]) -> None:
        for field in (
            "business_capabilities",
            "technologies",
            "entry_points",
            "auth_flows",
            "roles",
            "sensitive_data_types",
            "trust_boundaries",
            "external_dependencies",
            "assumptions",
            "unknowns",
        ):
            values = payload.get(field)
            if isinstance(values, list):
                current = getattr(profile, field)
                setattr(profile, field, self._unique([*current, *(str(item).strip() for item in values)]))
        model_facts = payload.get("facts")
        if isinstance(model_facts, list):
            for item in model_facts:
                if not isinstance(item, dict) or not str(item.get("statement") or "").strip():
                    continue
                source_type = str(item.get("source_type") or "model_inference")
                if source_type not in {"observed", "user_declared", "model_inference"}:
                    source_type = "model_inference"
                # A model cannot promote its own statement to an observed fact without evidence.
                evidence_ids = self._string_list(item.get("evidence_ids"))
                if source_type == "observed" and not evidence_ids:
                    source_type = "model_inference"
                profile.facts.append(
                    ScenarioFact(
                        fact_id=str(item.get("fact_id") or f"fact_model_{len(profile.facts) + 1}"),
                        statement=str(item.get("statement") or "").strip(),
                        source_type=source_type,
                        evidence_ids=evidence_ids,
                        confidence=min(0.85, max(0.0, float(item.get("confidence") or 0.5))),
                    )
                )

    def _merge_planner_payload(
        self,
        profile: SecurityScenarioProfile,
        threats: list[ThreatHypothesis],
        payload: dict[str, Any],
    ) -> None:
        raw_threats = payload.get("threat_hypotheses") or payload.get("threats")
        if not isinstance(raw_threats, list):
            return
        known_fact_ids = {fact.fact_id for fact in profile.facts}
        for item in raw_threats:
            if not isinstance(item, dict) or not str(item.get("technique") or "").strip():
                continue
            fact_ids = [fact_id for fact_id in self._string_list(item.get("supporting_fact_ids")) if fact_id in known_fact_ids]
            attack_references = self._validated_attack_references(
                profile,
                self._string_list(item.get("attack_references")),
            )
            threats.append(
                ThreatHypothesis(
                    threat_id=str(item.get("threat_id") or f"threat_model_{len(threats) + 1}"),
                    scenario_id=profile.scenario_id,
                    asset_id=str(item.get("asset_id") or ""),
                    actor=str(item.get("actor") or "unauthenticated"),
                    entry_point=str(item.get("entry_point") or ""),
                    trust_boundary=str(item.get("trust_boundary") or ""),
                    technique=str(item.get("technique") or "").strip(),
                    cwe_ids=self._string_list(item.get("cwe_ids")),
                    owasp_categories=self._string_list(item.get("owasp_categories")),
                    attack_references=attack_references,
                    expected_impact=self._string_list(item.get("expected_impact")),
                    supporting_fact_ids=fact_ids,
                    assumptions=self._string_list(item.get("assumptions")),
                    priority=self._priority(item.get("priority")),
                    confidence=min(0.85, max(0.0, float(item.get("confidence") or 0.5))),
                )
            )

    def _build_threats(self, profile: SecurityScenarioProfile) -> list[ThreatHypothesis]:
        fact_ids = [fact.fact_id for fact in profile.facts]
        common = [
            ("HTTP security control validation", "CWE-693", "A05:2021-Security Misconfiguration", 70),
            ("Technology and exposed-service fingerprint validation", "CWE-200", "A01:2021-Broken Access Control", 60),
        ]
        specific: dict[str, list[tuple[str, str, str, int]]] = {
            "admin": [("Administrative authentication and authorization boundary review", "CWE-862", "A01:2021-Broken Access Control", 95)],
            "ecommerce": [("Cart, order, and checkout workflow authorization review", "CWE-639", "A01:2021-Broken Access Control", 95)],
            "payment": [("Payment state and transaction-integrity boundary review", "CWE-841", "A04:2021-Insecure Design", 100)],
            "api": [("API object-level authorization and schema exposure review", "CWE-639", "API1:2023-Broken Object Level Authorization", 95)],
            "ai": [("Prompt, tool, and data trust-boundary review", "CWE-74", "LLM01:2025-Prompt Injection", 90)],
        }
        rows = [*specific.get(profile.product_type, []), *common]
        return [
            ThreatHypothesis(
                threat_id=f"threat_{profile.scenario_id}_{index}",
                scenario_id=profile.scenario_id,
                actor="unauthenticated",
                entry_point=profile.entry_points[0] if profile.entry_points else profile.target,
                trust_boundary=profile.trust_boundaries[0] if profile.trust_boundaries else "client-to-target",
                technique=technique,
                cwe_ids=[cwe],
                owasp_categories=[owasp],
                expected_impact=self._sensitive_data(profile.product_type),
                supporting_fact_ids=fact_ids,
                assumptions=list(profile.assumptions),
                priority=priority,
                confidence=min(0.9, profile.confidence),
            )
            for index, (technique, cwe, owasp, priority) in enumerate(rows, start=1)
        ]

    def _business_capabilities(self, product_type: str) -> list[str]:
        return {
            "admin": ["administration", "privileged configuration"],
            "ecommerce": ["catalog browsing", "cart", "order processing", "checkout"],
            "payment": ["payment processing", "billing"],
            "api": ["machine-to-machine API"],
            "ai": ["model interaction", "agent tool execution"],
            "content": ["content publishing"],
        }.get(product_type, ["web application access"])

    def _roles(self, product_type: str) -> list[str]:
        return {
            "admin": ["anonymous", "operator", "administrator"],
            "ecommerce": ["anonymous", "customer", "support", "administrator"],
            "payment": ["customer", "merchant", "finance operator"],
            "api": ["anonymous client", "authenticated client", "service account"],
            "ai": ["user", "agent", "tool service", "administrator"],
        }.get(product_type, ["anonymous", "authenticated user"])

    def _sensitive_data(self, product_type: str) -> list[str]:
        return {
            "admin": ["privileged configuration", "user records"],
            "ecommerce": ["customer PII", "orders", "payment references"],
            "payment": ["transaction records", "payment references", "billing PII"],
            "api": ["API data objects", "access tokens"],
            "ai": ["prompts", "model context", "tool credentials"],
        }.get(product_type, ["session identifiers", "application data"])

    def _trust_boundaries(self, product_type: str) -> list[str]:
        boundaries = ["untrusted client to application"]
        if product_type in {"admin", "ecommerce", "payment", "api", "ai"}:
            boundaries.append("authenticated identity to protected business operations")
        if product_type in {"payment", "ai"}:
            boundaries.append("application to external privileged dependency")
        return boundaries

    def _entry_points(self, target: str, product_type: str) -> list[str]:
        values = [target] if target else []
        if product_type == "api" and target:
            values.extend([f"{target.rstrip('/')}/openapi.json", f"{target.rstrip('/')}/swagger"])
        return self._unique(values)

    def _auth_flows(self, request: SecurityTestingRequestState, product_type: str) -> list[str]:
        if request.auth_hint:
            return [request.auth_hint]
        if product_type in {"admin", "ecommerce", "payment", "api", "ai"}:
            return ["Authentication likely required for protected operations; mechanism is unknown."]
        return []

    def _assumptions(self, product_type: str) -> list[str]:
        if product_type in {"admin", "ecommerce", "payment", "api", "ai"}:
            return [f"Product type '{product_type}' is inferred from the request or URL and requires runtime confirmation."]
        return ["Business purpose is not yet confirmed by authenticated or source-code evidence."]

    def _unknowns(self, request: SecurityTestingRequestState, assets: list[AssetNode]) -> list[str]:
        unknowns = ["Exact framework and component versions", "Server-side authorization rules"]
        if not request.auth_hint:
            unknowns.append("Authentication mechanism and available test roles")
        if not any(asset.technologies for asset in assets):
            unknowns.append("Observed technology fingerprint")
        return unknowns

    def _asset_technologies(self, assets: list[AssetNode]) -> list[str]:
        return self._unique([str(item) for asset in assets for item in asset.technologies])

    def _profile_confidence(self, facts: list[ScenarioFact]) -> float:
        if not facts:
            return 0.1
        return round(min(0.8, sum(fact.confidence for fact in facts) / len(facts)), 2)

    def _string_list(self, value: Any) -> list[str]:
        if isinstance(value, str):
            return [value.strip()] if value.strip() else []
        if not isinstance(value, list):
            return []
        return self._unique([str(item).strip() for item in value])

    def _priority(self, value: Any) -> int:
        if isinstance(value, str) and not value.strip().isdigit():
            return {
                "critical": 100,
                "p0": 100,
                "high": 80,
                "p1": 80,
                "medium": 50,
                "p2": 50,
                "low": 20,
                "p3": 20,
                "info": 10,
                "p4": 10,
            }.get(
                value.strip().lower(), 50
            )
        try:
            return max(0, min(100, int(value or 50)))
        except (TypeError, ValueError):
            return 50

    def _validated_attack_references(
        self,
        profile: SecurityScenarioProfile,
        references: list[str],
    ) -> list[str]:
        trusted_fact_text = " ".join(
            fact.statement.lower()
            for fact in profile.facts
            if fact.source_type in {"observed", "user_declared"}
        )
        accepted: list[str] = []
        standards = (
            "owasp",
            "cwe-",
            "capec-",
            "mitre att&ck",
            "mitre attack",
            "asvs",
            "api security top 10",
            "llm top 10",
        )
        for reference in references:
            normalized = reference.strip().lower()
            cve_ids = re.findall(r"cve-\d{4}-\d{4,}", normalized)
            if cve_ids and not all(cve_id in trusted_fact_text for cve_id in cve_ids):
                logger.warning(
                    "security.threat_reference.rejected %s",
                    json.dumps(
                        {
                            "scenario_id": profile.scenario_id,
                            "reference": reference,
                            "reason": "cve_not_supported_by_observed_or_user_declared_fact",
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                )
                continue
            if cve_ids or normalized.startswith(standards):
                accepted.append(reference)
                continue
            logger.warning(
                "security.threat_reference.rejected %s",
                json.dumps(
                    {
                        "scenario_id": profile.scenario_id,
                        "reference": reference,
                        "reason": "unverified_external_reference",
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            )
        return self._unique(accepted)

    def _unique(self, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value for value in values if value))


def extract_json_object(text: str) -> dict[str, Any]:
    """Extract one JSON object from a specialist response without eval."""
    content = str(text or "").strip()
    if not content:
        return {}
    candidates = [content]
    candidates.extend(
        match.group(1).strip()
        for match in re.finditer(
            r"```(?:json)?\s*([\s\S]*?)```",
            content,
            flags=re.IGNORECASE,
        )
    )
    decoder = json.JSONDecoder()
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            parsed = None
            for index, character in enumerate(candidate):
                if character != "{":
                    continue
                try:
                    parsed, _ = decoder.raw_decode(candidate[index:])
                    break
                except json.JSONDecodeError:
                    continue
        if isinstance(parsed, dict):
            return parsed
    return {}


__all__ = ["SecurityScenarioAnalysisService", "extract_json_object"]
