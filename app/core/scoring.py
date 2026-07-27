from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any
import hashlib
import json

import yaml

ACTIVE_STATUSES = {"OPEN", "IN_PROGRESS"}
RESOLVED_STATUSES = {"MITIGATED", "RISK_ACCEPTED", "CLOSED"}
ALLOWED_STATUSES = ACTIVE_STATUSES | RESOLVED_STATUSES


class StrictPolicyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects aliases and duplicate mapping keys."""

    def compose_node(self, parent, index):  # type: ignore[override]
        if self.check_event(yaml.AliasEvent):
            raise ValueError("정책 YAML에서는 alias(*)를 사용할 수 없습니다.")
        return super().compose_node(parent, index)


def _construct_unique_mapping(loader: StrictPolicyLoader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"정책 YAML에 중복 키가 있습니다: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictPolicyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


@dataclass(frozen=True)
class PrioritizationResult:
    score: int
    threat_score: int
    asset_context_score: int
    remediation_urgency_score: int
    decision: str
    decision_label: str
    sla_days: int
    target_date: str
    reasons: list[str]
    mitigation_required: bool
    policy_version: str


REQUIRED_WEIGHTS = {
    "kev", "internet_exposed", "patch_available", "no_compensating_control",
    "overdue", "asset_criticality_per_level", "data_sensitivity_per_level",
}
REQUIRED_DECISIONS = {"immediate", "urgent_review", "scheduled", "monitor"}


def _strict_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field}은(는) true/false가 아닌 정수여야 합니다.")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field}은(는) 정수여야 합니다.") from exc


def _normalize_special_rules(policy: dict[str, Any]) -> None:
    rules = policy.get("special_rules") or {}
    if not isinstance(rules, dict):
        raise ValueError("special_rules는 객체여야 합니다.")

    immediate = rules.get("kev_and_internet_exposed", {"enabled": True, "decision": "immediate"})
    if isinstance(immediate, str):
        immediate = {"enabled": True, "decision": immediate}
    if not isinstance(immediate, dict):
        raise ValueError("special_rules.kev_and_internet_exposed 구조가 올바르지 않습니다.")
    enabled = immediate.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("special_rules.kev_and_internet_exposed.enabled는 true/false여야 합니다.")
    decision = str(immediate.get("decision") or "immediate").strip()
    if decision not in REQUIRED_DECISIONS:
        raise ValueError("special_rules.kev_and_internet_exposed.decision이 유효하지 않습니다.")

    mitigation = rules.get("mitigation_without_patch")
    if mitigation is None and rules.get("high_priority_without_patch") == "mitigation_required":
        mitigation = {"enabled": True, "min_score": 65, "include_kev": True}
    if mitigation is None:
        mitigation = {"enabled": True, "min_score": 65, "include_kev": True}
    if not isinstance(mitigation, dict):
        raise ValueError("special_rules.mitigation_without_patch 구조가 올바르지 않습니다.")
    mitigation_enabled = mitigation.get("enabled", True)
    include_kev = mitigation.get("include_kev", True)
    if not isinstance(mitigation_enabled, bool) or not isinstance(include_kev, bool):
        raise ValueError("완화조치 special rule의 enabled/include_kev는 true/false여야 합니다.")
    min_score = _strict_int(mitigation.get("min_score", 65), "special_rules.mitigation_without_patch.min_score")
    score_cap = _strict_int(policy.get("score_cap", 140), "score_cap")
    if not 0 <= min_score <= score_cap:
        raise ValueError("special_rules.mitigation_without_patch.min_score는 0~score_cap 범위여야 합니다.")

    policy["special_rules"] = {
        "kev_and_internet_exposed": {"enabled": enabled, "decision": decision},
        "mitigation_without_patch": {
            "enabled": mitigation_enabled, "min_score": min_score, "include_kev": include_kev,
        },
    }


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a prioritization policy before it can be used."""
    if not isinstance(policy, dict):
        raise ValueError("우선순위 정책은 YAML 객체여야 합니다.")
    version = str(policy.get("version") or "").strip()
    name = str(policy.get("name") or "").strip()
    if not version or len(version) > 80:
        raise ValueError("정책 version은 1~80자여야 합니다.")
    if not name or len(name) > 200:
        raise ValueError("정책 name은 1~200자여야 합니다.")
    score_cap = _strict_int(policy.get("score_cap", 140), "score_cap")
    if not 1 <= score_cap <= 1000:
        raise ValueError("score_cap은 1~1000 범위여야 합니다.")

    weights = policy.get("weights")
    if not isinstance(weights, dict) or not REQUIRED_WEIGHTS.issubset(weights):
        missing = sorted(REQUIRED_WEIGHTS - set(weights or {}))
        raise ValueError("weights 필수 항목 누락: " + ", ".join(missing))
    for key, value in weights.items():
        number = _strict_int(value, f"weights.{key}")
        if not 0 <= number <= 500:
            raise ValueError(f"weights.{key}는 0~500 범위여야 합니다.")

    discount = _strict_int(policy.get("compensating_control_discount", 0), "compensating_control_discount")
    if not 0 <= discount <= 500:
        raise ValueError("compensating_control_discount는 0~500 범위여야 합니다.")

    def validate_bands(key: str, upper: float) -> None:
        bands = policy.get(key)
        if not isinstance(bands, list) or not bands:
            raise ValueError(f"{key}는 비어 있지 않은 목록이어야 합니다.")
        mins: set[float] = set()
        has_zero = False
        for idx, band in enumerate(bands):
            if not isinstance(band, dict) or "min" not in band or "points" not in band:
                raise ValueError(f"{key}[{idx}]에는 min과 points가 필요합니다.")
            try:
                minimum = float(band["min"])
                points = _strict_int(band["points"], f"{key}[{idx}].points")
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{key}[{idx}] 값 형식이 올바르지 않습니다.") from exc
            if not 0 <= minimum <= upper:
                raise ValueError(f"{key}[{idx}].min은 0~{upper} 범위여야 합니다.")
            if not 0 <= points <= 500:
                raise ValueError(f"{key}[{idx}].points는 0~500 범위여야 합니다.")
            if minimum in mins:
                raise ValueError(f"{key}에 중복 min 값이 있습니다: {minimum}")
            mins.add(minimum)
            has_zero = has_zero or minimum == 0
        if not has_zero:
            raise ValueError(f"{key}에는 min: 0 기준 구간이 필요합니다.")

    validate_bands("cvss_bands", 10.0)
    validate_bands("epss_bands", 1.0)

    decisions = policy.get("decisions")
    if not isinstance(decisions, dict) or set(decisions) != REQUIRED_DECISIONS:
        raise ValueError("decisions는 immediate, urgent_review, scheduled, monitor를 모두 포함해야 합니다.")
    thresholds: dict[str, int] = {}
    for key, cfg in decisions.items():
        if not isinstance(cfg, dict):
            raise ValueError(f"decisions.{key} 구조가 올바르지 않습니다.")
        try:
            threshold = _strict_int(cfg["min_score"], f"decisions.{key}.min_score")
            sla_days = _strict_int(cfg["sla_days"], f"decisions.{key}.sla_days")
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"decisions.{key}에는 정수 min_score와 sla_days가 필요합니다.") from exc
        label = str(cfg.get("label") or "").strip()
        if not 0 <= threshold <= score_cap:
            raise ValueError(f"decisions.{key}.min_score는 0~score_cap 범위여야 합니다.")
        if not 0 <= sla_days <= 3650:
            raise ValueError(f"decisions.{key}.sla_days는 0~3650 범위여야 합니다.")
        if not label or len(label) > 100:
            raise ValueError(f"decisions.{key}.label은 1~100자여야 합니다.")
        thresholds[key] = threshold
    if thresholds["monitor"] != 0:
        raise ValueError("decisions.monitor.min_score는 0이어야 합니다.")
    if not (thresholds["immediate"] > thresholds["urgent_review"] > thresholds["scheduled"] > thresholds["monitor"]):
        raise ValueError("의사결정 임계값은 immediate > urgent_review > scheduled > monitor 순이어야 합니다.")
    _normalize_special_rules(policy)
    return policy


def parse_policy_text(text: str) -> dict[str, Any]:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("정책 YAML이 비어 있습니다.")
    if len(text.encode("utf-8")) > 256 * 1024:
        raise ValueError("정책 YAML은 최대 256KB입니다.")
    try:
        policy = yaml.load(text, Loader=StrictPolicyLoader)
    except (yaml.YAMLError, ValueError) as exc:
        raise ValueError(f"정책 YAML 구문 오류: {exc}") from exc
    return validate_policy(policy)


def policy_digest(policy: dict[str, Any]) -> str:
    canonical = json.dumps(policy, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_policy(path: str | Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_policy_text(fh.read())


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "y", "예", "포함", "있음"}


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int = 1) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _band_points(value: float, bands: list[dict[str, Any]]) -> int:
    for band in sorted(bands, key=lambda item: float(item["min"]), reverse=True):
        if value >= float(band["min"]):
            return int(band["points"])
    return 0


def parse_date(value: Any) -> date | None:
    if value in (None, "", "nan"):
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def effective_due_date(finding: dict[str, Any]) -> date | None:
    return parse_date(finding.get("due_date")) or parse_date(finding.get("target_date"))


def is_overdue(finding: dict[str, Any], *, today: date | None = None) -> bool:
    today = today or date.today()
    status = str(finding.get("status", "OPEN")).strip().upper()
    due = effective_due_date(finding)
    return status in ACTIVE_STATUSES and due is not None and due < today


def exception_state(finding: dict[str, Any], *, today: date | None = None) -> str:
    """Return none, active, expiring, or expired for a risk acceptance."""
    today = today or date.today()
    if str(finding.get("status", "")).strip().upper() != "RISK_ACCEPTED":
        return "none"
    expiry = parse_date(finding.get("exception_expiry"))
    if expiry is None:
        return "expired"
    if expiry < today:
        return "expired"
    if expiry <= today + timedelta(days=14):
        return "expiring"
    return "active"


def prioritize_finding(
    finding: dict[str, Any],
    policy: dict[str, Any],
    *,
    today: date | None = None,
) -> PrioritizationResult:
    """Return a transparent remediation-priority decision, not an exploit prediction."""
    today = today or date.today()
    weights = policy["weights"]
    reasons: list[str] = []

    kev = as_bool(finding.get("kev"))
    exposed = as_bool(finding.get("internet_exposed"))
    patch_available = as_bool(finding.get("patch_available"))
    control = as_bool(finding.get("compensating_control"))
    cvss = max(0.0, min(10.0, _as_float(finding.get("cvss"))))
    epss = max(0.0, min(1.0, _as_float(finding.get("epss"))))
    criticality = max(1, min(5, _as_int(finding.get("asset_criticality"))))
    sensitivity = max(1, min(5, _as_int(finding.get("data_sensitivity"))))
    status = str(finding.get("status", "OPEN")).strip().upper()

    threat_score = 0
    if kev:
        threat_score += int(weights["kev"])
        reasons.append("CISA KEV 등재")
    cvss_points = _band_points(cvss, policy["cvss_bands"])
    threat_score += cvss_points
    reasons.append(f"CVSS {cvss:.1f} (+{cvss_points})")
    epss_points = _band_points(epss, policy["epss_bands"])
    threat_score += epss_points
    reasons.append(f"EPSS {epss:.3f} (+{epss_points})")

    asset_context_score = 0
    if exposed:
        asset_context_score += int(weights["internet_exposed"])
        reasons.append("인터넷 노출 자산")
    criticality_points = criticality * int(weights["asset_criticality_per_level"])
    sensitivity_points = sensitivity * int(weights["data_sensitivity_per_level"])
    asset_context_score += criticality_points + sensitivity_points
    reasons.append(f"자산 중요도 {criticality}/5")
    reasons.append(f"데이터 민감도 {sensitivity}/5")

    remediation_urgency_score = 0
    if patch_available:
        remediation_urgency_score += int(weights["patch_available"])
        reasons.append("패치 사용 가능: 즉시 실행 가능성 반영")
    if control:
        discount = int(policy["compensating_control_discount"])
        remediation_urgency_score -= discount
        reasons.append(f"보완통제 적용 (-{discount})")
    else:
        remediation_urgency_score += int(weights["no_compensating_control"])
        reasons.append("보완통제 없음")

    if is_overdue(finding, today=today):
        remediation_urgency_score += int(weights["overdue"])
        reasons.append("조치기한 초과")

    raw_score = threat_score + asset_context_score + remediation_urgency_score
    score = max(0, min(int(policy.get("score_cap", 140)), raw_score))

    special_rules = policy.get("special_rules") or {}
    immediate_rule = special_rules.get("kev_and_internet_exposed") or {}
    if bool(immediate_rule.get("enabled", True)) and kev and exposed:
        decision = str(immediate_rule.get("decision") or "immediate")
    else:
        decision = "monitor"
        for name, cfg in sorted(
            policy["decisions"].items(),
            key=lambda item: int(item[1]["min_score"]),
            reverse=True,
        ):
            if score >= int(cfg["min_score"]):
                decision = name
                break

    cfg = policy["decisions"][decision]
    sla_days = int(cfg["sla_days"])
    anchor = parse_date(finding.get("first_scored_at")) or parse_date(finding.get("first_seen_at")) or today
    target_date = (anchor + timedelta(days=sla_days)).isoformat()
    mitigation_rule = special_rules.get("mitigation_without_patch") or {}
    mitigation_required = bool(
        bool(mitigation_rule.get("enabled", True))
        and not patch_available
        and (
            (bool(mitigation_rule.get("include_kev", True)) and kev)
            or score >= int(mitigation_rule.get("min_score", 65))
        )
        and status in ACTIVE_STATUSES
    )
    if mitigation_required:
        reasons.append("패치 부재: 완화조치·벤더 확인 필요")

    return PrioritizationResult(
        score=score,
        threat_score=threat_score,
        asset_context_score=asset_context_score,
        remediation_urgency_score=remediation_urgency_score,
        decision=decision,
        decision_label=str(cfg["label"]),
        sla_days=sla_days,
        target_date=target_date,
        reasons=reasons,
        mitigation_required=mitigation_required,
        policy_version=str(policy.get("version", "unknown")),
    )
