from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import date
from statistics import mean
import hashlib
from typing import Any, Iterable

import yaml

from app.core.scoring import parse_policy_text, policy_digest, prioritize_finding


def serialize_policy(policy: dict[str, Any]) -> str:
    return yaml.safe_dump(policy, allow_unicode=True, sort_keys=False)


def parse_and_describe_policy(text: str) -> tuple[dict[str, Any], str, str]:
    policy = parse_policy_text(text)
    return policy, serialize_policy(policy), policy_digest(policy)


def compare_policy_impact(
    findings: Iterable[dict[str, Any]],
    current_policy: dict[str, Any],
    candidate_policy: dict[str, Any],
    *,
    top_n: int = 20,
) -> dict[str, Any]:
    rows = [dict(row) for row in findings if str(row.get("record_state") or "ACTIVE").upper() != "ARCHIVED"]
    fingerprint_source = "\n".join(
        f"{row.get('finding_id','')}:{int(row.get('row_version') or 0)}"
        for row in sorted(rows, key=lambda item: str(item.get("finding_id") or ""))
    )
    dataset_fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()
    transitions: Counter[str] = Counter()
    changed: list[dict[str, Any]] = []
    score_deltas: list[int] = []
    decision_changed = 0
    sla_changed = 0
    score_changed = 0
    current_rank: list[tuple[int, str]] = []
    candidate_rank: list[tuple[int, str]] = []

    for row in rows:
        current = prioritize_finding(row, current_policy)
        candidate = prioritize_finding(row, candidate_policy)
        finding_id = str(row.get("finding_id") or "")
        current_rank.append((current.score, finding_id))
        candidate_rank.append((candidate.score, finding_id))
        delta = candidate.score - current.score
        score_deltas.append(delta)
        if delta:
            score_changed += 1
        if current.decision != candidate.decision:
            decision_changed += 1
            transitions[f"{current.decision} → {candidate.decision}"] += 1
        if current.sla_days != candidate.sla_days:
            sla_changed += 1
        if delta or current.decision != candidate.decision or current.sla_days != candidate.sla_days:
            changed.append({
                "finding_id": finding_id,
                "product": str(row.get("product") or ""),
                "cve_id": str(row.get("cve_id") or ""),
                "current_score": current.score,
                "candidate_score": candidate.score,
                "score_delta": delta,
                "current_decision": current.decision,
                "candidate_decision": candidate.decision,
                "current_label": current.decision_label,
                "candidate_label": candidate.decision_label,
                "current_sla_days": current.sla_days,
                "candidate_sla_days": candidate.sla_days,
            })

    changed.sort(key=lambda item: (abs(int(item["score_delta"])), item["finding_id"]), reverse=True)
    current_rank.sort(key=lambda item: (item[0], item[1]), reverse=True)
    candidate_rank.sort(key=lambda item: (item[0], item[1]), reverse=True)
    rank_size = min(max(1, top_n), len(rows)) if rows else 0
    current_top = {item[1] for item in current_rank[:rank_size]}
    candidate_top = {item[1] for item in candidate_rank[:rank_size]}
    union = current_top | candidate_top
    jaccard = len(current_top & candidate_top) / len(union) if union else 1.0

    return {
        "finding_count": len(rows),
        "score_changed": score_changed,
        "decision_changed": decision_changed,
        "sla_changed": sla_changed,
        "average_score_delta": round(mean(score_deltas), 3) if score_deltas else 0.0,
        "average_absolute_score_delta": round(mean(abs(value) for value in score_deltas), 3) if score_deltas else 0.0,
        "max_score_increase": max(score_deltas) if score_deltas else 0,
        "max_score_decrease": min(score_deltas) if score_deltas else 0,
        "top_n": rank_size,
        "top_n_jaccard": round(jaccard, 4),
        "decision_transitions": dict(sorted(transitions.items())),
        "largest_changes": changed[: min(50, max(1, top_n))],
        "current_policy_version": str(current_policy.get("version") or "unknown"),
        "candidate_policy_version": str(candidate_policy.get("version") or "unknown"),
        "dataset_fingerprint": dataset_fingerprint,
    }


def score_with_policy(
    finding: dict[str, Any], policy: dict[str, Any], *, policy_id: str,
) -> dict[str, Any]:
    row = deepcopy(finding)
    today = date.today().isoformat()
    if not str(row.get("first_seen_at") or "").strip():
        row["first_seen_at"] = today
    if not str(row.get("first_scored_at") or "").strip():
        row["first_scored_at"] = today
    result = prioritize_finding(row, policy)
    row.update({
        "score": result.score,
        "threat_score": result.threat_score,
        "asset_context_score": result.asset_context_score,
        "remediation_urgency_score": result.remediation_urgency_score,
        "decision": result.decision,
        "decision_label": result.decision_label,
        "sla_days": result.sla_days,
        "target_date": result.target_date,
        "mitigation_required": int(result.mitigation_required),
        "reasons": " | ".join(result.reasons),
        "policy_version": result.policy_version,
        "policy_id": policy_id,
        "last_scored_at": today,
    })
    return row
