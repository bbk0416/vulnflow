from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
import yaml

import app.main as main
from app.core.scoring import load_policy, parse_policy_text, policy_digest, prioritize_finding
from app.core.storage import (
    ConcurrencyError,
    approve_policy_activation_request,
    create_policy_activation_request,
    create_policy_version,
    get_active_policy_version,
    get_policy_activation_request,
    get_policy_version,
    init_db,
    list_findings,
    list_policy_versions,
)
from app.services.policies import compare_policy_impact, score_with_policy, serialize_policy

USERS = json.dumps({
    "viewer": {"password": "view-pass", "role": "viewer"},
    "operator": {"password": "ops-pass", "role": "operator"},
    "approver": {"password": "approve-pass", "role": "approver"},
    "admin": {"password": "admin-pass", "role": "admin"},
})
TOKENS = json.dumps({
    "reader": {"token": "reader-token-1234567890", "role": "viewer"},
    "scanner": {"token": "scanner-token-123456789", "role": "operator"},
    "approval-bot": {"token": "approval-token-12345678", "role": "approver"},
    "admin-api": {"token": "admin-token-12345678901", "role": "admin"},
})


def bearer(value: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {value}"}


def make_client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "v7.sqlite3")
    monkeypatch.setattr(main, "AUTH_USER", "")
    monkeypatch.setattr(main, "AUTH_PASSWORD", "")
    monkeypatch.setattr(main, "AUTH_USERS_JSON", USERS)
    monkeypatch.setattr(main, "AUTH_API_TOKENS_JSON", TOKENS)
    monkeypatch.setattr(main, "WEBHOOKS_JSON", "")
    monkeypatch.setattr(main, "WEBHOOK_INTERVAL_SECONDS", 0)
    monkeypatch.setattr(main, "MAINTENANCE_INTERVAL_MINUTES", 0)
    return TestClient(main.app)


def candidate_yaml(version: str = "2.1.0", kev_weight: int = 50) -> str:
    policy = deepcopy(load_policy(main.POLICY_PATH))
    policy["version"] = version
    policy["name"] = f"Candidate {version}"
    policy["weights"]["kev"] = kev_weight
    policy["decisions"]["urgent_review"]["min_score"] = 60
    return serialize_policy(policy)


def test_policy_validation_rejects_unsafe_or_incomplete_configuration():
    policy = yaml.safe_load(candidate_yaml())
    del policy["weights"]["kev"]
    with pytest.raises(ValueError, match="필수 항목"):
        parse_policy_text(serialize_policy(policy))

    policy = yaml.safe_load(candidate_yaml())
    policy["decisions"]["monitor"]["min_score"] = 10
    with pytest.raises(ValueError, match="monitor"):
        parse_policy_text(serialize_policy(policy))

    policy = yaml.safe_load(candidate_yaml())
    policy["epss_bands"][0]["min"] = 2
    with pytest.raises(ValueError, match="범위"):
        parse_policy_text(serialize_policy(policy))



def test_policy_yaml_rejects_duplicate_keys_and_aliases():
    duplicate = candidate_yaml() + "\nweights:\n  kev: 1\n"
    with pytest.raises(ValueError, match="중복 키"):
        parse_policy_text(duplicate)

    alias = """
version: 9.0.0
name: Alias policy
score_cap: 140
weights: &weights
  kev: 35
  internet_exposed: 15
  patch_available: 3
  no_compensating_control: 5
  overdue: 10
  asset_criticality_per_level: 4
  data_sensitivity_per_level: 2
copy: *weights
"""
    with pytest.raises(ValueError, match="alias"):
        parse_policy_text(alias)


def test_special_rules_are_policy_controlled_not_hardcoded():
    policy = parse_policy_text(candidate_yaml("9.1.0", 35))
    policy["special_rules"] = {
        "kev_and_internet_exposed": {"enabled": False, "decision": "immediate"},
        "mitigation_without_patch": {"enabled": True, "min_score": 100, "include_kev": False},
    }
    policy = parse_policy_text(serialize_policy(policy))
    finding = {
        "cvss": 0, "epss": 0, "kev": 1, "internet_exposed": 1,
        "asset_criticality": 1, "data_sensitivity": 1, "patch_available": 0,
        "compensating_control": 1, "status": "OPEN",
    }
    result = prioritize_finding(finding, policy)
    assert result.decision != "immediate"
    assert result.mitigation_required is False

def test_policy_impact_is_deterministic_and_explains_changes(client):
    active = main._ensure_policy_registry()
    current = parse_policy_text(active["content_yaml"])
    candidate = parse_policy_text(candidate_yaml())
    first = compare_policy_impact(list_findings(main.DB_PATH), current, candidate)
    second = compare_policy_impact(list_findings(main.DB_PATH), current, candidate)
    assert first == second
    assert first["finding_count"] == 10
    assert first["score_changed"] > 0
    assert 0 <= first["top_n_jaccard"] <= 1
    assert first["largest_changes"]


def test_api_policy_create_impact_request_approve_and_rollback(tmp_path: Path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        original = client.get("/api/v1/policies", headers=bearer("reader-token-1234567890")).json()["active"]
        created_response = client.post(
            "/api/v1/policies",
            headers=bearer("admin-token-12345678901"),
            json={"content_yaml": candidate_yaml(), "notes": "raise KEV priority"},
        )
        assert created_response.status_code == 200
        candidate = created_response.json()
        assert candidate["status"] == "DRAFT"

        denied = client.post(
            f"/api/v1/policies/{candidate['policy_id']}/activation-requests",
            headers=bearer("reader-token-1234567890"),
            json={"reason": "not allowed"},
        )
        assert denied.status_code == 403

        impact = client.get(
            f"/api/v1/policies/{candidate['policy_id']}/impact",
            headers=bearer("reader-token-1234567890"),
        )
        assert impact.status_code == 200
        assert impact.json()["score_changed"] > 0

        requested = client.post(
            f"/api/v1/policies/{candidate['policy_id']}/activation-requests",
            headers=bearer("admin-token-12345678901"),
            json={"reason": "reviewed in change window"},
        )
        assert requested.status_code == 200
        request_id = requested.json()["request_id"]

        approved = client.post(
            f"/api/v1/policy-activation-requests/{request_id}/decision",
            headers=bearer("approval-token-12345678"),
            json={"decision": "APPROVED", "decision_note": "impact accepted"},
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "APPROVED"
        active = client.get("/api/v1/policies", headers=bearer("reader-token-1234567890")).json()["active"]
        assert active["policy_id"] == candidate["policy_id"]
        findings = client.get("/api/v1/findings", headers=bearer("reader-token-1234567890")).json()["items"]
        assert all(item["policy_id"] == candidate["policy_id"] for item in findings if item["record_state"] != "ARCHIVED")

        rollback_request = client.post(
            f"/api/v1/policies/{original['policy_id']}/activation-requests",
            headers=bearer("admin-token-12345678901"),
            json={"reason": "rollback after monitoring"},
        )
        assert rollback_request.status_code == 200
        rolled_back = client.post(
            f"/api/v1/policy-activation-requests/{rollback_request.json()['request_id']}/decision",
            headers=bearer("approval-token-12345678"),
            json={"decision": "APPROVED", "decision_note": "rollback approved"},
        )
        assert rolled_back.status_code == 200
        active = client.get("/api/v1/policies", headers=bearer("reader-token-1234567890")).json()["active"]
        assert active["policy_id"] == original["policy_id"]


def test_policy_approval_blocks_if_active_policy_changed(tmp_path: Path):
    db = tmp_path / "policies.sqlite3"
    init_db(db)
    current = parse_policy_text(candidate_yaml("3.0.0", 35))
    active = create_policy_version(
        db, version=current["version"], name=current["name"], content_yaml=serialize_policy(current),
        content_sha256=policy_digest(current), created_by="seed", status="ACTIVE",
    )
    first_policy = parse_policy_text(candidate_yaml("3.1.0", 40))
    second_policy = parse_policy_text(candidate_yaml("3.2.0", 45))
    first = create_policy_version(
        db, version=first_policy["version"], name=first_policy["name"], content_yaml=serialize_policy(first_policy),
        content_sha256=policy_digest(first_policy), created_by="admin",
    )
    second = create_policy_version(
        db, version=second_policy["version"], name=second_policy["name"], content_yaml=serialize_policy(second_policy),
        content_sha256=policy_digest(second_policy), created_by="admin",
    )
    first_request = create_policy_activation_request(db, policy_id=first["policy_id"], requested_by="admin", reason="first", impact={})
    second_request = create_policy_activation_request(db, policy_id=second["policy_id"], requested_by="admin", reason="second", impact={})
    approve_policy_activation_request(db, first_request["request_id"], scored_rows=[], decided_by="approver", decision_note="ok")
    with pytest.raises((ValueError, ConcurrencyError)):
        approve_policy_activation_request(db, second_request["request_id"], scored_rows=[], decided_by="approver", decision_note="stale")
    assert get_active_policy_version(db)["policy_id"] == first["policy_id"]
    assert get_policy_activation_request(db, second_request["request_id"])["status"] == "CANCELLED"
    assert get_policy_version(db, active["policy_id"])["status"] == "RETIRED"



def test_policy_approval_requires_fresh_dataset_impact(tmp_path: Path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        created = client.post(
            "/api/v1/policies",
            headers=bearer("admin-token-12345678901"),
            json={"content_yaml": candidate_yaml("2.2.0", 52), "notes": "freshness check"},
        ).json()
        requested = client.post(
            f"/api/v1/policies/{created['policy_id']}/activation-requests",
            headers=bearer("admin-token-12345678901"),
            json={"reason": "approve after change review"},
        ).json()
        current = client.get(
            "/api/v1/findings/F-0001", headers=bearer("reader-token-1234567890")
        ).json()
        changed = client.post(
            "/api/v1/findings/F-0001/workflow",
            headers=bearer("scanner-token-123456789"),
            json={
                "status": "IN_PROGRESS", "owner": "policy-test", "due_date": "2026-12-31",
                "notes": "changed after impact analysis", "expected_row_version": current["row_version"],
            },
        )
        assert changed.status_code == 200
        decision = client.post(
            f"/api/v1/policy-activation-requests/{requested['request_id']}/decision",
            headers=bearer("approval-token-12345678"),
            json={"decision": "APPROVED", "decision_note": "stale request"},
        )
        assert decision.status_code == 409
        assert client.get(
            "/api/v1/policies", headers=bearer("reader-token-1234567890")
        ).json()["active"]["policy_id"] != created["policy_id"]

def test_duplicate_policy_content_and_version_are_rejected(tmp_path: Path):
    db = tmp_path / "dupe.sqlite3"
    init_db(db)
    policy = parse_policy_text(candidate_yaml("4.0.0", 41))
    content = serialize_policy(policy)
    create_policy_version(
        db, version=policy["version"], name=policy["name"], content_yaml=content,
        content_sha256=policy_digest(policy), created_by="admin", status="ACTIVE",
    )
    with pytest.raises(ValueError, match="version|동일한 내용"):
        create_policy_version(
            db, version=policy["version"], name=policy["name"], content_yaml=content,
            content_sha256=policy_digest(policy), created_by="admin",
        )
    assert len(list_policy_versions(db)) == 1
