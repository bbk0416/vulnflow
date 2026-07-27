
from datetime import date
from pathlib import Path
from app.core.scoring import load_policy, prioritize_finding
POLICY = load_policy(Path(__file__).parents[1] / "rules" / "prioritization_policy.yml")
TODAY = date(2026, 7, 19)

def base_finding():
    return {"cvss": 7.5, "epss": 0.02, "kev": 0, "internet_exposed": 0, "asset_criticality": 3, "data_sensitivity": 3, "patch_available": 1, "compensating_control": 0, "status": "OPEN", "due_date": "", "first_scored_at": "2026-07-01"}

def test_kev_exposed_is_immediate():
    r = prioritize_finding(base_finding() | {"kev": 1, "internet_exposed": 1}, POLICY, today=TODAY); assert r.decision == "immediate"

def test_compensating_control_lowers_score():
    assert prioritize_finding(base_finding() | {"compensating_control": 1}, POLICY, today=TODAY).score < prioritize_finding(base_finding(), POLICY, today=TODAY).score

def test_high_priority_no_patch_requires_mitigation():
    assert prioritize_finding(base_finding() | {"kev": 1, "patch_available": 0, "asset_criticality": 5}, POLICY, today=TODAY).mitigation_required

def test_overdue_adds_priority_only_for_active():
    current = prioritize_finding(base_finding() | {"due_date": "2026-07-25"}, POLICY, today=TODAY)
    overdue = prioritize_finding(base_finding() | {"due_date": "2026-07-01"}, POLICY, today=TODAY)
    closed = prioritize_finding(base_finding() | {"due_date": "2026-07-01", "status": "CLOSED"}, POLICY, today=TODAY)
    closed_future = prioritize_finding(base_finding() | {"due_date": "2026-07-25", "status": "CLOSED"}, POLICY, today=TODAY)
    assert overdue.score > current.score and closed.score == closed_future.score

def test_sla_target_is_anchored_to_first_score_date():
    r = prioritize_finding(base_finding(), POLICY, today=TODAY); assert r.target_date == "2026-07-31"

def test_subscores_add_to_total_without_cap_in_base_case():
    r = prioritize_finding(base_finding(), POLICY, today=TODAY); assert r.score == r.threat_score + r.asset_context_score + r.remediation_urgency_score
