
from __future__ import annotations

import copy
import csv
import random
import statistics
import sys
from dataclasses import asdict
from datetime import date, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from app.core.scoring import load_policy, prioritize_finding

POLICY_PATH = ROOT / "rules" / "prioritization_policy.yml"
OUT_DIR = ROOT / "benchmark"
SEED = 20260720
N = 1000
TODAY = date(2026, 7, 20)


def weighted_choice(rng: random.Random, values: list[tuple[Any, float]]) -> Any:
    return rng.choices([v for v, _ in values], weights=[w for _, w in values], k=1)[0]


def generate_findings(n: int = N, seed: int = SEED) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    rows = []
    for i in range(1, n + 1):
        criticality = weighted_choice(rng, [(1, 12), (2, 20), (3, 30), (4, 25), (5, 13)])
        sensitivity = weighted_choice(rng, [(1, 16), (2, 24), (3, 28), (4, 20), (5, 12)])
        exposed = int(rng.random() < 0.28)
        kev = int(rng.random() < 0.10)
        epss = round(min(0.999, rng.betavariate(0.8, 5.0) + (0.30 if kev else 0) + (0.08 if exposed else 0)), 4)
        cvss_band = weighted_choice(rng, [((4.0, 6.9), 28), ((7.0, 8.9), 54), ((9.0, 10.0), 18)])
        cvss = round(rng.uniform(*cvss_band), 1)
        overdue = rng.random() < 0.18
        rows.append({
            "finding_id": f"SYN-{i:04d}", "product": "Synthetic Product", "cve_id": f"CVE-{rng.randint(2018, 2026)}-{rng.randint(1000, 99999)}",
            "cvss": cvss, "epss": epss, "kev": kev, "internet_exposed": exposed,
            "asset_criticality": criticality, "data_sensitivity": sensitivity,
            "patch_available": int(rng.random() < 0.73), "compensating_control": int(rng.random() < 0.28),
            "status": "OPEN", "due_date": (TODAY - timedelta(days=rng.randint(1, 60)) if overdue else TODAY + timedelta(days=rng.randint(1, 90))).isoformat(),
            "first_scored_at": TODAY.isoformat(),
        })
    return rows


def curated_scenarios() -> list[dict[str, Any]]:
    base = {"cvss": 7.5, "epss": 0.02, "kev": 0, "internet_exposed": 0, "asset_criticality": 3, "data_sensitivity": 3, "patch_available": 1, "compensating_control": 0, "status": "OPEN", "due_date": "", "first_scored_at": TODAY.isoformat()}
    return [
        {"name": "KEV+외부노출 즉시조치", "finding": base | {"kev": 1, "internet_exposed": 1}, "expect": lambda r: r.decision == "immediate"},
        {"name": "보완통제 점수 감소", "finding": base | {"compensating_control": 1}, "compare": base, "expect_pair": lambda a, b: a.score < b.score},
        {"name": "패치 없는 고우선 항목 완화 필요", "finding": base | {"kev": 1, "patch_available": 0, "asset_criticality": 5}, "expect": lambda r: r.mitigation_required},
        {"name": "기한 초과 활성 항목 가점", "finding": base | {"due_date": "2026-07-01"}, "compare": base | {"due_date": "2026-07-25"}, "expect_pair": lambda a, b: a.score > b.score},
        {"name": "종료 항목은 기한 초과 가점 제외", "finding": base | {"due_date": "2026-07-01", "status": "CLOSED"}, "compare": base | {"due_date": "2026-07-25", "status": "CLOSED"}, "expect_pair": lambda a, b: a.score == b.score},
        {"name": "최초 평가일 기준 SLA 고정", "finding": base | {"first_scored_at": "2026-07-01"}, "expect": lambda r: r.target_date == "2026-07-31"},
        {"name": "외부노출 시 자산 맥락 증가", "finding": base | {"internet_exposed": 1}, "compare": base, "expect_pair": lambda a, b: a.asset_context_score > b.asset_context_score},
        {"name": "위협·자산·조치 하위점수 합계", "finding": base, "expect": lambda r: r.score == r.threat_score + r.asset_context_score + r.remediation_urgency_score},
    ]


def run_behavior_checks(policy: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for case in curated_scenarios():
        result = prioritize_finding(case["finding"], policy, today=TODAY)
        if "compare" in case:
            other = prioritize_finding(case["compare"], policy, today=TODAY)
            passed = bool(case["expect_pair"](result, other))
        else:
            passed = bool(case["expect"](result))
        out.append({"check": case["name"], "passed": int(passed), "score": result.score, "decision": result.decision})
    return out


def rank_ids(rows: list[dict[str, Any]], policy: dict[str, Any], pct: int = 20) -> set[str]:
    enriched = []
    for row in rows:
        result = prioritize_finding(row, policy, today=TODAY)
        enriched.append((row["finding_id"], result.score, int(row["kev"]), float(row["epss"])))
    enriched.sort(key=lambda x: (-x[1], -x[2], -x[3], x[0]))
    cutoff = max(1, len(enriched) * pct // 100)
    return {x[0] for x in enriched[:cutoff]}


def sensitivity(rows: list[dict[str, Any]], base_policy: dict[str, Any], seed: int = SEED, runs: int = 50) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    baseline = rank_ids(rows, base_policy)
    results = []
    for idx in range(runs):
        policy = copy.deepcopy(base_policy)
        for key, value in list(policy["weights"].items()):
            policy["weights"][key] = max(0, round(value * rng.uniform(0.85, 1.15)))
        for bands_key in ("cvss_bands", "epss_bands"):
            for band in policy[bands_key]:
                band["points"] = max(0, round(int(band["points"]) * rng.uniform(0.85, 1.15)))
        current = rank_ids(rows, policy)
        overlap = len(baseline & current) / len(baseline | current)
        results.append({"run": idx + 1, "top20_jaccard": round(overlap, 4)})
    return results


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows: return
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); writer.writeheader(); writer.writerows(rows)


def write_report(checks: list[dict[str, Any]], sens: list[dict[str, Any]]) -> None:
    passed = sum(r["passed"] for r in checks)
    vals = [r["top20_jaccard"] for r in sens]
    lines = [
        "# 합성 정책 동작·민감도 시험", "", "## 목적", "",
        "VulnFlow가 설계한 판정 규칙을 일관되게 적용하는지, 그리고 주요 가중치를 ±15% 변경했을 때 상위 20% 검토 목록이 얼마나 유지되는지 확인했습니다.", "",
        "이 시험은 **실제 공격 예측 정확도, 실제 조직의 조치시간 단축, 상용 효과를 입증하지 않습니다.** 정답 데이터와 비교한 성능평가가 아니라 정책 동작 및 안정성 확인입니다.", "",
        "## 정책 동작 확인", "", f"- 통과: {passed}/{len(checks)}", "", "| 확인 항목 | 결과 | 점수 | 판정 |", "|---|---:|---:|---|",
    ]
    for r in checks: lines.append(f"| {r['check']} | {'통과' if r['passed'] else '실패'} | {r['score']} | {r['decision']} |")
    lines += ["", "## 가중치 민감도", "", "- 합성 취약점: 1,000건", "- 반복: 50회", "- 가중치 변동: 각 항목 ±15%", "- 비교: 기준 정책 상위 20%와 변경 정책 상위 20%의 Jaccard 중첩", f"- 중앙값: {statistics.median(vals):.1%}", f"- 최소: {min(vals):.1%}", f"- 최대: {max(vals):.1%}", "", "## 해석", "", "- 대표 시나리오에서 정책이 의도한 방향으로 동작하는지 확인했습니다.", "- 가중치 변화에 따른 상위 목록 변화량을 공개해 정책의 임의성을 숨기지 않았습니다.", "- 실제 적용 전에는 조직의 과거 조치사례와 사고 데이터를 이용해 가중치와 임계값을 보정해야 합니다.", "", "## 재현", "", "```powershell", "python scripts/run_benchmark.py", "```", ""]
    (ROOT / "docs" / "04_BENCHMARK_REPORT.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    policy = load_policy(POLICY_PATH)
    rows = generate_findings()
    checks = run_behavior_checks(policy)
    sens = sensitivity(rows, policy)
    write_csv(OUT_DIR / "synthetic_findings_1000.csv", rows)
    write_csv(OUT_DIR / "policy_behavior_checks.csv", checks)
    write_csv(OUT_DIR / "weight_sensitivity_50runs.csv", sens)
    write_report(checks, sens)
    print(f"Policy checks: {sum(r['passed'] for r in checks)}/{len(checks)}")
    vals = [r['top20_jaccard'] for r in sens]
    print(f"Top-20 Jaccard median={statistics.median(vals):.4f}, min={min(vals):.4f}, max={max(vals):.4f}")


if __name__ == "__main__": main()
