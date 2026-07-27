# Multi-Scanner Canonical Finding Reconciliation

## 목적

여러 scanner가 동일한 취약점을 서로 다른 finding ID, CVSS, component version, patch 상태로 보고해도 조치 workflow가 중복 생성되지 않도록 합니다.

## 데이터 모델

### Canonical finding

기존 `findings` 행이 운영 단위입니다. `canonical_key`는 다음 값의 정규화된 SHA-256입니다.

```text
asset_ref_id + CVE + component(or product fallback)
```

scanner source, scanner-native ID, component version은 key에 포함하지 않습니다.

### Source finding record

`source_finding_records`는 scanner 원본 관측을 보존합니다.

- scanner source
- source finding ID
- canonical finding ID
- PRESENT / ABSENT
- source별 연속 누락 횟수
- 최근 batch와 관측 시각
- 정규화된 source snapshot JSON

### Reconciliation decision

`finding_reconciliation_decisions`는 충돌 필드의 권위 source 선택을 기록합니다.

지원 필드:

- product_version
- component_version
- cvss
- patch_available

결정은 삭제하지 않고 `ACTIVE / RETIRED`로 보존합니다.

## 병합 규칙

- CVSS: PRESENT source 중 최대값
- EPSS·KEV: 기존 intelligence 값과 source 값 중 보수적 최대값
- patch_available: PRESENT source 중 최대값
- asset context: 명시적 asset inventory가 scanner보다 우선
- compensating control: VulnFlow workflow 값 유지
- workflow status·owner·due date·notes: scanner 재가져오기로 덮어쓰지 않음

운영자가 권위 source를 선택하면 해당 필드는 선택한 source snapshot을 따릅니다. 다음 가져오기에서 같은 source 값이 바뀌면 결정은 유지되며 canonical 값이 함께 갱신됩니다.

## 생명주기

- 하나 이상의 source가 PRESENT: canonical ACTIVE
- 모든 source가 ABSENT: canonical STALE
- source 재탐지: canonical ACTIVE, 검증 완료 finding이면 OPEN 재개방
- 연속 미탐지 횟수: 모든 source별 누락 횟수의 최솟값

## 충돌 조정

`/reconciliation`에서 source record와 충돌 필드를 확인합니다. operator는 특정 source를 선택하고 사유를 남깁니다. 모든 결정은 감사 체인에 기록됩니다.

## 보안·정합성

- 같은 scanner source의 source-native ID가 다른 canonical identity로 이동하면 가져오기 거부
- 같은 batch에 동일 canonical key가 두 번 나오면 모호성으로 거부
- 빈 CSV 전체 스냅샷은 지원하지만 증분 가져오기는 빈 입력을 거부
- source record와 canonical workflow는 별도 계층으로 유지
