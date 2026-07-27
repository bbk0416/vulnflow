# 자산 식별 레지스트리와 안전 병합

## 목적

여러 scanner와 인벤토리는 같은 장비를 서로 다른 `asset_id`, hostname, FQDN, IP, cloud instance ID로 표현할 수 있습니다. VulnFlow 21.0은 이 값을 finding의 canonical identity와 분리된 자산 식별자 레지스트리로 관리합니다.

## 식별자 유형과 scope

| 유형 | 기본 scope | 기본 신뢰도 | 처리 |
|---|---|---:|---|
| `SCANNER_ASSET_ID` | `scanner:<source>` | 100 | 같은 scanner 내 권위 식별자 |
| `INVENTORY_ID` | `global` | 100 | 인벤토리 권위 식별자 |
| `CMDB_ID` | `global` | 100 | 권위 식별자 |
| `CLOUD_INSTANCE_ID` | `global` | 100 | 권위 식별자 |
| `EXTERNAL_ASSET_ID` | `global` | 70 | scanner 간 보조 비교 |
| `FQDN` | `global` | 85 | 보조 식별자 |
| `MAC_ADDRESS` | `global` | 80 | 보조 식별자 |
| `IP_ADDRESS` | `global` | 70 | 보조 식별자 |
| `HOSTNAME` | `environment:<value>` | 50 | 약한 보조 식별자 |

IP와 MAC은 정규 형식으로 변환하고, FQDN은 소문자와 후행 점 제거를 적용합니다. hostname은 environment scope를 포함합니다.

## 자동 해소와 후보 생성

```text
권위 식별자 1개가 기존 자산을 가리킴
→ 해당 자산으로 해소

권위 식별자가 서로 다른 자산을 가리킴
→ 가져오기 차단 + 검토 후보

보조 식별자 점수 합계가 150 이상이며 단일 자산이 우세
→ 해당 자산으로 제한적 자동 해소

약한 단일 보조 식별자만 일치
→ 신규 자산 유지 + PENDING 후보
```

자동 해소는 자산 소유권이나 CMDB 정확성을 증명하지 않습니다. 운영자는 `/asset-identities`에서 근거와 두 자산을 확인합니다.

## 병합 처리

operator가 대표 자산을 선택하면 하나의 SQLite 트랜잭션에서 다음을 수행합니다.

1. 원본 자산과 대표 자산이 모두 `ACTIVE`인지 확인
2. 대기 중인 위험수용·조치검증 충돌 확인
3. 원본 자산의 finding을 대표 자산으로 이동
4. 같은 canonical key가 이미 존재하면 source record와 관측을 대표 finding으로 통합
5. 원본 중복 finding을 `ARCHIVED`하고 `merged_into_finding_id` 기록
6. 캠페인 연결과 source reconciliation 상태 이동
7. 식별자를 대표 자산으로 이동하거나 중복 식별자를 `RETIRED`
8. 원본 자산을 `RETIRED`하고 `merged_into_asset_ref_id` 기록
9. 관련 후보를 `MERGED` 처리하고 제3 자산 후보는 대표 자산 기준으로 재연결
10. immutable 병합 이력과 감사 이벤트 기록

병합 자동 되돌리기는 지원하지 않습니다. 원본 자산·finding·병합 snapshot을 삭제하지 않아 수동 복구 근거를 남깁니다.

## CSV 입력 확장

finding CSV와 자산 CSV는 기존 컬럼 외에 다음 선택 컬럼을 지원합니다.

```text
cmdb_id
cloud_instance_id
fqdn
ip_address
mac_address
```

빈 값은 무시합니다. 형식이 잘못된 IP·MAC·FQDN은 가져오기를 거부합니다.

## API

```text
GET  /api/v1/asset-identities/candidates
POST /api/v1/asset-identities/candidates/{candidate_id}/merge
POST /api/v1/asset-identities/candidates/{candidate_id}/reject
GET  /api/v1/assets/{asset_ref_id}/identifiers
POST /api/v1/assets/{asset_ref_id}/identifiers
GET  /api/v1/asset-merges
```

쓰기 작업은 operator 이상 역할과 Bearer token이 필요합니다.

## 제한

- DHCP, hostname 재사용, NAT, cloud 재생성은 오탐 후보를 만들 수 있습니다.
- 식별자 신뢰도는 일반 운영 기본값이며 조직별 CMDB 품질을 자동 평가하지 않습니다.
- 자산 병합은 고영향 작업이므로 복구 번들 생성 후 수행하는 것을 권장합니다.
- 여러 서버의 PostgreSQL·외부 CMDB 동기화는 지원하지 않습니다.

## 22.0 변경

21.0의 operator 직접 병합 UI·API는 22.0에서 승인 요청 방식으로 변경했습니다. dry-run 영향분석, approver 승인, 승인 직전 recovery bundle 생성과 동시성 검증은 `31_ASSET_MERGE_GOVERNANCE.md`를 참고하세요.
