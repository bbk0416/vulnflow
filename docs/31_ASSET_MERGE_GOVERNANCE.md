# 자산 병합 영향분석·승인·복구

## 목적

자산 병합은 finding, scanner 원본 관측, 캠페인, 식별자와 감사 흐름을 동시에 변경하는 고영향 작업입니다. VulnFlow 22.0은 operator의 즉시 병합을 제거하고 영향분석과 역할 분리 승인을 적용합니다.

## 역할

| 역할 | 권한 |
|---|---|
| viewer | 후보, 영향분석, 요청, 병합 이력 조회 |
| operator | 영향분석 후 병합 승인 요청, 후보 거절 |
| approver | 요청 승인·반려 |
| admin | approver 권한과 recovery bundle 검증·복원 |

## dry-run 영향분석

`analyze_asset_merge`는 실제 데이터를 변경하지 않고 다음을 계산합니다.

- 원본 finding 수
- 대표 자산으로 그대로 이동할 finding
- 기존 canonical finding과 통합할 finding
- source finding record와 관측 수
- 캠페인 연결 수
- 검증 증거 레코드 수
- 이동·중복 retire 대상 식별자
- 제3 자산으로 재연결할 PENDING 후보
- FQDN·MAC 보조 식별자 불일치 경고
- CMDB·inventory·cloud 권위 식별자 충돌 blocker
- 중복 finding의 대기 위험수용·조치검증 blocker

영향 JSON은 정렬된 canonical JSON으로 직렬화하고 SHA-256을 저장합니다. 요청에는 source·target `row_version`도 함께 고정합니다.

## 승인 처리

```text
PENDING 요청 조회
→ 현재 영향 재계산
→ source/target row version 비교
→ impact SHA-256 비교
→ blocker 재확인
→ recovery bundle 파일·SHA-256 확인
→ 자산 병합
→ 요청 APPROVED 및 merge_id 연결
→ 감사 이벤트 기록
→ commit
```

재계산 결과가 달라지면 `ConcurrencyError`로 중단합니다. 요청을 자동 갱신하지 않으며 operator가 새 영향분석으로 다시 요청해야 합니다.

## recovery bundle

approver가 승인하면 애플리케이션은 병합 전에 다음 위치에 전용 복구 번들을 생성합니다.

```text
<VULNFLOW_RECOVERY_DIR>/asset-merges/<request_id>_<timestamp>.zip
```

번들은 기존 복구 체계를 그대로 사용합니다.

- 일관된 SQLite backup
- 활성 정책
- 비밀정보 제거 구성 감사
- 감사 체인 무결성 결과
- 증거 manifest와 증거 파일
- SHA-256 목록
- 설정 시 HMAC 서명

병합 요청에는 번들 경로, SHA-256과 최종 `merge_id`를 기록합니다. 부분 병합 rollback은 지원하지 않으며, 오류 복구가 필요하면 admin이 기존 recovery validation·restore 흐름으로 전체 시점을 복원합니다.

## 동시성·무결성

- 자산 또는 영향범위 변경 시 승인 차단
- 두 자산 중 하나가 다른 PENDING 병합 요청에 포함되면 신규 요청 차단
- candidate별 PENDING 요청 하나만 허용
- 병합 요청 핵심 필드 UPDATE 차단
- 병합 요청 DELETE 차단
- 병합 이력 UPDATE·DELETE 차단
- 승인과 실제 병합은 동일 DB 트랜잭션에서 처리

## API 예시

```text
GET /api/v1/asset-identities/candidates/{candidate_id}/impact?target_asset_ref_id=AST-...
POST /api/v1/asset-identities/candidates/{candidate_id}/merge-requests
GET /api/v1/asset-merge-requests?status=PENDING
POST /api/v1/asset-merge-requests/{request_id}/decision
```

요청 생성은 operator Bearer token, 결정은 approver Bearer token이 필요합니다.

## 제한

- partial rollback은 지원하지 않습니다.
- recovery bundle은 전체 DB·증거 시점 복원입니다.
- 영향분석은 DB 내부 참조를 대상으로 하며 외부 CMDB·ITSM의 연계 영향은 자동 계산하지 않습니다.
- 식별자 충돌 blocker는 보수적 기본 정책이며 조직별 자산 데이터 품질 정책을 대체하지 않습니다.
