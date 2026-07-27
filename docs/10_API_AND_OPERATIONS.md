# API와 운영

## 인증

- UI와 조회 API: Basic 또는 Bearer
- 쓰기 API: Bearer API 토큰만
- 헬스체크: 인증 예외 최소정보

자세한 토큰 구성은 `14_API_TOKENS_AUTOMATION.md`를 참고합니다.

## 조회 API

- `GET /api/v1/summary` — viewer
- `GET /api/v1/findings` — viewer
- `GET /api/v1/findings/{finding_id}` — viewer
- `GET /api/v1/audit` — viewer
- `GET /api/v1/imports` — viewer
- `GET /api/v1/approvals` — operator
- `GET /api/v1/maintenance-runs` — admin
- `GET /api/v1/webhooks` — admin
- `GET /api/v1/policies` — viewer
- `GET /api/v1/policies/{policy_id}` — viewer
- `GET /api/v1/policies/{policy_id}/impact` — viewer

## 쓰기 API

- `POST /api/v1/imports/csv` — operator Bearer
- `POST /api/v1/findings/{finding_id}/workflow` — operator Bearer
- `POST /api/v1/findings/{finding_id}/risk-acceptance-requests` — operator Bearer
- `POST /api/v1/approvals/{request_id}/decision` — approver Bearer
- `POST /api/v1/webhooks/deliver` — admin Bearer
- `POST /api/v1/policies` — admin Bearer
- `POST /api/v1/policies/{policy_id}/activation-requests` — admin Bearer
- `POST /api/v1/policy-activation-requests/{request_id}/decision` — approver Bearer

## 상태와 관측성

- `/health/live`, `/health/ready`, `/health`
- `/metrics` — viewer 인증 필요
- `/docs`, `/openapi.json`

## 동시 수정

워크플로와 위험수용 요청은 `expected_row_version`을 지원합니다. 정책 활성화 요청은 활성 정책 ID와 전체 현재 항목의 finding_id·row_version fingerprint를 저장하며, 승인 시 값이 바뀌면 HTTP 409를 반환합니다. 읽은 뒤 다른 작업이 변경하면 HTTP 409를 반환합니다.

## 다운로드

- `/export/findings.csv` — viewer
- `/export/audit.csv` — viewer
- `/export/report.html` — viewer
- `/export/backup.sqlite3` — admin
- `/policies/{policy_id}/download` — viewer


## 백그라운드 작업 API

```text
GET  /api/v1/jobs
GET  /api/v1/jobs/{job_id}
POST /api/v1/jobs/imports/csv
POST /api/v1/jobs/queue/{job_type}
POST /api/v1/jobs/{job_id}/cancel
POST /api/v1/jobs/{job_id}/retry
```

CSV_IMPORT 원본 행은 작업 조회 응답에서 제거됩니다. 상태·진행률·결과·오류만 운영 조회에 노출합니다.

## 10.0 인스턴스 API

```text
GET  /cluster                         admin UI
GET  /api/v1/system/cluster           admin Bearer
POST /api/v1/system/cluster/prune     admin Bearer
```

`GET /health/ready`는 현재 instance ID와 scheduler 역할을 반환합니다. `/metrics`에는 `vulnflow_cluster_instances_active`와 `vulnflow_scheduler_leader`가 추가됩니다.


## 11.0 감사 무결성 API

```text
GET  /api/v1/audit/integrity        approver 이상
POST /api/v1/audit/checkpoints      admin Bearer token
GET  /export/audit-integrity.json   approver 이상
```

체크포인트 생성 API는 `VULNFLOW_AUDIT_SIGNING_KEY`가 없으면 400을 반환합니다.

## 13.0 자산·군집·캠페인 API

```text
GET  /api/v1/assets
POST /api/v1/assets
GET  /api/v1/assets/{asset_ref_id}
GET  /api/v1/exposure-groups
GET  /api/v1/campaigns
POST /api/v1/campaigns
GET  /api/v1/campaigns/{campaign_id}
POST /api/v1/campaigns/{campaign_id}/members
DELETE /api/v1/campaigns/{campaign_id}/members/{finding_id}
POST /api/v1/campaigns/{campaign_id}/status
```

자산·캠페인 쓰기 API는 Bearer token과 operator 이상 역할이 필요합니다.

## 14.0 조치 검증 API

```text
GET  /api/v1/verifications?status=PENDING&finding_id=...
POST /api/v1/findings/{finding_id}/verification-requests
POST /api/v1/verifications/{verification_id}/decision
```

요청 생성은 operator 이상, 결정은 approver 이상 역할과 Bearer token이 필요합니다.


## 15.0 검증 증거 API

```text
GET  /api/v1/verifications/{verification_id}/evidence
POST /api/v1/verifications/{verification_id}/evidence
GET  /api/v1/evidence/{evidence_id}/download
POST /api/v1/evidence/{evidence_id}/retire
GET  /api/v1/system/evidence-integrity
```

업로드·다운로드·보관해제는 operator 이상 Bearer token, 전체 무결성 API는 admin token이 필요합니다. 다운로드는 항상 attachment이며 응답에 `nosniff`와 `no-store`를 적용합니다.


## 16.0 증거 검사 API

- `POST /api/v1/evidence/{evidence_id}/scan` — admin Bearer
- `POST /api/v1/evidence/{evidence_id}/scan-waiver` — admin Bearer
- `EVIDENCE_SCAN` 작업 유형 — clamscan 비동기 검사


## 20.0 다중 스캐너 조정 API

```text
GET  /api/v1/reconciliation
GET  /api/v1/findings/{finding_id}/sources
POST /api/v1/findings/{finding_id}/source-resolution
POST /api/v1/findings/{finding_id}/source-resolution/{field_name}/retire
```

`source-resolution` 요청 예시:

```json
{
  "field_name": "cvss",
  "chosen_source_record_id": "...",
  "reason": "authenticated scanner selected as authoritative source"
}
```

허용 조정 필드:

- `cvss`
- `product_version`
- `component_version`
- `patch_available`

자동 병합은 원천 값을 삭제하지 않습니다. canonical 값은 conservative aggregation과 활성 reconciliation decision을 이용해 계산됩니다.

## 21.0 자산 식별 API

```text
GET  /api/v1/asset-identities/candidates?status=PENDING
POST /api/v1/asset-identities/candidates/{candidate_id}/merge
POST /api/v1/asset-identities/candidates/{candidate_id}/reject
GET  /api/v1/assets/{asset_ref_id}/identifiers
POST /api/v1/assets/{asset_ref_id}/identifiers
GET  /api/v1/asset-merges?asset_ref_id=...
```

병합 요청 예시:

```json
{
  "target_asset_ref_id": "AST-...",
  "reason": "CMDB CI와 scanner 자산 태그를 대조해 동일 서버로 확인"
}
```

식별자 추가 요청 예시:

```json
{
  "identifier_type": "CMDB_ID",
  "value": "CI-2100",
  "scope": "global",
  "source": "cmdb-review",
  "confidence": 100
}
```

동일 활성 식별자가 다른 자산에 이미 연결돼 있으면 식별자를 강제로 이동하지 않고 `CANDIDATE` 응답을 반환합니다.

## 24.0 finding 페이지네이션 API

```text
GET /api/v1/findings?decision=immediate&status=OPEN&record_state=CURRENT&scanner_source=scanner-a&limit=100&page=2
```

응답 필드:

- `count`: 필터 전체 결과 건수
- `items`: 현재 페이지 finding
- `page`: 현재 페이지
- `page_size`: 페이지 크기
- `total_pages`: 전체 페이지 수
- `query_ms`: 서버 내부 SQL COUNT·페이지 조회 시간

기존 `limit`은 페이지 크기로 유지되며 최대 1,000입니다. 잘못된 exception 필터는 HTTP 400을 반환합니다.

## 42.0 Idempotency-Key

다음 생성형 API는 선택적 `Idempotency-Key` 헤더를 지원합니다.

```text
POST /api/v1/jobs/imports/csv
POST /api/v1/jobs/queue/{job_type}
POST /api/v1/exports/findings
POST /api/v1/sboms/{sbom_id}/osv-scan
```

동일 principal·key·요청은 기존 결과를 replay합니다. 동일 key로 다른 요청을 보내면 HTTP 409입니다. key는 8~200자의 `[A-Za-z0-9._:-]` 형식이며 원문은 저장하지 않습니다.
