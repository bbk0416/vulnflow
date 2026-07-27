# 30.0 승인형 구성 변경 통제

VulnFlow 30.0은 29.0의 비밀정보 제거 구성 기준선과 드리프트 비교 위에 변경 요청·승인·변경 창구·기준선 승격 흐름을 추가합니다. 애플리케이션은 환경변수, 배포 manifest, secret manager 값을 직접 변경하지 않습니다.

## 목적

기존 기준선 이후 설정이 달라졌을 때 관리자가 즉시 재기준화하면 검토·승인 기록 없이 드리프트가 사라질 수 있습니다. 30.0은 다음 통제를 적용합니다.

```text
redacted 목표 구성
→ 기준선 대비 경로별 영향분석
→ operator 요청
→ approver 승인·반려
→ 변경 창구에서 현재 구성과 목표 hash 비교
→ 정확히 일치할 때만 새 기준선 승격
```

## 저장하는 정보

`config_change_requests`에는 다음을 저장합니다.

- 요청 당시 활성 기준선 ID·hash
- 비밀정보 제거 목표 snapshot·SHA-256
- 기준선 대비 변경 경로·심각도
- 제목·사유·롤백 계획
- 변경 창구 시작·종료 시각
- 요청자·결정자·적용자와 시각
- 새 기준선 ID
- 동시 수정 검사용 row version

비밀번호, Bearer token, HMAC secret, signing key 원문, webhook 전체 URL은 목표 snapshot에 넣을 수 없습니다. API로 목표 JSON을 제출할 때도 secret-bearing 필드를 거부합니다.

## 상태

- `PENDING`: 승인 대기
- `APPROVED`: 승인됐지만 아직 새 기준선으로 승격되지 않음
- `REJECTED`: 반려
- `APPLIED`: 현재 구성이 승인 목표와 일치해 새 기준선으로 승격됨
- `CANCELLED`: 예약 상태값. 현재 UI에서는 생성하지 않음

변경 창구 상태는 별도로 계산합니다.

- `SCHEDULED`
- `OPEN`
- `EXPIRED`

현재 드리프트의 통제 상태:

- `UNAPPROVED`: 일치하는 요청 없음
- `PENDING`: 목표는 일치하지만 승인 대기
- `APPROVED_SCHEDULED`: 승인됐지만 창구 시작 전
- `APPROVED_WINDOW`: 승인 목표와 정확히 일치하며 창구가 열림
- `EXPIRED`: 목표는 일치하지만 창구 종료

기존 `IN_SYNC / DRIFT` 상태는 호환성을 위해 유지합니다. 승인된 변경도 새 기준선 승격 전에는 기술적으로 `DRIFT`입니다.

## 역할 분리

- operator 이상: 변경 요청 생성
- approver 이상: 승인·반려·기준선 승격
- 요청자 본인의 승인·반려: 차단
- 기존 기준선이 있는 상태의 직접 재기준화 UI·API: 차단

초기 기준선은 admin이 `/system`에서 생성합니다. 이후 변경은 `/config-changes` 흐름을 사용합니다.

## 변경 전·후 검증

요청 생성 시 기준선과 목표 snapshot을 비교해 변경 경로와 심각도를 고정합니다. 승인 시 다음을 다시 확인합니다.

- 요청 당시 기준선이 여전히 활성 상태인지
- 기준선 hash가 변경되지 않았는지
- 변경 창구가 종료되지 않았는지

적용 시 다음을 확인합니다.

- 요청 상태가 `APPROVED`인지
- 현재 시각이 승인 창구 안인지
- 현재 redacted 구성 hash가 목표 hash와 정확히 일치하는지
- 활성 기준선 ID·hash가 요청 당시와 같은지

승인 목표 외에 다른 경로가 추가로 변경되면 `UNAPPROVED`로 남고 기준선 승격을 거부합니다.

## 원자성과 감사

새 기준선 승격은 하나의 SQLite 트랜잭션에서 처리합니다.

```text
기존 ACTIVE 기준선 RETIRED
→ 새 ACTIVE 기준선 INSERT
→ 변경 요청 APPLIED
→ CONFIG_CHANGE_APPLIED 감사 이벤트
→ CONFIG_BASELINE_CREATED 감사 이벤트
```

실패하면 이전 기준선과 요청 상태를 유지합니다. 요청의 목표·영향·창구·요청자 등 핵심 필드는 SQLite trigger로 수정할 수 없으며 요청 삭제도 차단합니다.

## UI·API

UI:

```text
GET  /config-changes
POST /config-changes/request
POST /config-changes/{request_id}/decision
POST /config-changes/{request_id}/apply
```

Bearer API:

```text
GET  /api/v1/system/config-changes
POST /api/v1/system/config-changes
POST /api/v1/system/config-changes/{request_id}/decision
POST /api/v1/system/config-changes/{request_id}/apply
```

API는 `target_snapshot`을 생략하면 현재 서버의 redacted 구성 감사를 목표로 사용합니다. 사전 변경 계획을 등록하려면 `/export/config-audit.json` 형식의 비밀정보 제거 목표 JSON을 제공합니다.

## 메트릭

```text
vulnflow_config_change_pending
vulnflow_config_change_approved
```

## 제한

- VulnFlow는 외부 환경변수·Kubernetes·systemd·secret manager를 변경하거나 롤백하지 않습니다.
- 롤백 계획은 운영자가 입력한 절차 기록이며 자동 실행되지 않습니다.
- redacted snapshot 비교이므로 실제 secret 값 교체 여부는 확인하지 못합니다.
- 프로세스 시작 후 환경변수를 바꾸면 재시작 전까지 현재 구성 감사에 반영되지 않을 수 있습니다.
- SQLite 불변 trigger와 감사 hash chain은 외부 WORM·독립 변경관리 시스템을 대체하지 않습니다.
