# 영속 백그라운드 작업

## 목적

CSV 가져오기, 위협정보 갱신, 전체 재평가, 유지관리와 웹훅 전송을 HTTP 요청 수명과 분리합니다. 작업 상태는 SQLite에 저장되므로 애플리케이션이 재시작돼도 대기·재시도 작업이 유지됩니다.

## 작업 유형

| 유형 | 최소 역할 | 설명 |
|---|---|---|
| CSV_IMPORT | operator | 검증된 취약점 행을 증분 또는 전체 스냅샷으로 반영 |
| INTEL_REFRESH | operator | CISA KEV와 FIRST EPSS를 수집하고 재평가 |
| RESCORE_ALL | operator | 현재 ACTIVE 정책으로 전체 현재 항목 재평가 |
| MAINTENANCE | admin | 예외 만료·STALE 보관·이력 보존정책 실행 |
| WEBHOOK_DELIVERY | admin | 전송 예정 웹훅을 임대 기반으로 처리 |

## 상태 전이

```text
PENDING ─► RUNNING ─► SUCCEEDED
   │          │
   │          ├─ 실패·잔여 시도 ─► RETRY ─► RUNNING
   │          ├─ 최대 시도 도달 ─► FAILED
   │          └─ 취소 요청 ─────► CANCELLED
   └─ 실행 전 취소 ─────────────► CANCELLED
```

## 임대와 다중 워커

워커는 `BEGIN IMMEDIATE` 트랜잭션 안에서 한 작업을 선택하고 `RUNNING`, `lease_owner`, `lease_expires_at`을 원자적으로 기록합니다. 다른 프로세스는 같은 작업을 선점할 수 없습니다.

워커가 종료돼 임대가 만료되면 다음 claim 시 작업을 `RETRY`로 회수합니다. 실행 중 취소는 즉시 프로세스를 강제 종료하지 않으며 작업 경계에서 `CANCELLED`로 반영합니다.

## 재시도와 멱등성

실패 작업은 15초부터 시작하는 지수형 지연으로 재시도하며 최대 1시간으로 제한합니다. 최대 시도 횟수에 도달하면 `FAILED`가 됩니다.

`CSV_IMPORT`는 `import_batches.source_job_id`를 사용합니다. 데이터 반영이 커밋된 직후 워커가 종료돼 동일 작업이 재실행돼도 기존 배치 결과를 반환하므로 finding row_version과 감사 이력이 중복 증가하지 않습니다.

다른 작업은 다음 특성을 이용합니다.

- RESCORE_ALL: 점수 변화가 없는 항목은 갱신하지 않음
- MAINTENANCE: 조건 기반 갱신·삭제
- WEBHOOK_DELIVERY: 별도 웹훅 전송 임대 사용
- INTEL_REFRESH: 최신 정보로 덮어쓰는 재실행 가능 작업

## UI와 API

- `GET /jobs`
- `POST /jobs/imports/csv`
- `POST /jobs/queue/{job_type}`
- `POST /jobs/{job_id}/cancel`
- `POST /jobs/{job_id}/retry`

API:

- `GET /api/v1/jobs`
- `GET /api/v1/jobs/{job_id}`
- `POST /api/v1/jobs/imports/csv`
- `POST /api/v1/jobs/queue/{job_type}`
- `POST /api/v1/jobs/{job_id}/cancel`
- `POST /api/v1/jobs/{job_id}/retry`

쓰기 API는 Bearer 토큰이 필요합니다. 작업 조회 API는 CSV_IMPORT 원본 행 배열을 반환하지 않고 `row_count`만 반환합니다.

## 예약 작업

유지관리와 웹훅 스케줄러는 직접 업무를 실행하지 않고 시간 구간별 dedupe key를 가진 작업을 등록합니다. 여러 애플리케이션 프로세스가 같은 SQLite DB를 사용해도 같은 구간의 작업은 하나만 생성됩니다.

웹훅 대기 건이 없으면 WEBHOOK_DELIVERY 작업을 생성하지 않습니다.

## 설정

```text
VULNFLOW_JOB_WORKER_ENABLED=1
VULNFLOW_JOB_WORKER_INTERVAL_SECONDS=2
VULNFLOW_JOB_LEASE_SECONDS=120
VULNFLOW_JOB_MAX_ATTEMPTS=3
VULNFLOW_JOB_RETENTION_DAYS=30
```

- worker enabled: 현재 프로세스에서 워커 루프 실행
- interval: 대기 작업이 없을 때 polling 간격
- lease: 한 작업의 기본 임대 시간
- max attempts: 신규 작업의 기본 최대 시도 횟수
- retention: 완료·실패·취소 작업 보존일. 유지관리 실행 시 정리

긴 외부 호출 시간이 lease보다 길어질 수 있다면 lease 값을 늘려야 합니다.

## 한계

- SQLite 단일 파일을 공유할 수 있는 프로세스 범위에서 동작합니다.
- 다중 서버가 네트워크 파일시스템의 SQLite를 공유하는 구성은 지원하지 않습니다.
- 작업 payload가 SQLite에 저장되므로 CSV는 기존 5MB·5,000행 제한을 유지합니다.
- 실행 중 Python 함수를 강제 중단하는 취소는 제공하지 않습니다.


## 43.0 작업 시도 영수증

각 background job 시도는 상태 변경과 같은 transaction에서 receipt를 생성합니다. 입력·결과·오류·worker 원문 대신 SHA-256과 제한된 metadata를 저장합니다. 최종 `FAILED / CANCELLED` receipt는 기존 job을 수정하지 않고 새 job을 만드는 one-time replay를 지원합니다.
