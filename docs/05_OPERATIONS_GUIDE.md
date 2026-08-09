# 운영 가이드

## 1. 최초 실행

애플리케이션은 `data/vulnflow.db`를 생성하고 운영 모드에서는 빈 데이터베이스로 시작합니다. 합성 샘플은 명시적인 데모 모드에서만 적재됩니다. 최초 실행 전에 관리자 계정과 프로젝트별 저장 경로를 확인합니다.

## 2. 스캐너 원천 설정

업로드 시 조직에서 구분 가능한 이름을 사용합니다.

```text
nessus-dmz
qualys-prod
manual-vdp
container-ci
```

같은 스캐너·범위를 반복 업로드할 때 동일한 이름을 유지해야 전체 스냅샷 대조가 정확합니다.

## 3. 증분과 전체 스냅샷

- 증분: 신규·변경분만 담긴 파일
- 전체 스냅샷: 해당 원천의 현재 전체 탐지 결과

전체 스냅샷에서 누락된 항목은 즉시 삭제하지 않고 STALE로 표시합니다. 스캔 실패·범위 변경 가능성을 검토한 뒤 ARCHIVED로 보관합니다.

## 4. 워크플로

ACTIVE 또는 STALE 항목에서 OPEN, IN_PROGRESS, MITIGATED, RISK_ACCEPTED, CLOSED를 관리합니다. ARCHIVED 항목은 ACTIVE로 복원해야 워크플로를 변경할 수 있습니다.

## 5. 동시 수정

오래 열린 상세화면에서 저장할 때 다른 작업이 먼저 수정했다면 409 충돌이 발생합니다. 새로고침해 최신 감사 이력과 값을 확인한 뒤 다시 저장합니다.

## 6. 백업·복원

프로젝트별 복구 ZIP을 정기 생성하고, 가능하면 `VULNFLOW_EXTERNAL_BACKUP_DIR`을 별도 드라이브 또는 NAS mount로 지정합니다. 외부 복사본은 프로젝트별 디렉터리에 원자적으로 기록되고 SHA-256 sidecar로 검증됩니다. 같은 물리 디스크의 다른 폴더는 오프사이트 백업이 아닙니다.

`관리자 메뉴 → 고객사·프로젝트`에서 로컬 또는 외부 번들의 격리 복원 리허설을 주기적으로 실행합니다. 리허설은 임시 DB·증거 저장소에 실제 복원해 SQLite·감사 체인·증거 무결성을 확인하지만 라이브 데이터를 변경하지 않습니다. 실제 복원은 별도 확인 문구와 쓰기 차단, 실행 중 작업 확인, 사전 안전 백업을 거쳐 수행합니다.


## 작업 큐 운영

- `/jobs`에서 PENDING·RUNNING·RETRY·FAILED 작업을 확인합니다.
- admin은 실행 전 작업을 취소하고 FAILED·CANCELLED 작업을 재시도할 수 있습니다.
- RUNNING 작업이 lease 시간보다 오래 멈춰 있으면 다음 워커가 자동 회수합니다.
- 반복적으로 lease가 만료되면 `VULNFLOW_JOB_LEASE_SECONDS`를 늘리고 외부 API 지연을 확인합니다.
- 작업 이력 정리는 유지관리와 `VULNFLOW_JOB_RETENTION_DAYS`로 관리합니다.

## 다중 프로세스 운영

- 모든 프로세스는 같은 `VULNFLOW_CONTROL_DB`, `VULNFLOW_DEFAULT_PROJECT_DB`, 프로젝트 저장소와 `VULNFLOW_COORDINATION_DB`를 사용합니다. `VULNFLOW_DB`는 72.0.24 이하 단일 DB 업그레이드 시 보존되는 원본 경로입니다.
- 각 프로세스의 `VULNFLOW_INSTANCE_ID`는 고유해야 합니다.
- `/cluster`에서 ACTIVE 인스턴스, scheduler leader, fencing token, 쓰기 activity를 확인합니다.
- leader 프로세스가 종료되면 TTL 이후 follower가 자동 승계합니다.
- 복원 중 503 응답은 정상적인 보호 동작이며 `Retry-After` 이후 재시도합니다.
- 11.0 미만 프로세스와 동시에 실행하지 않습니다.
