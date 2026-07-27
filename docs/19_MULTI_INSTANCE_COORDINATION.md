# 다중 인스턴스 조정

## 목적

VulnFlow 10.0은 동일 호스트에서 여러 API·워커 프로세스가 하나의 운영 SQLite DB를 사용할 때 다음 문제를 줄입니다.

- 각 프로세스가 같은 예약 작업을 중복 생성
- 복원 중 다른 프로세스가 운영 DB를 수정
- 리더 장애 후 예약 작업이 중단
- 오래된 리더가 승계 후에도 작업을 계속 수행
- 같은 인스턴스 ID를 여러 프로세스가 사용해 split-brain 발생

## 두 데이터베이스

```text
운영 DB
- findings, 정책, 승인, 감사, 작업, 웹훅
- 복구 번들의 백업·복원 대상

coordination DB
- 인스턴스 하트비트
- scheduler·restore·policy activation 임대
- 처리 중 HTTP 쓰기 activity
- 복구 번들에 포함하지 않는 일시적 실행 상태
```

coordination DB를 운영 DB와 분리한 이유는 운영 DB를 교체하는 복원 과정에서도 복원 잠금이 유지되어야 하기 때문입니다.

## 인스턴스 등록

각 프로세스는 시작할 때 다음을 등록합니다.

- `instance_id`
- hostname과 PID
- 앱 버전
- API·worker·scheduler 기능
- 시작·마지막 하트비트 시각

활성 상태의 동일 `instance_id`가 다른 PID에서 사용 중이면 시작을 차단합니다. TTL이 지나 `STALE` 처리된 이후에만 같은 ID를 새 프로세스가 인수할 수 있습니다.

## 리더 선출과 fencing token

`scheduler:singleton` 임대를 하나의 인스턴스만 소유합니다. 리더만 유지관리·웹훅 전송·복구 번들 예약 작업을 큐에 등록합니다.

- 정상 갱신: token 유지
- 정상 종료 후 승계: token 증가
- 임대 만료 후 승계: token 증가
- 오래된 token으로 갱신·해제: 실패

임대 해제 시 행을 삭제하지 않고 만료 처리하므로 token은 임대 이름별로 단조 증가합니다.

## 복원 프로토콜

HTTP 쓰기 요청:

```text
복원 임대 확인
→ write activity 등록
→ 복원 임대 재확인
→ 실제 요청 처리
→ activity 제거
```

복원 요청:

```text
exclusive:restore 획득
→ 활성 백그라운드 작업 0건 확인
→ 활성 write activity 0건 확인
→ 운영 DB 안전 백업·복원
→ 임대 만료 처리
```

다른 프로세스의 쓰기 요청은 복원 중 HTTP 503과 `Retry-After: 5`를 받습니다. 워커와 예약 스케줄러도 복원 임대가 활성화된 동안 신규 작업을 실행하거나 등록하지 않습니다.

## 설정

```text
VULNFLOW_CLUSTER_COORDINATION_ENABLED=1
VULNFLOW_COORDINATION_DB=./data/vulnflow-coordination.db
VULNFLOW_INSTANCE_ID=api-01
VULNFLOW_INSTANCE_HEARTBEAT_SECONDS=10
VULNFLOW_INSTANCE_TTL_SECONDS=30
VULNFLOW_SCHEDULER_LEASE_SECONDS=30
VULNFLOW_EXCLUSIVE_OPERATION_LEASE_SECONDS=300
VULNFLOW_WRITE_ACTIVITY_TTL_SECONDS=600
```

TTL과 scheduler lease는 heartbeat의 2배 이상이어야 합니다.

## 검증 범위

- 실제 Uvicorn 프로세스 2개 동시 실행
- 초기 리더 1개 확인
- 리더 종료 후 follower 자동 승계
- 승계 후 fencing token 증가
- 복원 임대 중 다른 프로세스의 쓰기 HTTP 503
- 활성 인스턴스 ID 충돌 차단
- 운영 DB 복원 중 coordination 임대 유지

## 제한

- 네트워크 파일시스템 SQLite 공유는 지원하지 않습니다.
- 다중 서버 고가용성은 PostgreSQL·외부 분산 잠금 도입이 필요합니다.
- 복원은 임대 TTL 안에 끝나는 로컬 파일 작업을 전제로 합니다.
- 11.0 미만 프로세스는 coordination 프로토콜을 알지 못하므로 동시에 실행하면 안 됩니다.
