# Remediation verification and recurrence

## 목적

취약점의 `MITIGATED` 상태는 조치가 적용됐다는 운영자의 주장이고, `CLOSED`는 별도의 검증을 통과한 상태로 구분합니다.

## 상태

```text
UNVERIFIED
READY_FOR_VERIFICATION
PENDING
VERIFIED
REJECTED
REOPENED
NOT_REQUIRED
```

- `MITIGATED + UNVERIFIED`: 조치 적용, 검증 전
- `MITIGATED + READY_FOR_VERIFICATION`: 연속 스냅샷 미탐지 기준 충족
- `MITIGATED + PENDING`: 검증 승인 대기
- `CLOSED + VERIFIED`: approver가 검증 승인
- `IN_PROGRESS + REJECTED`: 검증 반려
- `OPEN + REOPENED`: 검증 후 재탐지 또는 수동 재개방

## 검증 방식

### SCAN_ABSENCE

- 전체 스냅샷만 미탐지 근거로 사용
- 기본 연속 2회 이상
- finding이 `STALE`이어야 함
- 최신 미탐지 import batch를 요청에 연결

### RETEST

- 재시험 결과·범위·도구·시각을 근거 메모에 기록
- approver가 검토 후 승인 또는 반려

### MANUAL_EVIDENCE

- 변경 티켓, 패치 버전, 설정 변경 등 외부 증거 위치를 기록
- 민감 원문이나 비밀정보는 저장하지 않음

## 재발 처리

`CLOSED + VERIFIED` finding이 같은 scanner source에서 다시 탐지되면:

```text
status=OPEN
resolution_state=REOPENED
resolved_at 제거
reopen_count + 1
last_reopened_at 기록
감사 이벤트 finding_reopened 생성
```

대기 중 검증 요청도 자동 취소합니다.

## API

```text
GET  /api/v1/verifications
POST /api/v1/findings/{finding_id}/verification-requests
POST /api/v1/verifications/{verification_id}/decision
```

## 운영 주의

- 미탐지는 스캔 범위·자격증명·플러그인·네트워크 오류에 영향을 받습니다.
- 자동 `CLOSED`는 지원하지 않습니다.
- 승인자는 원천 배치, 연속 미탐지 횟수, 재시험 메모와 자산 범위를 함께 검토합니다.
