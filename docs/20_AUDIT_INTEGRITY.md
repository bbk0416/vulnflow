# 감사 체인·서명 체크포인트

## 목적

`audit_events`를 직접 수정·삭제했는지 사후 검증할 수 있도록 각 이벤트를 SHA-256 체인으로 연결합니다. 이 통제는 데이터베이스 쓰기를 물리적으로 막는 WORM이 아니라 **변조 탐지**를 목적으로 합니다.

## 이벤트 해시

각 이벤트 해시는 다음 canonical JSON의 SHA-256입니다.

```text
chain_seq
finding_id
event_type
actor
summary
details_json (키 정렬·공백 제거)
created_at
prev_hash
```

첫 체인은 64자리 0 해시에서 시작합니다. 보존정책으로 앞부분을 정리한 뒤에는 `audit_chain_state.anchor_hash`가 새로운 검증 시작점입니다.

## 저장 구조

```text
audit_events
- chain_seq
- prev_hash
- event_hash

audit_chain_state
- anchor_seq / anchor_hash
- last_seq / last_hash

audit_checkpoints
- chain_seq / event_hash
- HMAC-SHA256 signature

audit_prune_history
- 정리 범위·건수·anchor hash
```

## 서명 체크포인트

체크포인트 서명 payload:

```json
{"format":"vulnflow-audit-checkpoint/1","chain_seq":123,"event_hash":"...","created_at":"..."}
```

환경변수:

```text
VULNFLOW_AUDIT_SIGNING_KEY
VULNFLOW_AUDIT_REQUIRE_SIGNATURE
```

키는 SQLite와 복구 번들에 포함하지 않습니다. 체크포인트는 시작 시 최신 이벤트, 관리자 수동 실행, 보존정책 경계에서 생성됩니다.

## 보존정책

임의의 오래된 행을 삭제하면 체인 중간에 구멍이 생깁니다. 따라서 보존정책은 현재 anchor 다음 이벤트부터 날짜 기준을 만족하는 **연속 prefix**만 정리합니다.

1. 정리 경계 이벤트 해시를 체크포인트로 기록
2. anchor_seq·anchor_hash 갱신
3. 해당 prefix 삭제
4. pruning 자체를 새 감사 이벤트로 기록
5. 새 anchor부터 전체 체인 재검증

날짜가 오래됐더라도 최신 이벤트 뒤에 비정상적으로 삽입된 행은 임의 삭제하지 않습니다.

## 복구 번들

`audit-integrity.json`에 생성 시점의 anchor, last hash, 검증 이벤트 수와 체크포인트 결과를 저장합니다. 번들 검증 시 SQLite에서 체인을 다시 계산하고 기록 파일과 교차검증합니다.

공격자가 번들의 DB를 수정하고 manifest·SHA256SUMS·번들 HMAC까지 다시 만들더라도, 감사 이벤트 해시 체인이 일치하지 않으면 복원이 거부됩니다. 단, 감사 서명 키까지 유출된 상황은 별도의 키 관리·외부 체크포인트 보관이 필요합니다.

## 운영 절차

```text
매일 또는 주요 변경 후 체크포인트 생성
→ integrity JSON 별도 보관
→ 복구 번들 생성 전 자동 검증
→ 오류 발생 시 원본 DB 수정 금지
→ 정상 복구 번들 또는 안전 백업으로 복구
```

체인 오류를 자동으로 다시 계산해 덮어쓰는 repair 기능은 제공하지 않습니다. 마이그레이션 시에만 10.0 이하 이벤트를 최초 체인으로 변환합니다.
