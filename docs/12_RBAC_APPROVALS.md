# 역할·위험수용 승인

## 역할

| 역할 | 조회·내보내기 | 운영 변경 | 위험수용 결정 | 백업·복원·유지관리 |
|---|---|---|---|---|
| viewer | 가능 | 불가 | 불가 | 불가 |
| operator | 가능 | 가능 | 요청만 가능 | 불가 |
| approver | 가능 | 가능 | 승인·반려 가능 | 불가 |
| admin | 가능 | 가능 | 직접 처리·승인 가능 | 가능 |

브라우저 사용자는 SQLite `app_users` 테이블에서 관리하며 비밀번호는 scrypt 해시로만 저장합니다. 최초 관리자는 `python -m scripts.manage_users --db ./data/vulnflow.db create --username admin --role admin`으로 생성합니다. 로그인 후에는 원문을 저장하지 않는 불투명 세션 쿠키를 사용하고, 기본 5회 연속 실패 시 15분 잠금, 비활성화 시 전체 세션 종료, 비밀번호 변경 시 기존 세션 폐기를 적용합니다. 관리자 화면 `/admin/users`에서 계정 생성·활성화·비활성화·잠금 해제·비밀번호 초기화·세션 종료를 수행합니다.

자동화는 별도의 `VULNFLOW_API_TOKENS_JSON` Bearer 토큰을 사용하며, 쓰기 API는 Bearer 인증만 허용합니다. HTTP Basic과 과거 평문 `VULNFLOW_USERS_JSON`, `VULNFLOW_AUTH_USER`, `VULNFLOW_AUTH_PASSWORD`는 거부됩니다. 사용자 또는 API 토큰이 없으면 기본적으로 시작을 거부합니다. `VULNFLOW_DEMO_MODE=1`과 `VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK=1`을 함께 명시한 직접 loopback 데모에서만 `local-user / admin` fallback을 사용할 수 있고, 프록시 전달 헤더가 있는 요청에는 적용되지 않습니다.

## 위험수용 흐름

1. operator가 상세화면에서 `RISK_ACCEPTED`, 만료일, 수용 사유를 입력합니다.
2. VulnFlow는 항목 상태를 즉시 변경하지 않고 PENDING 승인 요청을 생성합니다.
3. approver 또는 admin이 `/approvals`에서 승인·반려합니다.
4. 승인 시 인증된 승인자 이름, 사유, 만료일을 저장합니다.
5. 요청 생성 이후 항목이 변경되면 행 버전 충돌로 승인을 차단하고 재요청하도록 합니다.
6. 만료일이 지나면 유지관리 작업이 상태를 `OPEN`으로 재개방하고 감사 이력을 남깁니다.

admin·approver가 상세화면에서 직접 RISK_ACCEPTED로 변경하는 경우 인증된 사용자 이름이 승인자로 기록됩니다. 자유 입력 승인자 값은 신뢰하지 않습니다.


## 자산 병합 승인 흐름

1. operator가 중복 자산 후보에서 대표 자산을 선택하고 dry-run 영향분석을 확인합니다.
2. 요청 시 양쪽 자산 row version, 이동·통합 finding, 식별자 충돌과 영향범위를 SHA-256으로 고정합니다.
3. approver 또는 admin이 승인 직전 같은 영향분석을 다시 수행합니다.
4. 요청 이후 자산·finding·식별자가 변경되었거나 새로운 차단 조건이 생기면 승인을 거부합니다.
5. 승인 전에 전체 복구 번들을 생성하고 실제 파일 SHA-256을 확인합니다.
6. 병합과 승인 상태 변경을 하나의 SQLite 트랜잭션으로 처리합니다.
7. 반려는 병합을 수행하지 않고 요청·감사 이력만 보존합니다.

operator는 병합 요청까지만 가능하며, 최종 병합 결정은 approver 또는 admin 역할로 분리합니다.
