# 29.0 구성 기준선·드리프트

VulnFlow 29.0은 현재 환경변수와 운영 설정을 직접 변경하지 않고, 비밀정보가 제거된 구성 감사 결과를 승인 기준선으로 저장한 뒤 현재 상태와 비교합니다.

## 저장 범위

기준선에는 다음만 포함됩니다.

- 앱 버전과 인증 구성 여부·계정 수
- Secure cookie, 작업 워커, 클러스터 lease·TTL
- 유지관리·보존기간·내보내기 quota와 reserve
- 서명 키 ID·키 개수·서명 필수 여부
- 증거 저장소 scanner mode·clean requirement
- 복구 번들 주기·보존 개수·서명 여부
- webhook 이름·scheme·이벤트 수
- OSV endpoint scheme·timeout·retry·batch
- 커서 서명 키 구성 여부와 SQLite 운영 방식
- redacted 구성 감사 warning 목록

비밀번호, API token, HMAC secret, signing key 값, webhook 전체 URL·인증정보·경로는 저장하지 않습니다.

## 데이터 흐름

```text
build_config_audit
→ generated_at 제외 안정 snapshot
→ canonical JSON
→ SHA-256
→ ACTIVE baseline

현재 snapshot
→ baseline 경로별 비교
→ LOW / MEDIUM / HIGH
→ 선택적 immutable drift check 기록
```

## 위험 분류

HIGH 예시:

- 로컬 인증 fallback 활성화 변경
- 평문 HTTP webhook 허용 변경
- evidence clean requirement 변경
- audit·recovery 서명 필수 설정 변경
- cluster coordination 활성 상태 변경

MEDIUM 예시:

- 인증 계정 수·token 수
- active signing key ID
- worker·lease·retention·quota
- evidence scanner mode

나머지 설정과 앱 버전 변경은 LOW로 분류합니다. 이 분류는 정책 검토 우선순위이며 보안 인증이나 규정 준수 판정이 아닙니다.

## 상태

- `NO_BASELINE`: 승인 기준선 없음
- `IN_SYNC`: 현재 snapshot hash와 경로 값이 기준선과 일치
- `DRIFT`: 하나 이상의 경로 변경

기준선 상태:

- `ACTIVE`
- `RETIRED`

검사 이력은 `IN_SYNC` 또는 `DRIFT` 상태와 변경 경로 JSON을 보존합니다.

## 역할과 API

admin UI:

```text
GET  /system
POST /system/config-baseline
POST /system/config-drift/check
```

admin Bearer API:

```text
GET  /api/v1/system/config-drift
POST /api/v1/system/config-baseline
POST /api/v1/system/config-drift/check
```

기준선 생성 API 본문:

```json
{"note":"approved change ticket CHG-2026-0042"}
```

## 불변성과 복구

- `config_baselines` 핵심 snapshot·hash·생성정보 수정 차단
- 기준선 삭제 차단
- `config_drift_checks` 수정·삭제 차단
- 기준선 생성·검사 기록을 감사 hash chain에 추가
- recovery bundle의 SQLite 백업과 table counts에 포함
- schema 29 이상 복원 시 두 테이블과 허용 trigger 검증

## 메트릭

```text
vulnflow_config_baseline_present
vulnflow_config_drift_changes
```

메트릭은 현재 비교 결과만 제공하며 변경 값 전체는 admin 화면과 API에서 확인합니다.

## 운영 절차

1. 업그레이드 후 `/system`의 현재 구성 감사를 검토합니다.
2. 비밀저장소 값 자체가 아닌 공개 요약이 적절한지 확인합니다.
3. 변경 티켓·승인 사유를 note에 기록하고 기준선을 승인합니다.
4. 배포·키 교체·retention 변경 후 드리프트를 확인합니다.
5. 의도된 변경이면 검토 후 새 기준선을 승인하고 이전 기준선을 RETIRED로 남깁니다.
6. 예기치 않은 HIGH drift는 외부 환경변수·배포 manifest·secret manager audit와 교차검증합니다.

## 제한

- 프로세스 시작 후 환경변수 변경은 재시작 전까지 애플리케이션 상수에 반영되지 않을 수 있습니다.
- redacted 구성만 비교하므로 secret 값 자체의 교체·변조 여부는 검증하지 않습니다.
- 외부 secret manager, Kubernetes manifest, systemd unit, reverse proxy 설정 전체를 수집하지 않습니다.
- SQLite 불변 trigger는 DB 파일과 호스트가 함께 탈취된 공격자를 막는 WORM이 아닙니다.
