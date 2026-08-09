# 제어 DB 복구와 로그인 실패 제한

VulnFlow 72.0.26은 프로젝트 복구와 별도로 `data/control.db`를 백업·검증·복원하는 오프라인 CLI를 제공합니다. 또한 잘못된 비밀번호 누적으로 계정 전체를 잠그던 방식을 제거하고 출처별 sliding-window 제한으로 교체합니다.

## 로그인 실패 제한

기본값은 다음과 같습니다.

```text
VULNFLOW_AUTH_RATE_WINDOW_SECONDS=300
VULNFLOW_AUTH_RATE_USERNAME_CLIENT_ATTEMPTS=5
VULNFLOW_AUTH_RATE_CLIENT_ATTEMPTS=25
```

첫 번째 제한은 같은 사용자명과 클라이언트 조합의 실패를 계산합니다. 두 번째 제한은 한 클라이언트가 여러 사용자명을 순환하는 공격을 계산합니다. 올바른 비밀번호 검증은 실패 제한보다 먼저 수행되므로 다른 클라이언트가 만든 실패 기록 때문에 정상 계정 전체가 잠기지 않습니다.

없는 사용자, 비활성 사용자, 잘못된 비밀번호와 제한된 요청은 외부에 동일한 401 응답과 일반 메시지를 반환합니다. 정확한 원인은 내부 로그인 시도 기록과 감사 로그에서만 구분합니다.

schema 45 migration은 과거 `failed_attempts`와 `locked_until` 값을 초기화합니다. 해당 컬럼과 `unlock` 호환 명령은 구형 설치·운영 스크립트 호환성을 위해 남지만 계정 전체 잠금 판단에는 사용하지 않습니다.

## 제어 DB 번들 생성

서비스 실행 중에는 SQLite backup API로 일관된 snapshot을 만들 수 있지만, 운영 절차상 제어 DB 생성·특히 복원은 서비스를 중지한 상태에서 수행하는 것을 원칙으로 합니다.

```bash
python -m scripts.manage_control_recovery \
  --db ./data/control.db \
  create \
  --output ./backups/control/control-20260803.zip
```

번들에는 다음이 포함됩니다.

```text
manifest.json
control.sqlite3
SHA256SUMS.txt
manifest.hmac        # 서명 키를 지정한 경우만
```

복구 snapshot은 다음 데이터를 의도적으로 제거합니다.

- 브라우저 로그인 세션
- 로그인 실패 시도 기록
- 구형 계정 잠금 상태

사용자, 비밀번호 hash, 프로젝트 등록정보, 프로젝트 멤버십과 제어 평면 감사기록은 유지합니다.

## 검증

```bash
python -m scripts.manage_control_recovery validate \
  --bundle ./backups/control/control-20260803.zip
```

검증 항목:

- ZIP 경로 순회·중복·symlink·해제 크기 제한
- 필수 파일과 허용 파일 집합
- SHA-256 일치
- 선택 HMAC 서명
- SQLite `integrity_check`
- 현재보다 새로운 schema 거부
- `database_role=control`, `project_id=control`
- 정확히 하나의 기본 프로젝트
- 감사 hash chain

운영에서 서명 없는 번들을 거부하려면 검증과 복원에 `--require-signature`를 사용합니다.

## 복원

```bash
python -m scripts.manage_control_recovery \
  --db ./data/control.db \
  --projects-dir ./data/projects \
  restore \
  --bundle ./backups/control/control-20260803.zip \
  --confirm RESTORE-CONTROL
```

복원 절차:

1. 번들을 임시 위치에서 검증합니다.
2. 현재 제어 DB를 `backups/control/` 아래 안전 백업으로 만듭니다.
3. 검증된 snapshot으로 제어 DB를 교체합니다.
4. 현재 schema migration과 제어 DB identity를 다시 적용합니다.
5. 모든 세션·로그인 시도·구형 잠금 상태를 제거합니다.
6. 백업 이후 생성됐고 `data/projects/<id>/vulnflow.db`가 남아 있는 프로젝트 등록정보를 병합합니다.
7. 복원된 사용자와 호환되는 보존 프로젝트 멤버십만 다시 연결합니다.
8. 제어 DB 감사 이벤트를 기록합니다.
9. 실패하면 복원 전 안전 백업으로 rollback합니다.

복원 뒤에는 모든 사용자가 다시 로그인해야 합니다.

## 한계

- 웹 UI를 통한 온라인 복원을 제공하지 않습니다.
- 제어 DB와 프로젝트 DB를 동시에 한 시점으로 되돌리는 분산 snapshot은 아닙니다.
- 삭제된 사용자 계정을 디스크 프로젝트 정보만으로 재구성하지 않습니다.
- HMAC은 공유 비밀 기반이며 외부 공개키 서명이나 HSM 신뢰근을 대체하지 않습니다.
- 프로젝트 DB가 표준 경로 밖에 있으면 자동 재발견되지 않습니다.
- MFA, OIDC, SAML과 네트워크 경계 rate limiter는 별도 과제입니다.
