# 백업과 복원

## 원시 SQLite 백업

`GET /export/backup.sqlite3`는 SQLite Backup API를 사용해 일관된 DB 사본을 생성합니다. 운영 중 빠른 DB 복사나 이전 버전 호환을 위해 유지합니다.

## 9.0 복구 번들

`GET /export/recovery-bundle.zip`은 다음을 포함합니다.

- SQLite DB 사본
- 활성 우선순위 정책
- 비밀정보 제거 구성 감사
- 앱·스키마·테이블 건수 manifest
- 구성 파일 SHA-256
- 설정 시 manifest+해시목록 HMAC-SHA256

자세한 형식과 API는 `docs/18_RECOVERY_BUNDLES_CONFIG_AUDIT.md`를 참고합니다.

## 복원 검사

원시 DB와 복구 번들은 공통적으로 다음 조건을 확인합니다.

- SQLite `PRAGMA integrity_check = ok`
- findings, audit_events 필수 테이블과 필수 컬럼
- SQLite 트리거 미포함
- 현재 애플리케이션보다 새로운 `PRAGMA user_version` 차단

복구 ZIP은 추가로 경로 순회, 파일 수, 압축 해제 크기, 필수 파일, SHA-256, 선택적 HMAC을 확인합니다.

## 안전 백업과 마이그레이션

복원 직전 현재 데이터베이스는 다음 위치에 자동 저장됩니다.

```text
data/backups/vulnflow_pre_restore_<UTC timestamp>.sqlite3
```

복원 중 오류가 발생하면 안전 백업으로 되돌립니다. 복원 성공 후 `init_db`가 호환 마이그레이션을 수행하고 스키마 이력을 기록합니다.

## 주의

- 복원은 현재 전체 운영 상태를 교체합니다.
- 복구 번들과 원시 DB에는 민감한 운영정보가 포함될 수 있습니다.
- HMAC 키는 번들과 별도 위치에 보관해야 합니다.
- 서명 필수 모드에서 키를 잃으면 기존 서명 번들을 검증할 수 없습니다.
- 실제 운영에서는 복구 번들 생성뿐 아니라 별도 환경의 정기 복원 훈련이 필요합니다.

## 10.0 다중 프로세스 복원

복원 임대는 별도 coordination DB의 `exclusive:restore`에 저장됩니다. 복원 요청은 임대를 획득한 뒤 활성 백그라운드 작업과 HTTP write activity가 모두 0건인지 확인합니다.

coordination DB는 복구 번들에 포함하지 않습니다. 인스턴스·임대·activity는 복원할 업무 데이터가 아니라 재생성 가능한 실행 상태입니다.


## 11.0 감사 체인 검증

11.0 DB와 복구 번들은 복원 전에 감사 체인을 검증합니다. 복구 번들의 `audit-integrity.json`과 SQLite에서 재계산한 anchor·last hash가 다르면 복원을 거부합니다. 10.0 이하 DB는 마이그레이션 과정에서 기존 감사 이벤트를 최초 체인으로 변환합니다.


## 자산 병합 복구 지점

승인형 자산 병합은 적용 직전에 `recovery/asset-merges/` 아래에 검증 가능한 전체 복구 번들을 생성합니다. 승인 레코드에는 번들 경로와 실제 SHA-256이 저장됩니다. 현재 버전은 개별 병합의 역연산 rollback을 제공하지 않으며, 잘못된 병합의 복구는 전체 번들 검증·복원 절차를 사용합니다.


## 23.0 scoped merge rollback과 recovery bundle의 차이

- scoped rollback은 23.0 이후 특정 자산 병합이 변경한 레코드만 되돌립니다.
- 병합 이후 관련 레코드가 바뀌면 안전을 위해 scoped rollback을 거부합니다.
- recovery bundle restore는 전체 데이터베이스 복원이며, scoped journal이 없거나 후속 변경이 발생한 경우에만 운영 판단에 따라 사용합니다.
- 두 기능 모두 감사 이벤트를 삭제하지 않습니다.

## 42.0 schema 31 복원 검사

`PRAGMA user_version >= 31`인 DB는 `idempotency_records` 테이블과 digest·resource·response·expiry 필수 컬럼을 검사합니다. 원시 `idempotency_key` 컬럼이 존재하면 복원을 거부합니다. 복구 번들 table count에는 ledger가 포함되지만 원시 key는 포함되지 않습니다.


## 43.0 schema 32 복원 검사

`PRAGMA user_version >= 32`인 DB는 `execution_receipts`, `execution_replays`와 receipt digest·sequence·metadata 필수 컬럼을 검사합니다. receipt 테이블에 `payload_json`, `result_json`, 원문 `error`, `worker_id`, `actor` 컬럼이 있으면 복원을 거부합니다. 불변 trigger는 허용 목록과 대조합니다.

## 44.0 schema 33 복원 검사

`PRAGMA user_version >= 33`인 DB는 `execution_receipt_archives`와 archive ID·cutoff·건수·기간·digest·집계·actor hash 필수 컬럼을 검사합니다. archive 불변 trigger가 허용 목록에 포함돼야 하며, 허용되지 않은 trigger가 있으면 복원을 거부합니다.


## 47.0 schema 34 복원 검사

- `integrity_proof_key_transitions` 테이블과 필수 공개정보·서명 컬럼을 확인합니다.
- `from_private_key`, `to_private_key`, 원문 `reason` 컬럼이 있으면 복원을 거부합니다.
- update/delete 차단 trigger 존재 여부를 검사합니다.
- 복구 번들은 전환 공개문서와 서명은 포함하지만 private key는 포함하지 않습니다.


## 48.0 schema 35 복원 검사

- `integrity_proof_key_revocations` 테이블과 공개키·fingerprint·시각·공동서명 필수 컬럼을 확인합니다.
- revoked/replacement/recovery private key 또는 원문 `reason` 컬럼이 있으면 복원을 거부합니다.
- update/delete 차단 trigger를 허용 목록과 대조합니다.
- revocation 공개문서와 서명은 복구 DB에 포함되지만 private key는 포함하지 않습니다.


## Schema 36 revocation registry checkpoint validation

- `integrity_proof_revocation_checkpoints` and its public digest/signature columns are required for schema 36 backups.
- private/recovery private key, secret and token columns are rejected.
- immutable update/delete triggers must be present and no unapproved trigger may be introduced.


## Schema 37 witness records

- `integrity_proof_checkpoint_witnesses` and its public statement/signature columns are required for schema 37 backups.
- Backup validation rejects witness tables containing private-key, secret or token columns.
- Immutable witness update/delete triggers are part of the approved restore schema.

## Schema 39 trust-material validation

Recovery validation requires the transparency mirror receipt table and its public fields when `PRAGMA user_version` is 39 or later. A recovery database is rejected if the table is missing required columns or contains private-key, secret or token columns. Receipt rows remain immutable after restore.

Recovery bundles do not contain mirror private keys. Operators must restore mirror key custody separately and revalidate the latest accepted receipt digest through an authenticated external channel.

## Schema 40 trust-material validation

Schema 40 recovery validation requires `integrity_proof_mirror_consistency_checkpoints` with its full public-document column set and immutable update/delete triggers. Backups containing private-key, secret or token columns in this table are rejected.
