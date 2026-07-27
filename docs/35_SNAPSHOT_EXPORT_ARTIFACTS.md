# 26.0 스냅샷 내보내기와 산출물 무결성

## 목적

기존 CSV·HTML 출력은 모든 finding을 Python 리스트와 문자열 버퍼에 올렸습니다. 데이터가 커질수록 응답 지연과 메모리 사용이 finding 수에 비례해 증가했습니다.

26.0은 두 경로를 구분합니다.

1. 즉시 트랜잭션 스트리밍 CSV
2. 영속 백그라운드 스냅샷 CSV

## 즉시 스트리밍

`GET /export/findings.csv`

- SQLite 읽기 트랜잭션을 시작합니다.
- 고정 정렬로 `fetchmany()`를 반복합니다.
- UTF-8 BOM·헤더·행을 작은 청크로 반환합니다.
- 전체 finding 리스트와 전체 CSV 문자열을 만들지 않습니다.
- CSV 수식 삽입 방어를 적용합니다.

긴 스트리밍은 읽기 트랜잭션을 유지하므로 WAL checkpoint를 늦출 수 있습니다. 대형 데이터에는 비동기 스냅샷을 사용합니다.

## 스냅샷 작업

`FINDINGS_EXPORT` 작업은 다음 순서로 처리합니다.

```text
운영 DB
→ SQLite Backup API 임시 스냅샷
→ 필터 결과 정확한 COUNT
→ keyset cursor 배치 조회
→ .part 파일 작성
→ fsync
→ os.replace 원자적 완료
→ SHA-256·크기 계산
→ export_artifacts 등록
```

운영 DB가 작업 중 변경돼도 출력은 백업 시점의 일관된 스냅샷을 사용합니다.

## 멱등성

`export_artifacts.job_id`는 UNIQUE입니다.

작업이 파일과 DB 메타데이터를 완료한 뒤 worker가 종료돼 같은 작업이 재실행되면:

- 기존 산출물을 찾습니다.
- 크기와 SHA-256을 다시 검증합니다.
- 유효하면 기존 `artifact_id`를 반환합니다.
- 손상됐으면 자동으로 새 정상 산출물로 덮지 않고 작업을 실패시킵니다.

## 데이터 모델

`export_artifacts` 주요 필드:

- `artifact_id`
- `job_id`
- `export_type`
- `status`: `READY / EXPIRED / CORRUPT`
- `stored_filename`
- `download_filename`
- `row_count`
- `size_bytes`
- `sha256`
- `filters_json`
- `snapshot_at`
- `created_by / created_at`
- `expires_at`
- `downloaded_count / last_downloaded_at`

파일 경로 전체는 DB에 저장하지 않습니다. 서버 설정의 export root와 안전한 basename을 결합합니다.

## 다운로드 검증

다운로드 전에 다음을 확인합니다.

1. 상태가 `READY`인지
2. 만료되지 않았는지
3. 파일이 export root 바로 아래에 있는지
4. 실제 파일 크기가 DB 값과 같은지
5. 실제 SHA-256이 DB 값과 같은지

무결성이 맞지 않으면 `CORRUPT`로 전환하고 HTTP 409로 차단합니다.

## 보존과 복구

- `VULNFLOW_EXPORT_RETENTION_DAYS`가 지나면 유지관리에서 파일을 삭제하고 `EXPIRED`로 전환합니다.
- 관리자는 UI·API에서 즉시 만료할 수 있습니다.
- 내보내기 파일은 recovery bundle에 포함하지 않습니다.
- 복원 후 DB에 READY 산출물이 남았지만 파일이 없으면 시작 시 검증해 `CORRUPT`로 전환합니다.

## 보안 제한

- 산출물 파일은 `app/static` 밖에 저장합니다.
- 저장 파일명은 서버가 생성하며 사용자 입력을 사용하지 않습니다.
- 다운로드 파일명은 고정 패턴입니다.
- CSV 셀 값이 `=`, `+`, `-`, `@`로 시작하면 작은따옴표를 붙입니다.
- 작업 결과 API에는 파일 시스템 절대경로를 반환하지 않습니다.

## 검증 범위

- 스키마 25 → 26 마이그레이션
- 스트리밍 BOM·헤더·수식 삽입 방어
- 필터된 스냅샷 행 수
- 작업 완료와 파일 SHA-256
- worker 재실행 멱등성
- 변조 다운로드 차단
- 만료 파일 제거
- UI·Bearer API 작업 등록
- 50,000건 합성 내보내기와 Python 할당 메모리 비교

성능 수치는 현재 로컬 합성 환경의 검증이며 운영 SLA가 아닙니다.
