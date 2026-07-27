# Evidence Chain of Custody

VulnFlow 17.0은 조치 검증 증거가 어디에서 수집됐고 누가 보관·검사·열람·인계했는지를 증거별 해시 체인으로 기록합니다.

## 출처 메타데이터

- `source_type`: USER_UPLOAD, SCANNER_EXPORT, TICKET_ATTACHMENT, SYSTEM_LOG, MANUAL_CAPTURE, OTHER
- `source_reference`: 티켓 번호, 스캐너 작업 ID 등 비밀정보가 아닌 참조
- `acquisition_method`: UPLOAD, EXPORT, API, CAPTURE, COLLECTION, OTHER
- `collected_by`, `collected_at`
- `current_custodian`

출처 핵심 필드는 등록 후 SQLite 트리거로 변경을 차단합니다.

## 보관 사슬 이벤트

각 이벤트는 `event_seq`, `prev_hash`, `event_hash`를 갖습니다. 이벤트 해시는 증거 ID, 순번, 이벤트 유형, 행위자, 이전·새 보관자, 목적, canonical JSON 세부정보, 시각과 이전 해시를 결합해 계산합니다.

지원 이벤트:

- ACQUIRED / LEGACY_IMPORTED
- SCANNED / SCAN_WAIVED
- DOWNLOADED
- TRANSFERRED
- RETIRED

## 인계

활성 증거는 operator 이상이 새 보관 책임자와 인계 목적을 지정해 이전할 수 있습니다. 현재 보관자와 같은 담당자에게 재인계하는 요청은 차단합니다.

## 검증과 복구

`verify_evidence_store`는 파일 크기·SHA-256, 예상하지 않은 파일, 검사 상태와 함께 모든 증거의 보관 사슬을 검증합니다. 복구 번들은 출처 메타데이터와 마지막 보관 사슬 상태를 manifest에 포함하며 복원 전에 DB와 교차검증합니다.

## 보장 범위

이 구조는 DB 내부 변조를 탐지하기 위한 것입니다. 호스트와 코드·키를 모두 장악한 공격자에 대한 법적 부인 방지는 외부 WORM 저장소, 신뢰 타임스탬프, KMS/HSM과 별도 로그 전송이 필요합니다.
