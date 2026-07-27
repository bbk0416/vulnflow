# 조치 검증 증거 저장소

## 목적

RETEST·MANUAL_EVIDENCE·SCAN_ABSENCE 검증 요청에 재시험 로그, 패치 확인 결과, 변경 티켓, 화면 캡처를 연결합니다. 메모만 남기는 방식보다 승인 근거를 재검토하기 쉽도록 파일 본문과 메타데이터를 분리 보관합니다.

## 저장 흐름

```text
대기 중 검증 요청
→ 확장자·파일 시그니처·크기 검증
→ SHA-256 계산
→ 임시 파일 fsync
→ evidence 디렉터리로 원자적 rename
→ SQLite 메타데이터·감사 이벤트 commit
```

DB 저장이 실패하면 생성한 파일을 삭제합니다. 검증 요청이 먼저 승인·반려되면 업로드를 거부합니다.

## 허용 형식

- UTF-8: txt, log, csv, json
- 바이너리 시그니처: PDF, PNG, JPEG
- 기본 최대 크기: 10MB (`VULNFLOW_EVIDENCE_MAX_BYTES`)

실행파일·압축파일·Office 문서는 허용하지 않습니다.

## 무결성

- 메타데이터: evidence ID, 검증 요청, finding, 원본명, MIME, 크기, SHA-256, 업로더, 시각
- 다운로드 전 실제 파일 크기와 SHA-256 재검증
- 관리자 시스템 화면과 `/api/v1/system/evidence-integrity`에서 전체 검사
- 미등록 파일, 누락 파일, 크기·해시 불일치를 오류로 처리

## 불변성

파일 본문은 덮어쓰지 않습니다. 핵심 DB 메타데이터 변경과 hard delete는 SQLite 트리거로 차단합니다. 대기 중 검증의 잘못된 첨부만 `RETIRED`로 논리 보관해제할 수 있으며 파일은 유지합니다.

## 복구

서명 복구 번들에는 `evidence-manifest.json`과 `evidence/` 파일이 포함됩니다. 복원 전 다음을 교차검증합니다.

1. ZIP 안전 경로와 전체 파일 SHA-256
2. evidence manifest의 파일 경로·크기·해시
3. 복원 DB의 evidence 레코드와 manifest
4. 복구 번들 HMAC와 감사 체인

증거 레코드가 있는 원시 SQLite 파일은 단독 복원하지 않고 복구 번들 ZIP을 사용합니다.

## 제한

- 악성코드 탐지·CDR·샌드박스는 제공하지 않습니다.
- 파일 암호화 at rest는 OS·디스크 계층에 맡깁니다.
- 외부 객체 스토리지·WORM 보관은 지원하지 않습니다.
