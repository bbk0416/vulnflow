# Public repository scope

이 패키지는 채용 검토와 기술 공개를 위한 공개용 소스 저장소입니다.

## 포함

- 전체 애플리케이션 소스
- 합성 샘플 데이터와 정책
- 핵심 운영 문서
- 대표 화면과 아키텍처 이미지
- 핵심 업무 흐름을 검증하는 238개 대표 테스트
- 로컬 실행·Docker 구성·SBOM

## 제외

- 실제 군·고객·기업 데이터
- 로컬 SQLite DB와 증거파일
- 비밀번호, API token, private signing key
- 14MiB runtime dependency snapshot
- wheel·sdist와 서명형 전체 릴리스 키트
- 내부 release journal과 대량 생성 검증 보고서
- 포트폴리오 DOCX 등 개인 지원문서

## 전체 기준본과의 관계

공개본은 72.0.11 애플리케이션 소스를 유지하지만, 저장소 가독성과 용량을 위해 공급망·릴리스 검증 산출물을 제외했습니다. 전체 제출 기준본은 별도 보관하며 공개 저장소와 섞지 않습니다.
