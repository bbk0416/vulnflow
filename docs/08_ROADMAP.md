# Roadmap

72.0.13 기준 핵심 기능, 안전 기본값, 릴리스 메타데이터, 의존성 버전 잠금, schema 35→40 업그레이드·복구 리허설, 반복 runtime soak, container-equivalent 비루트 배포 리허설, 재현 가능한 wheel·sdist 빌드, Linux CPython 런타임 dependency snapshot, 호스트 site-packages 연결 없는 설치본 실행은 완료 단계입니다. 다음 우선순위는 신규 proof 계층이나 줄 수 중심 리팩터링이 아니라 **실제 Docker 엔진 배포와 장시간 운영 검증**입니다.

## Release Candidate 진입 전

1. Docker engine에서 image build·Compose run·health status·volume ownership 검증
2. 실제 Docker named volume에 71.x 또는 이전 schema 40 DB를 마운트한 upgrade rehearsal
3. recovery bundle 생성·새 컨테이너 restore 훈련
4. 24시간 soak test와 RSS·thread·async task·WAL·lease 추세 기록
5. 실제 OSV.dev·CISA KEV·FIRST EPSS 제한된 read-only 연동
6. line·branch coverage와 핵심 browser E2E 추가
7. upstream Linux·Windows dependency wheelhouse와 `pip --require-hashes`·provenance 고정
8. Windows 실제 실행 smoke와 Windows wheel 재현성, Docker CI 추가

## 이후 검토

- OIDC·SAML·MFA adapter
- PostgreSQL repository protocol 실험
- 객체 저장소 evidence/export adapter
- KMS/HSM과 외부 WORM·trusted timestamp 연계
- Jira·ServiceNow·SIEM integration

합성 성능 수치를 운영 용량으로 표현하지 않으며, 자동 자산 병합·자동 영향판정·분산 배포는 실제 운영 검증 없이 확대하지 않습니다.
