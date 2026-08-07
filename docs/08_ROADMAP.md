# Roadmap

72.0.32 기준 제어 DB와 모든 프로젝트 DB를 분리하고 프로젝트 정체성 기반 복원 차단을 적용했으며, 세션을 제외하는 제어 DB 오프라인 복구, 복원 전 안전 백업, 디스크에 남은 프로젝트 등록정보 보존을 추가했습니다. 로그인은 계정 전역 잠금 대신 사용자명·클라이언트 및 클라이언트 전체 sliding-window 제한을 사용하고 외부 실패 응답을 통일합니다. 운영 프로필은 HTTPS·Secure 쿠키·세션 결합·유휴 만료·서명 백업과 외부 백업을 강제하며, Bearer 토큰은 명시한 프로젝트에만 접근합니다. 서비스 레지스트리·스캐너 가져오기 모듈 분리, XML 구조 제한, Nessus CPE 2.2/CVSS4, Greenbone ref 속성, DB 사용자 인증, 프로젝트 물리 분리, 프로젝트별 무결성·예약 작업, 외부 백업·격리 복원, SMTP·Jira 연동도 유지합니다. schema 42→46 호스트 업그레이드, 9개 합성 스캐너 호환성 매트릭스와 6개 파서 강건성 계약을 제공합니다. 웹훅·Jira HTTP와 SMTP 전송은 사설·메타데이터 주소와 혼합 DNS를 기본 차단하고, 검증된 IP 고정 연결·원래 호스트 TLS 검증·선택형 allowlist를 적용합니다. SMTP 평문 전송은 운영 프로필에서 금지됩니다. 실제 production Compose build·TLS·재기동·영속성 검증을 필수 CI gate로 추가했습니다. OSV·CISA KEV·FIRST EPSS도 DNS 고정·사설망 차단·환경 프록시 무시·응답 크기 제한이 적용된 outbound JSON 경계로 이동했으며, 내장 정적 감사가 새 직접 네트워크 클라이언트와 위험한 실행 경계를 검사합니다. 다음 우선순위는 **실제 스캐너 파일 호환성 표, 실제 SMTP·Jira·intelligence 시험 tenant, Docker CI 결과 축적, 라이브 복원 시간·장시간 운영 측정, MFA/OIDC와 실제 네트워크 경계 rate limit**입니다.

## Release Candidate 진입 전

1. 필수 Docker CI의 image build·Compose run·health status·volume ownership 결과를 축적하고 Linux host에서 재현
2. 실제 Docker named volume에 schema 42 DB를 마운트한 schema 46 upgrade rehearsal
3. 기본 프로젝트와 비기본 프로젝트의 실제 라이브 복원 훈련, 복구시간과 운영자 절차 기록
4. NAS·분리 디스크·백업 agent 환경에서 외부 복사 실패·재시도·보존·복구 검증
5. 24시간 soak test와 RSS·thread·async task·WAL·lease 추세 기록
6. 승인된 Nessus·OpenVAS 실제 내보내기 호환성 표와 실패 샘플 회귀시험
7. 승인된 네트워크에서 실제 OSV.dev·CISA KEV·FIRST EPSS read-only 연동과 provider rate-limit·오류 계약 기록
8. line·branch coverage와 핵심 browser E2E 추가
9. upstream Linux·Windows dependency wheelhouse와 `pip --require-hashes`·provenance 고정
10. Windows 실제 실행 smoke와 Windows wheel 재현성, Docker CI 추가

## 이후 검토

- OIDC·SAML·MFA adapter
- PostgreSQL repository protocol 실험
- 객체 저장소 evidence/export adapter
- KMS/HSM과 외부 WORM·trusted timestamp 연계
- Teams·Slack 알림과 ServiceNow 연동
- Jira OAuth·custom field·양방향 상태 동기화
- SIEM integration

합성 성능 수치를 운영 용량으로 표현하지 않으며, 자동 자산 병합·자동 영향판정·분산 배포는 실제 운영 검증 없이 확대하지 않습니다.
