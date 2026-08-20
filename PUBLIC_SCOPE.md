# Public repository scope

이 패키지는 제품 파일럿 검토와 기술 공개를 위한 공개용 소스 저장소입니다.

## 포함

- 전체 애플리케이션 소스
- 합성 샘플 데이터와 정책
- 핵심 운영 문서
- 대표 화면과 아키텍처 이미지
- 핵심 업무 흐름을 검증하는 721개 수집형 핵심 회귀시험과 Chromium 브라우저 E2E 3개
- 프로젝트별 SMTP 이메일 알림과 Jira Cloud 이슈·댓글 연동
- 프로젝트별 파일럿 준비도 점검과 고객용 경영진 보고서
- 책임별 서비스 레지스트리와 CSV/XLSX·Nessus/OpenVAS 가져오기 모듈 경계
- schema 42→46 업그레이드, 9개 스캐너 fixture, 6개 파서 강건성 계약, SMTP·Jira 읽기 전용 연결 진단을 위한 운영 검증 도구
- 원본 파일명과 치환표를 제외하는 스캐너 익명화 수집 번들 및 잔존 구조화 식별자 검사
- 제어 DB와 모든 프로젝트 DB의 물리 분리, 보존형 단일 DB 마이그레이션, 프로젝트 정체성 기반 복원 차단
- 세션을 제외하는 제어 DB 오프라인 복구 번들, 복원 전 안전 백업과 프로젝트 등록정보 보존
- 계정 전역 잠금 없는 sliding-window 로그인 실패 제한과 통일된 외부 인증 오류
- 운영 보안 프로필, 세션 유휴 만료·브라우저 결합, Bearer 토큰 프로젝트 범위 fail-closed
- 운영 Docker/Nginx TLS 구성 계약, 실제 로컬 Nginx/Uvicorn TLS 리허설, 컨테이너 등가 영속성 리허설
- schema 46을 유지하는 migration·trigger·search·backfill 모듈 분리와 전달 헤더 위조 방어
- 격리형 12회 runtime soak, 원자적 SQLite 백업 발행, 동시 쓰기·락·프로세스 중단 장애 주입 리허설
- SMTP STARTTLS/SMTPS DNS 고정 연결·사설망 차단·호스트 allowlist와 실제 로컬 STARTTLS 리허설
- OSV·CISA KEV·FIRST EPSS의 DNS 고정 bounded JSON 전송, 응답 크기 제한과 환경 프록시 무시
- 직접 네트워크 클라이언트·검증 해제 TLS·승인되지 않은 raw socket·shell·동적 실행을 검사하는 내장 정적 보안 경계 감사
- 연동 진단과 스캐너 호환성 평가·보고서 모듈 경계 분리
- 실제 production Compose build·TLS·재기동·named-volume 영속성을 요구하는 공개 CI gate
- pinned 개발 의존성을 wheelhouse로 내려받아 SHA-256을 기록하고 인덱스 없이 새 가상환경에 재설치하는 공개 CI gate
- Requests와 전용 전이 의존성을 production runtime에서 제거하고 검토된 오프라인 관리 스크립트만 Docker image에 포함
- Chromium과 별도로 실제 HTTP 폼·CSRF·역할 분리를 검증하는 서버 렌더링 workflow E2E
- packaged runtime dependency manifest와 production fail-closed 설치 버전 검증
- 서명된 release index에서 schemaVersion을 가져오는 오프라인 배포 경계
- 검증된 배포 identity, 이전 배포 인벤토리·원자적 rollback·보존 정책과 standalone signed-kit 관리 도구
- 이전 배포 전체 트리 HMAC seal, 위변조 후보 fail-closed 격리, legacy history 명시적 adoption
- 배포 이력 current/retired HMAC keyring, 원자적 키 회전·재봉인, 0600 keyring 백업/검증 복원과 외부 체인형 감사 로그
- 로컬 keyring·audit 동시 rollback을 탐지하는 외부 Ed25519 witness receipt, trusted public key와 audit prefix 검증
- keyring·audit·witness를 한 시점으로 묶는 private recovery bundle, 외부 최소 witness 검증과 중단 복구 journal
- 중단 복구 journal의 파일 크기·SHA-256 inventory, 별도 HMAC 키로 인증된 transaction manifest, signed offline startup preflight, legacy journal 명시적 수동 복구
- recovery-journal HMAC 키의 상태 조회, 대상 결합형 0600 백업, pending journal 사전검증 복원, 무중단 키 회전과 감사 실패 rollback
- 외부 검증 결과의 pass/fail/blocked/unavailable/not-provided 분리, 하위 명령 종료코드·JSON 보고서·실행 로그 SHA-256 결합
- collector 소유 마커 기반 안전한 증거 디렉터리 교체, 재귀형 증거 manifest, 독립 증거 디렉터리 검증기
- 고객 스캐너 corpus 심볼릭 링크·파일 수·총바이트 제한, 단일 읽기 기반 파싱·해시, 파일명·원본 오류문구 비노출
- 요청자 서명으로 소스 snapshot·challenge·공개키·실행 래퍼를 결합하는 결정론적 외부 검증 runner kit, 안전한 ZIP 검증·추출·실행 전 재검증
- manifest 전체 파일 해시 검증, unlisted 파일 제외 private execution snapshot, 실행 전·후 source attestation 서명
- 서명된 외부 검증 challenge에 승인된 운영자 Ed25519 key ID·fingerprint를 고정하고, 다른 private key의 응답·runner 실행을 사전 차단
- 요청자 서명 hash-chain acceptance ledger, 동일 응답 replay 차단, 같은 request의 상충 응답 equivocation 차단
- 로컬 실행·Docker 구성·SBOM

## 제외

- 실제 군·고객·기업 데이터
- 로컬 SQLite DB, 프로젝트별 증거파일, 복구 번들, 외부 백업 복사본과 리허설 보고서
- 비밀번호, API token, private signing key
- 14MiB runtime dependency snapshot
- wheel·sdist와 서명형 전체 릴리스 키트
- 내부 release journal과 대량 생성 검증 보고서
- 포트폴리오 DOCX 등 개인 지원문서

## 전체 기준본과의 관계

공개본은 72.0.96 애플리케이션 소스를 유지하지만, 저장소 가독성과 용량을 위해 공급망·릴리스 검증 산출물을 제외했습니다. 전체 제출 기준본은 별도 보관하며 공개 저장소와 섞지 않습니다.

## Windows 외부 검증 경계

72.0.57은 Windows에서 생성된 경로를 POSIX 구분자로 비교하던 마지막 공개 회귀시험 계약을 수정합니다. 서명형 오프라인 배포 활성화·복구 계층은 POSIX 전용이며 Windows에서는 명시적으로 skip됩니다. skip은 PASS로 계산하지 않습니다.

72.0.58은 Windows 외부 검증 실행에서 드러난 Compose 직접 실행 import, 브라우저 가시성 assertion, bounded-soak warm-up 측정 계약을 수정합니다. 제품 기능이나 schema는 변경하지 않습니다.

72.0.60은 격리 라우터 모듈이 종료된 FastAPI 애플리케이션을 역참조하지 않도록 lifespan 종료 계약을 추가하고, 동일 애플리케이션 재시작 시 전체 의존성을 재결합합니다. 제품 기능과 schema는 변경하지 않습니다.

72.0.61은 Windows CPython 3.13에서 synthetic `ModuleType` 객체가 framework metadata에 남는 경계를 제거하기 위해 격리 라우터 globals의 holder를 `SimpleNamespace`로 변경합니다. 애플리케이션별 globals 격리, 재시작, schema와 제품 기능은 유지됩니다.


72.0.63은 FastAPI 0.140.9가 child router를 원본 참조로 유지하는 동작과 무관하게, 격리 `APIRoute`를 애플리케이션 라우터로 직접 이전하고 private source route list를 비웁니다. 276개 route table, 재시작, schema와 제품 기능은 유지됩니다.


72.0.67은 라우터 소스 재읽기와 `compile/exec` 재실행을 제거합니다. 이미 import된 router module의 함수 code object와 APIRoute 메타데이터를 앱별 private namespace로 복제하며, 기존 route 276개·schema 46·격리 수명주기와 callable cache 정리 경계는 유지합니다.

72.0.68은 `pilot` 라우터 4개를 요청별 FastAPI `ApplicationContext` 의존성으로 전환합니다. 이 라우터는 앱별 endpoint 함수·globals·APIRoute 복제 없이 정상 등록되며, 나머지 15개 라우터만 기존 호환 복제 경계를 유지합니다.

72.0.69는 요청 범위 DI 라우터를 FastAPI의 공개 `app.include_router()` API로 등록합니다. 72.0.70은 FastAPI 0.140.9의 lazy route-context를 유효 라우트 inventory로 펼쳐 직접 272개와 공유 pilot 4개를 정상 276개로 검증합니다.

72.0.71은 legacy 라우터 함수 기본값에서 FastAPI가 파생한 alias·annotation을 복제하지 않고 생성자 당시 metadata로 복원하며, legacy clone과 공유 DI router include를 포함한 전체 라우터 조립을 하나의 재진입 잠금으로 직렬화합니다. 제품 route·schema·HTTP 동작은 변경하지 않습니다.


## 72.0.72 제품 완성 동결

72.0.72부터 현재 로컬 취약점 운영 파일럿 범위의 신규 기능 개발을 동결합니다. 스캐너 데이터가 없는 빈 프로젝트는 더 이상 파일럿 시작 가능으로 표시하지 않으며, 조치 검증 화면은 내부 상태값 중심의 이력 목록 대신 검토 대기 작업을 우선하는 큐로 정리했습니다. 이후 변경은 실제 스캐너 호환성, 사용자 파일럿 또는 보안·신뢰성 결함에서 확인된 문제에 한정합니다.


## 72.0.74 scanner host-identity patch

72.0.74은 72.0.72의 기능 동결 정책을 유지하면서, scanner host 값을 IP로 추정하던 느슨한 정규식 때문에 `db01`, `cafe`, `face01`, `dead.beef` 같은 정상 hostname이 IP로 오인되던 결함을 수정했습니다. Python `ipaddress` 기반 정확한 분류를 사용하고, 잘못된 Nessus `host-ip`는 canonical IP를 오염시키지 않도록 warning으로 처리합니다. 72.0.73의 CSV/XLSX fail-closed 무결성 보호, schema 46, dependency lock, 제품 범위는 그대로 유지합니다.


## 72.0.75 scanner import contract patch

72.0.75는 공격검증에서 재현된 preview/apply 계약 및 자산 식별자 정확성 결함을 최소 수정합니다. 명시적 FQDN/IP/MAC은 preview에서 reconciliation과 동일한 규칙으로 검증하고, bracketed IPv6는 중앙 IP 정규화에서 일관되게 처리해 가짜 HOSTNAME alias가 생기지 않게 합니다. 또한 multiline CSV와 앞부분 빈 행이 있는 XLSX의 오류·미리보기에서 실제 물리 행번호를 유지합니다. UTF-16 generic CSV 지원은 추가하지 않으며 문서화된 UTF-8 계열 및 CP949/EUC-KR 범위는 그대로입니다. schema 46, dependency lock, remediation/reconciliation 상태 모델과 제품 범위는 변경하지 않습니다.

## 72.0.76 scanner import integrity patch

72.0.76은 72.0.75 이후 공격검증에서 재현된 세 가지 결함을 최소 수정합니다. CSV/XLSX의 중복 헤더 자동 suffix가 실제 헤더명과 다시 충돌할 때 셀 값이 조용히 덮어써지는 문제를 막고, 명백히 잘못된 FQDN을 중앙 자산 식별자 경계에서 거부합니다. 또한 scanner source 이름의 대소문자만 달라진 재가져오기가 동일 source record identity와 일관되게 reconciliation되도록 수정합니다. schema 46, dependency package pins, scanner connector 및 기능 동결 범위는 변경하지 않습니다.


## 72.0.77 scanner source and IDNA identity patch

72.0.77은 72.0.76 이후 공격검증에서 재현된 scanner-source 및 국제화 FQDN 동치성 결함을 최소 수정합니다. snapshot absence reconciliation이 SQLite의 ASCII 중심 `LOWER()`에 의존하지 않고 Python Unicode `casefold()` 경계를 사용하도록 하고, 대소문자만 다른 동일 source가 canonical `source_count`에서 중복 집계되지 않게 합니다. 또한 안정적으로 round-trip되는 IDNA Unicode/punycode FQDN 표기를 동일 자산 식별 신호로 취급하되, 권위 scanner asset ID가 서로 다른 경우 자동 병합하지 않습니다. schema 46, dependency package pins, scanner connector 및 기능 동결 범위는 변경하지 않습니다.


## 72.0.78 IDNA canonicalization and scanner-source normalization patch

72.0.78은 72.0.77 이후 공격검증에서 재현된 두 가지 identity integrity 결함을 최소 수정합니다. FQDN 정규화가 Unicode `casefold()`와 Python built-in IDNA 호환 매핑을 먼저 적용해 IDNA2008에서 서로 다른 `faß.de`/`fass.de`, sigma/final-sigma 도메인을 하나의 자산으로 잘못 병합하던 문제를, 이미 고정된 `idna` 패키지의 non-transitional IDNA2008/UTS #46 A-label canonicalization으로 교체합니다. 또한 scanner source가 NFC/NFD처럼 canonically equivalent한 Unicode 표기로 들어와도 동일 source key로 취급되도록 NFC 정규화 후 casefold를 적용합니다. 기존 72.0.77 Unicode FQDN identifier는 U-label compatibility lookup으로 계속 연결되며 schema 46, dependency package pins, scanner connector 및 기능 동결 범위는 변경하지 않습니다.

## 72.0.79 Unicode source/canonical identity parity patch

72.0.79는 72.0.78 이후 공격검증에서 재현된 세 가지 import identity-integrity 결함을 최소 수정합니다. scanner-independent canonical key의 component/product text를 Unicode NFC 후 casefold로 정규화해 NFC/NFD 차이만 있는 동일 구성요소가 별도 canonical finding으로 분리되지 않게 합니다. 자동 생성 finding ID의 identity fields도 동일한 Unicode canonicalization을 사용해 같은 scanner/source row가 composed/decomposed 표기만으로 다른 source record가 되지 않게 합니다. preview와 apply의 source-native finding ID 중복 판정도 source-record 계약인 NFC + casefold 기준으로 맞춰, preview에서 허용한 배치가 apply에서 뒤늦게 거부되는 불일치를 제거합니다. schema 46, dependency package pins, scanner connector 및 기능 동결 범위는 변경하지 않습니다.



## 72.0.96 Greenbone CSV multi-CVE EPSS attribution fail-safe

72.0.96은 Greenbone 상세 CSV의 `EPSS score`/`EPSS percentile`이 NVT의 highest-severity CVE 대표값인데 CSV 행 자체에는 그 대표 CVE ID가 없는 경계를 fail-safe로 처리합니다. 72.0.95까지는 `CVE references`가 여러 개인 행을 canonical CVE별로 확장하면서 하나의 EPSS tuple을 모든 CVE에 복제해 다른 CVE의 우선순위 입력값을 잘못 채울 수 있었습니다. 72.0.96은 단일-CVE 행의 EPSS 보존은 유지하고, 다중-CVE 행은 대표 CVE를 추측하지 않고 CVE별 EPSS를 비우며 parser warning을 남깁니다. 72.0.95의 XML nested `cve@id` 기반 정확한 귀속, schema 46과 dependency package pins는 변경하지 않습니다.


## 72.0.95 Greenbone XML per-CVE EPSS attribution

72.0.95는 Greenbone GMP XML result NVT의 `epss/max_severity`와 `epss/max_epss`가 각각 nested `cve@id`로 지정하는 대표 CVE를 확인한 뒤 해당 CVE의 canonical `epss`/`epss_percentile`에만 값을 귀속합니다. 72.0.94는 `max_severity` 값을 보존했지만 다중-CVE NVT에서 그 값을 모든 expanded CVE 행에 복제해 다른 CVE의 우선순위 입력값을 잘못 덮을 수 있었습니다. 72.0.95는 XML이 명시한 두 대표 CVE 외의 CVE에는 scanner-supplied EPSS를 임의로 복제하지 않습니다. schema 46과 dependency package pins는 변경하지 않습니다.

## 72.0.94 current Greenbone XML EPSS preservation

72.0.94는 Greenbone GMP XML result NVT의 `epss/max_severity/score`와 `epss/max_severity/percentile`을 canonical `epss`/`epss_percentile`로 보존합니다. 72.0.93은 현재 상세 CSV EPSS 필드는 보존했지만 XML adapter가 공식 GMP EPSS 구조를 읽지 않아 XML import에서 우선순위 입력값이 유실될 수 있었습니다. 72.0.94는 Greenbone의 `max_severity` 대표 값을 읽되, 당시에는 다중-CVE NVT의 per-CVE 귀속까지 구분하지 않았습니다. schema 46과 dependency package pins는 변경하지 않았습니다.

## 72.0.93 current Greenbone EPSS preservation

72.0.93은 현재 Greenbone OPENVAS SECURITY INTELLIGENCE/OPENVAS REPORT 상세 CSV의 `EPSS score`와 `EPSS percentile`을 scanner-specific import에서 canonical `epss`/`epss_percentile`로 보존합니다. 72.0.92는 현재 상세 CSV를 정상 감지하고 CVE/endpoint identity를 보존했지만 이 두 공식 risk-intelligence 필드를 adapter 단계에서 버려 import 후 우선순위 입력값이 0으로 떨어질 수 있었습니다. 72.0.93은 기존 CVE/endpoint, Customizable CSV, XML, host-level identity 동작을 유지하며 schema 46과 dependency package pins는 변경하지 않습니다.

## 72.0.92 current Greenbone Security Intelligence CSV compatibility

72.0.92는 현재 Greenbone OPENVAS SECURITY INTELLIGENCE/OPENVAS REPORT의 상세 CSV export에서 사용하는 `Vulnerability name`, `CVE references`, `Port/Protocol`, `Host name`, `IP address` 계열 헤더를 OpenVAS CSV로 자동 감지하고 CVE identity를 보존합니다. 72.0.91은 `CVE references`를 CVE 헤더/값 alias로 인식하지 않아 이러한 공식 export가 generic CSV로 처리되고 유효 finding이 0건이 될 수 있었습니다. 72.0.92는 현재 Greenbone 프로필을 scanner-specific adapter로 라우팅하고 `CVE references`를 정규화하며, 기존 Customizable CSV `CVEs`/`VT Name`, legacy `NVT Name`, `Port` + `Port Protocol`, combined `Port/Protocol`, XML 및 host-level identity 동작은 유지합니다. schema 46과 dependency package pins, feature-frozen 제품 범위는 변경하지 않습니다.

## 72.0.91 Greenbone/OpenVAS customizable CSV schema compatibility

72.0.91은 Greenbone/OpenVAS Customizable CSV에서 endpoint가 `Port`와 `Port Protocol` 두 컬럼으로 분리되고 취약점명이 `VT Name`으로 제공되는 형식을 정상화합니다. 72.0.90은 `Port Protocol`을 canonical endpoint에 합치지 않아 같은 숫자 포트의 TCP/UDP finding이 충돌할 수 있었고, `VT Name`을 scanner auto-detect/product alias로 인식하지 못했습니다. 72.0.91은 `Port` + `Port Protocol`을 `port/protocol` endpoint로 결합하고 `VT Name` 기반 CSV를 OpenVAS adapter로 자동 감지합니다. 기존 `Port/Protocol`, legacy `NVT Name`/`Port`, XML 및 host-level identity 동작은 유지하며 schema 46, dependency package pins와 feature-frozen 제품 범위는 변경하지 않습니다.

## 72.0.90 Greenbone/OpenVAS modern CSV Port/Protocol identity integrity

72.0.90은 최신 Greenbone/OpenVAS CSV export의 `Port/Protocol` 헤더를 endpoint source로 인식하지 못하던 결함을 수정합니다. 72.0.89는 legacy `Port` 헤더만 읽어 현대 CSV에서 `443/tcp`, `8443/tcp`가 component identity에서 사라졌고, 동일 NVT/CVE가 같은 canonical key로 충돌해 배치 전체가 거부될 수 있었습니다. 72.0.90은 `Port/Protocol`과 기존 `Port`를 모두 지원하며 XML 동작, host-level identity, schema 46, dependency package pins와 feature-frozen 제품 범위는 변경하지 않습니다.

## 72.0.89 Greenbone/OpenVAS multi-port finding identity integrity

72.0.89은 Greenbone/OpenVAS CSV·XML에서 동일 NVT/CVE가 같은 자산의 여러 숫자 포트에 각각 존재할 때 `Port`/`<port>`를 notes에만 남기고 canonical component identity에서는 버려 서로 다른 endpoint finding이 같은 canonical key로 충돌하던 결함을 수정합니다. `443/tcp`, `8443/tcp`처럼 구체적인 non-zero 숫자 endpoint는 component identity에 보존하고, `0/tcp`, `general/tcp`, 빈 포트 같은 host-level 값은 기존 component identity를 유지합니다. schema 46, dependency package pins, 지원 scanner connector 범위와 feature-frozen 제품 범위는 변경하지 않습니다.

## 72.0.88 Tenable/Nessus multi-port finding identity integrity

72.0.88은 Tenable `.nessus`가 같은 취약점 플러인을 동일 호스트의 여러 포트에서 각각 `ReportItem`으로 내보낼 수 있는데도, port/protocol을 notes에만 남기고 canonical component identity에서 버려 같은 CVE/plugin의 multi-port 결과를 하나로 충돌시키던 결함을 수정합니다. `port>0` 결과는 component identity에 `port/protocol` endpoint를 보존해 서로 다른 포트 finding을 독립적으로 가져오며, `port=0` host-level 플러그인은 기존 component identity를 유지합니다. schema 46, dependency package pins, 지원 scanner connector 범위와 feature-frozen 제품 범위는 변경하지 않습니다.

## 72.0.87 Tenable/Nessus SMBIOS UUID sentinel integrity

72.0.87은 Tenable `.nessus`에서 `host-uuid`가 없을 때 `bios-uuid`를 곧바로 authoritative scanner asset ID로 승격하던 경계에서, SMBIOS가 UUID 부재를 뜻하도록 정의한 all-zero/all-FF 값을 실제 자산 ID처럼 신뢰하던 결함을 수정합니다. 해당 sentinel은 자산 ID로 사용하지 않고, `mcafee-epo-guid`가 있으면 기존 fallback을 계속 사용합니다. `host-uuid` 우선순위와 유효한 BIOS UUID 동작은 유지합니다. 이 수정은 서로 다른 장비가 동일한 부재 sentinel 때문에 하나의 VulnFlow 자산으로 false merge되는 것을 막습니다. schema 46, dependency package pins, 지원 scanner connector 범위와 feature-frozen 제품 범위는 변경하지 않습니다.

## 72.0.86 Greenbone/OpenVAS asset identity continuity

72.0.86은 Greenbone XML result host의 `<asset asset_id="...">` UUID를 버리던 결함을 수정합니다. scanner-provided stable asset UUID를 canonical `asset_id`로 보존해 동일 자산의 IP/FQDN이 바뀌어도 별도 자산/finding으로 분리되지 않게 하며, UUID가 없는 export에서는 기존 IP/FQDN/hostname identity 경계를 유지합니다. schema 46, dependency package pins, 지원 scanner connector 범위와 feature-frozen 제품 범위는 변경하지 않습니다.

## 72.0.85 Greenbone/OpenVAS delta-result integrity

72.0.85는 Greenbone/OpenVAS XML delta report에서 현재 `<result>` 안의 비교용 과거 `<result>`를 독립 active finding으로 중복 import하던 결함을 수정합니다. 일반 report XML과 direct result 문서는 유지하면서 첫 importable result 경계에서 재귀 탐색을 멈춰 historical delta result가 현재 remediation 데이터에 섞이지 않게 합니다. schema 46, dependency package pins, 지원 scanner connector 범위와 feature-frozen 제품 범위는 변경하지 않습니다.

## 72.0.84 Tenable/Nessus patch availability semantics

72.0.84는 Tenable `.nessus`의 구조화된 `has_patch` boolean을 무시하고 일반 `solution` 텍스트만으로 `patch_available`을 추론하던 결함을 수정합니다. `has_patch`가 명시되면 그 값을 우선하고, malformed 값은 fail-closed로 0 처리하면서 parser warning을 남깁니다. `has_patch`가 생략된 구형 export에만 기존 solution-text fallback을 유지합니다. 이 수정은 우선순위 점수와 mitigation-required 판정에 잘못된 패치 가용성이 전달되는 것을 막습니다. schema 46, dependency package pins, 지원 scanner connector 범위와 feature-frozen 제품 범위는 변경하지 않습니다.

## 72.0.83 Greenbone/OpenVAS remediation semantics

72.0.83은 실제 Greenbone/OpenVAS 형식 공격검증에서 재현된 remediation 의미론 결함을 수정합니다. 명시적 `Solution Type`이 있는 경우 `VendorFix`만 `patch_available=1`로 정규화하고 `Workaround`, `Mitigation`, `NoneAvailable`, `WillNotFix` 및 기타 비-`VendorFix` 타입은 0으로 처리합니다. 타입이 생략된 구형 export는 기존 solution-text fallback을 유지합니다. 이 수정은 우선순위 점수와 mitigation-required 판정에 잘못된 패치 가용성이 전달되는 것을 막습니다. schema 46, dependency package pins, 지원 scanner connector 범위와 feature-frozen 제품 범위는 변경하지 않습니다.

## 72.0.82 documentation consistency gate

72.0.82는 72.0.81에서 재현된 운영 문서 drift를 수정합니다. 공개 회귀시험 수, schema, 제어 DB와 기본 프로젝트 DB 경로, 로그인 sliding-window 기본값을 실행 코드에서 파생해 README·PUBLIC_SCOPE·PUBLIC_VERIFICATION·운영/RBAC 문서·환경 예제와 대조하며, 불일치하면 공개 CI가 fail-closed 합니다. 애플리케이션 기능, schema 46, dependency package pins, scanner connector 및 feature-frozen 범위는 변경하지 않습니다.

## 72.0.80 asset/reconciliation state integrity patch

72.0.80은 72.0.79 이후 공격검증에서 재현된 두 가지 무결성 결함을 최소 수정합니다. 일반 자산 식별자와 HOSTNAME 환경 scope, fallback asset identity를 Unicode NFC 후 casefold로 정규화해 canonically equivalent NFC/NFD 표기가 재가져오기 거부나 자산 분리를 만들지 않게 합니다. 또한 충돌 조정에서 선택한 source record가 snapshot에서 ABSENT인 동안에는 그 결정을 canonical aggregate와 unresolved 판단에 적용하지 않고, 해당 source가 다시 PRESENT로 돌아오면 기존 결정을 다시 유효하게 적용합니다. schema 46, dependency package pins, scanner connector 및 기능 동결 범위는 변경하지 않습니다.
