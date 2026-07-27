# Security

## Supported versions

Only the latest public repository version is actively reviewed. Older internal package versions are not supported through the public repository.

## Reporting a vulnerability

Do not open a public issue for a vulnerability in VulnFlow. Use a private GitHub Security Advisory after the repository is published. Include the affected version, a minimal synthetic reproduction, impact, and suggested mitigation. Do not attach real organizational vulnerability data, credentials, tokens, personal information, or private keys.

There is no emergency-response SLA. This is a personal portfolio project, not a commercial security service.

## Deployment warning

The local helper scripts are intended for loopback-only evaluation. Do not expose the application remotely without explicit authentication, TLS termination, secret management, network restrictions, backup controls, and an independent security review.

## Technical security boundaries

## 비상 Ed25519 proof 키 폐기

- 정상 rotation과 침해 대응을 구분합니다. 침해가 의심된 private key로 교차서명 rotation을 만들지 않습니다.
- 비상 폐기는 별도로 배포·고정한 recovery public key와 replacement key의 공동서명을 요구합니다.
- `invalid_after` 이후 구키로 생성된 proof는 현재 revocation registry가 제공될 때 거부됩니다.
- 오래된 proof ZIP 자체에는 미래 폐기 정보가 없으므로 검증자는 최신 revocation 문서를 별도로 받아야 합니다.
- recovery private key는 평상시 애플리케이션 환경에 두지 않고 사고 대응 창에서만 일시적으로 로드합니다.
- recovery root가 침해된 경우 이 체인을 신뢰하지 말고 별도의 인증된 경로로 새 trust root를 배포합니다.
- 원문 사고 사유와 private key는 SQLite, proof ZIP, 감사 상세에 저장하지 않습니다.


VulnFlow 72.0.11은 로컬 또는 제한된 내부망에서 사용하는 취약점 운영 도구입니다.


## Ed25519 키 전환 신뢰 체인

- proof key transition은 이전 키와 신규 키가 동일한 canonical statement를 각각 Ed25519로 서명합니다.
- 전환 생성 시 두 private key가 모두 필요하지만 SQLite에는 public key, fingerprint, signature, 시각, 사유 SHA-256만 저장합니다.
- proof v3 검증은 외부에서 고정한 공개키를 시작점으로 최대 8단계의 유효한 전환만 따라갑니다.
- proof ZIP에 동봉된 공개키나 전환만으로는 신뢰 루트를 만들지 않으며 `embedded-key-untrusted`로 구분합니다.
- 미래 효력 전환은 proof 생성 시점 이전의 신뢰 근거로 사용하지 않습니다.
- 교차서명은 키 소유권의 연속성만 증명합니다. CA 신원, 신뢰 타임스탬프, HSM 보호, 폐기 목록 배포, 법적 부인방지를 제공하지 않습니다.
- 이전 private key가 침해된 경우 공격자가 악성 successor를 교차서명할 수 있으므로 별도 신뢰 경로를 통한 비상 키 교체가 필요합니다.
- 전환 검증 완료 후 retiring private key는 제거할 수 있지만 외부 검증자는 기존 pinned public key와 관련 proof를 보존해야 합니다.


## Ed25519 공개 검증 proof 경계

- v2 integrity proof는 Ed25519 private key로 서명하고 외부에서 고정한 public key로 검증합니다.
- 번들에 동봉된 public key만 사용하면 서명 일치만 확인할 수 있으며 signer identity 신뢰가 성립하지 않습니다. 결과는 `embedded-key-untrusted`로 표시됩니다.
- private seed는 URL-safe base64 32바이트 형식이며 SQLite·복구 번들·proof ZIP·감사 이벤트·config audit에 저장하지 않습니다.
- public key fingerprint는 `sha256:` 형식으로 별도 신뢰 채널에서 배포해야 합니다.
- 내부 감사 checkpoint는 HMAC을 유지합니다. 공유 HMAC 키가 없는 외부 검증자는 checkpoint 문서가 Ed25519 proof에 봉인됐음을 확인하지만 HMAC 자체를 독립 검증하지는 않습니다.
- Ed25519 서명은 trusted timestamp, WORM, 인증서 기반 조직 신원, HSM 보호 또는 법적 부인방지를 자동 제공하지 않습니다.
- 공개서명 필수 모드(`VULNFLOW_INTEGRITY_PROOF_REQUIRE_PUBLIC_SIGNATURE=1`)는 활성 private key가 없으면 proof 생성을 거부합니다.


## 실행 영수증 보존 archive 경계

- `VULNFLOW_EXECUTION_RECEIPT_RETENTION_DAYS` 기본값은 180일이며 0으로 설정하면 상세 receipt 자동 정리를 비활성화합니다.
- 성공 job과 전달 완료 webhook의 오래된 상세 receipt만 정리하며, 미재처리 dead letter와 replay 연결 receipt는 유지합니다.
- 정리 전 redacted receipt 행의 정렬된 canonical 문서 SHA-256과 유형·결과·subtype 집계를 immutable archive로 저장합니다.
- archive에는 payload·result·error·worker·actor 원문을 저장하지 않습니다.
- receipt DELETE 보호 trigger는 하나의 `BEGIN EXCLUSIVE` transaction 안에서만 임시 교체되며 실패 시 SQLite rollback으로 원복됩니다.
- archive digest는 외부 신뢰 타임스탬프나 WORM 증명이 아니며, 별도 보존이 필요한 조직은 복구 번들과 외부 백업을 함께 사용합니다.
- 상세 행 삭제는 SQLite freelist를 늘려 이후 쓰기에 공간을 재사용하게 하지만 DB 파일을 즉시 축소하지 않습니다. 자동 full VACUUM은 실행하지 않습니다.

## 실행 영수증·Dead Letter 경계

- job·webhook receipt에는 payload·결과·오류·worker·actor 원문을 저장하지 않고 SHA-256과 제한된 구조 metadata만 저장합니다.
- receipt와 replay 연결은 SQLite trigger로 UPDATE·DELETE를 차단합니다.
- 최종 실패 replay는 admin 전용이며 사유와 신규 resource를 감사 hash chain에 기록합니다.
- hash는 낮은 엔트로피 원문의 추측을 완전히 막지 못하므로 receipt API를 외부 공개하지 않습니다.
- replay는 신규 resource 생성이며 기존 부작용을 rollback하거나 exactly-once를 보장하지 않습니다.
- 원본 job/event가 retention으로 삭제되면 receipt만으로 payload를 복원하거나 replay할 수 없습니다.

## 내구성 멱등성 경계

- 원시 `Idempotency-Key`는 DB·감사·로그·진단 snapshot에 저장하지 않고 principal과 결합한 SHA-256만 저장합니다.
- 같은 principal·scope·key의 요청 digest가 다르면 기존 결과를 재사용하지 않고 충돌로 차단합니다.
- job/webhook resource 생성과 ledger 기록은 같은 SQLite write transaction에서 commit 또는 rollback됩니다.
- ledger retention 만료 후 key는 재사용될 수 있으므로 보존기간은 클라이언트의 최대 재시도 기간보다 길어야 합니다.
- idempotency는 권한 검사를 대체하지 않습니다. 키가 같아도 다른 principal에는 별도 namespace가 적용됩니다.
- webhook 전송은 at-least-once이며 수신 시스템은 `X-VulnFlow-Event-ID` 중복 제거를 유지해야 합니다.

## Lifecycle·worker 격리

- scheduler와 background worker는 owning `ApplicationContext`의 DB·lease·서비스만 사용합니다.
- 파싱된 webhook endpoint는 앱별 context에 저장되며 다른 추가 app으로 전파되지 않습니다.
- worker는 작업 claim·heartbeat·complete·fail 전 과정에서 동일 context DB를 사용합니다.
- scheduler lease token과 leader 상태는 앱별 coordination state에 저장됩니다.
- 동일 프로세스 app 격리는 편의·회귀 방지 경계이며, 서로 다른 신뢰영역은 별도 프로세스와 비밀을 사용해야 합니다.

## Operation guard·복원 write barrier

- HTTP 요청, background worker와 scheduler는 owning `ApplicationContext`의 동일 `OperationGuard`로 restore lease를 확인합니다.
- POST·PUT·PATCH·DELETE 요청은 restore lease 확인 후 write activity를 등록하고 다시 lease를 확인해 경합 구간을 닫습니다.
- 요청이 성공하거나 예외로 종료돼도 등록된 write activity를 정리합니다. TTL은 프로세스 강제 종료 시 남은 activity의 최종 안전장치입니다.
- 정책 활성화·SQLite 유지관리·복원 작업의 exclusive lease는 해당 app의 coordination DB·instance ID·fencing token만 사용합니다.
- 추가 app의 restore lease는 다른 app의 HTTP 요청이나 worker를 차단하지 않습니다.
- coordination DB 오류를 침해 탐지로 오인하지 않으며, 복원 전에는 `/cluster`와 실제 활성 작업을 운영자가 함께 확인해야 합니다.
- 동일 프로세스 app 격리는 강한 보안 경계가 아니므로 서로 다른 신뢰영역은 별도 프로세스·DB·coordination DB·비밀을 사용합니다.

## SQLite 트랜잭션 경계

- 작업 큐·클러스터 lease·웹훅 outbox·감사 체인은 공통 `SQLiteTransactionRuntime`을 사용합니다.
- 쓰기 경계는 기본 `BEGIN IMMEDIATE`로 시작하고 정상 종료 시 commit, 예외 시 rollback 후 연결을 닫습니다.
- 감사 이벤트처럼 기존 연결을 전달받는 함수는 새 트랜잭션을 열지 않고 호출자 경계에 참여합니다.
- HTTP·lifespan·worker·scheduler는 owning app의 transaction registry를 활성화하므로 추가 app 간 통계와 DB runtime이 섞이지 않습니다.
- transaction diagnostics에는 DB 경로·SQL·payload·인증정보를 포함하지 않습니다.
- SQLite는 단일 호스트 로컬 저장소 범위이며 분산 트랜잭션이나 PostgreSQL 수준의 격리 의미를 주장하지 않습니다.

## 재시도·중복 실행 경계

- background job의 입력 오류와 지원하지 않는 작업은 자동 재시도하지 않습니다.
- timeout·연결 오류·SQLite busy 계열만 작업별 최대 시도 횟수 안에서 재시도합니다.
- webhook은 408·425·429·5xx와 전송 오류만 재시도하며 3xx·기타 4xx는 terminal failure로 처리합니다.
- `Retry-After`는 최대 3,600초까지만 반영해 외부 응답이 scheduler를 무기한 정지시키지 못하게 합니다.
- retry audit에는 payload·URL·token·secret을 저장하지 않습니다.
- 응답 유실로 동일 webhook이 다시 전달될 수 있으므로 수신 측은 `X-VulnFlow-Event-ID`로 멱등성을 구현해야 합니다.
- 재시도 정책은 exactly-once 또는 분산 트랜잭션을 의미하지 않습니다.

## 기본 통제

- 기본 루프백 바인딩
- viewer·operator·approver·admin 역할 기반 HTTP Basic 인증
- 위험수용 요청자와 승인자 분리, 인증된 승인자 이름 기록
- POST 요청 CSRF 이중 제출 토큰
- CSP, 프레이밍 차단, 캐시 금지, MIME 스니핑 차단
- 업로드 크기·행 수·문자 길이·형식·수치 범위 검증
- CSV 수식 삽입 방어와 HTML 출력 이스케이프
- SQLite 파라미터 바인딩, WAL, busy timeout, trusted_schema 비활성화
- SQLite 복원 전 무결성·필수 스키마 검사와 자동 안전 백업
- 행 버전 기반 동시 수정·승인 충돌 감지
- 주요 변경·승인·유지관리의 감사 이력
- Docker 비루트 사용자

## 인증 주의

- Basic 인증은 HTTPS 없이 네트워크에 노출하면 안 됩니다.
- 운영환경에서는 TLS 역방향 프록시와 강한 비밀번호를 사용합니다.
- `VULNFLOW_USERS_JSON`과 비밀번호를 저장소·로그·셸 기록에 남기지 않습니다.
- 인증 계정·API token이 없으면 기본적으로 애플리케이션 시작이 거부됩니다.
- `VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK=1`은 loopback 전용 개발 실행에서만 사용하며 원격 주소에는 적용되지 않습니다.
- Dockerfile과 Docker Compose는 local admin fallback을 기본적으로 비활성화합니다.
- 72.0.11 릴리스 검증은 UID 10001, 읽기 전용 소스, 영속 데이터 디렉터리, healthcheck, 인증, SIGTERM과 재시작 보존을 container-equivalent 프로세스로 확인합니다. 실제 Docker 엔진의 image layer·volume driver·network 동작은 별도 검증 대상입니다.
- wheel·sdist는 반복 빌드 SHA-256과 설치본 실행을 검증합니다. 72.0.11은 잠금된 Linux CPython 런타임 파일 snapshot을 빈 venv에 복원하고 호스트 `site-packages` 경로가 없음을 확인합니다. 이 snapshot은 upstream wheel hash·서명·provenance 또는 Windows 배포 아티팩트를 대체하지 않습니다.
- 중앙 인증, 세션 폐기, MFA가 필요한 조직 환경은 OIDC·SAML 연동 전까지 배포하지 않습니다.

## 데이터 주의

- 민감한 군·고객·개인정보 원본은 입력하지 않습니다.
- 백업 파일에는 취약점, 승인, 감사 이력이 포함되므로 접근권한과 보관기간을 관리합니다.
- 보존정책 삭제 전 조직의 감사·법적 보존 요구를 확인합니다.
- 위험수용 승인 기능은 조직의 공식 권한 위임과 법적 책임을 대신하지 않습니다.

## 취약점 신고

비공개 운영 시 프로젝트 소유자에게 직접 전달합니다. 공개 저장소로 전환할 경우 비공개 보안 신고 채널을 별도로 구성합니다.

## API 토큰

- API 토큰은 저장소·로그·SQLite에 저장하지 않습니다.
- 쓰기 API는 Bearer 토큰만 허용합니다.
- 토큰은 역할별로 분리하고 유출 시 환경변수 값을 교체한 뒤 프로세스를 재시작합니다.

## 웹훅

- 웹훅 secret은 환경변수에만 두고 데이터베이스에는 endpoint 이름만 저장합니다.
- 원격 URL은 기본적으로 HTTPS만 허용하며, 수신 측에서 HMAC 서명을 원문 바이트 기준으로 검증합니다.
- HTTP 리다이렉트는 따르지 않습니다.
- 웹훅 대상은 관리자 통제 환경변수이므로 변경 시 SSRF·내부주소 접근 위험을 검토합니다.


## 정책 변경 보안

정책 YAML은 alias와 중복 키를 허용하지 않으며 크기·범위·임계값을 검증합니다. 운영 정책은 파일을 직접 교체하는 방식이 아니라 DRAFT 등록, 데이터 영향분석, admin 요청과 approver 승인 후 SQLite 트랜잭션으로 활성화합니다. 정책 승인 요청 이후 데이터나 활성 정책이 바뀌면 승인하지 않습니다.


## 구성 기준선·드리프트

- 기준선에는 `build_config_audit`가 이미 제거한 설정만 저장하며 비밀번호·API 토큰·웹훅 secret·전체 URL을 저장하지 않습니다.
- 기준선 승인과 재기준화는 admin만 수행하며 기존 활성 기준선은 삭제하지 않고 `RETIRED`로 보존합니다.
- 구성 드리프트는 외부 환경변수나 비밀저장소를 수정하지 않으며 승인된 redacted snapshot과 현재 상태를 비교합니다.
- 고위험 경로 분류는 운영 검토 우선순위를 위한 보수적 규칙이며 규정 준수 판정이나 침해 탐지를 대신하지 않습니다.
- 기준선과 검사 기록의 핵심 필드는 SQLite 트리거로 수정·삭제를 차단하지만 외부 WORM이나 독립 SIEM 보존을 대체하지 않습니다.
- 앱 업그레이드, 키 교체, webhook·retention 변경처럼 의도된 변경도 드리프트로 표시될 수 있으므로 변경 승인 후 새 기준선을 검토합니다.

## 승인형 구성 변경

- 초기 기준선 이후 직접 재기준화 UI·API를 차단하고 구성 변경 요청·승인·적용 흐름을 사용합니다.
- 변경 요청자는 자신의 요청을 승인하거나 반려할 수 없습니다.
- 목표 snapshot은 비밀정보 제거 구성만 허용하며 비밀번호·token·secret 원문 필드를 거부합니다.
- 승인 창구 안에서 현재 구성 hash가 승인 목표와 정확히 일치할 때만 새 기준선으로 승격합니다.
- 승인 목표에 포함되지 않은 추가 변경은 `UNAPPROVED` 드리프트로 남습니다.
- 입력된 롤백 계획은 절차 기록이며 VulnFlow가 외부 환경이나 secret manager를 자동 복원하지 않습니다.
- 구성 변경 이력은 내부 SQLite·감사 체인에 남지만 독립 ITSM 승인·외부 WORM·배포 플랫폼 감사를 대체하지 않습니다.

## 복구 번들

- `VULNFLOW_BACKUP_SIGNING_KEY`는 최소 16자 이상으로 설정하고 번들과 분리 보관합니다.
- 서명 필수 운영에서는 `VULNFLOW_BACKUP_REQUIRE_SIGNATURE=1`을 사용합니다.
- 구성 감사는 비밀번호·API 토큰·웹훅 비밀키와 전체 URL을 출력하지 않습니다.
- 복원 전 모든 백그라운드 작업을 완료하거나 취소해야 합니다.
- 11.0은 동일 호스트의 11.0 프로세스 간 복원 잠금과 쓰기 activity를 조정합니다. 11.0 미만 프로세스와 혼합 실행하지 않습니다.
- coordination DB는 운영 DB와 분리하며 같은 로컬 디스크에 둡니다. 네트워크 파일시스템 공유는 지원하지 않습니다.
- 각 프로세스는 고유 `VULNFLOW_INSTANCE_ID`를 사용해야 하며 활성 ID 충돌은 시작 오류로 처리합니다.
- 복원 임대 TTL보다 오래 걸리는 복원은 지원 범위를 벗어나므로 대용량 환경에서는 모든 인스턴스를 중지합니다.

## 감사 무결성

- 감사 이벤트는 SHA-256 해시 체인으로 연결되며 UPDATE가 차단됩니다.
- `VULNFLOW_AUDIT_SIGNING_KEY`는 최소 16자 이상으로 설정하고 SQLite·복구 번들과 분리 보관합니다.
- `VULNFLOW_AUDIT_REQUIRE_SIGNATURE=1`이면 서명 키가 없을 때 시작하지 않습니다.
- 해시 체인은 변조 탐지 기능이며 WORM·외부 증거보전 저장소를 대체하지 않습니다.
- 보존기간 적용은 체인 앞부분의 연속 구간만 제거하고 경계 해시를 anchor로 유지합니다.
- 감사 체인 검증 실패 시 애플리케이션 시작과 11.0 백업·복구 번들 처리를 중단합니다.


## 서명 키 교체

서명 키는 환경변수 키링으로 관리하고 SQLite·복구 번들·로그에 저장하지 않습니다. 키를 교체할 때는 새 키를 추가하고 활성 ID를 변경한 뒤, 시스템 화면의 참조 수가 0이 되기 전까지 과거 키를 제거하지 마세요. 호스트와 모든 신뢰 키가 동시에 탈취된 경우 HMAC 기반 검증만으로는 공격자를 구분할 수 없습니다.

## 13.0 자산·캠페인 데이터

- 자산명, 소유자, 사업부서, 태그는 조직 내부정보일 수 있으므로 외부 공개 데이터베이스에 저장하지 않습니다.
- 자산 CSV는 최대 5MB·5,000행이며 숫자 범위와 상태값을 검증합니다.
- 자산·캠페인 CSV 출력에도 스프레드시트 수식 삽입 방어를 적용합니다.
- 캠페인 쓰기 API는 Bearer token과 operator 이상 역할만 허용합니다.
- 캠페인 완료는 구성원의 활성 finding이 0건일 때만 허용합니다.


## 14.0 조치 검증 보안

- 단일 스캔 미탐지를 자동 종료 근거로 사용하지 않습니다.
- `SCAN_ABSENCE`는 전체 스냅샷에서 연속 미탐지 기준을 충족해야 하며 approver 승인이 필요합니다.
- 재시험·수동 증거 메모에는 비밀번호·토큰·고객 개인정보·민감 원문을 넣지 않습니다.
- 검증 요청 이후 finding이 변경되면 행 버전 불일치로 승인을 차단합니다.
- 검증 완료 finding이 다시 탐지되면 자동 재개방하므로 재발 경보와 감사 이력을 확인합니다.
- `CLOSED`는 조치 검증 승인 결과이며 스캐너 범위·인증 실패·플러그인 누락을 별도로 검토해야 합니다.


## 15.0 검증 증거 파일 보안

- 증거는 웹 정적 디렉터리 밖에 저장하고 무작위 내부 파일명을 사용합니다.
- txt·log·csv·json·pdf·png·jpg만 허용하며 파일 시그니처·UTF-8·JSON 구조를 검증합니다.
- 업로드 파일은 원자적으로 저장하고 가능한 환경에서 `0600` 권한을 적용합니다.
- 다운로드 전 크기와 SHA-256을 다시 검증하고 attachment·`nosniff`·`no-store`로 응답합니다.
- 증거 레코드와 파일은 approver 결정 이후 수정·보관해제하지 않습니다.
- 복구 번들에서 DB 레코드, evidence manifest, 실제 파일 해시를 교차검증합니다.
- 파일 형식·해시 검증은 악성코드 검사를 대체하지 않습니다. 외부에서 받은 증거는 별도 격리·백신·샌드박스 정책을 적용하세요.
- 증거에 인증정보, 개인정보, 고객 원문, 군·기관 비공개 자료를 넣지 않습니다.


## 16.0 증거 격리·보안 검사

- 신규 증거는 `PENDING`으로 저장되며 검사 완료 전 다운로드와 승인 사용이 차단됩니다.
- `builtin`은 EICAR 기준선 확인만 수행하며 실제 악성코드 탐지 성능을 주장하지 않습니다.
- `clamscan` 모드는 shell을 사용하지 않고 설정된 실행 파일을 인자 배열로 호출하며 timeout을 적용합니다.
- `INFECTED` 증거는 관리자 면제가 불가능하며 보관해제 후 안전한 파일로 교체해야 합니다.
- `ERROR` 또는 `NOT_SCANNED`는 admin만 사유를 기록해 `WAIVED`로 전환할 수 있습니다.
- 검사 결과·엔진·서명·면제는 감사 이력과 복구 번들 manifest에 기록됩니다.

## 증거 보관 사슬

- 출처·수집자·수집 시각·원본 SHA-256은 등록 후 변경할 수 없습니다.
- 검사·면제·다운로드·인계·보관해제는 증거별 해시 체인 이벤트로 기록됩니다.
- 보관 사슬은 변조 방지 저장소가 아니라 변조 탐지 구조입니다. DB와 호스트를 완전히 장악한 공격자에 대한 부인 방지는 외부 WORM·KMS·타임스탬프가 필요합니다.
- 다운로드는 파일 무결성과 검사 상태를 확인한 뒤 접근 이벤트를 기록합니다.
- 출처 참조에는 비밀번호·토큰·주민번호·고객 원문을 입력하지 않아야 합니다.


## SBOM·VEX 신뢰 경계

- SBOM 자동 연결은 제품·구성요소·버전 문자열의 명시적 일치만 사용하며 실제 코드 도달성이나 런타임 사용을 증명하지 않습니다.
- VEX `NOT_AFFECTED`, `FALSE_POSITIVE`, `RESOLVED`는 approver 검토 후에만 내보냅니다.
- 외부 SBOM의 vulnerability analysis는 신뢰하지 않고 DRAFT로 가져옵니다.
- SBOM과 VEX에는 비밀번호, 토큰, 상세 고객정보를 포함하지 않습니다.


## OSV 공급망 탐색

- 원격 OSV API endpoint는 HTTPS만 허용합니다. 루프백 HTTP는 테스트 목적으로만 허용합니다.
- HTTP 리다이렉트는 따라가지 않습니다.
- OSV 응답은 외부 입력으로 취급하며 자동 finding 확정·VEX 승인을 수행하지 않습니다.
- CVE alias가 없는 OSV 레코드는 finding으로 승격할 수 없습니다.
- OSV 정성 severity를 실제 CVSS 점수나 조직 영향도로 오인하지 않습니다.


## 다중 스캐너 조정

- 자동 병합은 자산·CVE·구성요소 identity가 일치하는 원천만 대상으로 합니다.
- 같은 scanner-native ID가 다른 canonical identity로 이동하면 가져오기를 거부합니다.
- 원천별 snapshot은 canonical finding과 분리해 보존합니다.
- CVSS·버전·패치 상태 충돌을 자동으로 숨기지 않고 조정 대기 상태로 표시합니다.
- 권위 원천 선택은 operator 이상 역할만 가능하며 이유와 감사 이벤트를 남깁니다.
- partial update가 자산 identity 필드를 생략한 경우 기존 source record의 identity를 상속하지만, 명시적으로 다른 identity를 제공한 경우에는 차단합니다.

## 자산 식별·병합 보안

- scanner asset ID는 scanner별 scope로 분리하며 다른 scanner의 동일 문자열만으로 같은 자산을 확정하지 않습니다.
- CMDB ID·cloud instance ID·inventory ID는 권위 식별자로 취급하므로 입력 권한과 원본 시스템 신뢰도를 별도로 관리해야 합니다.
- FQDN·IP·MAC·hostname은 재사용·변경 가능성이 있어 단일 보조 신호만으로 자동 병합하지 않습니다.
- hostname은 environment scope를 포함하지만 환경값 오류가 있으면 잘못된 후보가 생성될 수 있습니다.
- operator 병합은 finding·source 관측·식별자를 이동하는 고영향 작업이며 사유와 감사 이력을 남깁니다.
- 대기 중인 위험수용·조치검증이 있는 중복 finding은 먼저 처리해야 병합할 수 있습니다.
- 병합 원본 자산과 finding은 삭제하지 않고 RETIRED·ARCHIVED 및 merged-into 참조로 보존합니다.
- 자산 식별자 core 필드, 후보 근거, 병합 이력은 SQLite 트리거로 직접 수정·삭제를 차단합니다.
- 이 기능은 자산 소유권 증명이나 CMDB 정합성 보증을 대신하지 않습니다.


## Application context

VulnFlow 35.0 stores the runtime namespace in an application-owned context. Its
structural diagnostic snapshot exposes setting names only and must not be changed
to serialize passwords, API tokens, signing keys, webhook secrets or environment
values. Additional app instances are a construction/testing boundary, not a claim
of isolated multi-tenant runtimes within one process.


## Immutable runtime dependency boundary

VulnFlow 36.0 copies environment-derived settings and service dependencies into
read-only containers. Diagnostic snapshots expose structural names and counts only;
they must never serialize passwords, API tokens, signing keys, webhook secrets or
configuration values. The `app.main` namespace remains a compatibility overlay for
legacy tests and local integrations. It is not a secure dynamic configuration API,
and concurrent isolated multi-tenant apps within one Python process are not claimed.

## 다중 app 인스턴스 격리

- 추가 `create_app()` 인스턴스는 별도 router runtime namespace를 사용해 HTTP route 설정과 service override의 상호 덮어쓰기를 차단합니다.
- request runtime에는 serving app context와 인증 주체만 저장하며 비밀번호·token·secret 원문은 포함하지 않습니다.
- 기본 `app.main` compatibility namespace는 기존 테스트와 로컬 통합을 위해 유지됩니다.
- lifecycle scheduler, background worker, 파일 저장소와 coordination DB는 단일 호스트 운영 모델을 전제로 하며 동일 프로세스 멀티테넌트 보안 경계를 제공하지 않습니다.
- 서로 다른 신뢰영역을 운영하려면 프로세스·DB·저장 디렉터리·인증 비밀을 모두 분리합니다.


## Portable integrity proof bundles

- Proof creation requires an active audit signing key and first verifies the current audit chain.
- The ZIP contains audit event actors, summaries and detail JSON because those values are required for hash recomputation; do not treat it as a sanitized public report.
- The ZIP never stores the signing secret, database path, finding rows, credentials, job payloads, webhook payloads or execution-result plaintext.
- File hashes, proof HMAC and the final signed checkpoint are all verified before a proof is accepted.
- HMAC uses a shared secret and does not provide public-key non-repudiation. Anyone with the secret can create a valid signature.
- Key retirement checks include retained proof ZIP references. Keep historical keys available for as long as their proofs must be verified.
- Export retention or storage eviction can remove unpinned proof files. Pin required records or copy them to independently controlled immutable storage.
- A proof is not a trusted timestamp, legal hold or WORM archive. Version 52 can include a locally signed append-only transparency-log view and independently signed mirror receipts, but it is not a globally discoverable public log or an automatic network gossip service.

## Proof transparency-log boundary

- The transparency-log private key is never stored in SQLite or recovery bundles.
- Log verification requires an externally pinned Ed25519 log public key.
- Entry and head rows are immutable and form separate SHA-256 chains.
- Minimum tree-size and trusted-head checks protect only verifiers that retain prior state.
- A first-time verifier cannot detect a newer head that was never delivered.
- Log timestamps are signed operator assertions, not trusted time evidence.


## Transparency mirror gossip boundary

- Mirror private keys are never stored in SQLite or recovery bundles.
- A receipt is an independently signed observation of an existing signed log head; it is not a new trust root.
- Quorum is meaningful only when mirror key custody and operators are genuinely independent.
- A verifier should retain at least one accepted receipt digest outside the proof bundle.
- A first-time verifier can still be isolated on a stale but internally consistent mirror view.
- Receipt timestamps are not externally trusted timestamps, and mirror receipts do not provide WORM storage or legal non-repudiation.

- 72.0.11 release provenance는 소스와 배포 산출물의 SHA-256 연결 및 Ed25519 DSSE 검증 계약을 확인합니다. 기본 릴리스 리허설 키는 메모리에서 생성되는 비신뢰 시험 키이며, 외부 조직 신원·하드웨어 키 보관·공개 transparency log 또는 신뢰 타임스탬프를 의미하지 않습니다.


## Signed offline deployment bootstrap boundary

- 72.0.11 requires an out-of-band release-kit SHA-256 and Ed25519 public-key fingerprint before extracting or executing kit content.
- The bootstrap rejects ZIP traversal, duplicate paths, symlinks, runtime-snapshot path changes, file-size changes, and SHA-256 changes.
- Initial credentials, API tokens, and HMAC keys are generated per deployment and stored only in mode-0600 JSON files; verification reports contain paths and status only.
- The deployment binds to loopback, disables local-admin fallback, and verifies authentication, health checks, bounded SIGTERM, and SQLite persistence over two process cycles.
- The Linux CPython runtime snapshot remains ABI-, machine-, and libc-specific. It is not an upstream wheelhouse, package-provider signature, or public provenance service.
- TLS reverse proxy configuration, systemd registration, actual Docker volume/network behavior, Windows, and Python 3.12 remain outside this rehearsal.


## Scheduler lease authority

- Scheduler work is allowed only while the local instance ID and cached fencing token match the currently active coordination-database lease.
- A stale local leader flag is cleared immediately when the authoritative lease is missing, expired, transferred, or has a different fencing token.
- Cluster status reports the authoritative lease holder/token separately from the local role.
- Real-process cluster verification uses dynamic ports and validates the expected instance identity so an orphaned process cannot satisfy readiness for a newly spawned node.

## Evidence scanner status

The built-in scanner only detects the EICAR test marker and records `BASELINE_ONLY`. It does not issue a malware-clean verdict. Download or verification approval requires an actual `CLEAN` result from the configured scanner or an explicit administrator `WAIVED` decision with a recorded reason.
