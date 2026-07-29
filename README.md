# VulnFlow 72.0.12

[![public-ci](https://github.com/bbk0416/vulnflow/actions/workflows/public-ci.yml/badge.svg)](https://github.com/bbk0416/vulnflow/actions/workflows/public-ci.yml)


> FastAPI·SQLite 기반의 로컬 취약점 운영 플랫폼 — 스캐너 결과를 수집한 뒤 자산 식별, 우선순위, 조치, 승인, 증거, 감사와 복구까지 연결합니다.
>
> A local vulnerability-operations platform that connects scanner findings to prioritization, remediation, approval, evidence, audit and recovery.

![VulnFlow architecture](assets/architecture.png)

## 프로젝트 목적

취약점 스캐너는 결과를 만들어 주지만, 조직은 그 이후에도 중복 정리, 자산 식별, 우선순위 결정, 담당자 지정, 조치 확인, 예외 승인과 감사 대응을 수행해야 합니다. VulnFlow는 이 운영 흐름을 하나의 로컬 애플리케이션으로 구조화한 개인 Security Engineering 프로젝트입니다.

**이 프로젝트는 취약점 스캐너가 아닙니다.** 실제 영향 자동판정이나 상용 엔터프라이즈 제품을 주장하지 않습니다. 포함된 모든 샘플 데이터는 합성 데이터이며 군·고객·회사 운영데이터를 포함하지 않습니다.

## 핵심 흐름

```text
Scanner CSV / SBOM
        ↓
Finding·Asset normalization
        ↓
CVSS + KEV + EPSS + asset context
        ↓
Owner·due date·campaign·retest
        ↓
Risk acceptance·evidence·audit
        ↓
Backup·restore·operational verification
```

## 3단계 시연 시나리오

### 1. 대시보드에서 우선순위와 조치 대상을 확인

합성 취약점 데이터를 기준으로 즉시 조치, 기한 초과, 검증 대기 항목을 먼저 확인하고 상세 화면으로 이동합니다.

![Dashboard](assets/screenshots/dashboard.png)

### 2. 취약점·자산 맥락을 확인하고 조치 상태를 갱신

CVSS·KEV·EPSS·외부 노출·자산 중요도와 담당자, 목표일, 조치 메모를 한 흐름에서 확인합니다.

![Finding detail](assets/screenshots/finding-detail.png)

![Asset inventory](assets/screenshots/asset-inventory.png)

### 3. 데이터를 반영하고 위험수용을 승인 흐름으로 분리

CSV 또는 SBOM을 반영한 뒤 operator의 위험수용 요청을 approver가 별도로 검토하도록 구성했습니다.

![Data import](assets/screenshots/data-import.png)

![Risk acceptance approvals](assets/screenshots/risk-approvals.png)

화면은 합성 데이터와 임시 SQLite 데이터베이스를 이용해 `scripts/capture_public_screenshots.py`로 반복 생성할 수 있습니다. 생성 시각이나 런타임 식별자가 표시되는 영역 때문에 PNG 바이트가 매번 동일하다고 주장하지는 않습니다.

## 구현 범위

- 다중 스캐너 CSV 수집과 full/incremental snapshot reconciliation
- ACTIVE·STALE·ARCHIVED finding 생명주기
- CVSS·CISA KEV·EPSS·자산 중요도 기반 설명 가능한 우선순위
- 담당자·목표일·캠페인·재시험·위험수용 승인
- 자산 식별자, 병합 영향분석, 승인형 병합과 제한적 롤백
- 증거파일 격리, baseline/ClamAV 검사 경계, custody chain
- SQLite 작업 queue, lease, retry, idempotency, webhook outbox
- 감사 hash chain, 백업·복구, restore write barrier
- SBOM·VEX·OSV 기반 공급망 취약점 운영
- 동일 호스트 다중 프로세스 coordination과 leader fencing

## 빠른 실행

Python 3.12 이상을 권장합니다.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./run_linux.sh
```

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
.\run_windows.ps1
```

브라우저에서 `http://127.0.0.1:8000`을 엽니다. 제공된 로컬 실행 스크립트는 loopback 전용 관리자 fallback을 명시적으로 켭니다. 원격 또는 컨테이너 배포에서는 `.env.example`을 참고해 계정이나 API token을 반드시 설정해야 합니다.

데모 데이터를 초기 상태로 되돌리려면:

```bash
python scripts_reset_demo.py
```

## 공개 검증 범위

이 공개 저장소에는 **243개 핵심 회귀시험**과 **Chromium 브라우저 E2E 3개**를 포함합니다.

```bash
python scripts/run_public_tests.py
pip install -r requirements-e2e.txt
python -m playwright install chromium
python scripts/run_browser_e2e.py
pip install -r requirements-quality.txt
python scripts/run_quality_gates.py
```

핵심 회귀시험은 인증, 수집, 우선순위, 조치·승인, 자산 병합, 증거, SBOM·OSV, 백업·복구와 동일 호스트 coordination을 검증합니다. 브라우저 E2E는 대시보드에서 조치 상태 변경, CSV 가져오기 후 검색, operator 위험수용 요청과 approver 승인을 실제 Chromium 동선으로 검증합니다. GitHub Actions에서는 E2E를 Ubuntu/Python 3.13 단일 job으로 실행해 4개 핵심 회귀 행렬과 중복되지 않게 구성했습니다.
정적 품질 job은 Python 구문 컴파일, Ruff의 치명적 오류 규칙, Bandit의 high-severity/high-confidence 결과와 pip-audit 의존성 취약점 검사를 별도로 실행합니다. pip-audit은 외부 advisory 서비스에 의존하므로 네트워크가 차단된 로컬 환경에서는 `--skip-dependency-audit` 옵션으로 나머지 게이트만 실행할 수 있습니다.


2026년 7월 29일 Windows Docker Desktop에서 배포본 `Dockerfile`과 `docker-compose.yml`을 이용해 image build, readiness, 비루트 UID 10001, SQLite schema 40, 합성 finding API import, restart·컨테이너 재생성 후 named-volume 영속성, SQLite 백업과 새 volume 복원을 실제로 확인했습니다. 이는 단일 실기동 검증이며 24시간 endurance, 고객 배포 또는 운영 SLA를 입증하지 않습니다. 자세한 범위는 [Docker runtime 검증](docs/94_DOCKER_RUNTIME_VALIDATION.md)을 확인하세요.

내부 제출 기준본 72.0.11에서는 전체 자동시험 555개와 애플리케이션 line coverage 79.96%를 확인했습니다. 공개 저장소에서는 채용 검토에 필요한 핵심 코드와 시험을 우선하며, 결정적 wheel/sdist, runtime snapshot, DSSE provenance 및 전체 릴리스 리허설 산출물은 저장소 용량과 가독성을 위해 제외했습니다.

## 기술 구성

- Python / FastAPI / Pydantic
- SQLite / FTS5
- Jinja2 server-rendered UI
- Background jobs and webhook outbox
- CycloneDX SBOM / VEX / OSV
- Pytest / Playwright Chromium E2E

## 문서 읽는 순서

1. [문제와 범위](docs/01_PROBLEM_AND_SCOPE.md)
2. [아키텍처](docs/02_ARCHITECTURE.md)
3. [방법과 한계](docs/03_METHOD_AND_LIMITATIONS.md)
4. [운영 가이드](docs/05_OPERATIONS_GUIDE.md)
5. [보안·개인정보 경계](docs/07_SECURITY_PRIVACY.md)
6. [API와 운영](docs/10_API_AND_OPERATIONS.md)
7. [공개 정적 품질 게이트](docs/93_PUBLIC_QUALITY_GATES.md)
8. [Docker runtime 검증](docs/94_DOCKER_RUNTIME_VALIDATION.md)

## 저장소 참여와 지원

- 변경 제안: [CONTRIBUTING.md](CONTRIBUTING.md)
- 보안 취약점 신고: [SECURITY.md](SECURITY.md)
- 일반 지원 범위: [SUPPORT.md](SUPPORT.md)
- 공개 로드맵: [ROADMAP.md](ROADMAP.md)
- 변경 이력: [CHANGELOG.md](CHANGELOG.md)
- 72.0.12 유지보수 릴리스 노트: [RELEASE_NOTES_72.0.12.md](RELEASE_NOTES_72.0.12.md)

## 확인된 한계

- SQLite·단일 호스트 중심이며 다중 서버 분산제품이 아닙니다.
- OIDC·SAML·MFA와 PostgreSQL을 지원하지 않습니다.
- Windows Docker Desktop 단일 실기동은 검증했지만 Windows runtime snapshot과 24시간 endurance는 검증하지 않았습니다.
- 공개 OSV·KEV·EPSS 운영 endpoint의 지속적 가용성을 보장하지 않습니다.
- 합성 데이터 성능 수치는 운영 SLA가 아닙니다.
- 실제 사용자 파일럿과 업무시간 절감 효과는 아직 측정하지 않았습니다.

## 공개 범위와 개인정보

이 저장소에는 합성 샘플만 포함합니다. 실제 군·기관·기업 취약점 정보, 계정정보, 연락처, 상세주소, 운영 인증서와 private key는 포함하지 않습니다. 테스트에 보이는 비밀번호·token·example.test 주소는 시험용 고정값입니다.

## License

MIT License. 자세한 내용은 [LICENSE](LICENSE)를 확인하세요.

## Version identifier

`72.0.12` is an internal iteration identifier retained from the development process. It does not represent 72 public major releases. Public changes after this initial publication are tracked through normal issues, branches, pull requests, and commits.
