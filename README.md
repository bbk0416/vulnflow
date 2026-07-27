# VulnFlow 72.0.11

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

## 대표 화면

### Dashboard

![Dashboard](assets/screenshots/dashboard.png)

### Finding detail

![Finding detail](assets/screenshots/finding-detail.png)

### Asset inventory

![Asset inventory](assets/screenshots/asset-inventory.png)

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

이 공개 저장소에는 핵심 업무 흐름을 검증하는 **230개 대표 시험**을 포함합니다.

```bash
python scripts/run_public_tests.py
```

공개 시험 범위는 인증, 수집, 우선순위, 조치·승인, 자산 병합, 증거, SBOM·OSV, 백업·복구와 동일 호스트 coordination을 포함합니다.

내부 제출 기준본 72.0.11에서는 전체 자동시험 555개와 애플리케이션 line coverage 79.96%를 확인했습니다. 공개 저장소에서는 채용 검토에 필요한 핵심 코드와 시험을 우선하며, 결정적 wheel/sdist, runtime snapshot, DSSE provenance 및 전체 릴리스 리허설 산출물은 저장소 용량과 가독성을 위해 제외했습니다.

## 기술 구성

- Python / FastAPI / Pydantic
- SQLite / FTS5
- Jinja2 server-rendered UI
- Background jobs and webhook outbox
- CycloneDX SBOM / VEX / OSV
- Pytest

## 문서 읽는 순서

1. [문제와 범위](docs/01_PROBLEM_AND_SCOPE.md)
2. [아키텍처](docs/02_ARCHITECTURE.md)
3. [방법과 한계](docs/03_METHOD_AND_LIMITATIONS.md)
4. [운영 가이드](docs/05_OPERATIONS_GUIDE.md)
5. [보안·개인정보 경계](docs/07_SECURITY_PRIVACY.md)
6. [API와 운영](docs/10_API_AND_OPERATIONS.md)

## 저장소 참여와 지원

- 변경 제안: [CONTRIBUTING.md](CONTRIBUTING.md)
- 보안 취약점 신고: [SECURITY.md](SECURITY.md)
- 일반 지원 범위: [SUPPORT.md](SUPPORT.md)
- 공개 로드맵: [ROADMAP.md](ROADMAP.md)
- 변경 이력: [CHANGELOG.md](CHANGELOG.md)
- 72.0.11 공개 릴리스 노트: [RELEASE_NOTES_72.0.11.md](RELEASE_NOTES_72.0.11.md)

## 확인된 한계

- SQLite·단일 호스트 중심이며 다중 서버 분산제품이 아닙니다.
- OIDC·SAML·MFA와 PostgreSQL을 지원하지 않습니다.
- 실제 Docker 엔진, Windows runtime snapshot, 24시간 endurance는 이 공개본의 검증 범위가 아닙니다.
- 공개 OSV·KEV·EPSS 운영 endpoint의 지속적 가용성을 보장하지 않습니다.
- 합성 데이터 성능 수치는 운영 SLA가 아닙니다.
- 실제 사용자 파일럿과 업무시간 절감 효과는 아직 측정하지 않았습니다.

## 공개 범위와 개인정보

이 저장소에는 합성 샘플만 포함합니다. 실제 군·기관·기업 취약점 정보, 계정정보, 연락처, 상세주소, 운영 인증서와 private key는 포함하지 않습니다. 테스트에 보이는 비밀번호·token·example.test 주소는 시험용 고정값입니다.

## License

MIT License. 자세한 내용은 [LICENSE](LICENSE)를 확인하세요.
