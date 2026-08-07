# Docker runtime 검증

## 검증 목적

이 문서는 VulnFlow의 배포 설정이 실제 Docker 엔진에서 동작하는지 확인한 단일 실기동 기록입니다. 고객 배포, 운영 SLA, 장시간 안정성 또는 다중 서버 확장성을 주장하지 않습니다.

## 실행 기준

- 실행일: 2026-07-29
- 검증 대상 main commit: `91da24eb6f09ab1b187afeae6092fd68ca59114a`
- 검증 당시 애플리케이션 버전: `72.0.11`
- Docker Server: `29.1.3`
- Docker Compose: `2.40.3-desktop.1`
- 데이터: 저장소에 포함된 합성 데이터와 검증용 합성 finding 1건
- 공개 제외: 로컬 경로, 임시 계정·token, 원본 SQLite 백업

`72.0.12` 릴리스는 이 검증 이후 런타임 동작을 변경하지 않고 버전과 공개 검증 문서만 갱신합니다.

## 확인 항목

| 항목 | 결과 |
|---|---|
| 깨끗한 GitHub main clone | PASS |
| `docker compose build --pull` | PASS |
| 배포본 Compose 기동과 `/health/ready` | PASS |
| image 기본 사용자 | `vulnflow` |
| runtime UID | `10001` |
| SQLite schema version | `40` |
| 합성 finding API import | PASS |
| Compose restart 후 데이터 유지 | PASS |
| 컨테이너 제거·재생성 후 named-volume 데이터 유지 | PASS |
| 트랜잭션 SQLite 백업 | PASS |
| 새 named volume 복원과 readiness | PASS |

데이터 수 검증:

```text
initial: 10
after synthetic import: 11
after restart: 11
after container recreation: 11
after restore to a new volume: 11
```

검증용 합성 백업 SHA-256:

```text
358678bbe0cec7473b967e0180f53a9291bc2dbbb63c6506ee77b75bc591bdf0
```

## 해석 제한

- Windows Docker Desktop에서 한 차례 수행한 실기동 검증입니다.
- Linux Docker host, rootless Docker, Kubernetes와 외부 reverse proxy 배포는 검증하지 않았습니다.
- 24시간 endurance, 부하시험, 장애주입, 실제 고객 데이터 이관과 운영자 파일럿은 수행하지 않았습니다.
- SQLite·단일 호스트 중심이라는 제품 범위는 바뀌지 않습니다.
- 검증 중 사용한 임시 계정·token과 원본 백업은 공개 저장소에 포함하지 않습니다.

## 72.0.26 반복 업그레이드 리허설

72.0.26은 저장소에 포함된 72.0.18/schema 42 합성 fixture를 현재 schema 45로 실제 마이그레이션하고 기존 관리자·finding, 협업 테이블과 파일럿 프로필 테이블을 검증하는 `scripts/docker_upgrade_rehearsal.py`를 제공합니다.

```bash
python scripts/docker_upgrade_rehearsal.py --mode host
python scripts/docker_upgrade_rehearsal.py --mode docker --require-docker
```

호스트 모드는 이 소스 상태에서 통과했습니다. Docker 모드는 GitHub Actions의 별도 job에서 실행하도록 구성했지만, 본 작업 환경에는 Docker 명령이 없어 여기서 image build·readiness 성공을 주장하지 않습니다. 과거 72.0.11 Windows Docker Desktop 증거와 현재 자동 리허설 결과는 서로 구분해야 합니다.

## 72.0.31 production Compose CI gate

72.0.31 adds `scripts/production_compose_rehearsal.py`, which uses the checked-in production Compose and Nginx configuration instead of the older upgrade-only topology.

```bash
python scripts/production_compose_rehearsal.py --require-docker \
  --json-output reports/production_compose_rehearsal.json
```

The public CI job requires Docker and treats an unavailable engine as failure. The rehearsal builds the current image, starts Nginx and VulnFlow, verifies HTTPS readiness and redirect behavior, imports a synthetic finding through a project-scoped token, restarts the application, verifies named-volume persistence, checks runtime UID 10001, confirms port 8000 is not published, and confirms the backend network is internal.

The workspace used to prepare 72.0.31 did not have a Docker command. Therefore this document does not claim that the current image passed locally. Static Compose contract tests and the mandatory CI invocation passed; the CI runtime artifact must be reviewed after the workflow runs.
