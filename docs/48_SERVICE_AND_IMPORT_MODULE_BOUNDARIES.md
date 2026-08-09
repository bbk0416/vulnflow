# 서비스 레지스트리와 가져오기 모듈 경계

VulnFlow 72.0.22는 새 기능을 추가하지 않고, 변경 영향 범위가 지나치게 커진 두 composition module을 책임별 경계로 분리했습니다.

## 애플리케이션 서비스 레지스트리

`app/application_services.py`는 더 이상 repository와 domain service 수백 개를 직접 import하지 않습니다. 이 파일은 다음 작업만 담당합니다.

1. domain-owned registry group 결합
2. 중복 export 이름 차단
3. 기존 호환 순서 catalog 검증
4. application namespace 설치
5. 비밀정보가 없는 구조 snapshot 제공

실제 export 소유권은 `app/service_registry/` 아래에 있습니다.

- `foundation.py`: 인증, 계정, 프로젝트, scoring, DB 기반 기능
- `repositories.py`: persistence repository 함수
- `workflow.py`: finding import/query, evidence, report, export, maintenance
- `governance.py`: 정책, proof, recovery, configuration control, SBOM, webhook
- `runtime.py`: background worker와 lifecycle runtime
- `collaboration.py`: SMTP·Jira collaboration registry
- `catalog.py`: 기존 공개 service name 순서

각 그룹은 immutable mapping을 제공하며 다른 그룹과 같은 이름을 export하면 시작 단계에서 실패합니다.

## Finding import facade

`app/services/finding_imports.py`는 route와 scanner compatibility code가 사용하는 public facade만 유지합니다.

- `finding_import_common.py`: canonical fields, header alias, cell normalization, CVE extraction
- `finding_import_tabular.py`: CSV encoding·delimiter 처리와 XLSX archive/parser 경계
- `finding_import_scanners.py`: Nessus와 OpenVAS CSV/XML adapter
- `finding_import_preview.py`: 사용자 격리 임시 파일과 TTL·권한·정리
- `finding_imports.py`: format detection, mapping orchestration, public API

이 분리는 기존 parser 결과나 route contract를 바꾸기 위한 것이 아닙니다. 기존 CSV, XLSX, Nessus, OpenVAS 회귀 fixture가 같은 결과를 내는지 공개 회귀시험에서 확인합니다.

## 구조 게이트

`app/core/architecture.py`는 다음 회귀를 실패 처리합니다.

- composition root가 repository나 domain service를 다시 직접 import
- finding-import facade가 openpyxl, XML parser, ZIP, gzip storage 구현을 다시 소유
- 새 registry/import module 누락
- 각 경계의 line budget 초과
- registry group의 `app.main` 역참조

이 구조는 파일 수를 줄이기 위한 것이 아니라, 변경 시 영향을 받는 책임과 시험 범위를 줄이기 위한 것입니다.
