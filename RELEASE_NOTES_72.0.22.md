# VulnFlow 72.0.22

기능을 추가하지 않고, 파일럿 이후 유지보수 위험이 커지고 있던 두 개의 대형 조합 모듈을 책임별 경계로 분리한 구조 안정화 릴리스입니다.

## 주요 변경

- `app/application_services.py`를 645줄에서 약 50줄의 안정적인 composition root로 축소
- 서비스 export를 foundation, repositories, workflow, governance, runtime, collaboration 그룹으로 분리
- 기존 332개 서비스 export의 이름과 객체 identity, 충돌 차단 동작 유지
- 서비스 이름의 기존 호환 순서를 별도 catalog로 고정
- `app/services/finding_imports.py`를 699줄에서 약 170줄의 public facade로 축소
- CSV/XLSX 파서, Nessus/OpenVAS adapter, canonical mapping, 미리보기 임시 저장을 각각 독립 모듈로 분리
- architecture guardrail에 새 모듈 필수 존재, 줄 수 예산, composition-root domain import 금지 규칙 추가
- SQLite schema 44와 사용자 데이터 형식은 변경하지 않음

## 호환성

HTTP route, DB schema, 파일 가져오기 결과, 서비스 export surface는 변경하지 않았습니다. 기존 72.0.21 데이터 디렉터리를 그대로 사용할 수 있습니다.
