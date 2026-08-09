# 제어 DB 분리와 프로젝트 복원 경계

VulnFlow 72.0.25부터 사용자·세션·프로젝트 등록정보는 `data/control.db`에, 기본 프로젝트의 finding·asset·job·증거 메타데이터는 `data/projects/default/vulnflow.db`에 저장합니다. 비기본 프로젝트는 기존처럼 `data/projects/<project-id>/vulnflow.db`를 사용합니다.

## 72.0.24 이하 업그레이드

서비스를 중지하고 `data/` 전체를 별도 위치에 복사한 뒤 새 버전을 처음 실행합니다. `scripts.prepare_storage`는 기존 `data/vulnflow.db`를 삭제하지 않고 다음 작업을 수행합니다.

1. 사용자와 프로젝트 등록정보만 새 `control.db`로 이관합니다.
2. 운영 데이터는 기본 프로젝트 DB로 SQLite backup API를 통해 복사합니다.
3. 기본 프로젝트 DB에서 사용자 hash, session, login attempt, membership과 다른 프로젝트 등록행을 제거합니다.
4. 기존 evidence·exports·import preview·recovery 디렉터리는 최초 분리 때 한 번만 기본 프로젝트 트리로 복사합니다.
5. `data/split-storage-v1.json`에 마이그레이션 결과를 기록합니다.

부분 생성된 split DB가 있고 구형 원본이 남아 있으면 부분 파일을 `.pre-split-<timestamp>.bak`으로 보존한 후 두 대상 DB를 같은 원본 세대에서 다시 만듭니다.

## 복구 경계

각 프로젝트 DB의 `system_metadata`에는 다음 정체성이 기록됩니다.

```text
database_role = project-data
project_id = default 또는 실제 project ID
project_name = 표시 이름
```

제어 DB는 `database_role=control`, `project_id=control`을 사용합니다. 복구 ZIP format v2와 일반 SQLite 복원 모두 현재 활성 프로젝트의 ID와 database role을 검사합니다. 다른 프로젝트의 백업, 제어 DB, 정체성이 없는 구형 백업은 일반 프로젝트 복원 경로에서 거부됩니다.

구형 복구 ZIP을 꼭 사용해야 하는 경우 자동 우회하지 말고 별도 복제 환경에서 내용을 검증한 뒤 현재 형식으로 다시 백업해야 합니다.

## 운영 확인

```powershell
python -m scripts.prepare_storage
python -m scripts.manage_users --db .\data\control.db list
```

확인할 파일:

```text
data/vulnflow.db                         # 보존된 구형 원본
data/control.db                          # 제어 DB
data/projects/default/vulnflow.db        # 기본 프로젝트 DB
data/split-storage-v1.json               # 분리 결과
```

분리 완료 후에도 구형 원본은 자동 삭제되지 않습니다. 새 구조로 로그인·프로젝트 전환·백업·복원 리허설을 완료한 뒤 조직의 보존 정책에 따라 오프라인 보관하거나 폐기합니다.
