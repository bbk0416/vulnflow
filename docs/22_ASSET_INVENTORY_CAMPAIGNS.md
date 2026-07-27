# Asset Inventory, Exposure Groups, and Remediation Campaigns

## 목적

finding 한 건의 점수만으로는 다음 운영 질문을 해결하기 어렵습니다.

- 어떤 서비스와 사업부서가 해당 자산을 소유하는가?
- 동일 CVE가 몇 개 자산에 확산돼 있는가?
- 여러 자산을 한 번에 조치할 공통 담당자와 목표일은 무엇인가?
- 스캐너가 보내는 자산 중요도보다 내부 CMDB 성격의 인벤토리 값을 우선할 수 있는가?

13.0은 finding과 자산을 분리하고, 동일 취약점 노출을 군집화하며, 관련 finding을 조치 캠페인으로 관리합니다.

## 자산 식별

스캐너의 `asset_id`는 원문 그대로 `external_asset_id`에 보존합니다. 내부 연결에는 `asset_ref_id`를 사용합니다.

```text
asset_id가 있으면
  SHA-256("external|" + normalized asset_id)

asset_id가 없으면
  SHA-256("derived|" + asset_name + product + environment)
```

이 방식은 finding ID를 변경하지 않으며 스캐너별 표현 차이를 내부 연결 키와 분리합니다.

## 권위 있는 자산 맥락

스캐너 finding에서 최초 파생된 자산은 `source=finding-derived`입니다. 별도 자산 CSV/API가 같은 `asset_id`를 반영하면 `source=inventory`로 전환합니다.

인벤토리 값이 설정된 뒤 스캐너가 낮은 중요도나 노출 값을 다시 보내더라도 다음 값은 인벤토리를 우선합니다.

- asset_name
- environment
- criticality
- data_sensitivity
- internet_exposed

finding을 다시 점수화해 자산 맥락 변경을 우선순위에 반영합니다.

## 자산 CSV

필수:

- `asset_id` 또는 `asset_name`

선택:

- `service_name`
- `business_unit`
- `owner`
- `environment`
- `criticality` 1~5
- `data_sensitivity` 1~5
- `internet_exposed`
- `tags`
- `status` (`ACTIVE`, `RETIRED`)

UI:

```text
GET  /assets
POST /assets/upload
GET  /asset/{asset_ref_id}
```

API:

```text
GET  /api/v1/assets
POST /api/v1/assets
GET  /api/v1/assets/{asset_ref_id}
GET  /export/assets.csv
```

## 노출 군집

`/exposure-groups`와 `/api/v1/exposure-groups`는 `cve_id + component + component_version` 기준으로 다음을 집계합니다.

- finding 수
- 고유 자산 수
- 활성 조치 대상 수
- KEV 수
- 인터넷 노출 수
- 최대 조치 우선순위 점수
- 최대 EPSS
- 가장 빠른 목표일
- 고유 finding 담당자 수

이 집계는 공격 예측이 아니라 조치 캠페인 후보를 식별하기 위한 운영 뷰입니다.

## 조치 캠페인

상태:

```text
PLANNED → ACTIVE → COMPLETED
                  ↘ CANCELLED
```

기능:

- finding ID 또는 CVE로 구성원 선택
- 캠페인 소유자·목표일·설명
- 생성 즉시 구성원을 `IN_PROGRESS`로 전환하는 선택 기능
- 구성원 추가·제거
- 진행률과 활성 finding 수 집계
- 행 버전 기반 동시 수정 충돌 방지
- 활성 finding이 남은 상태에서 `COMPLETED` 전환 차단
- 완료·취소 캠페인의 구성 변경 차단

UI:

```text
GET  /campaigns
POST /campaigns
GET  /campaigns/{campaign_id}
POST /campaigns/{campaign_id}/members
POST /campaigns/{campaign_id}/members/{finding_id}/remove
POST /campaigns/{campaign_id}/status
```

API:

```text
GET    /api/v1/campaigns
POST   /api/v1/campaigns
GET    /api/v1/campaigns/{campaign_id}
POST   /api/v1/campaigns/{campaign_id}/members
DELETE /api/v1/campaigns/{campaign_id}/members/{finding_id}
POST   /api/v1/campaigns/{campaign_id}/status
GET    /export/campaigns.csv
```

쓰기 API는 operator 이상 역할의 Bearer token이 필요합니다.

## 감사와 웹훅

감사 이벤트:

- `asset_inventory_import`
- `campaign_created`
- `campaign_members_added`
- `campaign_member_removed`
- `campaign_status_changed`

웹훅 이벤트:

- `asset_inventory.imported`
- `campaign.created`
- `campaign.members_added`
- `campaign.member_removed`
- `campaign.status_changed`

## 제한

- 외부 CMDB·Jira·ServiceNow와 양방향 동기화하지 않습니다.
- asset_id가 없을 때의 파생 ID는 이름·제품·환경 품질에 의존합니다.
- 자산 병합·분할 UI는 제공하지 않습니다.
- 캠페인은 릴리스 계획·변경승인·개발 스프린트 전체를 대체하지 않습니다.
