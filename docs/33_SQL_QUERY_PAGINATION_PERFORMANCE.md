# 24.0 SQL 조회·페이지네이션·성능 검증

## 배경

23.0까지 대시보드와 finding API는 모든 finding을 점수순으로 읽어 Python에서 필터링·페이지 분할했습니다. 데이터가 커지면 요청마다 전체 행과 긴 텍스트 필드를 메모리에 적재하고, UI 제한과 관계없이 전체 목록을 정렬·순회하는 문제가 있었습니다.

24.0은 사용자에게 보이는 판정·필터 의미를 유지하면서 조회 전용 경로를 `app/services/finding_query.py`로 분리했습니다.

## 조회 흐름

```text
FindingQuery 정규화
→ SQL WHERE + 바인딩 파라미터
→ SELECT COUNT(*)로 정확한 결과 건수
→ 고정 ORDER BY
→ LIMIT / OFFSET
→ page metadata와 query_ms 반환
```

고정 정렬:

```sql
ORDER BY score DESC,
         kev DESC,
         epss DESC,
         cve_id ASC,
         finding_id ASC
```

`finding_id`를 마지막 동점 기준으로 사용해 동일 점수·KEV·EPSS·CVE 항목도 페이지 간 순서가 고정됩니다.

## 지원 필터

- decision
- status
- query: finding ID, 제품, 자산, CVE, 구성요소, 담당자 부분 문자열
- overdue
- exception: active, expiring, expired
- record_state: CURRENT, ACTIVE, STALE, ARCHIVED, ALL
- scanner_source

입력값은 SQL 문자열에 삽입하지 않고 바인딩 파라미터로 전달합니다.

## SQL 집계

대시보드와 `/api/v1/summary`는 다음 값을 전체 Python 객체 없이 계산합니다.

- 전체·활성·종료 finding
- KEV·인터넷 노출·완화조치 필요
- 기한 초과
- 위험수용 만료·14일 내 만료
- 판정·record state·검증 상태별 건수
- 재발 누계
- 자산·노출 군집·활성 캠페인 정확한 건수

기존 `report_summary(list_findings())`와 SQL 결과가 같은지 회귀시험으로 비교합니다.

## 인덱스

스키마 24는 다음 인덱스를 추가합니다.

```text
idx_findings_list_state_score
idx_findings_list_filters
idx_findings_active_due
idx_findings_exception_expiry
```

`EXPLAIN QUERY PLAN`을 이용해 상태·판정·scanner 조합 조회가 `idx_findings_list_filters`를 사용하는지 검증합니다.

## API 호환성

기존 `limit` 파라미터는 페이지 크기로 유지하며 `page`를 추가합니다.

```http
GET /api/v1/findings?status=OPEN&record_state=CURRENT&limit=100&page=2
```

응답:

```json
{
  "count": 1609,
  "items": [],
  "page": 2,
  "page_size": 100,
  "total_pages": 17,
  "query_ms": 3.973
}
```

기존 클라이언트가 사용하던 `count`와 `items`는 유지됩니다. `count`는 현재 페이지 크기가 아니라 필터 전체 결과 건수입니다.

## 합성 성능 시험

`scripts/query_performance_smoke.py`는 로컬 임시 SQLite에 합성 finding 50,000건을 생성합니다.

검증 내용:

- SQL 결과 건수와 기존 전체 적재·Python 필터 결과 일치
- 100개 페이지 반환
- 페이지 내부 ID 중복 없음
- SQL 요약의 전체 건수 일치
- 복합 인덱스 실행계획 확인
- 인덱스 페이지 조회가 전체 적재·Python 필터보다 빠른지 확인

2026-07-21 현재 실행환경 결과:

```text
Synthetic findings: 50000
Filtered findings: 1609
Indexed page query median: 3.973 ms
SQL summary median: 551.047 ms
Legacy full materialize + Python filter: 1713.977 ms
Composite index plan: PASS
```

## 해석 제한

- 합성 데이터와 로컬 디스크 SQLite 측정입니다.
- 운영 SLA, 최대 동시 사용자, 최대 DB 크기 또는 다중 서버 처리량을 입증하지 않습니다.
- 자유 부분 문자열 검색은 앞뒤 `%`가 있는 LIKE이므로 대규모 데이터에서 선형 탐색이 남을 수 있습니다.
- OFFSET 페이지네이션은 매우 깊은 페이지에서 비용이 증가할 수 있습니다.
- 실제 운영 데이터가 확보되면 FTS, keyset pagination, 별도 읽기 모델 또는 PostgreSQL 전환을 검토해야 합니다.
