# 아키텍처

```text
Basic 사용자 계정 ─┐
Bearer API 토큰 ───┼──► viewer / operator / approver / admin 권한검사
                   │
스캐너·원천별 CSV ─┘
       │  증분 / 스냅샷
       ▼
입력 검증·정규화·안정 ID
       │
       ├──► 가져오기 배치 이력
       ├──► 신규·갱신·누락(STALE) 판정
       └──► ACTIVE 재등장 / ARCHIVED 보관
                         │
CISA KEV / FIRST EPSS ─┼── ACTIVE 정책 레지스트리
                         ▼
                      SQLite ─► 조치 우선순위 엔진
                         │
      ┌──────────────────┼──────────────────────┐
      ▼                  ▼                      ▼
대시보드·API      운영자 워크플로       감사·CSV·HTML·DB 백업
                         │
                    위험수용 요청
                         ▼
                    승인·반려
                         │
                  row_version 충돌감지

상태변화 ─► webhook_events 아웃박스 ─► 원자적 선점(SENDING)
                                         ├─► HMAC 서명 전송 ─► DELIVERED
                                         └─► 지수 백오프 ───► RETRY / FAILED

긴 작업·예약 작업 ─► background_jobs SQLite 큐 ─► 원자적 워커 선점
                                                    ├─► 임대 연장·진행률
                                                    ├─► 성공·실패·취소
                                                    └─► 임대 만료 회수·재시도

예약 유지관리 ─► 중복 방지 작업 등록 ─► 만료 위험수용 재개방 / 오래된 요청 취소 /
                                      STALE 자동보관 / 감사·가져오기·웹훅·작업 이력 보존

요청 미들웨어 ─► X-Request-ID / JSON 로그 / HTTP 메트릭

정책 YAML 초안 ─► 엄격 검증 ─► 데이터 영향분석 ─► 활성화 요청
                                                   ▼
                                             승인·반려
                                                   ▼
                                    원자적 재평가·이전 정책 보관

CycloneDX A + CycloneDX B ─► 인벤토리 파싱·구성요소 차이 비교
```

## 현재 모듈 경계

- `app/main.py`: compatibility entrypoint와 application factory bootstrap
- `app/application_lifespan.py`: 인증·설정 검증, DB·증거·감사 초기화, lifecycle 시작·종료
- `app/http_runtime.py`: 인증, CSRF, 보안 헤더, request telemetry, cluster write barrier
- `app/endpoint_workflows.py`: 요청 중심 정책·점수·위협정보·maintenance·job workflow 조립
- `app/factory.py`: FastAPI instance와 router runtime 조립
- `app/core/context*.py`: 앱별 불변 설정·서비스·transaction registry·진단 snapshot
- `app/core/auth.py`: Basic 계정·Bearer token·명시적 loopback fallback 검증
- `app/core/database_schema.py`: SQLite 초기화·migration·FTS·무결성 trigger
- `app/repositories/`: finding·asset·audit·job·webhook·cluster·policy persistence
- `app/services/`: scoring·정책·증거·복구·proof·worker·maintenance 실행 경계
- `app/routers/`: findings·assets·evidence·governance·trust·exports·operations HTTP 경계
- `rules/`: 설명 가능한 우선순위 정책 YAML
- `tests/`, `scripts/*_smoke.py`: 단위·통합·실제 프로세스·독립 검증

`app.main`과 compatibility facade는 기존 import를 보존하지만, 애플리케이션 내부는 실제 소유 모듈을 직접 참조합니다. 추가 `create_app()` 인스턴스는 설정·서비스·DB·transaction·router runtime을 공유하지 않습니다.

## 10.0 coordination plane

```text
API/worker process A ─┐
API/worker process B ─┼─ local operational SQLite (business data)
API/worker process C ─┘
          │
          └──────────── separate coordination SQLite
                         - instance heartbeats
                         - scheduler/restore/policy leases
                         - fencing tokens
                         - active HTTP write activities
```

운영 DB 복원 중에도 잠금 상태가 교체되지 않도록 coordination DB를 분리합니다. 두 DB는 동일 호스트의 로컬 디스크에 둡니다.


## 11.0 감사 무결성 plane

```text
운영 변경 ─► add_audit_event ─► chain_seq + prev_hash + event_hash
                                      │
                                      ├─► audit_chain_state last hash
                                      ├─► HMAC signed checkpoint
                                      └─► integrity verification

보존정책 ─► contiguous prefix checkpoint ─► anchor advance ─► prefix delete
복구 번들 ─► audit-integrity.json ─► DB chain recalculation and comparison
```

감사 체인은 운영 DB 안에 저장하되 HMAC 키는 환경변수에만 둡니다. WORM 저장소는 현재 범위가 아닙니다.

## 13.0 자산·캠페인 plane

```text
finding import
  ├─ asset_ref_id resolution
  ├─ derived asset upsert
  └─ authoritative inventory context merge

assets
  ├─ service / business unit / owner
  ├─ criticality / sensitivity / exposure
  └─ linked finding aggregate

exposure groups
  └─ CVE + component + version aggregate

remediation campaigns
  ├─ campaign metadata
  ├─ campaign_findings membership
  └─ workflow progress and completion guard
```
