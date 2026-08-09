# OSV 공급망 취약점 탐색

## 목적

CycloneDX 제품 릴리스의 PURL·버전을 OSV.dev에 질의해 알려진 오픈소스 취약점을 검토 후보로 생성합니다. 이 기능은 VEX 영향판정을 자동 확정하지 않습니다.

## 공식 API 사용 방식

- batch 질의: `POST /v1/querybatch`
- 전체 레코드: `GET /v1/vulns/{id}`
- versioned PURL은 PURL만 전송
- unversioned PURL은 top-level `version`과 함께 전송
- querybatch 결과 순서는 입력 순서와 동일
- 결과에 `next_page_token`이 있으면 해당 질의만 후속 요청

공식 문서:

- https://google.github.io/osv.dev/post-v1-querybatch/
- https://google.github.io/osv.dev/post-v1-query/
- https://google.github.io/osv.dev/get-v1-vulns/
- https://ossf.github.io/osv-schema/

## 데이터 모델

### osv_scan_runs

탐색 요청자·시각·대상 구성요소·건너뛴 구성요소·API 요청·캐시 적중·후보 수·오류를 기록합니다.

### osv_vulnerability_records

OSV ID별 전체 원본 JSON, aliases, severity, affected, references, modified, SHA-256과 수집 시각을 저장합니다.

### sbom_osv_matches

SBOM 구성요소와 OSV 레코드의 연결 후보를 저장합니다.

```text
CANDIDATE → CONFIRMED / REJECTED
```

`CONFIRMED`에는 CVE alias가 필요합니다. 확정 시 안정적인 finding ID를 생성하고 기존 SBOM finding 링크에 `OSV_CONFIRMED`로 연결합니다.

## 캐시와 재시도

querybatch는 OSV ID와 modified만 반환합니다. 로컬 레코드의 modified가 동일하면 전체 레코드 GET을 생략합니다. HTTP 429·5xx는 제한된 지수형 재시도를 적용하며 리다이렉트는 차단합니다.

백그라운드 작업 재시도 시 동일 `source_job_id`의 실패 scan run을 재사용해 중복 scan 이력을 만들지 않습니다.

## 보안 경계

- 원격 API는 HTTPS만 허용
- DNS 결과 전체 검증과 IP 고정 연결을 적용
- 원래 호스트로 TLS SNI·인증서 검증
- 리다이렉트와 환경 프록시 사용 차단
- 루프백·사설망은 명시적인 테스트 설정과 정확한 allowlist가 있을 때만 허용
- 응답은 JSON 객체와 예상 결과 개수를 검증
- 원본 OSV details는 Jinja autoescape 하에 표시
- CVE alias가 없으면 finding 생성 차단
- 자동 결과는 조직 환경의 실제 영향·도달성·악용 가능성을 보장하지 않음

## 환경변수

```env
VULNFLOW_OSV_API_BASE=https://api.osv.dev
VULNFLOW_OSV_TIMEOUT_SECONDS=15
VULNFLOW_OSV_RETRIES=3
VULNFLOW_OSV_BATCH_SIZE=100
VULNFLOW_OSV_MAX_RESPONSE_BYTES=4194304
VULNFLOW_OUTBOUND_ALLOW_PRIVATE_NETWORKS=0
VULNFLOW_OUTBOUND_HOST_ALLOWLIST=api.osv.dev,www.cisa.gov,api.first.org,*.atlassian.net
```

## 검증

`tests/test_osv_discovery_v19.py`와 `scripts/osv_discovery_smoke.py`는 다음을 확인합니다.

- PURL version 규칙
- 리다이렉트 차단
- querybatch·전체 레코드 조회
- modified 기반 캐시
- 실패 작업 재시도 멱등성
- CVE alias 후보 확정과 finding 생성
- CVE alias 없는 후보의 확정 차단
- 루프백 기본 차단과 명시적 테스트 허용
- 호스트 allowlist·응답 크기 제한
- 실제 로컬 서버를 통한 DNS 고정 OSV querybatch·record 조회
