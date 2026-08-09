# 제품 파일럿 전 운영 검증

VulnFlow 72.0.32은 제품 파일럿 전에 반복 실행할 수 있는 자체 검증 도구를 제공합니다. 이 검증은 **실제 고객 환경 인증이 아니라**, 저장소 안에서 재현 가능한 업그레이드·스캐너 파서·외부 연동 연결 경계를 확인하기 위한 것입니다.

## 한 번에 실행

```bash
python scripts/production_validation.py --docker auto --json-output reports/production_validation.json
```

검사 항목:

1. 72.0.18 / SQLite schema 42 fixture를 현재 schema 46로 실제 마이그레이션
2. 기존 관리자와 finding 보존 확인
3. schema 43 협업 테이블, schema 44 파일럿 프로필, schema 46 로그인 제한 migration과 암호화 자격증명 쓰기 확인
4. 합성 Nessus·OpenVAS·CSV·XLSX fixture 9개 호환성 계약 확인
5. BOM·CPE 2.2·Greenbone ref·중복·비정상 XML 6개 강건성 계약 확인
6. Docker가 있으면 현재 image build, bind-mounted legacy DB migration, readiness 확인

Docker 검증을 반드시 요구하려면:

```bash
python scripts/production_validation.py --docker required
```

Docker가 없는 환경에서 호스트 검증만 수행하려면:

```bash
python scripts/production_validation.py --docker skip
```

## 스캐너 파일 호환성 보고서

고객이 제공한 승인된 내보내기 파일을 **반영하지 않고** 오프라인 분석합니다.

```bash
python scripts/scanner_compatibility_report.py customer.nessus report.xml findings.xlsx \
  --json-output reports/customer_scanner_compatibility.json
```

결과 상태:

- `READY`: 현재 파서 기준 오류 없이 정규화 가능
- `REVIEW`: 일부 항목 제외, 필드 누락 또는 행 오류 검토 필요
- `BLOCKED`: 파일 형식·보안 제한·파싱 오류로 반영 불가

저장소의 `tests/fixtures/scanners/`는 파서 회귀용 **합성 fixture**입니다. 특정 Nessus·Greenbone 버전 전체를 인증하거나 실제 고객 파일 호환을 보장하지 않습니다.

합성 파일 계약만 다시 확인하려면:

```bash
python scripts/scanner_fixture_matrix.py --json-output reports/scanner_fixture_matrix.json
python scripts/scanner_parser_robustness.py --json-output reports/scanner_parser_robustness.json
```

## SMTP·Jira 읽기 전용 연결 점검

저장된 프로젝트 연동 설정으로 인증과 조회 권한만 확인합니다. 이메일을 보내거나 Jira 이슈를 생성하지 않습니다.

```bash
VULNFLOW_INTEGRATION_SECRET_KEY='운영-마스터-키' \
python scripts/integration_connection_check.py \
  --db ./data/projects/customer-a/vulnflow.db \
  --channel all \
  --json-output reports/integration_connection_check.json
```

관리자 UI의 `관리자 메뉴 → 이메일·Jira 연동 → 저장된 설정 연결 점검`에서도 동일한 읽기 전용 진단을 실행할 수 있습니다.

## Docker 업그레이드 리허설

```bash
python scripts/docker_upgrade_rehearsal.py --mode docker --require-docker \
  --json-output reports/docker_upgrade_rehearsal.json
```

Docker가 없는 개발 환경에서는 정확한 schema migration만 호스트에서 검증할 수 있습니다.

```bash
python scripts/docker_upgrade_rehearsal.py --mode host
```

## HTTP 외부 통신 경계 리허설

웹훅·Jira용 pinned HTTP client의 DNS 검증, TLS SNI·인증서 호스트 검증, 원래 `Host` 헤더, 환경 프록시 무시, 사설망 차단과 allowlist를 임시 로컬 CA에서 확인합니다.

```bash
python scripts/outbound_egress_rehearsal.py
pytest -q tests/test_outbound_egress_v89.py
```

이 검증은 로컬 합성 endpoint를 사용하며 실제 Jira tenant, 고객 방화벽, DNS resolver 또는 운영 egress ACL을 인증하지 않습니다. SMTP는 별도의 pinned STARTTLS/SMTPS 경계로 검증합니다.

## SMTP 외부 통신 경계 리허설

```bash
python scripts/smtp_egress_rehearsal.py
pytest -q tests/test_smtp_egress_v90.py
```

임시 로컬 CA와 STARTTLS 서버에서 검증된 IP 직접 연결, 원래 호스트 SNI·인증서 검증, 인증과 실제 DATA 전송, 사설망·allowlist·평문 SMTP 차단을 확인합니다. 실제 고객 SMTP relay나 메일 도달률을 인증하지 않습니다.

## Production Compose 실기동 게이트

```bash
python scripts/production_compose_rehearsal.py --require-docker \
  --json-output reports/production_compose_rehearsal.json
```

Docker가 있는 CI에서는 현재 image build, Nginx TLS proxy, project-scoped 인증, 합성 import, container restart, named-volume 영속성, UID 10001과 내부 backend network를 실제로 검사합니다. Docker가 없는 환경에서는 이 결과를 통과로 간주하지 않습니다.

## 판정 한계

- 로컬 SMTP STARTTLS 전송은 합성 서버에서 확인했지만 실제 고객 relay의 인증·라우팅·도달률과 Jira 이슈 생성은 별도 승인된 시험 계정에서 확인해야 합니다.
- 합성 스캐너 fixture와 강건성 변형은 실제 고객사 export 대체물이 아닙니다.
- Docker host, NAS, proxy, TLS, 방화벽과 운영 ACL은 배포 대상 환경에서 다시 검증해야 합니다.
- `READY`는 구조 호환 판정이며 취약점 내용의 정확성이나 스캐너 품질을 보증하지 않습니다.


## Intelligence outbound validation

72.0.32부터 OSV·CISA KEV·FIRST EPSS는 일반 `requests` 연결 대신 검증된 IP에 고정되는 bounded JSON 전송을 사용합니다. 공개 준비 환경에서는 실제 공급자를 호출하지 않았으므로 이 검증은 로컬 전송 계약이며 공급자 가용성 인증이 아닙니다.
