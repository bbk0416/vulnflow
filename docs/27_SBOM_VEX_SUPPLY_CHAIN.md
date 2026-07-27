# SBOM·Finding 연계와 VEX 관리

VulnFlow 18.0은 CycloneDX JSON을 제품 릴리스 단위로 저장하고, 구성요소를 기존 취약점 finding과 연결한 뒤 VEX 영향판정을 검토·승인·내보냅니다.

## 데이터 흐름

```text
CycloneDX SBOM
→ sbom_documents
→ sbom_components
→ sbom_finding_links(CANDIDATE)
→ operator CONFIRMED / REJECTED
→ vex_statements revision
→ 승인된 최신 revision
→ CycloneDX VEX JSON
```

## 자동 연결 기준

자동 연결은 다음 조건을 사용합니다.

1. 정규화한 구성요소 이름이 동일해야 합니다.
2. SBOM과 finding 양쪽에 버전이 있으면 동일해야 합니다.
3. 제품명·제품 버전 일치는 신뢰도를 높입니다.
4. 신뢰도 80 미만의 약한 일치는 저장하지 않습니다.

자동 연결은 `CANDIDATE` 상태의 검토 후보이며 실제 영향판정이 아닙니다. operator가 `CONFIRMED`로 확정한 링크만 finding 연계 VEX 근거로 사용할 수 있고, `REJECTED` 링크는 재조정 전까지 자동 연결을 반복하지 않습니다.

## VEX 상태

- `IN_TRIAGE`
- `EXPLOITABLE`
- `NOT_AFFECTED`
- `RESOLVED`
- `FALSE_POSITIVE`

`NOT_AFFECTED`와 `FALSE_POSITIVE`에는 CycloneDX justification이 필요합니다. `NOT_AFFECTED`에는 영향 분석, `RESOLVED`에는 조치 내용이나 상세 근거가 필요합니다.

## Revision·승인

VEX를 수정하면 기존 행을 덮어쓰지 않고 revision 번호가 증가한 새 DRAFT를 생성합니다.

```text
DRAFT → PENDING → APPROVED / REJECTED
```

내보내기는 각 `SBOM + 구성요소 + CVE` 조합의 최신 승인 revision만 사용합니다. 새 DRAFT가 있어도 이전 승인 revision은 계속 내보낼 수 있습니다.

## Embedded vulnerability analysis

입력 CycloneDX의 `vulnerabilities[].analysis`는 다음 정보를 읽습니다.

- state
- justification
- response
- detail
- affects ref

외부 분석을 자동 신뢰하지 않기 위해 항상 DRAFT로 가져옵니다.

## CycloneDX VEX 내보내기

내보내기 문서는 CycloneDX 1.6 JSON이며 다음을 포함합니다.

- 제품 metadata
- 구성요소와 bom-ref 또는 PURL
- 승인된 vulnerability analysis
- affects 참조
- VulnFlow VEX ID·revision·승인자 property

## 제한

- PURL 기반 외부 취약점 데이터베이스 자동 조회는 하지 않습니다.
- 코드 도달성·호출 그래프·실행환경을 자동 분석하지 않습니다.
- CSAF·OpenVEX 출력은 아직 지원하지 않습니다.
- 자동 연결·VEX는 조직의 제품보안 검토와 승인 절차를 대체하지 않습니다.
