# 스캐너 익명화 수집 번들

실제 Nessus·Greenbone·CSV·XLSX 파일의 파서 호환성을 확인하려면 원본 구조를 유지한 재현 샘플이 필요합니다. 그러나 원본에는 호스트명, IP, FQDN, UUID, MAC, 담당자, 이메일, 내부 설명과 경로가 포함될 수 있습니다. VulnFlow는 원본을 그대로 공유하지 않고 진단에 필요한 구조만 남기는 수집 번들을 생성합니다.

## 화면에서 생성

```text
결과 가져오기
→ 공유용 익명화 진단 번들
→ 파일 선택
→ 호환성 우선 또는 엄격 익명화
→ ZIP 다운로드
```

서버는 파일을 메모리에서 처리하며 원본이나 치환표를 미리보기 저장소에 기록하지 않습니다. ZIP 파일명도 원본 파일명을 사용하지 않습니다.

## CLI에서 생성

```bash
python scripts/scanner_collection_bundle.py customer-export.nessus \
  --output reports/vulnflow-scanner-collection-bundle.zip \
  --profile compatibility
```

엄격 익명화:

```bash
python scripts/scanner_collection_bundle.py customer-export.xml \
  --output reports/vulnflow-scanner-collection-bundle.zip \
  --profile strict
```

## ZIP 내용

```text
sample/sanitized-scanner-sample.<원본 형식 확장자>
reports/anonymization.json
reports/compatibility.json
README.txt
```

원본 파일, 원본 파일명, source-to-alias 치환표와 원본 SHA-256은 포함하지 않습니다.

## 익명화 범위

두 프로필 모두 다음 값을 일관된 가명으로 바꾸거나 제거합니다.

- 호스트명, FQDN, IP 주소
- UUID·GUID·자산 ID·MAC 주소
- 사용자명, 담당자와 이메일
- 내부 URL
- description, synopsis, solution, plugin output와 기타 자유서술
- XLSX workbook 작성자, 시트명, 링크, 수식, 서식과 숨은 객체

`compatibility`는 파서 재현에 필요한 제품·플러그인·버전·CPE 값을 유지합니다. `strict`는 이 값도 가명 처리합니다. CVE, CVSS, severity, 포트·프로토콜과 XML·열 구조는 유지합니다.

## 생성 차단 조건

익명화 도중 구조화된 원본 식별자로 수집한 값이 결과 파일에 그대로 남으면 ZIP 생성을 중단합니다. 결과 보고서에는 치환 개수, 범주별 alias 개수, 출력 SHA-256, 파서 호환성 상태와 제한사항이 기록됩니다.

## 반드시 사람이 다시 확인할 항목

자동 처리는 구조화된 필드와 알려진 scanner element를 중심으로 동작합니다. 임의 형식의 API 토큰, 비밀번호, 고객명, 사내 코드, 티켓 번호나 제품명 자체의 민감성까지 완전히 판별할 수는 없습니다. 따라서 공유 전 다음을 수행해야 합니다.

1. `reports/anonymization.json`의 제한사항과 residual 항목 확인
2. 샘플 파일에서 고객명·사내 도메인·토큰을 문자열 검색
3. 제품 inventory도 공유하면 안 되는 조직은 `strict` 프로필 사용
4. 승인된 전달 경로와 보존 기간 적용

이 도구는 데이터 유출 방지 제품이나 법적 익명성 보증이 아닙니다. 실제 파일 공유 승인 절차를 대체하지 않습니다.
