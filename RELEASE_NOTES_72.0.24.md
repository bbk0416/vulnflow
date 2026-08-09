# VulnFlow 72.0.24

실제 고객 스캐너 파일 호환성 문제를 안전하게 재현할 수 있도록 원본 형식을 유지하는 익명화 수집 번들을 추가한 릴리스입니다.

## 주요 변경

- Nessus·Greenbone XML·CSV·XLSX의 원본 형식을 유지하는 익명화 샘플 생성
- 호스트명, IP, FQDN, UUID·GUID, MAC, 담당자, 이메일과 내부 URL 가명 처리
- description, synopsis, solution, plugin output 등 자유서술 제거
- XLSX를 values-only workbook으로 재생성해 작성자, 시트명, 링크, 수식, 서식과 숨은 객체 제거
- `compatibility`와 제품·플러그인·버전·CPE까지 가명 처리하는 `strict` 프로필 제공
- 원본 파일명, 원본 파일, 치환표와 원본 SHA-256을 ZIP에서 제외
- 구조화된 원본 식별자가 결과에 남으면 번들 생성 차단
- 익명화 보고서와 기존 scanner compatibility 보고서를 하나의 ZIP으로 제공
- 결과 가져오기 화면과 오프라인 CLI에서 동일 기능 제공
- 공개 핵심 회귀시험 342개로 확대
- SQLite schema 44 유지

## 한계

자동 익명화는 알려진 구조화 필드와 scanner element 중심입니다. 임의 문자열에 포함된 비밀번호·토큰·고객 코드와 제품 inventory의 민감성을 완전히 판별하지는 않습니다. 공유 전 사람이 결과 파일과 보고서를 다시 검토해야 하며, 이 기능은 법적 익명성 보증이나 DLP 제품을 대체하지 않습니다.
