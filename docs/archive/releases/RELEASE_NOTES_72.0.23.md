# VulnFlow 72.0.23

실제 고객 스캐너 파일을 받기 전 단계에서, Nessus·Greenbone 가져오기 경계가 조용히 잘못 해석되거나 비정상 XML에 과도한 자원을 쓰지 않도록 파서 계약과 진단 정보를 강화한 릴리스입니다.

## 주요 변경

- XML DTD·ENTITY 차단에 더해 업로드 크기, 요소 수, 중첩 깊이, 텍스트 총량, 요소 속성 수 제한 추가
- 확장자 없는 UTF-8 BOM XML의 Nessus·Greenbone 자동 판별
- Nessus CPE 2.2/2.3 제품·버전 해석, CVSS v4 점수, host UUID 보존
- Greenbone XML의 `<ref type="cve" id="CVE-...">` 참조와 solution 정보 지원
- Greenbone 세미콜론 CSV와 `Host` IP 열 변형 지원
- 동일 자산·CVE·제품·구성요소 중복 행을 호환성 경고로 표시
- 오프라인 호환성 CLI에서 최대 파일 크기를 읽기 전에 검사
- 합성 스캐너 fixture 5개에서 9개로 확대
- BOM·CPE 2.2·중복·DOCTYPE·과도한 깊이·잘린 XML을 검증하는 6개 강건성 계약 추가
- 공개 핵심 회귀시험 335개로 확대
- SQLite schema 44 유지

## 한계

합성 fixture와 변형 계약은 파서 회귀 방지용이며 특정 Nessus 또는 Greenbone 버전 전체의 호환 인증이 아닙니다. 실제 고객 파일은 별도 승인 후 오프라인 호환성 보고서로 검증해야 합니다.
