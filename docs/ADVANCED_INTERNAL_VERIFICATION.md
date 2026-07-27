# Advanced verification retained in the internal release

VulnFlow의 내부 72.0.11 기준본에는 다음 검증 계층이 추가로 존재합니다.

- 555개 전체 자동시험
- 애플리케이션 line coverage 79.96%
- 결정적 wheel·sdist 반복 빌드
- Linux CPython runtime dependency snapshot
- in-toto/SLSA provenance와 DSSE 서명 리허설
- 서명형 전체 릴리스 키트와 오프라인 설치 bootstrap
- 교차버전 업그레이드·복구, runtime soak, 실제 Uvicorn·worker·cluster 리허설

이 공개 저장소에서는 취약점 운영 문제와 애플리케이션 코드가 먼저 보이도록 생성 산출물과 장문의 릴리스 보고서를 제외했습니다. 위 검증은 상용 운영 실적이나 제3자 인증이 아니라, 로컬 시험환경에서 수행한 자체 회귀·릴리스 검증입니다.
