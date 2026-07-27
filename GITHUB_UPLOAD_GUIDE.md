# GitHub upload guide

## 권장 저장소 설정

- Repository name: `vulnflow`
- Description: `FastAPI + SQLite vulnerability operations platform for prioritization, remediation, evidence, audit and recovery.`
- Visibility: Public
- License: MIT

## 추천 Topics

`vulnerability-management`, `security-engineering`, `security-automation`, `fastapi`, `sqlite`, `sbom`, `vex`, `osv`, `cybersecurity`, `python`

## 업로드 전 확인

1. 이 폴더의 내용을 저장소 루트에 업로드합니다.
2. `.env`, `*.db`, 증거파일, private key를 추가하지 않습니다.
3. Actions의 `public-ci`가 230개 시험을 통과하는지 확인합니다.
4. GitHub Releases에는 필요할 때만 전체 프로젝트 ZIP 또는 wheel을 별도로 올립니다.
5. README의 지원 범위와 한계 문구를 삭제하지 않습니다.

## 첫 커밋 예시

```bash
git init
git add .
git commit -m "Publish VulnFlow 72.0.11 portfolio source"
git branch -M main
git remote add origin <YOUR_REPOSITORY_URL>
git push -u origin main
```

## 업로드 후 바로 수정할 항목

1. GitHub 저장소의 **Settings → Security → Private vulnerability reporting**을 활성화합니다.
2. `RELEASE_NOTES_72.0.11.md` 내용을 이용해 `v72.0.11` GitHub Release를 만듭니다.
3. 저장소 설명과 Topics는 `GITHUB_REPOSITORY_TEXT.txt` 값을 사용합니다.
4. 대표 저장소로 사용할 경우 프로필에서 Pin 처리합니다.
