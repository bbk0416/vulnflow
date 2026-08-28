# VulnFlow documentation map

Current application/repository line: **72.0.102**.

이 문서는 현재 운영자가 먼저 읽어야 할 문서와 엔지니어링 검증 기록을 분리해 보여주는 문서 지도입니다.
검증·증거 문서는 품질 추적용 엔지니어링 기록이며, 고객 검증·상용 준비 완료·엔터프라이즈 운영 승인 자체를 의미하지 않습니다.

## Start here

- [Project README](../README.md)
- [Public scope](../PUBLIC_SCOPE.md)
- [Changelog](../CHANGELOG.md)

## Operator and workflow

- [운영 가이드](05_OPERATIONS_GUIDE.md)
- [백업과 복원](09_BACKUP_RESTORE.md)
- [Witness-signed recovery-journal key backup](105_WITNESSED_RECOVERY_JOURNAL_KEY_BACKUP.md)
- [API와 운영](10_API_AND_OPERATIONS.md)
- [Authorized external-validation operator](112_AUTHORIZED_EXTERNAL_VALIDATION_OPERATOR.md)
- [Locked local runtime installation](126_LOCKED_LOCAL_RUNTIME_INSTALLATION.md)
- [P0 real/public scanner corpus closure](132_P0_REAL_PUBLIC_SCANNER_CORPUS_CLOSURE.md)
- [Multi-Scanner Canonical Finding Reconciliation](29_MULTI_SCANNER_RECONCILIATION.md)
- [Scanner Import Wizard](41_SCANNER_IMPORT_WIZARD.md)
- [Project integrity and scheduled operations](43_PROJECT_INTEGRITY_AND_SCHEDULED_OPERATIONS.md)
- [Recovery drills and external backup retention](44_RECOVERY_DRILLS_AND_EXTERNAL_BACKUPS.md)
- [서비스 레지스트리와 가져오기 모듈 경계](48_SERVICE_AND_IMPORT_MODULE_BOUNDARIES.md)
- [스캐너 익명화 수집 번들](49_SCANNER_ANONYMIZATION_COLLECTION.md)
- [제어 DB 분리와 프로젝트 복원 경계](50_CONTROL_DATABASE_AND_RESTORE_BOUNDARY.md)
- [Dependency install and runtime image boundary](58_DEPENDENCY_INSTALL_AND_RUNTIME_IMAGE_BOUNDARY.md)
- [Container-equivalent deployment rehearsal](86_CONTAINER_DEPLOYMENT_REHEARSAL.md)
- [72.0.15 Scanner Import Stabilization](92_SUBMISSION_STABILIZATION.md)
- [Atomic offline deployment activation](96_ATOMIC_OFFLINE_DEPLOYMENT_ACTIVATION.md)

## Current technical reference

- [문제와 범위](01_PROBLEM_AND_SCOPE.md)
- [보안·개인정보 설계](07_SECURITY_PRIVACY.md)
- [FastAPI router-transfer compatibility](123_FASTAPI_ROUTER_TRANSFER_COMPATIBILITY.md)
- [FastAPI callable-cache lifecycle release](125_FASTAPI_CALLABLE_CACHE_RELEASE.md)
- [Request-scoped router DI migration](128_REQUEST_SCOPED_ROUTER_DI_MIGRATION.md)
- [Asset Merge Scoped Rollback](32_ASSET_MERGE_SCOPED_ROLLBACK.md)
- [29.0 구성 기준선·드리프트](38_CONFIGURATION_BASELINE_DRIFT.md)
- [30.0 승인형 구성 변경 통제](39_CONFIGURATION_CHANGE_CONTROL.md)
- [Production security profile](52_PRODUCTION_SECURITY_PROFILE.md)
- [Live TLS and database schema boundaries](53_LIVE_TLS_AND_SCHEMA_BOUNDARIES.md)
- [Runtime dependency attestation and release schema boundary](59_RUNTIME_DEPENDENCY_ATTESTATION_AND_RELEASE_SCHEMA.md)
- [Repository maintenance policy](95_REPOSITORY_MAINTENANCE_POLICY.md)

## Other active engineering documents

- [방법과 제한](03_METHOD_AND_LIMITATIONS.md)
- [Roadmap](08_ROADMAP.md)
- [Windows path-contract completion](118_WINDOWS_PATH_CONTRACT_COMPLETION.md)
- [Windows router namespace runtime](121_WINDOWS_ROUTER_NAMESPACE_RUNTIME.md)
- [Windows garbage-collection baseline contract](124_WINDOWS_GC_BASELINE_CONTRACT.md)
- [In-memory router namespace cloning](127_IN_MEMORY_ROUTER_NAMESPACE_CLONING.md)
- [역할·위험수용 승인](12_RBAC_APPROVALS.md)
- [Long-running background-job lease heartbeat](135_LONG_RUNNING_JOB_LEASE_HEARTBEAT.md)
- [웹훅과 관측성](15_WEBHOOKS_OBSERVABILITY.md)
- [영속 백그라운드 작업](17_BACKGROUND_JOBS.md)
- [다중 인스턴스 조정](19_MULTI_INSTANCE_COORDINATION.md)
- [Asset Inventory, Exposure Groups, and Remediation Campaigns](22_ASSET_INVENTORY_CAMPAIGNS.md)
- [SBOM·Finding 연계와 VEX 관리](27_SBOM_VEX_SUPPLY_CHAIN.md)
- [OSV 공급망 취약점 탐색](28_OSV_SUPPLY_CHAIN_DISCOVERY.md)
- [자산 식별 레지스트리와 안전 병합](30_ASSET_IDENTITY_RESOLUTION.md)
- [자산 병합 영향분석·승인·복구](31_ASSET_MERGE_GOVERNANCE.md)
- [24.0 SQL 조회·페이지네이션·성능 검증](33_SQL_QUERY_PAGINATION_PERFORMANCE.md)
- [26.0 스냅샷 내보내기와 산출물 무결성](35_SNAPSHOT_EXPORT_ARTIFACTS.md)
- [Easy UI product mode](40_EASY_UI_PRODUCT_MODE.md)
- [Project email and Jira integrations](45_EMAIL_AND_JIRA_INTEGRATIONS.md)
- [파일럿 시작 센터](47_PILOT_LAUNCH_CENTER.md)
- [제어 DB 복구와 로그인 실패 제한](51_CONTROL_RECOVERY_AND_AUTH_RATE_LIMIT.md)
- [Runtime fault resilience](54_RUNTIME_FAULT_RESILIENCE.md)
- [HTTP outbound egress boundary](55_OUTBOUND_EGRESS_BOUNDARY.md)
- [SMTP egress and production Compose boundary](56_SMTP_EGRESS_AND_PRODUCTION_COMPOSE.md)
- [Intelligence egress and service boundaries](57_INTELLIGENCE_EGRESS_AND_SERVICE_BOUNDARIES.md)
- [Bounded runtime stability soak](85_RUNTIME_STABILITY_SOAK.md)
- [Public quality gates](93_PUBLIC_QUALITY_GATES.md)

## Validation and engineering evidence

아래 문서는 현재 저장소의 검증·증거 추적용입니다. 제품 사용 순서보다 엔지니어링 근거 확인이 필요할 때 사용합니다.

- [External validation evidence gate](106_EXTERNAL_VALIDATION_EVIDENCE_GATE.md)
- [External validation execution and report binding](107_EXTERNAL_VALIDATION_EXECUTION_BINDING.md)
- [Signed external validation challenge-response exchange](108_SIGNED_EXTERNAL_VALIDATION_EXCHANGE.md)
- [Signed external validation runner kit](109_SIGNED_EXTERNAL_VALIDATION_RUNNER_KIT.md)
- [External validation source attestation and execution snapshot](110_EXTERNAL_VALIDATION_SOURCE_ATTESTATION.md)
- [Requester acceptance ledger for external validation](113_EXTERNAL_VALIDATION_ACCEPTANCE_LEDGER.md)
- [External-validation acceptance checkpoint series](115_EXTERNAL_VALIDATION_CHECKPOINT_SERIES.md)
- [External-validation checkpoint-series transfer](116_EXTERNAL_VALIDATION_CHECKPOINT_TRANSFER.md)
- [Windows external-validation remediation](117_WINDOWS_EXTERNAL_VALIDATION_REMEDIATION.md)
- [Isolated Router Runtime Release](119_ISOLATED_ROUTER_RUNTIME_RELEASE.md)
- [Windows isolated source-route release](122_WINDOWS_ISOLATED_SOURCE_ROUTE_RELEASE.md)
- [GitHub publication lifecycle](133_GITHUB_PUBLICATION_LIFECYCLE.md)
- [감사 체인·서명 체크포인트](20_AUDIT_INTEGRITY.md)
- [Remediation verification and recurrence](23_REMEDIATION_VERIFICATION.md)
- [조치 검증 증거 저장소](24_VERIFICATION_EVIDENCE_STORE.md)
- [Evidence quarantine and malware scanning](25_EVIDENCE_QUARANTINE_MALWARE_SCAN.md)
- [Evidence Chain of Custody](26_EVIDENCE_CHAIN_OF_CUSTODY.md)
- [제품 파일럿 전 운영 검증](46_PRODUCTION_VALIDATION.md)
- [Docker runtime 검증](94_DOCKER_RUNTIME_VALIDATION.md)

## Historical material

이전 release/validation 기록은 [`archive/`](archive/) 아래에 보존합니다.
현재 동작이나 현재 acceptance를 판단할 때는 archive 기록을 최신 상태로 오해하지 마세요.
