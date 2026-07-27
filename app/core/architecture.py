from __future__ import annotations

"""Static architecture inventory and guardrails for the local codebase."""

import ast
import re
import json
from pathlib import Path
from typing import Any

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}
HARD_LINE_BUDGETS = {
    "app/main.py": 760,
    "app/application_runtime.py": 60,
    "app/application_runtime_common.py": 60,
    "app/application_lifespan.py": 180,
    "app/http_runtime.py": 260,
    "app/endpoint_workflows.py": 500,
    "app/application_services.py": 650,
    "app/core/storage.py": 160,
    "app/core/database_schema.py": 750,
    "app/services/database_lifecycle.py": 540,
    "app/factory.py": 120,
    "app/core/context.py": 130,
    "app/core/context_composition.py": 140,
    "app/core/context_diagnostics.py": 80,
    "app/core/transactions.py": 340,
    "app/core/retry.py": 260,
    "app/core/runtime.py": 180,
    "app/core/public_signing.py": 220,
    "app/services/proof_trust.py": 80,
    "app/services/proof_transitions.py": 320,
    "app/services/proof_trust_resolver.py": 220,
    "app/services/proof_checkpoint.py": 420,
    "app/services/proof_transparency.py": 560,
    "app/services/proof_mirror.py": 620,
    "app/services/proof_consistency.py": 520,
    "app/services/integrity_proofs.py": 80,
    "app/services/integrity_proof_common.py": 100,
    "app/services/integrity_proof_bundle.py": 520,
    "app/services/integrity_proof_verifier.py": 760,
    "app/services/job_runtime.py": 60,
    "app/services/job_dispatch.py": 320,
    "app/services/job_worker_runtime.py": 160,
    "app/services/lifecycle_runtime.py": 380,
    "app/services/lifecycle_resources.py": 180,
    "app/services/operation_guard.py": 220,
    "app/services/request_processing.py": 360,
    "app/services/view_models.py": 80,
    "app/routers/__init__.py": 150,
    "app/routers/findings.py": 800,
    "app/routers/supply_chain.py": 800,
    "app/routers/assets.py": 800,
    "app/routers/evidence.py": 800,
    "app/routers/governance.py": 280,
    "app/routers/governance_policy.py": 320,
    "app/routers/governance_controls.py": 520,
    "app/routers/trust.py": 260,
    "app/routers/trust_observability.py": 340,
    "app/routers/exports.py": 800,
    "app/routers/operations.py": 800,
    "app/repositories/audit.py": 450,
    "app/repositories/campaigns.py": 240,
    "app/repositories/idempotency.py": 180,
    "app/repositories/execution_receipts.py": 360,
    "app/repositories/execution_receipt_retention.py": 220,
    "app/repositories/jobs.py": 80,
    "app/repositories/job_records.py": 280,
    "app/repositories/job_execution.py": 300,
    "app/repositories/webhooks.py": 60,
    "app/repositories/webhook_queue.py": 220,
    "app/repositories/webhook_delivery.py": 220,
    "app/repositories/cluster.py": 400,
    "app/repositories/policies.py": 350,
    "app/repositories/findings.py": 100,
    "app/repositories/assets.py": 150,
    "app/repositories/reconciliation.py": 500,
    "app/repositories/asset_writes.py": 120,
    "app/repositories/asset_identity_writes.py": 220,
    "app/repositories/asset_inventory.py": 180,
    "app/repositories/asset_merge.py": 820,
    "app/repositories/asset_merge_rollback.py": 380,
    "app/repositories/finding_writes.py": 100,
    "app/repositories/finding_ingestion.py": 760,
    "app/repositories/finding_workflow.py": 660,
    "app/repositories/finding_approvals.py": 220,
}

ROUTER_ROUTE_BUDGET = 50
EXPECTED_ROUTE_COUNT = 241
REQUIRED_ROUTER_MODULES = {
    "app/routers/findings.py",
    "app/routers/supply_chain.py",
    "app/routers/assets.py",
    "app/routers/evidence.py",
    "app/routers/governance.py",
    "app/routers/governance_policy.py",
    "app/routers/governance_controls.py",
    "app/routers/trust.py",
    "app/routers/trust_observability.py",
    "app/routers/exports.py",
    "app/routers/operations.py",
}


REQUIRED_REPOSITORY_MODULES = {
    "app/repositories/audit.py",
    "app/repositories/campaigns.py",
    "app/repositories/idempotency.py",
    "app/repositories/execution_receipts.py",
    "app/repositories/execution_receipt_retention.py",
    "app/repositories/jobs.py",
    "app/repositories/job_records.py",
    "app/repositories/job_execution.py",
    "app/repositories/webhooks.py",
    "app/repositories/webhook_queue.py",
    "app/repositories/webhook_delivery.py",
    "app/repositories/cluster.py",
    "app/repositories/policies.py",
    "app/repositories/findings.py",
    "app/repositories/assets.py",
    "app/repositories/reconciliation.py",
    "app/repositories/asset_writes.py",
    "app/repositories/asset_identity_writes.py",
    "app/repositories/asset_inventory.py",
    "app/repositories/asset_merge.py",
    "app/repositories/asset_merge_rollback.py",
    "app/repositories/finding_writes.py",
    "app/repositories/finding_ingestion.py",
    "app/repositories/finding_workflow.py",
    "app/repositories/finding_approvals.py",
}

RELOCATED_STORAGE_FUNCTIONS = {
    "add_audit_event", "create_audit_checkpoint", "verify_audit_integrity",
    "create_background_job", "claim_background_job", "complete_background_job",
    "enqueue_webhook_events", "record_webhook_delivery",
    "register_cluster_instance", "acquire_cluster_lease",
    "create_policy_version", "approve_policy_activation_request",
    "count_findings", "list_findings", "get_finding",
    "list_assets", "get_asset", "list_exposure_groups",
    "upsert_findings", "apply_import_batch", "update_workflow", "bulk_update_workflow",
    "bulk_update_intel", "update_scores", "update_record_state",
    "create_risk_approval_request", "decide_risk_approval_request",
    "add_asset_identifier", "apply_asset_inventory", "create_asset_merge_request",
    "approve_asset_merge_request", "create_asset_merge_rollback_request",
    "approve_asset_merge_rollback_request",
    "init_db", "init_coordination_db", "get_schema_info",
    "create_campaign", "list_campaigns", "get_campaign", "update_campaign_status",
    "add_campaign_findings", "remove_campaign_finding",
    "backup_database", "validate_database_file", "restore_database", "list_maintenance_runs",
}


def _module_name(root: Path, path: Path) -> str:
    relative = path.relative_to(root).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _assigned_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def _class_names(tree: ast.AST) -> list[str]:
    return [node.name for node in getattr(tree, "body", []) if isinstance(node, ast.ClassDef)]


def _route_count(tree: ast.AST) -> int:
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            target = call.func if call else decorator
            if isinstance(target, ast.Attribute) and target.attr.lower() in HTTP_METHODS:
                count += 1
    return count


def _internal_imports(tree: ast.AST) -> set[str]:
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "app" or alias.name.startswith("app."):
                    imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and (node.module == "app" or node.module.startswith("app.")):
                imports.add(node.module)
    return imports


def _cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    cycles: set[tuple[str, ...]] = set()
    visiting: list[str] = []
    active: set[str] = set()
    done: set[str] = set()

    def visit(node: str) -> None:
        if node in done:
            return
        if node in active:
            index = visiting.index(node)
            cycle = visiting[index:] + [node]
            body = cycle[:-1]
            rotations = [tuple(body[i:] + body[:i]) for i in range(len(body))]
            cycles.add(min(rotations))
            return
        active.add(node)
        visiting.append(node)
        for target in sorted(graph.get(node, set())):
            if target in graph:
                visit(target)
        visiting.pop()
        active.remove(node)
        done.add(node)

    for module in sorted(graph):
        visit(module)
    return [list(cycle) + [cycle[0]] for cycle in sorted(cycles)]


def build_architecture_report(root: str | Path) -> dict[str, Any]:
    root_path = Path(root).resolve()
    files: list[dict[str, Any]] = []
    graph: dict[str, set[str]] = {}
    parse_errors: list[dict[str, str]] = []

    for path in sorted((root_path / "app").rglob("*.py")):
        relative = path.relative_to(root_path).as_posix()
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            parse_errors.append({"path": relative, "error": str(exc)})
            continue
        module = _module_name(root_path, path)
        imports = _internal_imports(tree)
        graph[module] = imports
        files.append(
            {
                "path": relative,
                "module": module,
                "lines": len(text.splitlines()),
                "classes": len(_class_names(tree)),
                "functions": sum(
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(tree)
                ),
                "function_names": sorted(
                    node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                ),
                "routes": _route_count(tree),
                "internal_imports": sorted(imports),
                "assigned_names": sorted(_assigned_names(tree)),
                "class_names": _class_names(tree),
            }
        )

    by_path = {item["path"]: item for item in files}
    violations: list[str] = []
    for path, maximum in HARD_LINE_BUDGETS.items():
        actual = int((by_path.get(path) or {}).get("lines") or 0)
        if actual == 0:
            violations.append(f"required module missing: {path}")
        elif actual > maximum:
            violations.append(f"line budget exceeded: {path} {actual}>{maximum}")

    storage_names = set((by_path.get("app/core/storage.py") or {}).get("assigned_names") or [])
    for forbidden in ("SCHEMA", "COORDINATION_SCHEMA", "MIGRATION_COLUMNS"):
        if forbidden in storage_names:
            violations.append(f"schema declaration remains in storage.py: {forbidden}")

    main_classes = set((by_path.get("app/main.py") or {}).get("class_names") or [])
    api_classes = sorted(name for name in main_classes if name.startswith("Api"))
    if api_classes:
        violations.append("API request models remain in main.py: " + ", ".join(api_classes))

    for required in (
        "app/core/schema.py", "app/core/database_schema.py", "app/core/settings.py", "app/core/runtime.py", "app/core/context.py",
        "app/core/transactions.py", "app/core/retry.py",
        "app/services/database_lifecycle.py", "app/services/proof_trust.py", "app/services/proof_transitions.py", "app/services/proof_trust_resolver.py", "app/services/proof_revocation.py", "app/services/proof_checkpoint.py", "app/services/proof_witness.py", "app/services/proof_transparency.py", "app/services/proof_mirror.py", "app/services/proof_consistency.py", "app/services/integrity_proofs.py", "app/services/integrity_proof_common.py", "app/services/integrity_proof_bundle.py", "app/services/integrity_proof_verifier.py", "app/api/models.py", "app/factory.py", "app/services/job_runtime.py", "app/services/job_dispatch.py", "app/services/job_worker_runtime.py",
        "app/services/lifecycle_runtime.py", "app/services/lifecycle_resources.py", "app/services/operation_guard.py",
        "app/application_services.py", "app/application_runtime.py", "app/application_runtime_common.py", "app/application_lifespan.py", "app/http_runtime.py", "app/endpoint_workflows.py",
        "app/services/request_processing.py", "app/services/view_models.py",
    ):
        if required not in by_path:
            violations.append(f"required architecture module missing: {required}")

    for required in sorted(REQUIRED_ROUTER_MODULES):
        if required not in by_path:
            violations.append(f"required router module missing: {required}")
        elif int(by_path[required].get("routes") or 0) > ROUTER_ROUTE_BUDGET:
            violations.append(
                f"router route budget exceeded: {required} "
                f"{by_path[required]['routes']}>{ROUTER_ROUTE_BUDGET}"
            )
    main_route_count = int((by_path.get("app/main.py") or {}).get("routes") or 0)
    if main_route_count:
        violations.append(f"route decorators remain in main.py: {main_route_count}")
    main_text = (root_path / "app" / "main.py").read_text(encoding="utf-8")
    if re.search(r"\bFastAPI\s*\(", main_text):
        violations.append("FastAPI construction remains in main.py")
    main_internal_imports = set((by_path.get("app/main.py") or {}).get("internal_imports") or [])
    allowed_main_imports = {
        "app.api.models", "app.application_lifespan", "app.http_runtime", "app.application_services", "app.endpoint_workflows", "app.core.context",
        "app.core.runtime", "app.core.settings", "app.factory", "app.routers",
        "app.services.request_processing", "app.services.view_models",
    }
    unexpected_main_imports = sorted(main_internal_imports - allowed_main_imports)
    if unexpected_main_imports:
        violations.append(
            "domain imports remain in main.py: " + ", ".join(unexpected_main_imports)
        )
    application_runtime_text = (root_path / "app" / "application_runtime.py").read_text(encoding="utf-8") if (root_path / "app" / "application_runtime.py").exists() else ""
    application_runtime_imports = set((by_path.get("app/application_runtime.py") or {}).get("internal_imports") or [])
    lifespan_text = (root_path / "app" / "application_lifespan.py").read_text(encoding="utf-8") if (root_path / "app" / "application_lifespan.py").exists() else ""
    lifespan_imports = set((by_path.get("app/application_lifespan.py") or {}).get("internal_imports") or [])
    http_runtime_text = (root_path / "app" / "http_runtime.py").read_text(encoding="utf-8") if (root_path / "app" / "http_runtime.py").exists() else ""
    http_runtime_imports = set((by_path.get("app/http_runtime.py") or {}).get("internal_imports") or [])
    for path, imports in (
        ("app/application_runtime.py", application_runtime_imports),
        ("app/application_lifespan.py", lifespan_imports),
        ("app/http_runtime.py", http_runtime_imports),
    ):
        if "app.main" in imports:
            violations.append(f"application runtime boundary imports app.main: {path}")
    for marker in (
        "from app.application_lifespan import application_lifespan, lifespan_scoped",
        "from app.http_runtime import friendly_http_error, local_security, local_security_scoped",
    ):
        if marker not in application_runtime_text:
            violations.append(f"application runtime facade missing: {marker}")
    for marker in (
        "async def lifespan_scoped(",
        "async def application_lifespan(",
        "LifecycleSupervisor(context)",
    ):
        if marker not in lifespan_text:
            violations.append(f"application lifespan boundary missing: {marker}")
    for marker in (
        "async def local_security_scoped(",
        "async def local_security(",
        "async def friendly_http_error(",
        "begin_http_write(",
    ):
        if marker not in http_runtime_text:
            violations.append(f"HTTP runtime boundary missing: {marker}")
    if "LifecycleSupervisor(context)" in main_text or "begin_http_write(" in main_text:
        violations.append("ASGI lifecycle or HTTP security implementation remains in main.py")
    endpoint_workflows_text = (root_path / "app" / "endpoint_workflows.py").read_text(encoding="utf-8") if (root_path / "app" / "endpoint_workflows.py").exists() else ""
    endpoint_workflows_imports = set((by_path.get("app/endpoint_workflows.py") or {}).get("internal_imports") or [])
    if "app.main" in endpoint_workflows_imports:
        violations.append("endpoint workflow boundary imports app.main compatibility module")
    for marker in (
        "class EndpointWorkflows:",
        "def ensure_policy_registry(",
        "def refresh_intelligence(",
        "def rescore_all(",
        "def enqueue_simple_job(",
    ):
        if marker not in endpoint_workflows_text:
            violations.append(f"endpoint workflow boundary missing: {marker}")
    if "_ENDPOINT_WORKFLOWS = EndpointWorkflows(globals())" not in main_text:
        violations.append("main.py does not install the endpoint workflow boundary")
    if len(main_text.splitlines()) > 500:
        violations.append("main.py endpoint workflow extraction regressed above 500 lines")
    application_services_text = (root_path / "app" / "application_services.py").read_text(encoding="utf-8") if (root_path / "app" / "application_services.py").exists() else ""
    for marker in (
        "APPLICATION_SERVICE_EXPORTS",
        "APPLICATION_SERVICE_NAMES",
        "def install_application_services(",
        "def application_service_snapshot(",
    ):
        if marker not in application_services_text:
            violations.append(f"application service registry boundary missing: {marker}")
    application_service_imports = set((by_path.get("app/application_services.py") or {}).get("internal_imports") or [])
    if "app.main" in application_service_imports:
        violations.append("application service registry imports app.main compatibility module")
    if "install_application_services(globals())" not in main_text:
        violations.append("main.py does not install the application service registry")
    extracted_main_helpers = {
        "_bounded_text", "_date_text", "_number", "_active", "_csv_safe",
        "_filter_findings", "_public_job", "_job_role", "_export_filters_from_values",
    }
    main_functions = set((by_path.get("app/main.py") or {}).get("function_names") or [])
    remaining_helpers = sorted(extracted_main_helpers & main_functions)
    if remaining_helpers:
        violations.append("request-processing helpers remain implemented in main.py: " + ", ".join(remaining_helpers))
    request_processing_text = (root_path / "app" / "services" / "request_processing.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "request_processing.py").exists() else ""
    view_models_text = (root_path / "app" / "services" / "view_models.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "view_models.py").exists() else ""
    if "app.main" in request_processing_text or "app.main" in view_models_text:
        violations.append("extracted main helper services import app.main compatibility module")
    for marker in ("def normalize_finding_row(", "def parse_findings_csv(", "def parse_assets_csv("):
        if marker not in request_processing_text:
            violations.append(f"request-processing boundary missing: {marker}")
    for marker in ("def campaign_member_ids(", "def evidence_with_custody("):
        if marker not in view_models_text:
            violations.append(f"view-model boundary missing: {marker}")
    factory_text = (root_path / "app" / "factory.py").read_text(encoding="utf-8") if (root_path / "app" / "factory.py").exists() else ""
    if "def create_application(" not in factory_text:
        violations.append("application factory entrypoint missing")
    runtime_text = (root_path / "app" / "core" / "runtime.py").read_text(encoding="utf-8") if (root_path / "app" / "core" / "runtime.py").exists() else ""
    context_text = (root_path / "app" / "core" / "context.py").read_text(encoding="utf-8") if (root_path / "app" / "core" / "context.py").exists() else ""
    context_composition_text = (root_path / "app" / "core" / "context_composition.py").read_text(encoding="utf-8") if (root_path / "app" / "core" / "context_composition.py").exists() else ""
    context_diagnostics_text = (root_path / "app" / "core" / "context_diagnostics.py").read_text(encoding="utf-8") if (root_path / "app" / "core" / "context_diagnostics.py").exists() else ""
    if "class RuntimeSettings" not in runtime_text or "class ServiceContainer" not in runtime_text:
        violations.append("immutable runtime dependency containers missing")
    retry_text = (root_path / "app" / "core" / "retry.py").read_text(encoding="utf-8") if (root_path / "app" / "core" / "retry.py").exists() else ""
    if "class RetryPolicy" not in retry_text or "def parse_retry_after(" not in retry_text:
        violations.append("durable retry policy boundary missing")
    jobs_text = (root_path / "app" / "repositories" / "jobs.py").read_text(encoding="utf-8")
    job_records_text = (root_path / "app" / "repositories" / "job_records.py").read_text(encoding="utf-8")
    job_execution_text = (root_path / "app" / "repositories" / "job_execution.py").read_text(encoding="utf-8")
    webhooks_repo_text = (root_path / "app" / "repositories" / "webhooks.py").read_text(encoding="utf-8")
    webhook_queue_text = (root_path / "app" / "repositories" / "webhook_queue.py").read_text(encoding="utf-8")
    webhook_delivery_text = (root_path / "app" / "repositories" / "webhook_delivery.py").read_text(encoding="utf-8")
    webhook_service_text = (root_path / "app" / "services" / "webhooks.py").read_text(encoding="utf-8")
    if "RetryPolicy" not in job_execution_text or "RetryPolicy" not in webhook_delivery_text:
        violations.append("job/webhook repositories do not use shared retry policy")
    idempotency_text = (root_path / "app" / "repositories" / "idempotency.py").read_text(encoding="utf-8") if (root_path / "app" / "repositories" / "idempotency.py").exists() else ""
    if "class IdempotencyConflict" not in idempotency_text or "def replay_result(" not in idempotency_text:
        violations.append("durable idempotency ledger boundary missing")
    if "key_sha256" not in idempotency_text or "raw client key is never persisted" not in idempotency_text:
        violations.append("idempotency key redaction boundary missing")
    if "replay_result" not in job_records_text or "store_result" not in job_records_text:
        violations.append("background job idempotency boundary missing")
    if "replay_result" not in webhook_queue_text or "store_result" not in webhook_queue_text:
        violations.append("webhook idempotency boundary missing")
    receipts_text = (root_path / "app" / "repositories" / "execution_receipts.py").read_text(encoding="utf-8") if (root_path / "app" / "repositories" / "execution_receipts.py").exists() else ""
    if "def record_execution_receipt(" not in receipts_text or "def replay_execution_receipt(" not in receipts_text:
        violations.append("redacted execution receipt boundary missing")
    if "payload_json" in receipts_text.split("def record_execution_receipt", 1)[-1].split("def get_execution_receipt", 1)[0]:
        violations.append("execution receipt stores raw payload")
    retention_text = (root_path / "app" / "repositories" / "execution_receipt_retention.py").read_text(encoding="utf-8") if (root_path / "app" / "repositories" / "execution_receipt_retention.py").exists() else ""
    if "def archive_execution_receipts(" not in retention_text or "execution_receipt_archives" not in retention_text:
        violations.append("execution receipt retention archive boundary missing")
    if "bj.status='SUCCEEDED'" not in retention_text or "wh.status='DELIVERED'" not in retention_text:
        violations.append("execution receipt retention terminal-success boundary missing")
    if "DROP TRIGGER execution_receipts_no_delete" not in retention_text or "_RECEIPT_DELETE_TRIGGER" not in retention_text:
        violations.append("execution receipt controlled prune boundary missing")
    if "record_execution_receipt" not in job_execution_text or "record_execution_receipt" not in webhook_delivery_text:
        violations.append("job/webhook execution receipt integration missing")
    if "retryable_http_status" not in webhook_service_text or "parse_retry_after" not in webhook_service_text:
        violations.append("webhook retry classification boundary missing")
    proof_trust_text = (root_path / "app" / "services" / "proof_trust.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "proof_trust.py").exists() else ""
    proof_transitions_text = (root_path / "app" / "services" / "proof_transitions.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "proof_transitions.py").exists() else ""
    proof_resolver_text = (root_path / "app" / "services" / "proof_trust_resolver.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "proof_trust_resolver.py").exists() else ""
    if "def create_integrity_proof_key_transition(" not in proof_transitions_text or "def validate_transition_document(" not in proof_transitions_text:
        violations.append("integrity proof transition record boundary missing")
    if "def resolve_trusted_proof_signer(" not in proof_resolver_text:
        violations.append("integrity proof trust resolver boundary missing")
    if "from_private_key" in proof_transitions_text.split("def create_integrity_proof_key_transition", 1)[-1].split("def transition_document_from_values", 1)[0]:
        violations.append("integrity proof transition stores private key material")
    proof_trust_importers = []
    for item in files:
        if item["path"] == "app/services/proof_trust.py":
            continue
        if "app.services.proof_trust" in set(item.get("internal_imports") or []):
            proof_trust_importers.append(item["path"])
    if proof_trust_importers:
        violations.append("application modules import proof_trust compatibility facade: " + ", ".join(sorted(proof_trust_importers)))
    if "from app.services.proof_transitions import" not in proof_trust_text or "from app.services.proof_trust_resolver import" not in proof_trust_text:
        violations.append("proof_trust compatibility facade exports are incomplete")
    proof_revocation_text = (root_path / "app" / "services" / "proof_revocation.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "proof_revocation.py").exists() else ""
    if "def create_integrity_proof_key_revocation(" not in proof_revocation_text or "def validate_revocation_document(" not in proof_revocation_text:
        violations.append("integrity proof emergency revocation boundary missing")
    revocation_create = proof_revocation_text.split("def create_integrity_proof_key_revocation", 1)[-1].split("def revocation_document_from_values", 1)[0]
    proof_checkpoint_text = (root_path / "app" / "services" / "proof_checkpoint.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "proof_checkpoint.py").exists() else ""
    if "def create_integrity_proof_revocation_checkpoint(" not in proof_checkpoint_text or "def verify_revocation_checkpoint_chain(" not in proof_checkpoint_text:
        violations.append("integrity proof revocation checkpoint boundary missing")
    if "private_key" in proof_checkpoint_text.split("INSERT INTO integrity_proof_revocation_checkpoints", 1)[-1] if "INSERT INTO integrity_proof_revocation_checkpoints" in proof_checkpoint_text else False:
        violations.append("integrity proof revocation checkpoint persistence may include private key material")
    proof_witness_text = (root_path / "app" / "services" / "proof_witness.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "proof_witness.py").exists() else ""
    if "def create_integrity_proof_checkpoint_witness(" not in proof_witness_text or "def verify_checkpoint_witness_quorum(" not in proof_witness_text:
        violations.append("integrity proof checkpoint witness quorum boundary missing")
    if "private_key" in proof_witness_text.split("INSERT INTO integrity_proof_checkpoint_witnesses", 1)[-1] if "INSERT INTO integrity_proof_checkpoint_witnesses" in proof_witness_text else False:
        violations.append("integrity proof checkpoint witness persistence may include private key material")
    proof_transparency_text = (root_path / "app" / "services" / "proof_transparency.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "proof_transparency.py").exists() else ""
    if "def publish_integrity_proof_transparency_head(" not in proof_transparency_text or "def verify_integrity_proof_transparency_log(" not in proof_transparency_text:
        violations.append("integrity proof transparency log boundary missing")
    transparency_insert_columns = ""
    if "INSERT INTO integrity_proof_transparency_entries(" in proof_transparency_text:
        transparency_insert_columns = proof_transparency_text.split("INSERT INTO integrity_proof_transparency_entries(", 1)[1].split(") VALUES", 1)[0]
    if any(name in transparency_insert_columns for name in ("private_key", "secret", "token")):
        violations.append("integrity proof transparency persistence may include private key material")
    proof_mirror_text = (root_path / "app" / "services" / "proof_mirror.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "proof_mirror.py").exists() else ""
    if "def create_integrity_proof_transparency_mirror_receipt(" not in proof_mirror_text or "def verify_transparency_mirror_gossip(" not in proof_mirror_text:
        violations.append("integrity proof transparency mirror gossip boundary missing")
    mirror_insert_columns = ""
    if "INSERT INTO integrity_proof_transparency_mirror_receipts(" in proof_mirror_text:
        mirror_insert_columns = proof_mirror_text.split("INSERT INTO integrity_proof_transparency_mirror_receipts(", 1)[1].split(") VALUES", 1)[0]
    if any(name in mirror_insert_columns for name in ("private_key", "secret", "token")):
        violations.append("integrity proof transparency mirror persistence may include private key material")
    integrity_proofs_text = (root_path / "app" / "services" / "integrity_proofs.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "integrity_proofs.py").exists() else ""
    integrity_bundle_text = (root_path / "app" / "services" / "integrity_proof_bundle.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "integrity_proof_bundle.py").exists() else ""
    integrity_verifier_text = (root_path / "app" / "services" / "integrity_proof_verifier.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "integrity_proof_verifier.py").exists() else ""
    integrity_common_text = (root_path / "app" / "services" / "integrity_proof_common.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "integrity_proof_common.py").exists() else ""
    proof_facade_importers = sorted(
        item["path"] for item in files
        if item["path"].startswith("app/")
        and item["path"] != "app/services/integrity_proofs.py"
        and "app.services.integrity_proofs" in set(item.get("internal_imports") or [])
    )
    if proof_facade_importers:
        violations.append("internal modules import integrity-proof compatibility facade: " + ", ".join(proof_facade_importers))
    if "from app.services.integrity_proof_bundle import create_integrity_proof_bundle" not in integrity_proofs_text:
        violations.append("integrity-proof bundle compatibility export missing")
    if "from app.services.integrity_proof_verifier import verify_integrity_proof_bundle" not in integrity_proofs_text:
        violations.append("integrity-proof verifier compatibility export missing")
    if "def create_integrity_proof_bundle(" not in integrity_bundle_text:
        violations.append("integrity-proof bundle creation boundary missing")
    if "def verify_integrity_proof_bundle(" not in integrity_verifier_text:
        violations.append("integrity-proof offline verifier boundary missing")
    if 'PROOF_FORMAT_ED25519_CONSISTENT = "vulnflow-integrity-proof/9"' not in integrity_common_text:
        violations.append("integrity-proof common format registry missing")
    for owner_path in ("app/services/integrity_proof_bundle.py", "app/services/integrity_proof_verifier.py", "app/services/integrity_proof_common.py"):
        owner_imports = set((by_path.get(owner_path) or {}).get("internal_imports") or [])
        if "app.services.integrity_proofs" in owner_imports:
            violations.append(f"integrity-proof owner imports compatibility facade: {owner_path}")
    proof_consistency_text = (root_path / "app" / "services" / "proof_consistency.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "proof_consistency.py").exists() else ""
    if "def create_integrity_proof_mirror_consistency_checkpoint(" not in proof_consistency_text or "def verify_mirror_consistency_chain(" not in proof_consistency_text:
        violations.append("integrity proof mirror consistency boundary missing")
    consistency_insert_columns = ""
    if "INSERT INTO integrity_proof_mirror_consistency_checkpoints(" in proof_consistency_text:
        consistency_insert_columns = proof_consistency_text.split("INSERT INTO integrity_proof_mirror_consistency_checkpoints(", 1)[1].split(") VALUES", 1)[0]
    if any(name in consistency_insert_columns for name in ("private_key", "secret", "token")):
        violations.append("integrity proof mirror consistency persistence may include private key material")
    if "private_key" in revocation_create.split("INSERT INTO integrity_proof_key_revocations", 1)[-1] if "INSERT INTO integrity_proof_key_revocations" in revocation_create else False:
        violations.append("integrity proof revocation persistence may include private key material")
    if "def dependency_mapping(" not in context_text or "def mutable_dependency_overrides(" not in context_text:
        violations.append("application context compatibility methods missing")
    for marker in ("def initialize_context_dependencies(", "def build_dependency_mapping(", "def clone_application_context("):
        if marker not in context_composition_text:
            violations.append(f"application context composition boundary missing: {marker}")
    if "def application_runtime_snapshot(" not in context_diagnostics_text:
        violations.append("application context diagnostics boundary missing")
    if "dependencies = context.services.as_dict()" in context_text or "structural_snapshot()" in context_text:
        violations.append("application context composition or diagnostics remain implemented in context.py")
    routers_init_text = (root_path / "app" / "routers" / "__init__.py").read_text(encoding="utf-8")
    if "class RouterRuntime" not in routers_init_text or "def _clone_router_module(" not in routers_init_text:
        violations.append("isolated router runtime boundary missing")
    if "class RequestRuntime" not in context_text or "def get_request_runtime(" not in context_text:
        violations.append("request runtime boundary missing")
    job_runtime_text = (root_path / "app" / "services" / "job_runtime.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "job_runtime.py").exists() else ""
    job_dispatch_text = (root_path / "app" / "services" / "job_dispatch.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "job_dispatch.py").exists() else ""
    job_worker_text = (root_path / "app" / "services" / "job_worker_runtime.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "job_worker_runtime.py").exists() else ""
    lifecycle_runtime_text = (root_path / "app" / "services" / "lifecycle_runtime.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "lifecycle_runtime.py").exists() else ""
    if "from app.services.job_dispatch import execute_background_job" not in job_runtime_text or "from app.services.job_worker_runtime import job_worker_loop" not in job_runtime_text:
        violations.append("background job runtime compatibility facade missing")
    if "def execute_background_job(" not in job_dispatch_text:
        violations.append("context-bound background job dispatch missing")
    if "async def job_worker_loop(" not in job_worker_text:
        violations.append("context-bound background worker orchestration missing")
    if "classify_operation_exception" not in job_worker_text:
        violations.append("background job exception classification missing")
    facade_importers = sorted(
        item["path"] for item in files
        if item["path"].startswith("app/")
        and item["path"] != "app/services/job_runtime.py"
        and "app.services.job_runtime" in set(item.get("internal_imports") or [])
    )
    if facade_importers:
        violations.append("internal background job runtime facade imports remain: " + ", ".join(facade_importers))
    dispatch_imports = set((by_path.get("app/services/job_dispatch.py") or {}).get("internal_imports") or [])
    worker_imports = set((by_path.get("app/services/job_worker_runtime.py") or {}).get("internal_imports") or [])
    if "app.services.job_runtime" in dispatch_imports or "app.services.job_runtime" in worker_imports:
        violations.append("background job owner module imports compatibility facade")
    if "class LifecycleSupervisor" not in lifecycle_runtime_text or "def schedule_maintenance(" not in lifecycle_runtime_text:
        violations.append("context-bound lifecycle supervisor missing")
    lifecycle_resources_text = (root_path / "app" / "services" / "lifecycle_resources.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "lifecycle_resources.py").exists() else ""
    if "class LifecycleResourceTracker" not in lifecycle_resources_text or "shutdown_timed_out" not in lifecycle_resources_text:
        violations.append("deterministic lifecycle resource tracker missing")
    if "stop_event=tracker.stop_event" not in lifecycle_runtime_text or "tracker.wait_or_stop" not in lifecycle_runtime_text:
        violations.append("lifecycle cooperative shutdown boundary missing")
    operation_guard_text = (root_path / "app" / "services" / "operation_guard.py").read_text(encoding="utf-8") if (root_path / "app" / "services" / "operation_guard.py").exists() else ""
    if "class OperationGuard" not in operation_guard_text or "def begin_http_write(" not in operation_guard_text:
        violations.append("context-bound operation guard missing")
    if "def exclusive_operation(" not in operation_guard_text or "def bind_operation_guard(" not in operation_guard_text:
        violations.append("exclusive operation guard boundary incomplete")
    if "operation_guard: Any | None" not in context_text or "operation_guard.dependency_mapping()" not in context_composition_text:
        violations.append("application context operation guard ownership missing")
    transactions_text = (root_path / "app" / "core" / "transactions.py").read_text(encoding="utf-8") if (root_path / "app" / "core" / "transactions.py").exists() else ""
    if "class SQLiteTransactionRuntime" not in transactions_text or "class SQLiteTransactionRegistry" not in transactions_text:
        violations.append("SQLite transaction runtime boundary missing")
    if "def write_transaction(" not in transactions_text or "def read_connection(" not in transactions_text:
        violations.append("SQLite transaction context managers missing")
    if "transaction_registry: SQLiteTransactionRegistry | None" not in context_text:
        violations.append("application context transaction registry ownership missing")
    if "with transaction_scope(context.transaction_registry)" not in lifespan_text or "with transaction_scope(context.transaction_registry)" not in http_runtime_text:
        violations.append("HTTP or lifespan transaction scope missing")
    if "@context_transaction_scope" not in job_dispatch_text or "@context_transaction_scope" not in job_worker_text or "@context_transaction_scope" not in lifecycle_runtime_text:
        violations.append("worker or scheduler transaction scope missing")
    transaction_repositories = (
        "app/repositories/job_records.py",
        "app/repositories/job_execution.py",
        "app/repositories/cluster.py",
        "app/repositories/webhook_queue.py",
        "app/repositories/webhook_delivery.py",
        "app/repositories/audit.py",
    )
    for repository in transaction_repositories:
        repository_text = (root_path / repository).read_text(encoding="utf-8") if (root_path / repository).exists() else ""
        if "with connect(" in repository_text or 'execute("BEGIN IMMEDIATE")' in repository_text:
            violations.append(f"manual transaction boundary remains: {repository}")
        if ".commit()" in repository_text:
            violations.append(f"manual commit remains in managed repository: {repository}")
    if "begin_cluster_write_activity(" in main_text or "active_cluster_lease(_coordination_db_path" in main_text:
        violations.append("HTTP write barrier coordination remains in main.py")
    if '_service(context, "_restore_in_progress")' in job_worker_text:
        violations.append("background worker restore barrier uses compatibility service")
    runtime_imports = set((by_path.get("app/services/job_dispatch.py") or {}).get("internal_imports") or [])
    runtime_imports.update((by_path.get("app/services/job_worker_runtime.py") or {}).get("internal_imports") or [])
    runtime_imports.update((by_path.get("app/services/lifecycle_runtime.py") or {}).get("internal_imports") or [])
    if "app.main" in runtime_imports:
        violations.append("runtime orchestration imports app.main compatibility module")
    if "elif job_type ==" in main_text or "asyncio.create_task(" in main_text:
        violations.append("job dispatch or lifecycle task creation remains in main.py")
    actual_route_count = sum(int(item.get("routes") or 0) for item in files)
    if actual_route_count != EXPECTED_ROUTE_COUNT:
        violations.append(f"unexpected route decorator count: {actual_route_count}!={EXPECTED_ROUTE_COUNT}")

    for required in sorted(REQUIRED_REPOSITORY_MODULES):
        if required not in by_path:
            violations.append(f"required repository module missing: {required}")

    storage_functions = set((by_path.get("app/core/storage.py") or {}).get("function_names") or [])
    remaining = sorted(storage_functions & RELOCATED_STORAGE_FUNCTIONS)
    if remaining:
        violations.append("repository functions remain in storage.py: " + ", ".join(remaining))

    for repository in sorted(REQUIRED_REPOSITORY_MODULES):
        imports = set((by_path.get(repository) or {}).get("internal_imports") or [])
        if "app.core.storage" in imports:
            violations.append(f"repository imports storage facade: {repository}")

    for module_path, module_info in sorted(by_path.items()):
        if module_path == "app/core/storage.py":
            continue
        imports = set(module_info.get("internal_imports") or [])
        if "app.core.storage" in imports:
            violations.append(f"internal module imports compatibility storage facade: {module_path}")

    jobs_facade_importers = []
    for module_path, module_info in sorted(by_path.items()):
        if module_path == "app/repositories/jobs.py":
            continue
        imports = set(module_info.get("internal_imports") or [])
        if "app.repositories.jobs" in imports:
            jobs_facade_importers.append(module_path)
    if jobs_facade_importers:
        violations.append(
            "internal modules import background-job compatibility facade: "
            + ", ".join(jobs_facade_importers)
        )
    for marker in (
        "from app.repositories.job_records import",
        "from app.repositories.job_execution import",
        "__all__ =",
    ):
        if marker not in jobs_text:
            violations.append(f"background-job compatibility facade boundary missing: {marker}")

    webhooks_text = (root_path / "app" / "repositories" / "webhooks.py").read_text(encoding="utf-8")
    webhook_queue_text = (root_path / "app" / "repositories" / "webhook_queue.py").read_text(encoding="utf-8")
    webhook_delivery_text = (root_path / "app" / "repositories" / "webhook_delivery.py").read_text(encoding="utf-8")
    webhook_facade_importers = []
    for module_path, module_info in sorted(by_path.items()):
        if module_path == "app/repositories/webhooks.py":
            continue
        imports = set(module_info.get("internal_imports") or [])
        if "app.repositories.webhooks" in imports:
            webhook_facade_importers.append(module_path)
    if webhook_facade_importers:
        violations.append(
            "internal modules import webhook compatibility facade: "
            + ", ".join(webhook_facade_importers)
        )
    for marker in (
        "from app.repositories.webhook_queue import",
        "from app.repositories.webhook_delivery import",
        "__all__ =",
    ):
        if marker not in webhooks_text:
            violations.append(f"webhook compatibility facade boundary missing: {marker}")
    for marker in ("def enqueue_webhook_events(", "def list_webhook_events(", "def retry_webhook_event("):
        if marker not in webhook_queue_text:
            violations.append(f"webhook queue boundary missing: {marker}")
    for marker in ("def list_due_webhook_events(", "def record_webhook_delivery("):
        if marker not in webhook_delivery_text:
            violations.append(f"webhook delivery boundary missing: {marker}")
    queue_imports = set((by_path.get("app/repositories/webhook_queue.py") or {}).get("internal_imports") or [])
    delivery_imports = set((by_path.get("app/repositories/webhook_delivery.py") or {}).get("internal_imports") or [])
    if "app.repositories.webhooks" in queue_imports or "app.repositories.webhooks" in delivery_imports:
        violations.append("webhook owner module imports compatibility facade")
    if "app.repositories.webhook_delivery" in queue_imports:
        violations.append("webhook queue imports delivery owner")

    finding_writes_text = (root_path / "app" / "repositories" / "finding_writes.py").read_text(encoding="utf-8")
    finding_ingestion_text = (root_path / "app" / "repositories" / "finding_ingestion.py").read_text(encoding="utf-8")
    finding_workflow_text = (root_path / "app" / "repositories" / "finding_workflow.py").read_text(encoding="utf-8")
    finding_approvals_text = (root_path / "app" / "repositories" / "finding_approvals.py").read_text(encoding="utf-8")
    finding_writes_importers = []
    for module_path, module_info in sorted(by_path.items()):
        if module_path == "app/repositories/finding_writes.py":
            continue
        imports = set(module_info.get("internal_imports") or [])
        if "app.repositories.finding_writes" in imports:
            finding_writes_importers.append(module_path)
    if finding_writes_importers:
        violations.append(
            "internal modules import finding-write compatibility facade: "
            + ", ".join(finding_writes_importers)
        )
    for marker in (
        "from app.repositories.finding_ingestion import",
        "from app.repositories.finding_workflow import",
        "from app.repositories.finding_approvals import",
        "__all__ =",
    ):
        if marker not in finding_writes_text:
            violations.append(f"finding-write compatibility facade boundary missing: {marker}")
    for marker in ("def upsert_findings(", "def apply_import_batch(", "def update_scores("):
        if marker not in finding_ingestion_text:
            violations.append(f"finding ingestion boundary missing: {marker}")
    for marker in ("def update_workflow(", "def create_remediation_verification_request(", "def update_record_state("):
        if marker not in finding_workflow_text:
            violations.append(f"finding workflow boundary missing: {marker}")
    for marker in ("def create_risk_approval_request(", "def decide_risk_approval_request("):
        if marker not in finding_approvals_text:
            violations.append(f"finding approval boundary missing: {marker}")

    asset_writes_text = (root_path / "app" / "repositories" / "asset_writes.py").read_text(encoding="utf-8")
    asset_identity_text = (root_path / "app" / "repositories" / "asset_identity_writes.py").read_text(encoding="utf-8")
    asset_inventory_text = (root_path / "app" / "repositories" / "asset_inventory.py").read_text(encoding="utf-8")
    asset_merge_text = (root_path / "app" / "repositories" / "asset_merge.py").read_text(encoding="utf-8")
    asset_rollback_text = (root_path / "app" / "repositories" / "asset_merge_rollback.py").read_text(encoding="utf-8")
    asset_writes_importers = []
    for module_path, module_info in sorted(by_path.items()):
        if module_path == "app/repositories/asset_writes.py":
            continue
        imports = set(module_info.get("internal_imports") or [])
        if "app.repositories.asset_writes" in imports:
            asset_writes_importers.append(module_path)
    if asset_writes_importers:
        violations.append(
            "internal modules import asset-write compatibility facade: "
            + ", ".join(asset_writes_importers)
        )
    for marker in (
        "from app.repositories.asset_identity_writes import",
        "from app.repositories.asset_inventory import",
        "from app.repositories.asset_merge import",
        "from app.repositories.asset_merge_rollback import",
        "__all__ =",
    ):
        if marker not in asset_writes_text:
            violations.append(f"asset-write compatibility facade boundary missing: {marker}")
    for marker in ("def add_asset_identifier(", "def reject_asset_identity_candidate("):
        if marker not in asset_identity_text:
            violations.append(f"asset identity write boundary missing: {marker}")
    for marker in ("def extract_inventory_identifiers(", "def apply_asset_inventory("):
        if marker not in asset_inventory_text:
            violations.append(f"asset inventory boundary missing: {marker}")
    for marker in ("def analyze_asset_merge(", "def approve_asset_merge_request(", "def merge_assets("):
        if marker not in asset_merge_text:
            violations.append(f"asset merge boundary missing: {marker}")
    for marker in ("def analyze_asset_merge_rollback(", "def approve_asset_merge_rollback_request("):
        if marker not in asset_rollback_text:
            violations.append(f"asset merge rollback boundary missing: {marker}")

    cycle_list = _cycles(graph)
    if cycle_list:
        violations.extend("internal import cycle: " + " -> ".join(item) for item in cycle_list)
    if parse_errors:
        violations.extend(f"parse error: {item['path']}: {item['error']}" for item in parse_errors)

    largest = sorted(files, key=lambda item: (-int(item["lines"]), item["path"]))[:15]
    return {
        "root": ".",
        "python_modules": len(files),
        "total_lines": sum(int(item["lines"]) for item in files),
        "route_count": sum(int(item["routes"]) for item in files),
        "largest_modules": largest,
        "modules": files,
        "cycles": cycle_list,
        "parse_errors": parse_errors,
        "line_budgets": HARD_LINE_BUDGETS,
        "violations": violations,
        "status": "PASS" if not violations else "FAIL",
    }


def render_architecture_report(report: dict[str, Any]) -> str:
    lines = [
        "VulnFlow architecture review",
        "",
        f"status: {report['status']}",
        f"python modules: {report['python_modules']}",
        f"application lines: {report['total_lines']}",
        f"FastAPI route decorators: {report['route_count']}",
        f"internal import cycles: {len(report['cycles'])}",
        "",
        "largest modules:",
    ]
    for item in report["largest_modules"]:
        lines.append(
            f"- {item['path']}: {item['lines']} lines, {item['functions']} functions, "
            f"{item['classes']} classes, {item['routes']} routes"
        )
    lines.extend(["", "hard line budgets:"])
    by_path = {item["path"]: item for item in report.get("modules", report["largest_modules"])}
    for path, maximum in report["line_budgets"].items():
        actual = (by_path.get(path) or {}).get("lines", "not in top list")
        lines.append(f"- {path}: {actual} / {maximum}")
    lines.extend(["", "violations:"])
    if report["violations"]:
        lines.extend(f"- {item}" for item in report["violations"])
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def write_architecture_report(root: str | Path, text_path: str | Path, json_path: str | Path) -> dict[str, Any]:
    report = build_architecture_report(root)
    Path(text_path).write_text(render_architecture_report(report), encoding="utf-8")
    Path(json_path).write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report
