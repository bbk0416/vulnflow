from __future__ import annotations

"""Inspect, rollback, and prune retained VulnFlow offline deployments.

The service must be stopped before rollback or prune.  Mutating commands share
the same advisory lock as the signed offline deployment bootstrap.
"""

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from scripts.offline_deployment_activation import absolute_path, deployment_operation_lock
    from scripts.offline_deployment_audit import verify_deployment_audit_log
    from scripts.offline_deployment_bootstrap import _activation_verification
    from scripts.offline_deployment_witness import (
        generate_witness_keypair,
        issue_witness_receipt,
        verify_witness_receipt,
    )
    from scripts.offline_deployment_recovery import (
        backup_recovery_journal_key,
        create_history_recovery_bundle,
        inspect_interrupted_history_recovery,
        recover_interrupted_history_recovery,
        recovery_journal_key_status,
        restore_history_recovery_bundle,
        restore_recovery_journal_key,
        rotate_recovery_journal_key,
        verify_history_recovery_bundle,
    )
    from scripts.offline_deployment_history import (
        DeploymentIdentity,
        adopt_retained_deployment,
        backup_deployment_history_keyring,
        inventory_retained_deployments,
        load_deployment_identity,
        prune_retained_deployments,
        restore_deployment_history_keyring,
        rollback_to_retained_deployment,
        rotate_deployment_history_key,
    )
except ModuleNotFoundError:  # standalone signed release-kit execution
    from offline_deployment_activation import absolute_path, deployment_operation_lock
    from offline_deployment_audit import verify_deployment_audit_log
    from offline_deployment_bootstrap import _activation_verification
    from offline_deployment_witness import (
        generate_witness_keypair,
        issue_witness_receipt,
        verify_witness_receipt,
    )
    from offline_deployment_recovery import (
        backup_recovery_journal_key,
        create_history_recovery_bundle,
        inspect_interrupted_history_recovery,
        recover_interrupted_history_recovery,
        recovery_journal_key_status,
        restore_history_recovery_bundle,
        restore_recovery_journal_key,
        rotate_recovery_journal_key,
        verify_history_recovery_bundle,
    )
    from offline_deployment_history import (
        DeploymentIdentity,
        adopt_retained_deployment,
        backup_deployment_history_keyring,
        inventory_retained_deployments,
        load_deployment_identity,
        prune_retained_deployments,
        restore_deployment_history_keyring,
        rollback_to_retained_deployment,
        rotate_deployment_history_key,
    )


def _write_private_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def list_deployments(target: Path) -> dict[str, Any]:
    target = absolute_path(target)
    active: dict[str, Any] | None = None
    try:
        identity = load_deployment_identity(target, expected_target_name=target.name)
        active = {
            "path": str(target),
            "installation_id": identity.installation_id,
            "application_version": identity.application_version,
            "schema_version": identity.schema_version,
            "installed_at": identity.installed_at,
            "release_kit_sha256": identity.release_kit_sha256,
            "release_public_key_fingerprint": identity.release_public_key_fingerprint,
        }
    except Exception as exc:
        active = {"path": str(target), "error": str(exc)} if target.exists() else None
    return {"active": active, **inventory_retained_deployments(target)}



def adopt_deployment(target: Path, *, installation_id: str) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return adopt_retained_deployment(target, installation_id)


def rollback_deployment(
    target: Path,
    *,
    installation_id: str,
    run_cycles: int = 2,
    retain_previous: int | None = 3,
) -> dict[str, Any]:
    target = absolute_path(target)
    if run_cycles < 1:
        raise ValueError("rollback verification requires at least one cycle")
    with deployment_operation_lock(target):
        result = rollback_to_retained_deployment(
            target,
            installation_id=installation_id,
            verify=lambda activated_target, previous_root, identity: _verify_rollback(
                activated_target,
                previous_root,
                identity,
                run_cycles=run_cycles,
            ),
        )
        retention: dict[str, Any] = {
            "enabled": retain_previous is not None,
            "keep": retain_previous,
            "removed": [],
        }
        if retain_previous is not None:
            retention = {
                "enabled": True,
                **prune_retained_deployments(target, keep=int(retain_previous)),
            }
        report = {
            "format": "vulnflow-offline-deployment-rollback/1",
            **result,
            "retention": retention,
            "notice": "Rollback reactivates a retained fresh deployment tree; it is not an in-place database downgrade.",
        }
        _write_private_json(target / "OFFLINE_DEPLOYMENT_ROLLBACK_REPORT.json", report)
        return report


def _verify_rollback(
    activated_target: Path,
    previous_root: Path,
    identity: DeploymentIdentity,
    *,
    run_cycles: int,
) -> dict[str, Any]:
    verified = _activation_verification(
        activated_target,
        previous_root,
        expected_schema_version=identity.schema_version,
        run_cycles=run_cycles,
    )
    return {
        "application_version": identity.application_version,
        "schema_version": identity.schema_version,
        "installation_id": identity.installation_id,
        "activation_cycle": verified["activation_cycle"],
        "sqlite": verified["sqlite"],
        "credentials_file": str(verified["credentials_file"]),
    }


def prune_deployments(target: Path, *, keep: int, dry_run: bool = False) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return prune_retained_deployments(target, keep=keep, dry_run=dry_run)


def backup_history_key(target: Path, *, output: Path) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return backup_deployment_history_keyring(target, output)


def restore_history_key(target: Path, *, source: Path) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return restore_deployment_history_keyring(target, source)


def rotate_history_key(target: Path) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return rotate_deployment_history_key(target)


def verify_history_audit(target: Path) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return verify_deployment_audit_log(target)


def journal_key_status(target: Path) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return recovery_journal_key_status(target)


def backup_journal_key(target: Path, *, output: Path, witness_private_key: Path) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return backup_recovery_journal_key(
            target,
            output=output,
            witness_private_key=witness_private_key,
        )


def restore_journal_key(
    target: Path,
    *,
    source: Path,
    trusted_witness_public_key: Path,
    minimum_witness_receipt: Path,
) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return restore_recovery_journal_key(
            target,
            source=source,
            trusted_witness_public_key=trusted_witness_public_key,
            minimum_witness_receipt=minimum_witness_receipt,
        )


def rotate_journal_key(target: Path) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return rotate_recovery_journal_key(target)


def generate_history_witness_key(
    *,
    private_key: Path,
    public_key: Path,
    key_id: str,
) -> dict[str, Any]:
    return generate_witness_keypair(
        private_key_path=private_key,
        public_key_path=public_key,
        key_id=key_id,
    )


def issue_history_witness(
    target: Path,
    *,
    private_key: Path,
    output: Path,
) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return issue_witness_receipt(
            target,
            private_key_path=private_key,
            output_path=output,
        )


def verify_history_witness(
    target: Path,
    *,
    public_key: Path,
    receipt: Path,
) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return verify_witness_receipt(
            target,
            receipt_path=receipt,
            public_key_path=public_key,
        )


def create_history_recovery(
    target: Path,
    *,
    public_key: Path,
    witness_receipt: Path,
    output: Path,
) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return create_history_recovery_bundle(
            target,
            trusted_public_key=public_key,
            witness_receipt=witness_receipt,
            output=output,
        )


def verify_history_recovery(
    target: Path,
    *,
    bundle: Path,
    public_key: Path,
    minimum_witness: Path,
) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return verify_history_recovery_bundle(
            target,
            bundle=bundle,
            trusted_public_key=public_key,
            minimum_witness_receipt=minimum_witness,
        )


def restore_history_recovery(
    target: Path,
    *,
    bundle: Path,
    public_key: Path,
    minimum_witness: Path,
) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return restore_history_recovery_bundle(
            target,
            bundle=bundle,
            trusted_public_key=public_key,
            minimum_witness_receipt=minimum_witness,
        )


def interrupted_recovery_status(target: Path) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return inspect_interrupted_history_recovery(target)


def recover_interrupted_recovery(target: Path, *, allow_legacy: bool = False) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return recover_interrupted_history_recovery(target, allow_legacy=allow_legacy)


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage retained VulnFlow offline deployments.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List the active and retained deployments.")
    list_parser.add_argument("--target", required=True)

    adopt_parser = subparsers.add_parser("adopt", help="Seal a manually reviewed legacy retained deployment.")
    adopt_parser.add_argument("--target", required=True)
    adopt_parser.add_argument("--installation-id", required=True)
    adopt_parser.add_argument("--confirm", required=True)

    rollback_parser = subparsers.add_parser("rollback", help="Atomically reactivate a retained deployment.")
    rollback_parser.add_argument("--target", required=True)
    rollback_parser.add_argument("--installation-id", required=True)
    rollback_parser.add_argument("--confirm", required=True)
    rollback_parser.add_argument("--cycles", type=int, default=2)
    rollback_parser.add_argument("--retain-previous", type=int, default=3)

    prune_parser = subparsers.add_parser("prune", help="Remove old validated retained deployments.")
    prune_parser.add_argument("--target", required=True)
    prune_parser.add_argument("--keep", required=True, type=int)
    prune_parser.add_argument("--dry-run", action="store_true")
    prune_parser.add_argument("--confirm")

    backup_parser = subparsers.add_parser("backup-key", help="Create a private backup of the deployment history keyring.")
    backup_parser.add_argument("--target", required=True)
    backup_parser.add_argument("--output", required=True)
    backup_parser.add_argument("--confirm", required=True)

    restore_parser = subparsers.add_parser("restore-key", help="Restore and verify a private deployment history keyring backup.")
    restore_parser.add_argument("--target", required=True)
    restore_parser.add_argument("--source", required=True)
    restore_parser.add_argument("--confirm", required=True)

    rotate_parser = subparsers.add_parser("rotate-key", help="Rotate the history HMAC key and reseal managed deployments.")
    rotate_parser.add_argument("--target", required=True)
    rotate_parser.add_argument("--confirm", required=True)

    journal_status_parser = subparsers.add_parser("journal-key-status", help="Inspect the recovery-journal authentication key and pending transaction binding.")
    journal_status_parser.add_argument("--target", required=True)

    journal_backup_parser = subparsers.add_parser("backup-journal-key", help="Create an Ed25519 witness-signed private backup of the recovery-journal authentication key.")
    journal_backup_parser.add_argument("--target", required=True)
    journal_backup_parser.add_argument("--output", required=True)
    journal_backup_parser.add_argument("--witness-private-key", required=True)
    journal_backup_parser.add_argument("--confirm", required=True)

    journal_restore_parser = subparsers.add_parser("restore-journal-key", help="Restore a signed journal key backup without crossing the external witness generation floor.")
    journal_restore_parser.add_argument("--target", required=True)
    journal_restore_parser.add_argument("--source", required=True)
    journal_restore_parser.add_argument("--trusted-witness-public-key", required=True)
    journal_restore_parser.add_argument("--minimum-witness-receipt", required=True)
    journal_restore_parser.add_argument("--confirm", required=True)

    journal_rotate_parser = subparsers.add_parser("rotate-journal-key", help="Rotate the journal authentication key when no recovery transaction is pending.")
    journal_rotate_parser.add_argument("--target", required=True)
    journal_rotate_parser.add_argument("--confirm", required=True)

    audit_parser = subparsers.add_parser("verify-audit", help="Verify the external authenticated deployment audit chain.")
    audit_parser.add_argument("--target", required=True)

    witness_key_parser = subparsers.add_parser("generate-witness-key", help="Generate an offline Ed25519 witness key pair.")
    witness_key_parser.add_argument("--private-key", required=True)
    witness_key_parser.add_argument("--public-key", required=True)
    witness_key_parser.add_argument("--key-id", required=True)
    witness_key_parser.add_argument("--confirm", required=True)

    witness_issue_parser = subparsers.add_parser("issue-witness", help="Issue an externally stored signed audit checkpoint.")
    witness_issue_parser.add_argument("--target", required=True)
    witness_issue_parser.add_argument("--private-key", required=True)
    witness_issue_parser.add_argument("--output", required=True)
    witness_issue_parser.add_argument("--confirm", required=True)

    witness_verify_parser = subparsers.add_parser("verify-witness", help="Verify local history against an external witness receipt.")
    witness_verify_parser.add_argument("--target", required=True)
    witness_verify_parser.add_argument("--public-key", required=True)
    witness_verify_parser.add_argument("--receipt", required=True)

    recovery_create_parser = subparsers.add_parser("create-recovery-bundle", help="Create a consistent keyring, audit, and witness recovery bundle.")
    recovery_create_parser.add_argument("--target", required=True)
    recovery_create_parser.add_argument("--public-key", required=True)
    recovery_create_parser.add_argument("--witness-receipt", required=True)
    recovery_create_parser.add_argument("--output", required=True)
    recovery_create_parser.add_argument("--confirm", required=True)

    recovery_verify_parser = subparsers.add_parser("verify-recovery-bundle", help="Verify a recovery bundle against an external minimum witness.")
    recovery_verify_parser.add_argument("--target", required=True)
    recovery_verify_parser.add_argument("--bundle", required=True)
    recovery_verify_parser.add_argument("--public-key", required=True)
    recovery_verify_parser.add_argument("--minimum-witness", required=True)

    recovery_restore_parser = subparsers.add_parser("restore-recovery-bundle", help="Atomically restore keyring and audit from a witnessed recovery bundle.")
    recovery_restore_parser.add_argument("--target", required=True)
    recovery_restore_parser.add_argument("--bundle", required=True)
    recovery_restore_parser.add_argument("--public-key", required=True)
    recovery_restore_parser.add_argument("--minimum-witness", required=True)
    recovery_restore_parser.add_argument("--confirm", required=True)

    interrupted_status_parser = subparsers.add_parser(
        "interrupted-recovery-status",
        help="Inspect interrupted deployment-history recovery journals without modifying them.",
    )
    interrupted_status_parser.add_argument("--target", required=True)

    interrupted_recover_parser = subparsers.add_parser(
        "recover-interrupted",
        help="Restore the authenticated previous keyring and audit pair from one interrupted journal.",
    )
    interrupted_recover_parser.add_argument("--target", required=True)
    interrupted_recover_parser.add_argument("--allow-legacy", action="store_true")
    interrupted_recover_parser.add_argument("--confirm")

    args = parser.parse_args()
    target = Path(args.target) if hasattr(args, "target") else None
    if args.command == "list":
        result = list_deployments(target)
    elif args.command == "adopt":
        if args.confirm != f"ADOPT:{args.installation_id}":
            raise SystemExit("adoption confirmation must equal ADOPT:<installation-id>")
        result = adopt_deployment(target, installation_id=args.installation_id)
    elif args.command == "rollback":
        if args.confirm != f"ROLLBACK:{args.installation_id}":
            raise SystemExit("rollback confirmation must equal ROLLBACK:<installation-id>")
        result = rollback_deployment(
            target,
            installation_id=args.installation_id,
            run_cycles=args.cycles,
            retain_previous=args.retain_previous,
        )
    elif args.command == "backup-key":
        if args.confirm != "BACKUP-HISTORY-KEYRING":
            raise SystemExit("key backup confirmation must equal BACKUP-HISTORY-KEYRING")
        result = backup_history_key(target, output=Path(args.output))
    elif args.command == "restore-key":
        if args.confirm != "RESTORE-HISTORY-KEYRING":
            raise SystemExit("key restore confirmation must equal RESTORE-HISTORY-KEYRING")
        result = restore_history_key(target, source=Path(args.source))
    elif args.command == "rotate-key":
        if args.confirm != "ROTATE-HISTORY-KEY":
            raise SystemExit("key rotation confirmation must equal ROTATE-HISTORY-KEY")
        result = rotate_history_key(target)
    elif args.command == "journal-key-status":
        result = journal_key_status(target)
    elif args.command == "backup-journal-key":
        if args.confirm != "BACKUP-RECOVERY-JOURNAL-KEY":
            raise SystemExit("journal key backup confirmation must equal BACKUP-RECOVERY-JOURNAL-KEY")
        result = backup_journal_key(
            target,
            output=Path(args.output),
            witness_private_key=Path(args.witness_private_key),
        )
    elif args.command == "restore-journal-key":
        if args.confirm != "RESTORE-RECOVERY-JOURNAL-KEY":
            raise SystemExit("journal key restore confirmation must equal RESTORE-RECOVERY-JOURNAL-KEY")
        result = restore_journal_key(
            target,
            source=Path(args.source),
            trusted_witness_public_key=Path(args.trusted_witness_public_key),
            minimum_witness_receipt=Path(args.minimum_witness_receipt),
        )
    elif args.command == "rotate-journal-key":
        if args.confirm != "ROTATE-RECOVERY-JOURNAL-KEY":
            raise SystemExit("journal key rotation confirmation must equal ROTATE-RECOVERY-JOURNAL-KEY")
        result = rotate_journal_key(target)
    elif args.command == "verify-audit":
        result = verify_history_audit(target)
    elif args.command == "generate-witness-key":
        if args.confirm != "GENERATE-HISTORY-WITNESS":
            raise SystemExit("witness key confirmation must equal GENERATE-HISTORY-WITNESS")
        result = generate_history_witness_key(
            private_key=Path(args.private_key),
            public_key=Path(args.public_key),
            key_id=args.key_id,
        )
    elif args.command == "issue-witness":
        if args.confirm != "ISSUE-HISTORY-WITNESS":
            raise SystemExit("witness issue confirmation must equal ISSUE-HISTORY-WITNESS")
        result = issue_history_witness(
            target,
            private_key=Path(args.private_key),
            output=Path(args.output),
        )
    elif args.command == "verify-witness":
        result = verify_history_witness(
            target,
            public_key=Path(args.public_key),
            receipt=Path(args.receipt),
        )
    elif args.command == "create-recovery-bundle":
        if args.confirm != "CREATE-HISTORY-RECOVERY-BUNDLE":
            raise SystemExit("recovery bundle confirmation must equal CREATE-HISTORY-RECOVERY-BUNDLE")
        result = create_history_recovery(
            target,
            public_key=Path(args.public_key),
            witness_receipt=Path(args.witness_receipt),
            output=Path(args.output),
        )
    elif args.command == "verify-recovery-bundle":
        result = verify_history_recovery(
            target,
            bundle=Path(args.bundle),
            public_key=Path(args.public_key),
            minimum_witness=Path(args.minimum_witness),
        )
    elif args.command == "restore-recovery-bundle":
        if args.confirm != "RESTORE-HISTORY-RECOVERY-BUNDLE":
            raise SystemExit("recovery restore confirmation must equal RESTORE-HISTORY-RECOVERY-BUNDLE")
        result = restore_history_recovery(
            target,
            bundle=Path(args.bundle),
            public_key=Path(args.public_key),
            minimum_witness=Path(args.minimum_witness),
        )
    elif args.command == "interrupted-recovery-status":
        result = interrupted_recovery_status(target)
    elif args.command == "recover-interrupted":
        if args.allow_legacy and args.confirm != "RECOVER-LEGACY-HISTORY-JOURNAL":
            raise SystemExit("legacy journal recovery confirmation must equal RECOVER-LEGACY-HISTORY-JOURNAL")
        result = recover_interrupted_recovery(target, allow_legacy=bool(args.allow_legacy))
    else:
        if not args.dry_run and args.confirm != "PRUNE":
            raise SystemExit("prune confirmation must equal PRUNE")
        result = prune_deployments(target, keep=args.keep, dry_run=args.dry_run)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
