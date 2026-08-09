from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from app.core.db import ConcurrencyError, utc_now
from app.core.schema_versions import CURRENT_APP_VERSION
from app.core.transactions import read_connection, write_transaction


def _json_dict(value: Any) -> dict[str, Any]:
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _json_list(value: Any) -> list[Any]:
    try:
        parsed = json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []


def register_cluster_instance(
    db_path: str | Path,
    *,
    instance_id: str,
    hostname: str,
    process_id: int,
    app_version: str = CURRENT_APP_VERSION,
    capabilities: Iterable[str] = (),
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = utc_now()
    capabilities_json = json.dumps(sorted({str(item) for item in capabilities}), ensure_ascii=False)
    metadata_json = json.dumps(metadata or {}, ensure_ascii=False, separators=(",", ":"))
    with write_transaction(db_path, operation="register_cluster_instance") as conn:
        existing = conn.execute(
            "SELECT * FROM cluster_instances WHERE instance_id=?", (str(instance_id),)
        ).fetchone()
        if existing:
            same_process = (
                str(existing["hostname"]) == str(hostname)
                and int(existing["process_id"]) == int(process_id)
            )
            if str(existing["status"]) == "ACTIVE" and not same_process:
                conn.rollback()
                raise ConcurrencyError(
                    f"활성 인스턴스 ID가 이미 사용 중입니다: {instance_id} "
                    f"({existing['hostname']}:{existing['process_id']})"
                )
            started_at = str(existing["started_at"]) if same_process else now
        else:
            started_at = now
        conn.execute(
            """
            INSERT INTO cluster_instances(
                instance_id,hostname,process_id,app_version,capabilities_json,metadata_json,
                status,started_at,last_heartbeat_at,stopped_at
            ) VALUES(?,?,?,?,?,?,'ACTIVE',?,?,NULL)
            ON CONFLICT(instance_id) DO UPDATE SET
                hostname=excluded.hostname,process_id=excluded.process_id,
                app_version=excluded.app_version,capabilities_json=excluded.capabilities_json,
                metadata_json=excluded.metadata_json,status='ACTIVE',
                last_heartbeat_at=excluded.last_heartbeat_at,stopped_at=NULL
            """,
            (
                str(instance_id), str(hostname), int(process_id), str(app_version),
                capabilities_json, metadata_json, started_at, now,
            ),
        )
    return get_cluster_instance(db_path, instance_id) or {}


def heartbeat_cluster_instance(
    db_path: str | Path,
    *,
    instance_id: str,
    metadata: dict[str, Any] | None = None,
) -> bool:
    now = utc_now()
    with write_transaction(db_path, operation="heartbeat_cluster_instance") as conn:
        if metadata is None:
            cursor = conn.execute(
                "UPDATE cluster_instances SET last_heartbeat_at=?,status='ACTIVE',stopped_at=NULL WHERE instance_id=?",
                (now, str(instance_id)),
            )
        else:
            cursor = conn.execute(
                "UPDATE cluster_instances SET last_heartbeat_at=?,metadata_json=?,status='ACTIVE',stopped_at=NULL WHERE instance_id=?",
                (now, json.dumps(metadata, ensure_ascii=False, separators=(",", ":")), str(instance_id)),
            )
    return cursor.rowcount == 1


def deregister_cluster_instance(db_path: str | Path, *, instance_id: str) -> bool:
    now = utc_now()
    with write_transaction(db_path, operation="deregister_cluster_instance") as conn:
        cursor = conn.execute(
            "UPDATE cluster_instances SET status='STOPPED',stopped_at=?,last_heartbeat_at=? WHERE instance_id=?",
            (now, now, str(instance_id)),
        )
    return cursor.rowcount == 1


def get_cluster_instance(db_path: str | Path, instance_id: str) -> dict[str, Any] | None:
    with read_connection(db_path, operation="get_cluster_instance") as conn:
        row = conn.execute("SELECT * FROM cluster_instances WHERE instance_id=?", (str(instance_id),)).fetchone()
    if not row:
        return None
    item = dict(row)
    item["capabilities"] = _json_list(item.pop("capabilities_json", "[]"))
    item["metadata"] = _json_dict(item.pop("metadata_json", "{}"))
    return item


def list_cluster_instances(db_path: str | Path, *, include_stopped: bool = True) -> list[dict[str, Any]]:
    with read_connection(db_path, operation="list_cluster_instances") as conn:
        if include_stopped:
            rows = conn.execute(
                "SELECT * FROM cluster_instances ORDER BY status ASC,last_heartbeat_at DESC,instance_id"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM cluster_instances WHERE status='ACTIVE' ORDER BY last_heartbeat_at DESC,instance_id"
            ).fetchall()
    output=[]
    for row in rows:
        item=dict(row)
        item["capabilities"]=_json_list(item.pop("capabilities_json", "[]"))
        item["metadata"]=_json_dict(item.pop("metadata_json", "{}"))
        output.append(item)
    return output


def prune_stale_cluster_instances(db_path: str | Path, *, stale_before: str) -> int:
    now = utc_now()
    with write_transaction(db_path, operation="prune_stale_cluster_instances") as conn:
        cursor = conn.execute(
            """
            UPDATE cluster_instances
               SET status='STALE',stopped_at=COALESCE(stopped_at,?)
             WHERE status='ACTIVE' AND last_heartbeat_at<?
            """,
            (now, str(stale_before)),
        )
    return cursor.rowcount


def _lease_item(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None


def get_cluster_lease(db_path: str | Path, lease_name: str) -> dict[str, Any] | None:
    with read_connection(db_path, operation="get_cluster_lease") as conn:
        row = conn.execute("SELECT * FROM cluster_leases WHERE lease_name=?", (str(lease_name),)).fetchone()
    return _lease_item(row)


def list_cluster_leases(db_path: str | Path) -> list[dict[str, Any]]:
    with read_connection(db_path, operation="list_cluster_leases") as conn:
        rows = conn.execute("SELECT * FROM cluster_leases ORDER BY lease_name").fetchall()
    return [dict(row) for row in rows]


def acquire_cluster_lease(
    db_path: str | Path,
    *,
    lease_name: str,
    holder_id: str,
    ttl_seconds: int = 30,
    purpose: str = "",
) -> dict[str, Any] | None:
    from datetime import timedelta
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now = now_dt.isoformat()
    expires = (now_dt + timedelta(seconds=max(5, int(ttl_seconds)))).isoformat()
    with write_transaction(db_path, operation="acquire_cluster_lease") as conn:
        row = conn.execute("SELECT * FROM cluster_leases WHERE lease_name=?", (str(lease_name),)).fetchone()
        if row is None:
            token = 1
            conn.execute(
                """
                INSERT INTO cluster_leases(
                    lease_name,holder_id,fencing_token,purpose,acquired_at,renewed_at,lease_expires_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (str(lease_name), str(holder_id), token, str(purpose), now, now, expires),
            )
        else:
            item = dict(row)
            current_holder = str(item.get("holder_id") or "")
            expired = str(item.get("lease_expires_at") or "") <= now
            if current_holder != str(holder_id) and not expired:
                conn.rollback()
                return None
            ownership_changed = current_holder != str(holder_id) or expired
            token = int(item.get("fencing_token") or 0) + (1 if ownership_changed else 0)
            acquired_at = now if ownership_changed else str(item.get("acquired_at") or now)
            conn.execute(
                """
                UPDATE cluster_leases
                   SET holder_id=?,fencing_token=?,purpose=?,acquired_at=?,renewed_at=?,lease_expires_at=?
                 WHERE lease_name=?
                """,
                (str(holder_id), token, str(purpose), acquired_at, now, expires, str(lease_name)),
            )
        result = conn.execute("SELECT * FROM cluster_leases WHERE lease_name=?", (str(lease_name),)).fetchone()
    return _lease_item(result)


def renew_cluster_lease(
    db_path: str | Path,
    *,
    lease_name: str,
    holder_id: str,
    fencing_token: int,
    ttl_seconds: int = 30,
) -> dict[str, Any]:
    from datetime import timedelta
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now = now_dt.isoformat()
    expires = (now_dt + timedelta(seconds=max(5, int(ttl_seconds)))).isoformat()
    with write_transaction(db_path, operation="renew_cluster_lease") as conn:
        cursor = conn.execute(
            """
            UPDATE cluster_leases
               SET renewed_at=?,lease_expires_at=?
             WHERE lease_name=? AND holder_id=? AND fencing_token=? AND lease_expires_at>=?
            """,
            (now, expires, str(lease_name), str(holder_id), int(fencing_token), now),
        )
    if cursor.rowcount != 1:
        raise ConcurrencyError("분산 임대가 만료되었거나 다른 인스턴스로 승계되었습니다.")
    return get_cluster_lease(db_path, lease_name) or {}


def release_cluster_lease(
    db_path: str | Path,
    *,
    lease_name: str,
    holder_id: str,
    fencing_token: int | None = None,
) -> bool:
    from datetime import timedelta
    clauses = ["lease_name=?", "holder_id=?"]
    values: list[Any] = [str(lease_name), str(holder_id)]
    if fencing_token is not None:
        clauses.append("fencing_token=?")
        values.append(int(fencing_token))
    released_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).replace(microsecond=0).isoformat()
    with write_transaction(db_path, operation="release_cluster_lease") as conn:
        cursor = conn.execute(
            f"UPDATE cluster_leases SET renewed_at=?,lease_expires_at=?,purpose=CASE WHEN purpose='' THEN 'released' ELSE purpose END WHERE {' AND '.join(clauses)}",
            [released_at, released_at, *values],
        )
    return cursor.rowcount == 1


def active_cluster_lease(db_path: str | Path, lease_name: str) -> dict[str, Any] | None:
    now = utc_now()
    with read_connection(db_path, operation="active_cluster_lease") as conn:
        row=conn.execute(
            "SELECT * FROM cluster_leases WHERE lease_name=? AND lease_expires_at>=?",
            (str(lease_name), now),
        ).fetchone()
    return _lease_item(row)


def begin_cluster_write_activity(
    db_path: str | Path,
    *,
    activity_id: str,
    instance_id: str,
    actor: str,
    method: str,
    path: str,
    ttl_seconds: int = 600,
) -> dict[str, Any]:
    from datetime import timedelta
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now = now_dt.isoformat()
    expires = (now_dt + timedelta(seconds=max(30, int(ttl_seconds)))).isoformat()
    with write_transaction(db_path, operation="begin_cluster_write_activity") as conn:
        conn.execute(
            """
            INSERT INTO cluster_write_activities(
                activity_id,instance_id,actor,method,path,started_at,expires_at
            ) VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(activity_id) DO UPDATE SET
                instance_id=excluded.instance_id,actor=excluded.actor,method=excluded.method,
                path=excluded.path,started_at=excluded.started_at,expires_at=excluded.expires_at
            """,
            (
                str(activity_id), str(instance_id), str(actor), str(method).upper(),
                str(path), now, expires,
            ),
        )
        row = conn.execute(
            "SELECT * FROM cluster_write_activities WHERE activity_id=?", (str(activity_id),)
        ).fetchone()
    return dict(row) if row else {}


def end_cluster_write_activity(db_path: str | Path, *, activity_id: str) -> bool:
    with write_transaction(db_path, operation="end_cluster_write_activity") as conn:
        cursor = conn.execute(
            "DELETE FROM cluster_write_activities WHERE activity_id=?", (str(activity_id),)
        )
    return cursor.rowcount == 1


def count_cluster_write_activities(db_path: str | Path) -> int:
    now = utc_now()
    with read_connection(db_path, operation="count_cluster_write_activities") as conn:
        return int(conn.execute(
            "SELECT COUNT(*) FROM cluster_write_activities WHERE expires_at>=?", (now,)
        ).fetchone()[0])


def list_cluster_write_activities(db_path: str | Path, *, limit: int = 200) -> list[dict[str, Any]]:
    now = utc_now()
    limit = max(1, min(int(limit), 1000))
    with read_connection(db_path, operation="list_cluster_write_activities") as conn:
        rows = conn.execute(
            "SELECT * FROM cluster_write_activities WHERE expires_at>=? ORDER BY started_at DESC LIMIT ?",
            (now, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def prune_stale_cluster_write_activities(db_path: str | Path) -> int:
    now = utc_now()
    with write_transaction(db_path, operation="prune_stale_cluster_write_activities") as conn:
        cursor = conn.execute("DELETE FROM cluster_write_activities WHERE expires_at<?", (now,))
    return cursor.rowcount
