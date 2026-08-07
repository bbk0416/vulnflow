from __future__ import annotations

"""FTS5 index and synchronization-trigger installation."""

import sqlite3

def _install_finding_fts(conn: sqlite3.Connection, *, rebuild: bool = False) -> None:
    """Install the external-content FTS5 index and transactional sync triggers."""
    conn.execute(
        """CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
               finding_id,product,asset_name,cve_id,component,owner,
               content='findings',content_rowid='rowid',tokenize='unicode61 remove_diacritics 2'
           )"""
    )
    conn.executescript(
        """
        CREATE TRIGGER IF NOT EXISTS findings_fts_after_insert AFTER INSERT ON findings BEGIN
            INSERT INTO findings_fts(rowid,finding_id,product,asset_name,cve_id,component,owner)
            VALUES(new.rowid,new.finding_id,new.product,new.asset_name,new.cve_id,new.component,new.owner);
        END;
        CREATE TRIGGER IF NOT EXISTS findings_fts_after_delete AFTER DELETE ON findings BEGIN
            INSERT INTO findings_fts(findings_fts,rowid,finding_id,product,asset_name,cve_id,component,owner)
            VALUES('delete',old.rowid,old.finding_id,old.product,old.asset_name,old.cve_id,old.component,old.owner);
        END;
        CREATE TRIGGER IF NOT EXISTS findings_fts_after_update
        AFTER UPDATE OF finding_id,product,asset_name,cve_id,component,owner ON findings BEGIN
            INSERT INTO findings_fts(findings_fts,rowid,finding_id,product,asset_name,cve_id,component,owner)
            VALUES('delete',old.rowid,old.finding_id,old.product,old.asset_name,old.cve_id,old.component,old.owner);
            INSERT INTO findings_fts(rowid,finding_id,product,asset_name,cve_id,component,owner)
            VALUES(new.rowid,new.finding_id,new.product,new.asset_name,new.cve_id,new.component,new.owner);
        END;
        """
    )
    if rebuild:
        conn.execute("INSERT INTO findings_fts(findings_fts) VALUES('rebuild')")


__all__ = ["_install_finding_fts"]
