"""档案保存：SQLite 持久化密钥版本、模板、凭证、争议、密钥事故和审计记录。"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).with_name("data.db")


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat(timespec="seconds").replace("+00:00", "Z")


class Store:
    def __init__(self, path: str | os.PathLike[str] = DB_PATH):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS key_versions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              version INTEGER NOT NULL,
              secret_hex TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('active','retired')),
              created_at TEXT NOT NULL,
              retired_at TEXT,
              UNIQUE(issuer, version)
            );
            CREATE TABLE IF NOT EXISTS templates (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              code TEXT NOT NULL,
              name TEXT NOT NULL,
              fields_json TEXT NOT NULL,
              validity_days INTEGER NOT NULL CHECK(validity_days BETWEEN 1 AND 3650),
              status TEXT NOT NULL CHECK(status IN ('active','disabled')),
              created_at TEXT NOT NULL,
              UNIQUE(issuer, code)
            );
            CREATE TABLE IF NOT EXISTS credentials (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              template_id INTEGER NOT NULL REFERENCES templates(id),
              issuer TEXT NOT NULL,
              holder_id TEXT NOT NULL,
              claims_json TEXT NOT NULL,
              issued_at TEXT NOT NULL,
              valid_until TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('active','revoked','disputed')),
              key_version INTEGER NOT NULL,
              idempotency_key TEXT NOT NULL,
              revocation_reason TEXT,
              revocation_effective_at TEXT,
              UNIQUE(template_id, holder_id, idempotency_key)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_live_credential
              ON credentials(template_id, holder_id)
              WHERE status IN ('active','disputed');
            CREATE TABLE IF NOT EXISTS disputes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              credential_id INTEGER NOT NULL REFERENCES credentials(id),
              raised_by TEXT NOT NULL,
              reason TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('open','upheld','rejected')),
              resolution TEXT,
              created_at TEXT NOT NULL,
              resolved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS key_incidents (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              key_version INTEGER NOT NULL,
              discovered_at TEXT NOT NULL,
              effective_at TEXT NOT NULL,
              reason TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('open','corrected','withdrawn')),
              created_at TEXT NOT NULL,
              closed_at TEXT,
              close_note TEXT,
              FOREIGN KEY(issuer, key_version) REFERENCES key_versions(issuer, version)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_open_incident
              ON key_incidents(issuer, key_version)
              WHERE status='open';
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              at TEXT NOT NULL,
              actor TEXT NOT NULL,
              action TEXT NOT NULL,
              entity_type TEXT NOT NULL,
              entity_id TEXT NOT NULL,
              details_json TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def audit(self, actor: str, action: str, entity_type: str, entity_id: object, details: dict) -> None:
        self.conn.execute(
            "INSERT INTO audit_log(at,actor,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?,?)",
            (iso(), actor, action, entity_type, str(entity_id), json.dumps(details, ensure_ascii=False)),
        )

    # ---- 密钥事故档案 ----

    def add_incident(self, issuer: str, key_version: int, discovered_at: str, effective_at: str, reason: str) -> int:
        cur = self.conn.execute(
            """INSERT INTO key_incidents(issuer,key_version,discovered_at,effective_at,reason,status,created_at)
               VALUES(?,?,?,?,?,'open',?)""",
            (issuer, key_version, discovered_at, effective_at, reason, iso()),
        )
        return int(cur.lastrowid)

    def get_incident(self, incident_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM key_incidents WHERE id=?", (incident_id,)).fetchone()

    def open_incident(self, issuer: str, key_version: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM key_incidents WHERE issuer=? AND key_version=? AND status='open'",
            (issuer, key_version),
        ).fetchone()

    def close_incident(self, incident_id: int, status: str, note: str) -> None:
        self.conn.execute(
            "UPDATE key_incidents SET status=?,closed_at=?,close_note=? WHERE id=?",
            (status, iso(), note, incident_id),
        )

    def list_incidents(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM key_incidents ORDER BY id DESC"))

    def close(self) -> None:
        self.conn.close()
