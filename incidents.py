#!/usr/bin/env python3
"""事故判定：签发方密钥版本泄露事故的登记、关闭与核验期生效判定。

本模块只包含事故业务规则，不处理 HTTP 路由，也不直接建表
（持久化细节见 storage.Store）。
"""
from __future__ import annotations

import sqlite3

from storage import ApiError, iso, now, parse_time

# 更正：事故属实或事故信息有误，更正后关闭。
# 撤回：误报，撤回事故。
CLOSE_DECISIONS = {"correct", "withdraw"}
CLOSE_STATUS = {"correct": "corrected", "withdraw": "withdrawn"}
CLOSE_LABEL = {"correct": "更正", "withdraw": "撤回"}


def incident_number(row: sqlite3.Row) -> str:
    return f"INC-{int(row['id']):04d}"


def incident_dict(row: sqlite3.Row) -> dict:
    return {
        "incident_no": incident_number(row),
        "id": row["id"],
        "issuer": row["issuer"],
        "key_version": row["key_version"],
        "discovered_at": row["discovered_at"],
        "effective_at": row["effective_at"],
        "description": row["description"],
        "status": row["status"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "closed_at": row["closed_at"],
        "resolution": row["resolution"],
    }


class IncidentService:
    def __init__(self, conn, audit):
        self.conn = conn
        self.audit = audit

    @staticmethod
    def _require_issuer(actor: str | None, role: str | None) -> str:
        if not actor:
            raise ApiError(401, "缺少身份")
        if role != "issuer":
            raise ApiError(403, "需要角色 issuer")
        return actor

    def _key_version(self, issuer: str, version: int) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND version=?", (issuer, version)
        ).fetchone()
        if not row:
            raise ApiError(404, "密钥版本不存在")
        return row

    def register(
        self,
        actor: str | None,
        role: str | None,
        issuer: str | None,
        key_version: int,
        description: str,
        discovered_at: str | None = None,
        effective_at: str | None = None,
    ) -> dict:
        """签发方登记一个密钥版本事故；同一版本只允许一个未关闭事故。"""
        actor = self._require_issuer(actor, role)
        issuer = issuer or actor
        if issuer != actor:
            raise ApiError(403, "只能登记本机构的密钥事故")
        if not str(description or "").strip():
            raise ApiError(400, "事故说明不能为空")
        try:
            version = int(key_version)
        except (TypeError, ValueError) as exc:
            raise ApiError(400, "密钥版本必须是整数") from exc
        if version < 1:
            raise ApiError(400, "密钥版本无效")
        self._key_version(issuer, version)
        discovered = parse_time(discovered_at)
        effective = parse_time(effective_at) if effective_at else now()
        if effective < discovered:
            raise ApiError(400, "生效时间不能早于发现时间")
        open_incident = self.conn.execute(
            "SELECT id FROM key_incidents WHERE issuer=? AND key_version=? AND status='open'",
            (issuer, version),
        ).fetchone()
        if open_incident:
            raise ApiError(409, "该密钥版本已有未关闭事故")
        try:
            with self.conn:
                cur = self.conn.execute(
                    """INSERT INTO key_incidents(issuer,key_version,discovered_at,effective_at,description,status,created_by,created_at)
                       VALUES(?,?,?,?,?, 'open', ?,?)""",
                    (issuer, version, iso(discovered), iso(effective), description.strip(), actor, iso()),
                )
                incident_id = cur.lastrowid
                self.audit(actor, "incident.register", "key_incident", incident_id, {
                    "issuer": issuer,
                    "key_version": version,
                    "discovered_at": iso(discovered),
                    "effective_at": iso(effective),
                    "description": description.strip(),
                })
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "该密钥版本已有未关闭事故") from exc
        return incident_dict(self._get(incident_id))

    def close(
        self,
        actor: str | None,
        role: str | None,
        incident_id: int,
        decision: str,
        resolution: str,
    ) -> dict:
        """更正或撤回事故。关闭后受影响凭证回到撤销/争议/有效期判定。

        注意：本方法不改动任何凭证记录——凭证自始就保留各自的撤销、争议
        和有效期字段，事故只在生效期间覆盖核验结果。
        """
        actor = self._require_issuer(actor, role)
        if decision not in CLOSE_DECISIONS:
            raise ApiError(400, "处理方式只能是 correct（更正）或 withdraw（撤回）")
        if not str(resolution or "").strip():
            raise ApiError(400, "事故处理说明不能为空")
        row = self._get(incident_id)
        if row["issuer"] != actor:
            raise ApiError(403, "只能处理本机构登记的事故")
        if row["status"] != "open":
            raise ApiError(409, "事故已经关闭")
        closed_status = CLOSE_STATUS[decision]
        with self.conn:
            self.conn.execute(
                "UPDATE key_incidents SET status=?,resolution=?,closed_at=? WHERE id=?",
                (closed_status, resolution.strip(), iso(), incident_id),
            )
            self.audit(actor, "incident.close", "key_incident", incident_id, {
                "decision": decision,
                "decision_label": CLOSE_LABEL[decision],
                "resolution": resolution.strip(),
            })
        return incident_dict(self._get(incident_id))

    def effective_open(self, issuer: str, key_version: int, at) -> sqlite3.Row | None:
        """返回该密钥版本在指定时刻已生效且未关闭的事故，没有则 None。"""
        row = self.conn.execute(
            """SELECT * FROM key_incidents
               WHERE issuer=? AND key_version=? AND status='open'
               ORDER BY id DESC""",
            (issuer, key_version),
        ).fetchone()
        if row and parse_time(row["effective_at"]) <= at:
            return row
        return None

    def list_recent(self, limit: int = 30) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM key_incidents ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [incident_dict(row) for row in rows]

    def _get(self, incident_id: int) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM key_incidents WHERE id=?", (incident_id,)).fetchone()
        if not row:
            raise ApiError(404, "事故不存在")
        return row
