import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


DATABASE_PATH = Path(os.getenv("DATABASE_PATH", "data/threat_scans.db"))


def _connect() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def database() -> Iterator[sqlite3.Connection]:
    connection = _connect()
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialize_database() -> None:
    with database() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                normalized_url TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                signals TEXT NOT NULL,
                features TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_type TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                summary TEXT NOT NULL,
                signals TEXT NOT NULL,
                features TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def create_user(email: str, name: str, password_hash: str, role: str = "viewer") -> dict:
    with database() as connection:
        cursor = connection.execute(
            "INSERT INTO users (email, name, password_hash, role) VALUES (?, ?, ?, ?)",
            (email.strip().lower(), name.strip(), password_hash, role),
        )
        row = connection.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return dict(row)


def get_user_by_email(email: str) -> dict | None:
    with database() as connection:
        row = connection.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email.strip(),)).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict | None:
    with database() as connection:
        row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def list_users() -> list[dict]:
    with database() as connection:
        rows = connection.execute("SELECT id, email, name, role, created_at FROM users ORDER BY id").fetchall()
    return [dict(row) for row in rows]


def update_user_role(user_id: int, role: str) -> dict | None:
    with database() as connection:
        cursor = connection.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        if not cursor.rowcount:
            return None
        row = connection.execute("SELECT id, email, name, role, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row)


def save_scan(result: dict) -> dict:
    with database() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans (normalized_url, verdict, risk_score, signals, features)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                result["normalized_url"],
                result["verdict"],
                result["risk_score"],
                json.dumps(result["signals"]),
                json.dumps(result["features"]),
            ),
        )
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _deserialize(row)


def list_scans(limit: int = 20) -> list[dict]:
    with database() as connection:
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_deserialize(row) for row in rows]


def scan_summary() -> dict[str, int]:
    with database() as connection:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS scanned,
                SUM(CASE WHEN verdict != 'low_risk' THEN 1 ELSE 0 END) AS threats,
                SUM(CASE WHEN verdict = 'low_risk' THEN 1 ELSE 0 END) AS safe
            FROM scans
            """
        ).fetchone()
    return {key: int(row[key] or 0) for key in ("scanned", "threats", "safe")}


def _deserialize(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "normalized_url": row["normalized_url"],
        "verdict": row["verdict"],
        "risk_score": row["risk_score"],
        "signals": json.loads(row["signals"]),
        "features": json.loads(row["features"]),
        "created_at": row["created_at"],
    }


def create_incident(payload: dict) -> dict:
    with database() as connection:
        cursor = connection.execute(
            "INSERT INTO incidents (title, description, severity, source) VALUES (?, ?, ?, ?)",
            (payload["title"], payload["description"], payload["severity"], payload["source"]),
        )
        row = connection.execute("SELECT * FROM incidents WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return dict(row)


def list_incidents(limit: int = 50) -> list[dict]:
    with database() as connection:
        rows = connection.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def update_incident_status(incident_id: int, status: str) -> dict | None:
    with database() as connection:
        cursor = connection.execute(
            "UPDATE incidents SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (status, incident_id),
        )
        if not cursor.rowcount:
            return None
        row = connection.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    return dict(row)


def save_security_event(result: dict) -> dict:
    with database() as connection:
        cursor = connection.execute(
            """INSERT INTO security_events
            (analysis_type, verdict, risk_score, summary, signals, features)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (result["analysis_type"], result["verdict"], result["risk_score"], result["summary"], json.dumps(result["signals"]), json.dumps(result["features"])),
        )
        row = connection.execute("SELECT * FROM security_events WHERE id = ?", (cursor.lastrowid,)).fetchone()
    event = dict(row)
    event["signals"] = json.loads(event["signals"])
    event["features"] = json.loads(event["features"])
    return event


def analytics_summary() -> dict:
    with database() as connection:
        url_rows = connection.execute("SELECT verdict, COUNT(*) count, AVG(risk_score) average FROM scans GROUP BY verdict").fetchall()
        event_rows = connection.execute("SELECT analysis_type, verdict, COUNT(*) count, AVG(risk_score) average FROM security_events GROUP BY analysis_type, verdict").fetchall()
        incident_rows = connection.execute("SELECT severity, status, COUNT(*) count FROM incidents GROUP BY severity, status").fetchall()
    return {
        "url_verdicts": [dict(row) for row in url_rows],
        "event_verdicts": [dict(row) for row in event_rows],
        "incidents": [dict(row) for row in incident_rows],
    }
