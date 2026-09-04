import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DATABASE_URL = os.getenv("DATABASE_URL", "")
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", "data/threat_scans.db"))
USING_POSTGRES = DATABASE_URL.startswith(("postgres://", "postgresql://"))


class Connection:
    def __init__(self, raw): self.raw = raw
    def execute(self, sql: str, params=()):
        if USING_POSTGRES: sql = sql.replace("?", "%s").replace(" COLLATE NOCASE", "")
        return self.raw.execute(sql, params)


def _connect():
    if USING_POSTGRES:
        import psycopg
        from psycopg.rows import dict_row
        return psycopg.connect(DATABASE_URL, row_factory=dict_row)
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH); connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def database():
    raw = _connect()
    try:
        yield Connection(raw); raw.commit()
    except Exception:
        raw.rollback(); raise
    finally: raw.close()


def initialize_database() -> None:
    pk = "BIGSERIAL PRIMARY KEY" if USING_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"
    with database() as c:
        # Prefix every table so this app can safely share a Render PostgreSQL
        # instance with AttendTrack (which also owns tables such as `users`).
        c.execute(f"CREATE TABLE IF NOT EXISTS cyber_scans (id {pk}, normalized_url TEXT NOT NULL, verdict TEXT NOT NULL, risk_score INTEGER NOT NULL, signals TEXT NOT NULL, features TEXT NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        c.execute(f"CREATE TABLE IF NOT EXISTS cyber_incidents (id {pk}, title TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        c.execute(f"CREATE TABLE IF NOT EXISTS cyber_security_events (id {pk}, analysis_type TEXT NOT NULL, verdict TEXT NOT NULL, risk_score INTEGER NOT NULL, summary TEXT NOT NULL, signals TEXT NOT NULL, features TEXT NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        c.execute(f"CREATE TABLE IF NOT EXISTS cyber_users (id {pk}, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        c.execute(f"CREATE TABLE IF NOT EXISTS cyber_audit_logs (id {pk}, actor_id BIGINT, actor_email TEXT, action TEXT NOT NULL, resource TEXT NOT NULL, details TEXT NOT NULL DEFAULT '', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)")


def _dict(row): return dict(row) if row else None
def _time_fields(value):
    for key in ("created_at", "updated_at"):
        if key in value: value[key] = str(value[key])
    return value


def create_user(email, name, password_hash, role="viewer"):
    try:
        with database() as c: row = c.execute("INSERT INTO cyber_users (email, name, password_hash, role) VALUES (?, ?, ?, ?) RETURNING *", (email.strip().lower(), name.strip(), password_hash, role)).fetchone()
        return _time_fields(dict(row))
    except Exception as exc:
        if exc.__class__.__name__ == "UniqueViolation": raise sqlite3.IntegrityError(str(exc)) from exc
        raise


def get_user_by_email(email):
    with database() as c: row = c.execute("SELECT * FROM cyber_users WHERE LOWER(email) = LOWER(?)", (email.strip(),)).fetchone()
    return _time_fields(_dict(row)) if row else None


def get_user_by_id(user_id):
    with database() as c: row = c.execute("SELECT * FROM cyber_users WHERE id = ?", (user_id,)).fetchone()
    return _time_fields(_dict(row)) if row else None


def list_users():
    with database() as c: rows = c.execute("SELECT id, email, name, role, created_at FROM cyber_users ORDER BY id").fetchall()
    return [_time_fields(dict(row)) for row in rows]


def update_user_role(user_id, role):
    with database() as c: row = c.execute("UPDATE cyber_users SET role = ? WHERE id = ? RETURNING id, email, name, role, created_at", (role, user_id)).fetchone()
    return _time_fields(_dict(row)) if row else None


def upsert_admin(email, name, password_hash):
    normalized = email.strip().lower()
    with database() as c:
        row = c.execute("SELECT id FROM cyber_users WHERE LOWER(email) = LOWER(?)", (normalized,)).fetchone()
        if row: result = c.execute("UPDATE cyber_users SET name = ?, password_hash = ?, role = 'admin' WHERE id = ? RETURNING *", (name, password_hash, row["id"])).fetchone()
        else: result = c.execute("INSERT INTO cyber_users (email, name, password_hash, role) VALUES (?, ?, ?, 'admin') RETURNING *", (normalized, name, password_hash)).fetchone()
    return _time_fields(dict(result))


def record_audit(action, resource, actor=None, details=""):
    with database() as c: c.execute("INSERT INTO cyber_audit_logs (actor_id, actor_email, action, resource, details) VALUES (?, ?, ?, ?, ?)", (actor["id"] if actor else None, actor["email"] if actor else None, action, resource, details[:1000]))


def list_audit_logs(limit=100):
    with database() as c: rows = c.execute("SELECT * FROM cyber_audit_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_time_fields(dict(row)) for row in rows]


def _scan(row):
    result = _time_fields(dict(row)); result["signals"] = json.loads(result["signals"]); result["features"] = json.loads(result["features"]); return result


def save_scan(result):
    with database() as c: row = c.execute("INSERT INTO cyber_scans (normalized_url, verdict, risk_score, signals, features) VALUES (?, ?, ?, ?, ?) RETURNING *", (result["normalized_url"], result["verdict"], result["risk_score"], json.dumps(result["signals"]), json.dumps(result["features"]))).fetchone()
    return _scan(row)


def list_scans(limit=20):
    with database() as c: rows = c.execute("SELECT * FROM cyber_scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_scan(row) for row in rows]


def scan_summary():
    with database() as c: row = c.execute("SELECT COUNT(*) AS scanned, SUM(CASE WHEN verdict != 'low_risk' THEN 1 ELSE 0 END) AS threats, SUM(CASE WHEN verdict = 'low_risk' THEN 1 ELSE 0 END) AS safe FROM cyber_scans").fetchone()
    return {key: int(row[key] or 0) for key in ("scanned", "threats", "safe")}


def create_incident(payload):
    with database() as c: row = c.execute("INSERT INTO cyber_incidents (title, description, severity, source) VALUES (?, ?, ?, ?) RETURNING *", (payload["title"], payload["description"], payload["severity"], payload["source"])).fetchone()
    return _time_fields(dict(row))


def list_incidents(limit=50):
    with database() as c: rows = c.execute("SELECT * FROM cyber_incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_time_fields(dict(row)) for row in rows]


def update_incident_status(incident_id, status):
    with database() as c: row = c.execute("UPDATE cyber_incidents SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? RETURNING *", (status, incident_id)).fetchone()
    return _time_fields(dict(row)) if row else None


def save_security_event(result):
    with database() as c: row = c.execute("INSERT INTO cyber_security_events (analysis_type, verdict, risk_score, summary, signals, features) VALUES (?, ?, ?, ?, ?, ?) RETURNING *", (result["analysis_type"], result["verdict"], result["risk_score"], result["summary"], json.dumps(result["signals"]), json.dumps(result["features"]))).fetchone()
    event = _time_fields(dict(row)); event["signals"] = json.loads(event["signals"]); event["features"] = json.loads(event["features"]); return event


def analytics_summary():
    with database() as c:
        urls = c.execute("SELECT verdict, COUNT(*) count, AVG(risk_score) average FROM cyber_scans GROUP BY verdict").fetchall()
        events = c.execute("SELECT analysis_type, verdict, COUNT(*) count, AVG(risk_score) average FROM cyber_security_events GROUP BY analysis_type, verdict").fetchall()
        incidents = c.execute("SELECT severity, status, COUNT(*) count FROM cyber_incidents GROUP BY severity, status").fetchall()
    return {"url_verdicts": [dict(row) for row in urls], "event_verdicts": [dict(row) for row in events], "incidents": [dict(row) for row in incidents]}
