"""SQLite persistence for investigations. All queries are parameterised.

Connection lifecycle: every operation goes through `connection()`, which commits on success,
rolls back on ANY exception, and ALWAYS closes the connection (sqlite3's own context manager
only handles the transaction and leaves the connection open).
"""
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

import config
from utils.helpers import mask_sensitive

DEMO_ID_PREFIX = "PT-DEMO-"


@contextmanager
def connection():
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(config.DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with connection() as c:
        c.executescript(config.SCHEMA_PATH.read_text(encoding="utf-8"))


def new_id() -> str:
    return f"PT-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"


def demo_id(case_id: str) -> str:
    """Deterministic ID for a demonstration case (lets us detect 'already loaded' without a schema change)."""
    return DEMO_ID_PREFIX + case_id.upper()


def save_investigation(result: dict, evidence: str, is_demo: bool = False, inv_id: str = None) -> str:
    """Persist one investigation. `is_demo` is ONLY ever set by explicit demo actions, never inferred from content."""
    inv_id = inv_id or new_id()
    result = dict(result, investigation_id=inv_id)
    evidence = mask_sensitive(evidence)[: config.MAX_EVIDENCE_STORED]
    result["evidence"] = evidence
    result["is_demo"] = bool(is_demo)
    with connection() as c:
        c.execute("INSERT INTO investigations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
            inv_id, result["analysis_time"], result["input_type"], evidence, result["classification"],
            int(result["risk_score"]), result["risk_level"], json.dumps(result["entities"]),
            json.dumps(result["findings"]), json.dumps(result["recommendations"]), json.dumps(result), int(is_demo)))
    return inv_id


def _row_to_result(row):
    res = json.loads(row["result_json"])
    res["investigation_id"], res["evidence"], res["is_demo"] = row["id"], row["evidence"], bool(row["is_demo"])
    return res


def get_investigation(inv_id: str):
    with connection() as c:
        row = c.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,)).fetchone()
        return _row_to_result(row) if row else None


def find_demo_record(input_type: str, evidences) -> str:
    """ID of an existing DEMO record of this type whose stored evidence equals any candidate (covers records
    created by older versions with random IDs). Returns None if there is none."""
    cands = [mask_sensitive(e)[: config.MAX_EVIDENCE_STORED] for e in evidences]
    with connection() as c:
        for e in cands:
            row = c.execute("SELECT id FROM investigations WHERE is_demo = 1 AND input_type = ? AND evidence = ? LIMIT 1",
                            (input_type, e)).fetchone()
            if row:
                return row["id"]
    return None


def list_investigations(limit: int = 500, include_demo: bool = True):
    sql = "SELECT id, created_at, input_type, classification, risk_score, risk_level, is_demo FROM investigations"
    if not include_demo:
        sql += " WHERE is_demo = 0"
    sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
    with connection() as c:
        return [dict(r) for r in c.execute(sql, (limit,)).fetchall()]


def get_many(ids):
    return [r for r in (get_investigation(i) for i in ids) if r]


def count_records() -> dict:
    """{'real': n, 'demo': m} regardless of any dashboard filter."""
    with connection() as c:
        rows = c.execute("SELECT is_demo, COUNT(*) FROM investigations GROUP BY is_demo").fetchall()
    out = {"real": 0, "demo": 0}
    for flag, n in rows:
        out["demo" if flag else "real"] = n
    return out


def stats(include_demo: bool = False) -> dict:
    """Every figure is computed from the SAME record selection. Default excludes demonstration records."""
    where = "" if include_demo else "WHERE is_demo = 0"
    and_ = (where + " AND") if where else "WHERE"
    with connection() as c:
        total, avg = c.execute(f"SELECT COUNT(*), AVG(risk_score) FROM investigations {where}").fetchone()
        threats = c.execute(f"SELECT COUNT(*) FROM investigations {and_} risk_score >= ?", (config.THREAT_THRESHOLD,)).fetchone()[0]
        high = c.execute(f"SELECT COUNT(*) FROM investigations {and_} risk_level IN ('High Risk','Critical Risk')").fetchone()[0]
        by_level = dict(c.execute(f"SELECT risk_level, COUNT(*) FROM investigations {where} GROUP BY risk_level").fetchall())
        by_type = dict(c.execute(f"SELECT input_type, COUNT(*) FROM investigations {where} GROUP BY input_type").fetchall())
        by_class = dict(c.execute(f"SELECT classification, COUNT(*) FROM investigations {where} GROUP BY classification "
                                  "ORDER BY COUNT(*) DESC LIMIT 8").fetchall())
        per_day = [tuple(r) for r in c.execute(f"SELECT substr(created_at,1,10), COUNT(*) FROM investigations {where} "
                                               "GROUP BY 1 ORDER BY 1").fetchall()]
        scores = [r[0] for r in c.execute(f"SELECT risk_score FROM investigations {where}").fetchall()]
    return {"total": total or 0, "threats": threats, "high_risk": high,
            "avg_score": round(avg, 1) if avg is not None else None, "by_level": by_level,
            "by_type": by_type, "by_class": by_class, "per_day": per_day, "scores": scores}


def delete_investigation(inv_id: str):
    with connection() as c:
        c.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))


def delete_demo_records() -> int:
    """Remove ONLY demonstration records; real investigations are untouched. Returns the number deleted."""
    with connection() as c:
        return c.execute("DELETE FROM investigations WHERE is_demo = 1").rowcount


def delete_all():
    with connection() as c:
        c.execute("DELETE FROM investigations")
